/**
 * @file mptcp.c
 * @brief Реализация поддержки MPTCP для OpenVPN DCO.
 * @details Этот файл содержит реализацию функций для обработки MPTCP-соединений,
 *          включая чтение, запись и управление сокетами в контексте
 *          ускорителя канала данных OpenVPN.
 *
 * @copyright Copyright (C) 2019-2023 OpenVPN, Inc.
 * @author Antonio Quartulli <antonio@openvpn.net> (Оригинальная реализация для TCP)
 * @author Ivan Pecherskiy <ipecherskiy@avo.tel> (Адаптация для MPTCP и доработки)
 */

#include "main.h"
#include "ovpnstruct.h"
#include "ovpn.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"
#include "tcp.h"

#include <linux/ptr_ring.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/mptcp.h>
#include <net/route.h>

/**
 * @var ovpn_mptcp_prot
 * @brief Структура протокола MPTCP для OpenVPN.
 * @details Копия стандартной структуры `mptcp_prot` с переопределенными
 *          колбэками `recvmsg` и `sock_is_readable` для пользовательской
 *          обработки.
 */
static struct proto ovpn_mptcp_prot;

/**
 * @brief Считывает данные из сокета MPTCP.
 * @details Колбэк для `read_descriptor_t`, который вызывается, когда в сокете
 *          появляются данные. Он считывает префикс с длиной пакета, а затем
 *          и сам пакет. Пакеты данных DATA_V2 обрабатываются в ядре,
 *          остальные передаются в пользовательское пространство.
 * @param desc Указатель на `read_descriptor_t`.
 * @param in_skb Входящий `sk_buff` с данными.
 * @param in_offset Смещение во входящем `sk_buff`.
 * @param in_len Длина доступных данных.
 * @return Количество скопированных байт.
 */
static int ovpn_mptcp_read_sock(read_descriptor_t *desc, struct sk_buff *in_skb,
			      unsigned int in_offset, size_t in_len)
{
	struct sock *sk = desc->arg.data;
	struct ovpn_socket *sock;
	struct ovpn_skb_cb *cb;
	struct ovpn_peer *peer;
	size_t chunk, copied = 0;
	int status;
	void *data;
	u16 len;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	rcu_read_unlock();

	if (unlikely(!sock || !sock->peer)) {
		pr_err("ovpn: read_sock triggered for socket with no metadata\n");
		desc->error = -EINVAL;
		return 0;
	}

	peer = sock->peer;

	while (in_len > 0) {
		/* Если skb не выделен, значит, мы должны прочитать (или закончить чтение)
         * 2-байтного префикса, содержащего фактический размер пакета.
		 */
		if (!peer->tcp.skb) {
			chunk = min_t(size_t, in_len, sizeof(u16) - peer->tcp.offset);
			WARN_ON(skb_copy_bits(in_skb, in_offset,
					      peer->tcp.raw_len + peer->tcp.offset, chunk) < 0);
			peer->tcp.offset += chunk;

			/* Продолжаем чтение, пока не получим весь размер пакета */
			if (peer->tcp.offset != sizeof(u16))
				goto next_read;

			len = ntohs(*(__be16 *)peer->tcp.raw_len);
			/* Неверная длина пакета: это фатальная ошибка TCP */
			if (!len) {
				netdev_err(peer->ovpn->dev, "%s: received invalid packet length: %d\n",
					   __func__, len);
				desc->error = -EINVAL;
				goto err;
			}

			/* Добавляем 2 байта к выделенному пространству (и сразу же их резервируем) для
             * предварения длины пакета, на случай, если skb нужно будет переслать в
             * пользовательское пространство
			 */
			peer->tcp.skb = netdev_alloc_skb_ip_align(peer->ovpn->dev,
								  len + sizeof(u16));
			if (!peer->tcp.skb) {
				desc->error = -ENOMEM;
				goto err;
			}
			skb_reserve(peer->tcp.skb, sizeof(u16));

			peer->tcp.offset = 0;
			peer->tcp.data_len = len;
		} else {
			chunk = min_t(size_t, in_len, peer->tcp.data_len - peer->tcp.offset);

			/* Расширяем skb для размещения нового фрагмента и копируем его из входного skb */
			data = skb_put(peer->tcp.skb, chunk);
			WARN_ON(skb_copy_bits(in_skb, in_offset, data, chunk) < 0);
			peer->tcp.offset += chunk;

			/* Продолжаем чтение, пока не получим полный пакет */
			if (peer->tcp.offset != peer->tcp.data_len)
				goto next_read;

			/* Не выполнять IP-кеширование для TCP-соединений */
			cb = OVPN_SKB_CB(peer->tcp.skb);
			cb->sa_fam = AF_UNSPEC;

			/* На данный момент мы знаем, что пакет пришел от сконфигурированного пира.
             * Пакеты DATA_V2 обрабатываются в пространстве ядра, остальные — в
             * пользовательском пространстве.
			 *
			 * Помещаем skb в очередь для отправки в пользовательское пространство через recvmsg на сокете
			 */
			if (likely(ovpn_opcode_from_skb(peer->tcp.skb, 0) == OVPN_DATA_V2)) {
				/* Удерживаем ссылку на пира, как того требует ovpn_recv().
				 *
				 * ПРИМЕЧАНИЕ: в данном контексте мы уже должны удерживать
				 * ссылку на этого пира, поэтому сбой ovpn_peer_hold()
				 * не ожидается
				 */
				WARN_ON(!ovpn_peer_hold(peer));
				status = ovpn_recv(peer->ovpn, peer, peer->tcp.skb);
				if (unlikely(status < 0))
					ovpn_peer_put(peer);

			} else {
				/* Добавляем в начало skb длину пакета. Таким образом,
                 * пользовательское пространство может разобрать пакет, как если бы
                 * он только что прибыл с удаленной конечной точки
				 */
				void *raw_len = __skb_push(peer->tcp.skb, sizeof(u16));
				memcpy(raw_len, peer->tcp.raw_len, sizeof(u16));

				status = ptr_ring_produce_bh(&peer->sock->recv_ring, peer->tcp.skb);
				if (likely(!status))
					peer->tcp.sk_cb.sk_data_ready(sk);
			}

			/* skb не был использован — освобождаем его сейчас */
			if (unlikely(status < 0))
				kfree_skb(peer->tcp.skb);

			peer->tcp.skb = NULL;
			peer->tcp.offset = 0;
			peer->tcp.data_len = 0;
		}
next_read:
		in_len -= chunk;
		in_offset += chunk;
		copied += chunk;
	}

	return copied;
err:
	netdev_err(peer->ovpn->dev, "cannot process incoming TCP data: %d\n", desc->error);
	ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
	return 0;
}

/**
 * @brief Колбэк, вызываемый, когда в MPTCP-сокете появляются данные для чтения.
 * @param sk Указатель на структуру `sock`.
 */
static void ovpn_mptcp_data_ready(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;
	read_descriptor_t desc;

	if (unlikely(!sock || !sock->ops || !sock->ops->read_sock))
		return;

	desc.arg.data = sk;
	desc.error = 0;
	desc.count = 1;

	sock->ops->read_sock(sk, &desc, ovpn_mptcp_read_sock);
}

/**
 * @brief Колбэк, вызываемый, когда в MPTCP-сокете появляется место для записи.
 * @details Ставит в очередь задачу `tx_work` для отправки данных из буфера.
 * @param sk Указатель на структуру `sock`.
 */
static void ovpn_mptcp_write_space(struct sock *sk)
{
	struct ovpn_socket *sock;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	rcu_read_unlock();

	if (!sock || !sock->peer)
		return;

	queue_work(sock->peer->ovpn->events_wq, &sock->peer->tcp.tx_work);
}

/**
 * @brief Проверяет, доступны ли данные для чтения в MPTCP-сокете.
 * @param sk Указатель на структуру `sock`.
 * @return `true`, если в кольцевом буфере `recv_ring` есть данные, иначе `false`.
 */
static bool ovpn_mptcp_sock_is_readable(
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9, 0)
				      const struct sock *sk
#else
				      struct sock *sk
#endif
				      )

{
	struct ovpn_socket *sock;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	rcu_read_unlock();

	if (!sock || !sock->peer)
		return false;

	return !ptr_ring_empty_bh(&sock->recv_ring);
}

/**
 * @brief Получает сообщение из MPTCP-сокета.
 * @details Реализация колбэка `recvmsg` для MPTCP-сокетов OpenVPN.
 *          Считывает данные из кольцевого буфера `recv_ring` в
 *          пользовательский буфер.
 * @param sk Указатель на структуру `sock`.
 * @param msg Указатель на `msghdr`, куда будут скопированы данные.
 * @param len Максимальный размер данных для копирования.
 * @param noblock (Устарело) Флаг неблокирующей операции.
 * @param flags Флаги операции.
 * @param addr_len Указатель для сохранения длины адреса.
 * @return Количество скопированных байт или код ошибки.
 */
static int ovpn_mptcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
			    int noblock,
#endif
			    int flags, int *addr_len)
{
	bool tmp = flags & MSG_DONTWAIT;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int ret, chunk, copied = 0;
	struct ovpn_socket *sock;
	struct sk_buff *skb;
	long timeo;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
	tmp = noblock;
#endif

	if (unlikely(flags & MSG_ERRQUEUE))
		return sock_recv_errqueue(sk, msg, len, SOL_IP, IP_RECVERR);

	timeo = sock_rcvtimeo(sk, tmp);

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	rcu_read_unlock();

	if (!sock || !sock->peer) {
		ret = -EBADF;
		goto unlock;
	}

	while (ptr_ring_empty_bh(&sock->recv_ring)) {
		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;

		if (sock_flag(sk, SOCK_DONE))
			return 0;

		if (!timeo) {
			ret = -EAGAIN;
			goto unlock;
		}

		add_wait_queue(sk_sleep(sk), &wait);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		sk_wait_event(sk, &timeo, !ptr_ring_empty_bh(&sock->recv_ring), &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		remove_wait_queue(sk_sleep(sk), &wait);

		/* Обработка сигналов */
		if (signal_pending(current)) {
			ret = sock_intr_errno(timeo);
			goto unlock;
		}
	}

	while (len && (skb = __ptr_ring_peek(&sock->recv_ring))) {
		chunk = min_t(size_t, len, skb->len);
		ret = skb_copy_datagram_msg(skb, 0, msg, chunk);
		if (ret < 0) {
			pr_err("ovpn: cannot copy TCP data to userspace: %d\n", ret);
			kfree_skb(skb);
			goto unlock;
		}

		__skb_pull(skb, chunk);

		if (!skb->len) {
			/* skb был полностью использован и теперь может быть удален из кольца */
			__ptr_ring_discard_one(&sock->recv_ring);
			consume_skb(skb);
		}

		len -= chunk;
		copied += chunk;
	}
	ret = copied;

unlock:
	return ret ? : -EAGAIN;
}

/**
 * @brief Уничтожает (освобождает) skb.
 * @details Используется как колбэк для очистки кольцевого буфера.
 * @param skb Указатель на skb для освобождения.
 */
static void ovpn_destroy_skb(void *skb)
{
	consume_skb(skb);
}

/**
 * @brief Отсоединяет сокет MPTCP от пира.
 * @details Восстанавливает оригинальные колбэки сокета, отменяет все
 *          запланированные задачи и очищает кольцевые буферы приема и передачи.
 * @param sock Указатель на структуру `socket` для отсоединения.
 */
void ovpn_mptcp_socket_detach(struct socket *sock)
{
	struct ovpn_socket *ovpn_sock;
	struct ovpn_peer *peer;

	if (!sock)
		return;

	rcu_read_lock();
	ovpn_sock = rcu_dereference_sk_user_data(sock->sk);
	rcu_read_unlock();

	if (!ovpn_sock->peer)
		return;

	peer = ovpn_sock->peer;

	/* Восстанавливаем колбэки, которые были сохранены в ovpn_mptcp_socket_attach() */
	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready = peer->tcp.sk_cb.sk_data_ready;
	sock->sk->sk_write_space = peer->tcp.sk_cb.sk_write_space;
	sock->sk->sk_prot = peer->tcp.sk_cb.prot;
	rcu_assign_sk_user_data(sock->sk, NULL);
	write_unlock_bh(&sock->sk->sk_callback_lock);

	/* Отменяем все текущие задачи. Выполняется после удаления колбэков,
     * чтобы эти рабочие процессы не могли быть перезапущены
	 */
	cancel_work_sync(&peer->tcp.tx_work);

	ptr_ring_cleanup(&ovpn_sock->recv_ring, ovpn_destroy_skb);
	ptr_ring_cleanup(&peer->tcp.tx_ring, ovpn_destroy_skb);
}

/**
 * @brief Пытается отправить один skb (или его часть) через поток TCP.
 * @param peer Указатель на пира-получателя.
 * @param skb Указатель на `sk_buff` для отправки.
 * @return 0 в случае успеха или отрицательный код ошибки.
 * @note skb изменяется, удаляя отправленные данные. Вызывающая
 *       сторона должна проверить, равен ли `skb->len` нулю, чтобы
 *       понять, был ли отправлен весь skb.
 */
static int ovpn_mptcp_send_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iv = { 0 };
	int ret;

	if (skb_linearize(skb) < 0) {
		net_err_ratelimited("%s: can't linearize packet\n", __func__);
		return -ENOMEM;
	}

	/* Инициализируем структуру iv сейчас, так как skb_linearize() мог изменить skb->data */
	iv.iov_base = skb->data;
	iv.iov_len = skb->len;

	ret = kernel_sendmsg(peer->sock->sock, &msg, &iv, 1, iv.iov_len);
	if (ret > 0) {
		__skb_pull(skb, ret);

		/* Поскольку мы обновляем статистику для каждого CPU в контексте процесса,
         * нам нужно отключить softirqs
		 */
		local_bh_disable();
		dev_sw_netstats_tx_add(peer->ovpn->dev, 1, ret);
		local_bh_enable();

		return 0;
	}

	return ret;
}

/**
 * @brief Обрабатывает пакеты в очереди передачи TCP.
 * @details Рабочая функция (work function), которая извлекает пакеты из
 *          очереди `tx_ring` и отправляет их с помощью `ovpn_mptcp_send_one`.
 * @param work Указатель на `work_struct`.
 */
static void ovpn_mptcp_tx_work(struct work_struct *work)
{
	struct ovpn_peer *peer;
	struct sk_buff *skb;
	int ret;

	peer = container_of(work, struct ovpn_peer, tcp.tx_work);
	while ((skb = __ptr_ring_peek(&peer->tcp.tx_ring))) {
		ret = ovpn_mptcp_send_one(peer, skb);
		if (ret < 0 && ret != -EAGAIN) {
			net_warn_ratelimited("%s: cannot send TCP packet to peer %u: %d\n", __func__,
					    peer->id, ret);
			/* В случае ошибки TCP останавливаем цикл отправки и удаляем пира */
			ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
			break;
		} else if (!skb->len) {
			/* skb был полностью использован и теперь может быть удален из кольца */
			__ptr_ring_discard_one(&peer->tcp.tx_ring);
			consume_skb(skb);
		}

		/* Даем возможность перепланировщику, если необходимо */
		cond_resched();
	}
}

/**
 * @brief Помещает пакет в очередь передачи TCP и планирует его обработку.
 * @param peer Указатель на пира-получателя.
 * @param skb Указатель на `sk_buff` для отправки.
 */
void ovpn_queue_mptcp_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	int ret;

	ret = ptr_ring_produce_bh(&peer->tcp.tx_ring, skb);
	if (ret < 0) {
		kfree_skb_list(skb);
		return;
	}

	queue_work(peer->ovpn->events_wq, &peer->tcp.tx_work);
}

/**
 * @brief Присоединяет сокет MPTCP к пиру и устанавливает колбэки.
 * @details Инициализирует очередь передачи, сохраняет существующие колбэки
 *          сокета и устанавливает кастомные обработчики для MPTCP.
 *          Проверяет, что сокет является MPTCP и находится в состоянии ESTABLISHED.
 * @param sock Указатель на MPTCP-сокет.
 * @param peer Указатель на пира, к которому присоединяется сокет.
 * @return 0 в случае успеха, или код ошибки в противном случае.
 */
int ovpn_mptcp_socket_attach(struct socket *sock, struct ovpn_peer *peer)
{
	void *old_data;
	int ret;

	INIT_WORK(&peer->tcp.tx_work, ovpn_mptcp_tx_work);

	ret = ptr_ring_init(&peer->tcp.tx_ring, OVPN_QUEUE_LEN, GFP_KERNEL);
	if (ret < 0) {
		netdev_err(peer->ovpn->dev, "cannot allocate TCP TX ring\n");
		return ret;
	}

	peer->tcp.skb = NULL;
	peer->tcp.offset = 0;
	peer->tcp.data_len = 0;

	write_lock_bh(&sock->sk->sk_callback_lock);

	/* Убеждаемся, что не существует ранее установленного обработчика инкапсуляции */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(sock->sk);
	rcu_read_unlock();
	if (old_data) {
		netdev_err(peer->ovpn->dev, "provided socket already taken by other user\n");
		ret = -EBUSY;
		goto err;
	}

	/* Проверка на корректность */
	if (sock->sk->sk_protocol != IPPROTO_MPTCP) {
		netdev_err(peer->ovpn->dev, "provided socket is not MPTCP\n");
		ret = -EINVAL;
		goto err;
	}

	/* Ожидается только полностью установленный сокет.
     * Соединение должно обрабатываться в пользовательском пространстве.
	 */
	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		netdev_err(peer->ovpn->dev, "provided MPTCP socket is not in ESTABLISHED state: %d\n",
			   sock->sk->sk_state);
		ret = -EINVAL;
		goto err;
	}

	/* Сохраняем текущие колбэки, чтобы их можно было восстановить при освобождении сокета */
	peer->tcp.sk_cb.sk_data_ready = sock->sk->sk_data_ready;
	peer->tcp.sk_cb.sk_write_space = sock->sk->sk_write_space;
	peer->tcp.sk_cb.prot = sock->sk->sk_prot;

	/* Назначаем наши статические колбэки */
	sock->sk->sk_data_ready = ovpn_mptcp_data_ready;
	sock->sk->sk_write_space = ovpn_mptcp_write_space;
	sock->sk->sk_prot = &ovpn_mptcp_prot;

	write_unlock_bh(&sock->sk->sk_callback_lock);

	return 0;
err:
	write_unlock_bh(&sock->sk->sk_callback_lock);
	ptr_ring_cleanup(&peer->tcp.tx_ring, NULL);

	return ret;
}

/**
 * @brief Инициализирует подсистему MPTCP.
 * @details Создает кастомную структуру протокола `ovpn_mptcp_prot`,
 *          копируя `mptcp_prot` и переопределяя колбэки `recvmsg` и
 *          `sock_is_readable` для интеграции с OpenVPN.
 * @return Всегда возвращает 0.
 */
int __init ovpn_mptcp_init(void)
{
	/* Нам нужно заменить колбэки recvmsg и sock_is_readable
     * в члене sk_prot объекта sock для TCP-сокетов.
	 *
	 * Однако sock->sk_prot является указателем на статическую переменную,
     * и поэтому мы не можем напрямую изменять ее, иначе все сокеты,
     * указывающие на нее, будут затронуты.
	 *
	 * По этой причине мы создаем нашу собственную статическую копию и
     * изменяем то, что нам нужно. Затем мы делаем так, чтобы sk_prot
     * указывал на эту копию (в ovpn_mptcp_socket_attach()).
	 */
	ovpn_mptcp_prot = mptcp_prot;
	ovpn_mptcp_prot.recvmsg = ovpn_mptcp_recvmsg;
	ovpn_mptcp_prot.sock_is_readable = ovpn_mptcp_sock_is_readable;

	return 0;
}