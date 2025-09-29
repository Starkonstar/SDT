/**
 * @file mptcp.c
 * @brief ���������� ��������� MPTCP ��� OpenVPN DCO.
 * @details ���� ���� �������� ���������� ������� ��� ��������� MPTCP-����������,
 *          ������� ������, ������ � ���������� �������� � ���������
 *          ���������� ������ ������ OpenVPN.
 *
 * @copyright Copyright (C) 2019-2023 OpenVPN, Inc.
 * @author Antonio Quartulli <antonio@openvpn.net> (������������ ���������� ��� TCP)
 * @author Ivan Pecherskiy <ipecherskiy@avo.tel> (��������� ��� MPTCP � ���������)
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
 * @brief ��������� ��������� MPTCP ��� OpenVPN.
 * @details ����� ����������� ��������� `mptcp_prot` � �����������������
 *          ��������� `recvmsg` � `sock_is_readable` ��� ����������������
 *          ���������.
 */
static struct proto ovpn_mptcp_prot;

/**
 * @brief ��������� ������ �� ������ MPTCP.
 * @details ������ ��� `read_descriptor_t`, ������� ����������, ����� � ������
 *          ���������� ������. �� ��������� ������� � ������ ������, � �����
 *          � ��� �����. ������ ������ DATA_V2 �������������� � ����,
 *          ��������� ���������� � ���������������� ������������.
 * @param desc ��������� �� `read_descriptor_t`.
 * @param in_skb �������� `sk_buff` � �������.
 * @param in_offset �������� �� �������� `sk_buff`.
 * @param in_len ����� ��������� ������.
 * @return ���������� ������������� ����.
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
		/* ���� skb �� �������, ������, �� ������ ��������� (��� ��������� ������)
         * 2-�������� ��������, ����������� ����������� ������ ������.
		 */
		if (!peer->tcp.skb) {
			chunk = min_t(size_t, in_len, sizeof(u16) - peer->tcp.offset);
			WARN_ON(skb_copy_bits(in_skb, in_offset,
					      peer->tcp.raw_len + peer->tcp.offset, chunk) < 0);
			peer->tcp.offset += chunk;

			/* ���������� ������, ���� �� ������� ���� ������ ������ */
			if (peer->tcp.offset != sizeof(u16))
				goto next_read;

			len = ntohs(*(__be16 *)peer->tcp.raw_len);
			/* �������� ����� ������: ��� ��������� ������ TCP */
			if (!len) {
				netdev_err(peer->ovpn->dev, "%s: received invalid packet length: %d\n",
					   __func__, len);
				desc->error = -EINVAL;
				goto err;
			}

			/* ��������� 2 ����� � ����������� ������������ (� ����� �� �� �����������) ���
             * ����������� ����� ������, �� ������, ���� skb ����� ����� ��������� �
             * ���������������� ������������
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

			/* ��������� skb ��� ���������� ������ ��������� � �������� ��� �� �������� skb */
			data = skb_put(peer->tcp.skb, chunk);
			WARN_ON(skb_copy_bits(in_skb, in_offset, data, chunk) < 0);
			peer->tcp.offset += chunk;

			/* ���������� ������, ���� �� ������� ������ ����� */
			if (peer->tcp.offset != peer->tcp.data_len)
				goto next_read;

			/* �� ��������� IP-����������� ��� TCP-���������� */
			cb = OVPN_SKB_CB(peer->tcp.skb);
			cb->sa_fam = AF_UNSPEC;

			/* �� ������ ������ �� �����, ��� ����� ������ �� ������������������� ����.
             * ������ DATA_V2 �������������� � ������������ ����, ��������� � �
             * ���������������� ������������.
			 *
			 * �������� skb � ������� ��� �������� � ���������������� ������������ ����� recvmsg �� ������
			 */
			if (likely(ovpn_opcode_from_skb(peer->tcp.skb, 0) == OVPN_DATA_V2)) {
				/* ���������� ������ �� ����, ��� ���� ������� ovpn_recv().
				 *
				 * ����������: � ������ ��������� �� ��� ������ ����������
				 * ������ �� ����� ����, ������� ���� ovpn_peer_hold()
				 * �� ���������
				 */
				WARN_ON(!ovpn_peer_hold(peer));
				status = ovpn_recv(peer->ovpn, peer, peer->tcp.skb);
				if (unlikely(status < 0))
					ovpn_peer_put(peer);

			} else {
				/* ��������� � ������ skb ����� ������. ����� �������,
                 * ���������������� ������������ ����� ��������� �����, ��� ���� ��
                 * �� ������ ��� ������ � ��������� �������� �����
				 */
				void *raw_len = __skb_push(peer->tcp.skb, sizeof(u16));
				memcpy(raw_len, peer->tcp.raw_len, sizeof(u16));

				status = ptr_ring_produce_bh(&peer->sock->recv_ring, peer->tcp.skb);
				if (likely(!status))
					peer->tcp.sk_cb.sk_data_ready(sk);
			}

			/* skb �� ��� ����������� � ����������� ��� ������ */
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
 * @brief ������, ����������, ����� � MPTCP-������ ���������� ������ ��� ������.
 * @param sk ��������� �� ��������� `sock`.
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
 * @brief ������, ����������, ����� � MPTCP-������ ���������� ����� ��� ������.
 * @details ������ � ������� ������ `tx_work` ��� �������� ������ �� ������.
 * @param sk ��������� �� ��������� `sock`.
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
 * @brief ���������, �������� �� ������ ��� ������ � MPTCP-������.
 * @param sk ��������� �� ��������� `sock`.
 * @return `true`, ���� � ��������� ������ `recv_ring` ���� ������, ����� `false`.
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
 * @brief �������� ��������� �� MPTCP-������.
 * @details ���������� ������� `recvmsg` ��� MPTCP-������� OpenVPN.
 *          ��������� ������ �� ���������� ������ `recv_ring` �
 *          ���������������� �����.
 * @param sk ��������� �� ��������� `sock`.
 * @param msg ��������� �� `msghdr`, ���� ����� ����������� ������.
 * @param len ������������ ������ ������ ��� �����������.
 * @param noblock (��������) ���� ������������� ��������.
 * @param flags ����� ��������.
 * @param addr_len ��������� ��� ���������� ����� ������.
 * @return ���������� ������������� ���� ��� ��� ������.
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

		/* ��������� �������� */
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
			/* skb ��� ��������� ����������� � ������ ����� ���� ������ �� ������ */
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
 * @brief ���������� (�����������) skb.
 * @details ������������ ��� ������ ��� ������� ���������� ������.
 * @param skb ��������� �� skb ��� ������������.
 */
static void ovpn_destroy_skb(void *skb)
{
	consume_skb(skb);
}

/**
 * @brief ����������� ����� MPTCP �� ����.
 * @details ��������������� ������������ ������� ������, �������� ���
 *          ��������������� ������ � ������� ��������� ������ ������ � ��������.
 * @param sock ��������� �� ��������� `socket` ��� ������������.
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

	/* ��������������� �������, ������� ���� ��������� � ovpn_mptcp_socket_attach() */
	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_data_ready = peer->tcp.sk_cb.sk_data_ready;
	sock->sk->sk_write_space = peer->tcp.sk_cb.sk_write_space;
	sock->sk->sk_prot = peer->tcp.sk_cb.prot;
	rcu_assign_sk_user_data(sock->sk, NULL);
	write_unlock_bh(&sock->sk->sk_callback_lock);

	/* �������� ��� ������� ������. ����������� ����� �������� ��������,
     * ����� ��� ������� �������� �� ����� ���� ������������
	 */
	cancel_work_sync(&peer->tcp.tx_work);

	ptr_ring_cleanup(&ovpn_sock->recv_ring, ovpn_destroy_skb);
	ptr_ring_cleanup(&peer->tcp.tx_ring, ovpn_destroy_skb);
}

/**
 * @brief �������� ��������� ���� skb (��� ��� �����) ����� ����� TCP.
 * @param peer ��������� �� ����-����������.
 * @param skb ��������� �� `sk_buff` ��� ��������.
 * @return 0 � ������ ������ ��� ������������� ��� ������.
 * @note skb ����������, ������ ������������ ������. ����������
 *       ������� ������ ���������, ����� �� `skb->len` ����, �����
 *       ������, ��� �� ��������� ���� skb.
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

	/* �������������� ��������� iv ������, ��� ��� skb_linearize() ��� �������� skb->data */
	iv.iov_base = skb->data;
	iv.iov_len = skb->len;

	ret = kernel_sendmsg(peer->sock->sock, &msg, &iv, 1, iv.iov_len);
	if (ret > 0) {
		__skb_pull(skb, ret);

		/* ��������� �� ��������� ���������� ��� ������� CPU � ��������� ��������,
         * ��� ����� ��������� softirqs
		 */
		local_bh_disable();
		dev_sw_netstats_tx_add(peer->ovpn->dev, 1, ret);
		local_bh_enable();

		return 0;
	}

	return ret;
}

/**
 * @brief ������������ ������ � ������� �������� TCP.
 * @details ������� ������� (work function), ������� ��������� ������ ��
 *          ������� `tx_ring` � ���������� �� � ������� `ovpn_mptcp_send_one`.
 * @param work ��������� �� `work_struct`.
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
			/* � ������ ������ TCP ������������� ���� �������� � ������� ���� */
			ovpn_peer_del(peer, OVPN_DEL_PEER_REASON_TRANSPORT_ERROR);
			break;
		} else if (!skb->len) {
			/* skb ��� ��������� ����������� � ������ ����� ���� ������ �� ������ */
			__ptr_ring_discard_one(&peer->tcp.tx_ring);
			consume_skb(skb);
		}

		/* ���� ����������� ����������������, ���� ���������� */
		cond_resched();
	}
}

/**
 * @brief �������� ����� � ������� �������� TCP � ��������� ��� ���������.
 * @param peer ��������� �� ����-����������.
 * @param skb ��������� �� `sk_buff` ��� ��������.
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
 * @brief ������������ ����� MPTCP � ���� � ������������� �������.
 * @details �������������� ������� ��������, ��������� ������������ �������
 *          ������ � ������������� ��������� ����������� ��� MPTCP.
 *          ���������, ��� ����� �������� MPTCP � ��������� � ��������� ESTABLISHED.
 * @param sock ��������� �� MPTCP-�����.
 * @param peer ��������� �� ����, � �������� �������������� �����.
 * @return 0 � ������ ������, ��� ��� ������ � ��������� ������.
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

	/* ����������, ��� �� ���������� ����� �������������� ����������� ������������ */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(sock->sk);
	rcu_read_unlock();
	if (old_data) {
		netdev_err(peer->ovpn->dev, "provided socket already taken by other user\n");
		ret = -EBUSY;
		goto err;
	}

	/* �������� �� ������������ */
	if (sock->sk->sk_protocol != IPPROTO_MPTCP) {
		netdev_err(peer->ovpn->dev, "provided socket is not MPTCP\n");
		ret = -EINVAL;
		goto err;
	}

	/* ��������� ������ ��������� ������������� �����.
     * ���������� ������ �������������� � ���������������� ������������.
	 */
	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		netdev_err(peer->ovpn->dev, "provided MPTCP socket is not in ESTABLISHED state: %d\n",
			   sock->sk->sk_state);
		ret = -EINVAL;
		goto err;
	}

	/* ��������� ������� �������, ����� �� ����� ���� ������������ ��� ������������ ������ */
	peer->tcp.sk_cb.sk_data_ready = sock->sk->sk_data_ready;
	peer->tcp.sk_cb.sk_write_space = sock->sk->sk_write_space;
	peer->tcp.sk_cb.prot = sock->sk->sk_prot;

	/* ��������� ���� ����������� ������� */
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
 * @brief �������������� ���������� MPTCP.
 * @details ������� ��������� ��������� ��������� `ovpn_mptcp_prot`,
 *          ������� `mptcp_prot` � ������������� ������� `recvmsg` �
 *          `sock_is_readable` ��� ���������� � OpenVPN.
 * @return ������ ���������� 0.
 */
int __init ovpn_mptcp_init(void)
{
	/* ��� ����� �������� ������� recvmsg � sock_is_readable
     * � ����� sk_prot ������� sock ��� TCP-�������.
	 *
	 * ������ sock->sk_prot �������� ���������� �� ����������� ����������,
     * � ������� �� �� ����� �������� �������� ��, ����� ��� ������,
     * ����������� �� ���, ����� ���������.
	 *
	 * �� ���� ������� �� ������� ���� ����������� ����������� ����� �
     * �������� ��, ��� ��� �����. ����� �� ������ ���, ����� sk_prot
     * �������� �� ��� ����� (� ovpn_mptcp_socket_attach()).
	 */
	ovpn_mptcp_prot = mptcp_prot;
	ovpn_mptcp_prot.recvmsg = ovpn_mptcp_recvmsg;
	ovpn_mptcp_prot.sock_is_readable = ovpn_mptcp_sock_is_readable;

	return 0;
}