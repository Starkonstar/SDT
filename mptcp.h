/**
 * @file mptcp.h
 * @brief Заголовочный файл для поддержки MPTCP в OpenVPN DCO.
 * @details Это дополнение OpenVPN-DCO для поддержки MPTCP. Оно определяет интерфейсы
 *          для инициализации MPTCP, управления сокетами и отправки/получения пакетов
 *          по MPTCP-соединениям.
 *
 * @copyright Copyright (C) 2019-2023 OpenVPN, Inc.
 * @author Antonio Quartulli <antonio@openvpn.net> (Оригинальная реализация для TCP)
 * @author Ivan Pecherskiy <ipecherskiy@avo.tel> (Адаптация для MPTCP и доработки)
 */

#ifndef _NET_OVPN_DCO_MPTCP_H_
#define _NET_OVPN_DCO_MPTCP_H_

#include "peer.h"

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/**
 * @brief Инициализирует статические объекты MPTCP.
 * @details Эта функция должна быть вызвана при инициализации модуля для
 *          настройки необходимых структур данных для поддержки MPTCP.
 * @return 0 в случае успеха, или код ошибки в противном случае.
 */
int __init ovpn_mptcp_init(void);

/**
 * @brief Помещает skb в очередь для отправки через MPTCP.
 * @param peer Указатель на структуру `ovpn_peer`, представляющую удаленного пира.
 * @param skb Указатель на `sk_buff`, содержащий пакет для отправки.
 */
void ovpn_queue_mptcp_skb(struct ovpn_peer *peer, struct sk_buff *skb);

/**
 * @brief Присоединяет сокет MPTCP к пиру OpenVPN.
 * @details Настраивает колбэки сокета для обработки MPTCP-трафика
 *          для указанного пира.
 * @param sock Указатель на структуру `socket`, представляющую MPTCP-сокет.
 * @param peer Указатель на структуру `ovpn_peer`, к которой присоединяется сокет.
 * @return 0 в случае успеха, или код ошибки в противном случае.
 */
int ovpn_mptcp_socket_attach(struct socket *sock, struct ovpn_peer *peer);

/**
 * @brief Отсоединяет сокет MPTCP от пира OpenVPN.
 * @details Восстанавливает исходные колбэки сокета и очищает
 *          ресурсы, связанные с MPTCP.
 * @param sock Указатель на структуру `socket`, которую нужно отсоединить.
 */
void ovpn_mptcp_socket_detach(struct socket *sock);

/**
 * @brief Подготавливает и помещает skb в очередь для отправки пиру.
 * @details Подготовка заключается в добавлении размера полезной нагрузки skb
 *          в начало пакета. Это требуется протоколом OpenVPN для
 *          извлечения пакетов из потока MPTCP на стороне получателя.
 * @param peer Указатель на структуру `ovpn_peer`, представляющую удаленного пира.
 * @param skb Указатель на `sk_buff`, содержащий пакет для отправки.
 */
static inline void ovpn_mptcp_send_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	u16 len = skb->len;

	*(__be16 *)__skb_push(skb, sizeof(u16)) = htons(len);
	ovpn_queue_mptcp_skb(peer, skb);
}

#endif /* _NET_OVPN_DCO_MPTCP_H_ */