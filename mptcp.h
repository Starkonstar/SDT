/**
 * @file mptcp.h
 * @brief ������������ ���� ��� ��������� MPTCP � OpenVPN DCO.
 * @details ��� ���������� OpenVPN-DCO ��� ��������� MPTCP. ��� ���������� ����������
 *          ��� ������������� MPTCP, ���������� �������� � ��������/��������� �������
 *          �� MPTCP-�����������.
 *
 * @copyright Copyright (C) 2019-2023 OpenVPN, Inc.
 * @author Antonio Quartulli <antonio@openvpn.net> (������������ ���������� ��� TCP)
 * @author Ivan Pecherskiy <ipecherskiy@avo.tel> (��������� ��� MPTCP � ���������)
 */

#ifndef _NET_OVPN_DCO_MPTCP_H_
#define _NET_OVPN_DCO_MPTCP_H_

#include "peer.h"

#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/**
 * @brief �������������� ����������� ������� MPTCP.
 * @details ��� ������� ������ ���� ������� ��� ������������� ������ ���
 *          ��������� ����������� �������� ������ ��� ��������� MPTCP.
 * @return 0 � ������ ������, ��� ��� ������ � ��������� ������.
 */
int __init ovpn_mptcp_init(void);

/**
 * @brief �������� skb � ������� ��� �������� ����� MPTCP.
 * @param peer ��������� �� ��������� `ovpn_peer`, �������������� ���������� ����.
 * @param skb ��������� �� `sk_buff`, ���������� ����� ��� ��������.
 */
void ovpn_queue_mptcp_skb(struct ovpn_peer *peer, struct sk_buff *skb);

/**
 * @brief ������������ ����� MPTCP � ���� OpenVPN.
 * @details ����������� ������� ������ ��� ��������� MPTCP-�������
 *          ��� ���������� ����.
 * @param sock ��������� �� ��������� `socket`, �������������� MPTCP-�����.
 * @param peer ��������� �� ��������� `ovpn_peer`, � ������� �������������� �����.
 * @return 0 � ������ ������, ��� ��� ������ � ��������� ������.
 */
int ovpn_mptcp_socket_attach(struct socket *sock, struct ovpn_peer *peer);

/**
 * @brief ����������� ����� MPTCP �� ���� OpenVPN.
 * @details ��������������� �������� ������� ������ � �������
 *          �������, ��������� � MPTCP.
 * @param sock ��������� �� ��������� `socket`, ������� ����� �����������.
 */
void ovpn_mptcp_socket_detach(struct socket *sock);

/**
 * @brief �������������� � �������� skb � ������� ��� �������� ����.
 * @details ���������� ����������� � ���������� ������� �������� �������� skb
 *          � ������ ������. ��� ��������� ���������� OpenVPN ���
 *          ���������� ������� �� ������ MPTCP �� ������� ����������.
 * @param peer ��������� �� ��������� `ovpn_peer`, �������������� ���������� ����.
 * @param skb ��������� �� `sk_buff`, ���������� ����� ��� ��������.
 */
static inline void ovpn_mptcp_send_skb(struct ovpn_peer *peer, struct sk_buff *skb)
{
	u16 len = skb->len;

	*(__be16 *)__skb_push(skb, sizeof(u16)) = htons(len);
	ovpn_queue_mptcp_skb(peer, skb);
}

#endif /* _NET_OVPN_DCO_MPTCP_H_ */