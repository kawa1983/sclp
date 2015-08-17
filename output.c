/*
 * output.c : SCLP protocol
 * 
 * Copyright 2015 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/sclp.h>
#include <net/net_namespace.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/checksum.h>
#include "sclp_impl.h"


static void sclp_set_gso(struct sk_buff *skb, size_t l3_hlen, size_t mtu)
{
    if (skb->sk->sk_family == AF_INET)
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
    else if (skb->sk->sk_family == AF_INET6)
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
    else
	BUG_ON(1);

    skb_shinfo(skb)->gso_size = mtu - l3_hlen - sizeof(struct sclphdr);
    skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
}


static void sclp_set_payload(struct sk_buff *skb, struct msghdr *msg, size_t len)
{
    size_t copied;
    int i;

    skb_put(skb, len);
    copied = 0;

    for (i = 0; i < msg->msg_iovlen; i++) {
	memcpy(&skb->data[copied], msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
	copied += msg->msg_iov[i].iov_len;
    }
}


void sclp_set_header(struct sk_buff *skb, __be16 dport, __be16 sport, size_t l3_hlen, size_t mtu)
{
    struct sclphdr *sclph;
    __u32 id;

    skb_push(skb, sizeof(struct sclphdr));
    skb_reset_transport_header(skb);

    get_random_bytes(&id, sizeof(id));

    /*
     * Create an SCLP header
     */
    sclph = sclp_hdr(skb);
    sclph->source = sport;
    sclph->dest = dport;
    sclph->id = id & htonl(SCLP_ID_MASK);
    sclph->rem = 0;
    sclph->check = 0;

    sclp_set_first_segment(sclph);

    if (skb->len + l3_hlen > mtu) {
	sclp_set_gso(skb, l3_hlen, mtu);
	skb->ip_summed = CHECKSUM_PARTIAL;
    } else {
	off_t offset = skb_transport_offset(skb);
	sclph->check = csum_fold(skb_checksum(skb, offset, skb->len - offset, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
    }
}


int sclp_output(struct sock *sk, struct dst_entry *entry, __be16 dport, __be16 sport, 
		size_t l3_hlen, struct msghdr *msg, size_t len,
		int (*xmit_skb)(struct sk_buff *skb, struct sock *sk, struct dst_entry *entry))
{
    struct sk_buff *skb;
    size_t slen;
    int err;

    slen = LL_RESERVED_SPACE(entry->dev) + l3_hlen + sk->sk_prot->max_header + len;

    skb = sock_alloc_send_skb(sk, slen, (msg->msg_flags & MSG_DONTWAIT), &err);

    err = PTR_ERR(skb);
    if (!skb || IS_ERR(skb))
	goto out;

    skb_reserve(skb, slen - len);

    if (sk->sk_state != TCP_ESTABLISHED) {
	skb_dst_drop(skb);
	skb_dst_set(skb, dst_clone(entry));
    }

    sclp_set_payload(skb, msg, len);

    sclp_set_header(skb, dport, sport, l3_hlen, entry->dev->mtu);

    err = xmit_skb(skb, sk, entry);

out:
    return err;
}
