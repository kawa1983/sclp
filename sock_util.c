/*
 * sock_util.c : SCLP socket operation utilities
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

#include <asm/ioctls.h>
#include <linux/skbuff.h>
#include <linux/sclp.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/busy_poll.h>
#include "sclp_impl.h"


void sclp_close(struct sock *sk, long timeout)
{
    sk_common_release(sk);
}


static int do_sclp_setsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, unsigned int optlen)
{
    return 0;
}


static int do_sclp_getsockopt(struct sock *sk, int level, int optname,
			      char __user *optval, int __user *optlen)
{
    return 0;
}


int sclp_setsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, unsigned int optlen)
{
    if (level == SOL_SCLP) {
	return do_sclp_setsockopt(sk, level, optname, optval, optlen);
    }

    return ip_setsockopt(sk, level, optname, optval, optlen);
}


int sclp_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
    if (level == SOL_SCLP) {
	return do_sclp_getsockopt(sk, level, optname, optval, optlen);
    }

    return ip_getsockopt(sk, level, optname, optval, optlen);
}


#ifdef CONFIG_COMPAT
int compat_sclp_setsockopt(struct sock *sk, int level, int optname,
				  char __user *optval, unsigned int optlen)
{
    if (level == SOL_SCLP) {
	return do_sclp_setsockopt(sk, level, optname, optval, optlen);
    }

    return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}


int compat_sclp_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
    if (level == SOL_SCLP) {
	return do_sclp_getsockopt(sk, level, optname, optval, optlen);
    }

    return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif

/**
 *	first_packet_length	- return length of first packet in receive queue
 *	@sk: socket
 *
 *	Drops all bad checksum frames, until a valid one is found.
 *	Returns the length of found skb, or 0 if none is found.
 */
static unsigned int first_packet_length(struct sock *sk)
{
    struct sk_buff_head list_kill, *rcvq = &sk->sk_receive_queue;
    struct sk_buff *skb;
    unsigned int res;

    __skb_queue_head_init(&list_kill);

    spin_lock_bh(&rcvq->lock);
    while ((skb = skb_peek(rcvq)) != NULL) { 
	__skb_unlink(skb, rcvq);
	__skb_queue_tail(&list_kill, skb);
    }
    res = skb ? skb->len : 0;
    spin_unlock_bh(&rcvq->lock);

    if (!skb_queue_empty(&list_kill)) {
	lock_sock(sk);
	__skb_queue_purge(&list_kill);
	sk_mem_reclaim_partial(sk);
	release_sock(sk);
    }
    return res;
}


int sclp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
    switch (cmd) {
    case SIOCOUTQ:
    {
	int amount = sk_wmem_alloc_get(sk);

	return put_user(amount, (int __user *)arg);
    }
    case SIOCINQ:
    {
	unsigned int amount = first_packet_length(sk);

	if (amount)
	    amount -= sizeof(struct sclphdr);

	return put_user(amount, (int __user *)arg);
    }

    default:
	return -ENOIOCTLCMD;
    }

    return 0;
}
