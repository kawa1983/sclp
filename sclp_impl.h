/*
 * sclp_impl.h : Common use functions
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

#ifndef __SCLP4_IMPL_H
#define __SCLP4_IMPL_H

#include <net/protocol.h>
#include <net/inet_common.h>

struct udp_table;

extern struct udp_table sclp_table;


extern void sclp_close(struct sock *sk, long timeout);

extern int sclp_setsockopt(struct sock *sk, int level, int optname,
						   char __user *optval, unsigned int optlen);

extern int sclp_getsockopt(struct sock *sk, int level, int optname,
						   char __user *optval, int __user *optlen);

#ifdef CONFIG_COMPAT
extern int compat_sclp_setsockopt(struct sock *sk, int level, int optname,
								  char __user *optval, unsigned int optlen);

extern int compat_sclp_getsockopt(struct sock *sk, int level, int optname,
								  char __user *optval, int __user *optlen);
#endif

extern int sclp_ioctl(struct sock *sk, int cmd, unsigned long arg);

extern void sclp_set_header(struct sk_buff *skb, __be16 dport, __be16 sport,  size_t l3_hlen, size_t mtu);

extern int sclp_output(struct sock *sk, struct dst_entry *entry, __be16 dport,
					   __be16 sport, size_t l3_hlen, struct msghdr *msg, size_t len,
					   int (*xmit_skb)(struct sk_buff *skb, struct sock *sk, void *argp),
					   void *argp);

extern int sclp_check_csum(struct sk_buff *skb);

extern int sclp_rcv(struct sock *sk, struct sk_buff *skb);

extern int sclp4_init(void);

extern void sclp4_exit(void);

extern int sclp_offload_init(void);

extern void sclp_offload_exit(void);

#endif	/* __SCLP4_IMPL_H */
