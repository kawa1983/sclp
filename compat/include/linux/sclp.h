/*
 * sclp.h
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

#ifndef _LINUX_SCLP_H
#define _LINUX_SCLP_H

#include <linux/skbuff.h>
#include <net/inet_sock.h>
#include <uapi/linux/sclp.h>


static inline struct sclphdr *sclp_hdr(const struct sk_buff *skb)
{
    return (struct sclphdr*)skb_transport_header(skb);
}


struct sclp_sock
{
    struct inet_sock inet;
    int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
};


static inline struct sclp_sock *sclp_sk(const struct sock *sk)
{
    return (struct sclp_sock*)sk;
}

#endif /* _LINUX_SCLP_H */
