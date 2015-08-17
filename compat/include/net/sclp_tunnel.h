/*
 * sclp_tunnel.h : Tunneling interface definition
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

#ifndef __NET_SCLP_TUNNEL_H
#define __NET_SCLP_TUNNEL_H

#include <net/ip_tunnels.h>

struct sclp_port_cfg {
    u8 family;
 
    /* Used only for kernel-created sockets */
    union {
	struct in_addr local_ip;
    };
 
    union {
	struct in_addr peer_ip;
    };
 
    __be16 local_sclp_port;
    __be16 peer_sclp_port;
};


int sclp_sock_create4(struct net *net, struct sclp_port_cfg *cfg, struct socket **sockp);


static inline int sclp_sock_create(struct net *net,
				   struct sclp_port_cfg *cfg,
                                   struct socket **sockp)
{
    if (cfg->family == AF_INET)
	return sclp_sock_create4(net, cfg, sockp);
 
    return -EPFNOSUPPORT;
}

typedef int (*sclp_tunnel_encap_rcv_t)(struct sock *sk, struct sk_buff *skb);


struct sclp_tunnel_sock_cfg {
    sclp_tunnel_encap_rcv_t encap_rcv;
};
 

/* Setup the given (SCLP) sock to receive SCLP encapsulated packets */
void setup_sclp_tunnel_sock(struct net *net, struct socket *sock,
                            struct sclp_tunnel_sock_cfg *sock_cfg);

 
/* Transmit the skb using SCLP encapsulation. */
int sclp_tunnel_xmit_skb(struct sk_buff *skb, struct rtable *rt,
                         __be32 src, __be32 dst, __u8 tos, __u8 ttl,
                         __be16 df, __be16 src_port, __be16 dst_port);
 
 
void sclp_tunnel_sock_release(struct socket *sock);


#endif /* __NET_SCLP_TUNNEL_H */
