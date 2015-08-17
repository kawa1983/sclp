/*
 * tunnel.c : SCLP tunneling
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
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/sclp.h>
#include <net/net_namespace.h>
#include <net/sclp_tunnel.h>
#include "sclp_impl.h"


int sclp_sock_create4(struct net *net, struct sclp_port_cfg *cfg, struct socket **sockp)
{
    int err;
    struct socket *sock = NULL;
    struct sockaddr_in sclp_addr;

    err = sock_create_kern(AF_INET, SOCK_SCLP, 0, &sock);
    if (err < 0)
	goto error;

    sk_change_net(sock->sk, net);

    sclp_addr.sin_family = AF_INET;
    sclp_addr.sin_addr = cfg->local_ip;
    sclp_addr.sin_port = cfg->local_sclp_port;

    err = kernel_bind(sock, (struct sockaddr*)&sclp_addr, sizeof(sclp_addr));
    if (err < 0)
	goto error;

    if (cfg->peer_sclp_port) {
	sclp_addr.sin_family = AF_INET;
	sclp_addr.sin_addr = cfg->peer_ip;
	sclp_addr.sin_port = cfg->peer_sclp_port;
	err = kernel_connect(sock, (struct sockaddr*)&sclp_addr, sizeof(sclp_addr), 0);
	if (err < 0)
	    goto error;
    }

    *sockp = sock;
    return 0;

error:
    if (sock) {
	kernel_sock_shutdown(sock, SHUT_RDWR);
	sk_release_kernel(sock->sk);
    }
    *sockp = NULL;
    return err;
}
EXPORT_SYMBOL(sclp_sock_create4);


void setup_sclp_tunnel_sock(struct net *net, struct socket *sock,
			    struct sclp_tunnel_sock_cfg *cfg)
{
    struct sock *sk = sock->sk;

    /* Disable multicast loopback */
    inet_sk(sk)->mc_loop = 0;

    sclp_sk(sk)->encap_rcv = cfg->encap_rcv;
}
EXPORT_SYMBOL(setup_sclp_tunnel_sock);


int sclp_tunnel_xmit_skb(struct sk_buff *skb, struct rtable *rt, 
			 __be32 daddr, __be32 saddr, __u8 tos, __u8 ttl, 
			 __be16 df, __be16 dport, __be16 sport)
{
    struct iphdr *inner = NULL;

    sclp_set_header(skb, dport, sport, sizeof(struct iphdr), rt->u.dst.dev->mtu);

    skb->encapsulation = 0;

    if (skb->protocol == htons(ETH_P_IP))
	inner = ip_hdr(skb);

    return iptunnel_xmit(sock_net(skb->sk), rt, skb, saddr, daddr, IPPROTO_SCLP, 
			 tos, ttl, df, inner);
}
EXPORT_SYMBOL(sclp_tunnel_xmit_skb);


void sclp_tunnel_sock_release(struct socket *sock)
{
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sk_release_kernel(sock->sk);
}
EXPORT_SYMBOL(sclp_tunnel_sock_release);
