/*
 * ipv4.c : SCLP protocol implementation for IPv4
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
#include <linux/if_vlan.h>
#include <linux/sclp.h>

#include <net/net_namespace.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/icmp.h>
#include <net/tcp_states.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/busy_poll.h>

#include "sclp_impl.h"
#include "compat.h"


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)

static int get_rtable(struct sock *sk, struct rtable **rt, __be32 daddr, __be16 dport)
{
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);
    struct flowi fl = { .oif = sk->sk_bound_dev_if,
                        .mark = sk->sk_mark,
                        .nl_u = { .ip4_u = {
                                             .daddr = daddr,
                                             .saddr = inet->saddr,
                                             .tos = inet->tos
                                           }
                                },
                        .proto = sk->sk_protocol,
                        .flags = inet_sk_flowi_flags(sk),
                        .uli_u = { .ports = {
                                             .sport = inet->sport,
                                             .dport = dport
                                            }
                                 }
                      };
    int err;

    security_sk_classify_flow(sk, &fl);

    err = ip_route_output_flow(net, rt, &fl, sk, 1);
    if (err) {
        if (err == -ENETUNREACH)
            IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
    } else {
        if (((*rt)->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST))
            err = -EACCES;
    }

    return err;
}


static int sclp4_xmit_skb(struct sk_buff *skb, struct sock *sk, void *argp)
{
    struct rtable *rt = (struct rtable*)argp;

    return ip_build_and_send_pkt(skb, sk, rt->rt_src, rt->rt_dst, NULL);
}


static int __sclp4_sendmsg(struct sock *sk, struct rtable *rt, __be32 daddr,
                           __be16 dport, struct msghdr *msg, size_t len,
                           int connected)
{
    if (rt == NULL) {
        int err = get_rtable(sk, &rt, daddr, dport);
        if (err)
            return err;

        if (connected)
            sk_dst_set(sk, dst_clone(&compat_rt_dst(rt)));
    }
    BUG_ON(!rt);

    return sclp_output(sk, &compat_rt_dst(rt), dport, compat_inet_sport(sk),
                       sizeof(struct iphdr), msg, len, sclp4_xmit_skb, rt);
}

#else

static int get_rtable(struct sock *sk, struct rtable **rt, struct flowi4 *fl4,
                      __be32 daddr, __be16 dport)
{
    struct inet_sock *inet = inet_sk(sk);
    struct net *net = sock_net(sk);

    flowi4_init_output(fl4, sk->sk_bound_dev_if, sk->sk_mark, inet->tos,
                       RT_SCOPE_UNIVERSE, sk->sk_protocol,
                       inet_sk_flowi_flags(sk) | FLOWI_FLAG_CAN_SLEEP,
                       daddr, inet->inet_saddr, dport, inet->inet_sport);

    security_sk_classify_flow(sk, flowi4_to_flowi(fl4));

    *rt = ip_route_output_flow(net, fl4, sk);
    if (IS_ERR(*rt)) {
        int err = PTR_ERR(*rt);
        *rt = NULL;
        if (err == -ENETUNREACH)
            IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
        return err;
    } else {
        if (((*rt)->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST))
            return -EACCES;
    }

    return 0;
}

static int sclp4_xmit_skb(struct sk_buff *skb, struct sock *sk, void *argp)
{
    struct flowi4 *fl4 = (struct flowi4*)argp;

    return ip_build_and_send_pkt(skb, sk, fl4->saddr, fl4->daddr, NULL);
}


static int __sclp4_sendmsg(struct sock *sk, struct rtable *rt, __be32 daddr,
                           __be16 dport, struct msghdr *msg, size_t len,
                           int connected)
{
    struct inet_sock *inet = inet_sk(sk);
    struct flowi4 fl4;

    if (rt == NULL) {
        int err = get_rtable(sk, &rt, &fl4, daddr, dport);
        if (err)
            return err;

        if (connected)
            sk_dst_set(sk, dst_clone(&rt->dst));
    }
    BUG_ON(!rt);

    return sclp_output(sk, &compat_rt_dst(rt), dport, inet->inet_sport,
                       sizeof(struct iphdr), msg, len, sclp4_xmit_skb, &fl4);
}

#endif


static int sclp4_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct rtable *rt;
    __be32 daddr;
    __be16 dport;
    int connected;
    int err;

    if (len > 65535 + VLAN_ETH_HLEN)
        return -EMSGSIZE;

    /*
     *	Get the destination address
     */
    if (msg->msg_name) {
        struct sockaddr_in *sin = (struct sockaddr_in*)msg->msg_name;
        if (msg->msg_namelen < sizeof(*sin))
            return -EINVAL;
        if (sin->sin_family != AF_INET) {
            if (sin->sin_family != AF_UNSPEC)
                return -EAFNOSUPPORT;
        }

        daddr = sin->sin_addr.s_addr;
        dport = sin->sin_port;
        if (dport == 0)
            return -EINVAL;

        rt = NULL;
        connected = 0;
    } else {
        if (sk->sk_state != TCP_ESTABLISHED)
            return -EDESTADDRREQ;

        daddr = compat_inet_daddr(sk);
        dport = compat_inet_dport(sk);

        rt = (struct rtable *)sk_dst_check(sk, 0);
        connected = 1;
    }

    err = __sclp4_sendmsg(sk, rt, daddr, dport, msg, len, connected);

    ip_rt_put(rt);

    if (!err)
        return len;

    return err;
}


static int sclp4_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
			 size_t len, int noblock, int flags, int *addr_len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
    struct sk_buff *skb;
    unsigned int copied;
    int peeked;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    int off = 0;
#endif
    int err;

try_again:
    skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
                              &peeked,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
                              &off,
#endif
                              &err);
    if (!skb)
        goto out;

    copied = len;
    if (copied > skb->len)
        copied = skb->len;
    else if (copied < skb->len)
        msg->msg_flags |= MSG_TRUNC;

    if (copied < skb->len)
        if (udp_lib_checksum_complete(skb))
            goto csum_copy_err;

    if (skb_csum_unnecessary(skb)) {
        err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
    } else {
        err = skb_copy_and_csum_datagram_iovec(skb, 0, msg->msg_iov);
        if (err == -EINVAL)
            goto csum_copy_err;
    }

    if (err)
        goto out_free; /* Memory copy error */

    sock_recv_ts_and_drops(msg, sk, skb);

    /* Copy the address. */
    if (sin) {
        sin->sin_family = AF_INET;
        sin->sin_port = sclp_hdr(skb)->source;
        sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
        memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
        *addr_len = sizeof(*sin);
    }

    err = copied;
    if (flags & MSG_TRUNC)
        err = skb->len;

out_free:
    skb_free_datagram_locked(sk, skb);

out:
    return err;

csum_copy_err:
    lock_sock(sk);
    skb_kill_datagram(sk, skb, flags);
    release_sock(sk);

    if (noblock)
        return -EAGAIN;

    goto try_again;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static int compute_score(struct sock *sk, struct net *net, __be32 saddr,
                         unsigned short hnum,
                         __be16 sport, __be32 daddr, __be16 dport, int dif)
{
    int score = -1;

    if (net_eq(sock_net(sk), net) && sk->sk_hash == hnum &&
	!ipv6_only_sock(sk)) {
        struct inet_sock *inet = inet_sk(sk);

        score = (sk->sk_family == PF_INET ? 2 : 1);
        if (inet->rcv_saddr) {
            if (inet->rcv_saddr != daddr)
                return -1;
            score += 4;
        }
        if (inet->daddr) {
            if (inet->daddr != saddr)
                return -1;
            score += 4;
        }
        if (inet->dport) {
            if (inet->dport != sport)
                return -1;
            score += 4;
        }
        if (sk->sk_bound_dev_if) {
            if (sk->sk_bound_dev_if != dif)
                return -1;
            score += 4;
        }
    }
    return score;
}


static struct sock *__sclp4_lookup(struct net *net, __be32 saddr,
                                   __be16 sport, __be32 daddr, __be16 dport,
                                   int dif, struct udp_table *table)
{
    struct sock *sk, *result;
    struct hlist_nulls_node *node;
    unsigned short hnum = ntohs(dport);
    unsigned int slot = udp_hashfn(net, hnum);
    struct udp_hslot *hslot = &table->hash[slot];
    int score, badness, matches = 0, reuseport = 0;
    u32 hash = 0;

    rcu_read_lock();
begin:
    result = NULL;
    badness = 0;
    sk_nulls_for_each_rcu(sk, node, &hslot->head) {
	score = compute_score(sk, net, saddr, hnum, sport, daddr, dport, dif);
	if (score > badness) {
	    result = sk;
	    badness = score;
	    reuseport = sk->sk_reuseport;
	    if (reuseport) {
            hash = inet_ehashfn(net, daddr, hnum, saddr, htons(sport));
            matches = 1;
	    }
	} else if (score == badness && reuseport) {
	    matches++;
	    if (((u64)hash * matches) >> 32 == 0)
            result = sk;
            hash = next_pseudo_random32(hash);
        }
    }
    /*
     * if the nulls value we got at the end of this lookup is
     * not the expected one, we must restart lookup.
     * We probably met an item that was moved to another chain.
     */
    if (get_nulls_value(node) != slot)
        goto begin;

    if (result) {
        if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
            result = NULL;
        else if (unlikely(compute_score(result, net, saddr, hnum, sport,
            daddr, dport, dif) < badness)) {
            sock_put(result);
            goto begin;
        }
    }
    rcu_read_unlock();
    return result;
}


static struct sock *sclp4_lookup(struct net *net, __be32 saddr, __be16 sport,
                                 __be32 daddr, __be16 dport, int dif)
{
    return __sclp4_lookup(net, saddr, sport, daddr, dport, dif, &sclp_table);
}

#else

static struct sock *sclp4_lookup(struct net *net, __be32 saddr, __be16 sport,
                                 __be32 daddr, __be16 dport, int dif)
{
    return __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif, &sclp_table);
}

#endif


static void sclp4_err(struct sk_buff *skb, u32 info)
{
    struct inet_sock *inet;
    const struct iphdr *iph = (struct iphdr *)skb->data;
    const struct sclphdr *sclph = (struct sclphdr *)(skb->data + (iph->ihl << 2));
    const int type = icmp_hdr(skb)->type;
    const int code = icmp_hdr(skb)->code;
    struct sock *sk;
    int harderr;
    int err;
    struct net *net = dev_net(skb->dev);

    sk = sclp4_lookup(net, iph->daddr, sclph->dest, iph->saddr, sclph->source, skb->dev->ifindex);
    if (sk == NULL) {
        ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
        return;
    }

    err     = 0;
    harderr = 0;
    inet = inet_sk(sk);

    switch (type) {
    default:
    case ICMP_TIME_EXCEEDED:
        err = EHOSTUNREACH;
        break;
    case ICMP_SOURCE_QUENCH:
        /* Just silently ignore these. */
        goto out;
    case ICMP_PARAMETERPROB:
        err = EPROTO;
        break;
    case ICMP_DEST_UNREACH:
        if (code == ICMP_FRAG_NEEDED) { /* PMTU discovery (RFC1191) */
            if (inet->pmtudisc != IP_PMTUDISC_DONT) {
                err = EMSGSIZE;
                harderr = 1;
                break;
            }
            goto out;
        }
        err = EHOSTUNREACH;
        if (code <= NR_ICMP_UNREACH) {
            harderr = icmp_err_convert[code].fatal;
            err = icmp_err_convert[code].errno;
        }
        break;
    }

    /*
     *  RFC1122: OK.  Passes ICMP errors back to application, as per
     *	4.1.3.3.
     */
    if (!inet->recverr)
        if (! harderr || sk->sk_state != TCP_ESTABLISHED)
            goto out;

    sk->sk_err = err;
    sk->sk_error_report(sk);

out:
    sock_put(sk);
}


static int sclp4_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    int rc;

    if (compat_inet_daddr(sk))
        sock_rps_save_rxhash(sk,
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
                             skb->rxhash
#else
                             skb
#endif
                            );

    rc = sock_queue_rcv_skb(sk, skb);
    if (rc < 0) {
        kfree_skb(skb);
        return -1;
    }

    return 0;
}


static int sclp4_rcv(struct sk_buff *skb)
{
    struct sock *sk;
    struct sclphdr *sclph;
    unsigned short slen;
    __be32 saddr, daddr;
    struct net *net = dev_net(skb->dev);
    int ret;

    if (!pskb_may_pull(skb, sizeof(struct sclphdr)))
        goto drop;

    sclph = sclp_hdr(skb);
    slen  = skb->len;
    saddr = ip_hdr(skb)->saddr;
    daddr = ip_hdr(skb)->daddr;

    if (slen < sizeof(*sclph))
        goto short_packet;

    if (unlikely(!sclp_check_csum(skb)))
        goto csum_error;

    skb->ip_summed = CHECKSUM_UNNECESSARY;

    sk = sclp4_lookup(net, saddr, sclph->source, daddr, sclph->dest, inet_iif(skb));
    if (!sk) {
        nf_reset(skb);
        icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
        goto drop;
    }

    sk_mark_napi_id(sk, skb);
    ret = sclp_rcv(sk, skb);
    sock_put(sk);

    /* a return value > 0 means to resubmit the input, but
     * it wants the return to be -protocol, or 0
     */
    if (ret > 0)
        return -ret;

    return 0;

short_packet:
    LIMIT_NETDEBUG(KERN_DEBUG "SCLP: short packet: From %pI4:%u (len=%d) to %pI4:%u\n",
		   &saddr,
		   ntohs(sclph->source),
		   skb->len,
		   &daddr,
		   ntohs(sclph->dest));
    goto drop;

csum_error:
    /*
     * RFC1122: OK.  Discards the bad packet silently (as far as
     * the network is concerned, anyway) as per 4.1.3.4 (MUST).
     */
    LIMIT_NETDEBUG(KERN_DEBUG "SCLP: bad checksum. From %pI4:%u to %pI4:%u id 0x%X\n",
		   &saddr,
		   ntohs(sclph->source),
		   &daddr,
		   ntohs(sclph->dest),
		   ntohl(sclph->id) & SCLP_ID_MASK);
drop:
    kfree_skb(skb);

    return 0;
}


static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
    return (!ipv6_only_sock(sk2) &&
           (!compat_inet_rcv_saddr(sk1) || !compat_inet_rcv_saddr(sk2) ||
            compat_inet_rcv_saddr(sk1) == compat_inet_rcv_saddr(sk2)));
}


static int sclp4_get_port(struct sock *sk, unsigned short snum)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
    struct net *net = sock_net(sk);
    unsigned int hash2_nulladdr =
        jhash_1word((__force u32)htonl(INADDR_ANY),
                    net_hash_mix(net)) ^ snum;
	unsigned int hash2_partial =
        jhash_1word((__force u32)inet_sk(sk)->inet_rcv_saddr,
                    net_hash_mix(net)) ^ 0;

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
    return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal, hash2_nulladdr);
#else
    return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal);
#endif
}


static struct proto sclp4_prot = {
    .name              = "SCLP",
    .owner             = THIS_MODULE,
    .close             = sclp_close,
    .connect           = ip4_datagram_connect,
    .disconnect        = udp_disconnect,
    .ioctl             = sclp_ioctl,
    .setsockopt        = sclp_setsockopt,
    .getsockopt        = sclp_getsockopt,
    .sendmsg           = sclp4_sendmsg,
    .recvmsg           = sclp4_recvmsg,
    .backlog_rcv       = sclp4_queue_rcv_skb,
    .hash              = udp_lib_hash,
    .unhash            = udp_lib_unhash,
    .max_header        = sizeof(struct sclphdr),
    .get_port          = sclp4_get_port,
    .obj_size          = sizeof(struct sclp_sock),
    .slab_flags        = SLAB_DESTROY_BY_RCU,
    .h.udp_table       = &sclp_table,
#ifdef CONFIG_COMPAT
    .compat_setsockopt = compat_sclp_setsockopt,
    .compat_getsockopt = compat_sclp_getsockopt,
#endif
};


static const struct net_protocol sclp4_protocol = {
    .handler     = sclp4_rcv,
    .err_handler = sclp4_err,
    .no_policy   = 1,
    .netns_ok    = 1,
};

/* socket operations */
static const struct proto_ops inet_sclp_ops = {
    .family            = PF_INET,
    .owner             = THIS_MODULE,
    .release           = inet_release,
    .bind              = inet_bind,
    .connect           = inet_dgram_connect,
    .socketpair        = sock_no_socketpair,
    .accept            = sock_no_accept,
    .getname           = inet_getname,
    .poll              = udp_poll,
    .ioctl             = inet_ioctl,
    .listen            = sock_no_listen,
    .shutdown          = inet_shutdown,
    .setsockopt        = sock_common_setsockopt,
    .getsockopt        = sock_common_getsockopt,
    .sendmsg           = inet_sendmsg,
    .recvmsg           = sock_common_recvmsg,
    .mmap              = sock_no_mmap,
    .sendpage          = sock_no_sendpage,
#ifdef CONFIG_COMPAT
    .compat_setsockopt = compat_sock_common_setsockopt,
    .compat_getsockopt = compat_sock_common_getsockopt,
#endif
};


static struct inet_protosw sclp4_protosw = {
    .type     = SOCK_SCLP,
    .protocol = IPPROTO_SCLP,
    .prot     = &sclp4_prot,
    .ops      = &inet_sclp_ops,
#if (!defined(RHEL_RELEASE_CODE) && LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)) || \
    (defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
    .no_check = 0,
#endif
    .flags    = INET_PROTOSW_REUSE,
};


int sclp4_init(void)
{
    int err;

    err = proto_register(&sclp4_prot, 1);
    if (err)
        goto out;

    err = inet_add_protocol(&sclp4_protocol, IPPROTO_SCLP);
    if (err)
        goto out_proto_unregister;

    inet_register_protosw(&sclp4_protosw);

out:
    return err;

out_proto_unregister:
    proto_unregister(&sclp4_prot);

    return err;
}


void  sclp4_exit(void)
{
    inet_unregister_protosw(&sclp4_protosw);
    inet_del_protocol(&sclp4_protocol, IPPROTO_SCLP);
    proto_unregister(&sclp4_prot);
}
