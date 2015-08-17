/*
 * proto.c : SCLP protocol
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
#include <linux/sclp.h>
#include <net/udp.h>
#include "sclp_impl.h"
#include "frag_table.h"

struct udp_table sclp_table;


static int sclp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
    struct sclp_sock *sp = sclp_sk(sk);
    int rc;
    
    /*
     *	Charge it to the socket, dropping if the queue is full.
     */
    nf_reset(skb);

    if (sp->encap_rcv) {
	/*
	 * This is an encapsulation socket so pass the skb to
	 * the socket's sclp_encap_rcv() hook. Otherwise, just
	 * fall through and pass this up the SCLP socket.
	 * sp->encap_rcv() returns the following value:
	 * =0 if skb was successfully passed to the encap
	 *    handler or was discarded by it.
	 * >0 if skb should be passed on to SCLP.
	 * <0 if skb should be resubmitted as proto -N
	 */

	/* if we're overly short, let SCLP handle it */
	if (sp->encap_rcv != NULL) {
	    int ret;

	    ret = (*sp->encap_rcv)(sk, skb);
	    if (ret <= 0)
		return -ret;
	}	
	/* FALLTHROUGH -- it's a normal SCLP Packet */
    }

    if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
	goto drop;

    rc = 0;

    bh_lock_sock(sk);
    if (! sock_owned_by_user(sk)) {
	rc = sk->sk_prot->backlog_rcv(sk, skb);
    } else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
	bh_unlock_sock(sk);
	goto drop;
    }
    bh_unlock_sock(sk);

    return rc;

drop:
    kfree_skb(skb);
    return -1;
}


static int __sclp_handle_fragment(struct sk_buff *skb, struct sclp_fraginfo *frag, off_t frag_off)
{
    if (unlikely(frag->next_idx != frag_off)) {
	/* TBD: Reordering */
	return -EPROTO;
    } else if (unlikely(frag->next_idx + skb->len > frag->payload_len)) {
	return -E2BIG;
    }

    memcpy(skb_put(frag->skb, skb->len), skb->data, skb->len);
    frag->next_idx += skb->len;

    if (frag->next_idx != frag->payload_len) {
	/* Further fragment packets are needed */
	kfree_skb(skb);
	return -EAGAIN;
    }

    /* Reassembling has completed */

    swap(*skb, *frag->skb);

    delete_fraginfo(&frag->list);

    return 0;
}


static inline int sclp_handle_fragment(struct sock *sk, struct sk_buff *skb, struct sclp_fraginfo *frag)
{
    struct sclphdr *sclph = sclp_hdr(skb);
    size_t rem;

    rem = skb->len + ntohs(sclph->rem);

    return __sclp_handle_fragment(skb, frag, frag->payload_len - rem);
}


static int sclp_register_fragment(struct sk_buff *skb, __u32 key, __u32 id)
{
    struct sclphdr *sclph = sclp_hdr(skb);
    struct sclp_fraginfo *frag;
    size_t total_len;
    size_t rem;

    total_len = skb->len + ntohs(sclph->rem);

    if (skb->len >= total_len)
	return -EPROTO;

    rem = total_len - skb->len;

    if (skb_tailroom(skb) < rem) {
	if (pskb_expand_head(skb, 0, rem - skb_tailroom(skb), GFP_ATOMIC))
	    return -ENOMEM;
    }

    frag = (struct sclp_fraginfo*)kzalloc(sizeof(struct sclp_fraginfo), GFP_ATOMIC);
    if (unlikely(!frag))
	return -ENOMEM;

    frag->id = id;
    frag->next_idx = skb->len;
    frag->payload_len = total_len;
    frag->skb = skb;

    add_fraginfo(frag, key);

    return 0;
}


int sclp_check_csum(struct sk_buff *skb)
{
    __wsum csum;
    off_t offset;

    if ((skb->ip_summed == CHECKSUM_UNNECESSARY) ||
	(skb->ip_summed == CHECKSUM_PARTIAL)) {
	return 1;
    }

    offset = skb_transport_offset(skb);

    if (skb->ip_summed == CHECKSUM_COMPLETE) {
	skb_postpull_rcsum(skb, skb->data, offset);
	csum = skb->csum;
    } else {
	csum = skb_checksum(skb, offset, skb->len - offset, 0);
    }

    return likely(csum_fold(csum) == 0);
}


int sclp_rcv(struct sock *sk, struct sk_buff *skb)
{
    struct sclphdr *sclph = sclp_hdr(skb);
    __u32 id;
    __u32 key;
    int err;

    skb_pull(skb, sizeof(*sclph));

    id = sclph->id & htonl(SCLP_ID_MASK);
    key = id ^ ((sclph->dest << 16) | sclph->source);

    err = skb_linearize(skb);
    if (unlikely(err))
	goto error;

    if (sclp_is_first_segment(sclph)) {
	if (sclph->rem) {
	    err = sclp_register_fragment(skb, key, id);
	    if (unlikely(err))
		goto error;
	    return 0;
	}
    } else {
	struct sclp_fraginfo *frag;
	frag = find_fraginfo(key, id);
	if (unlikely(!frag)) {
	    err = -ENOENT;
	    goto error;
	}

	err = sclp_handle_fragment(sk, skb, frag);
	if (err == -EAGAIN)
	    return 0;
	else if (err)
	    goto error;
    }

    return sclp_queue_rcv_skb(sk, skb);

error:
    kfree_skb(skb);
    return err;
}


static int sclp_init_net(struct net *net)
{
    return 0;
}


static void sclp_exit_net(struct net *net)
{

}


static struct pernet_operations sclp_ops = {
    .init = sclp_init_net,
    .exit = sclp_exit_net,
};


static void sclp_table_init(struct udp_table *table)
{
    int i;

    for (i = 0; i < UDP_HTABLE_SIZE; i++) {
	INIT_HLIST_NULLS_HEAD(&table->hash[i].head, i);
	spin_lock_init(&table->hash[i].lock);
    }
}


static int __init sclp_init(void)
{
    int err;

    pr_info("[sclp] Segment-Oriented Connection-Less Protocol\n");

    sclp_table_init(&sclp_table);

    err = sclp4_init();
    if (err)
	goto out;

    err = sclp_offload_init();
    if (err)
	goto out_v4_exit;

    err = register_pernet_subsys(&sclp_ops);
    if (err)
	goto out_offload_exit;

    return 0;

out_offload_exit:
    sclp_offload_exit();

out_v4_exit:
    sclp4_exit();

out:
    return err;
}


static void __exit sclp_exit(void)
{
    delete_all_fraginfo();

    unregister_pernet_subsys(&sclp_ops);

    sclp_offload_exit();

    sclp4_exit();

    pr_info("[sclp] The module has been removed\n");
}

module_init(sclp_init);
module_exit(sclp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ryota Kawashima <kawa1983@ieee.org>");
MODULE_DESCRIPTION("SCLP - Segment-Oriented Connection-Less Protocol");
