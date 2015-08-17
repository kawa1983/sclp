/*
 * offload.c : GSO/GRO processing of SCLP
 * 
 * Copyright 2014-2015 Ryota Kawashima <kawa1983@ieee.org> Nagoya Institute of Technology
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/sclp.h>
#include <net/protocol.h>


static int sclp_gso_send_check(struct sk_buff *skb)
{
    if (! pskb_may_pull(skb, sizeof(struct sclphdr))) {
	return -EINVAL;
    }

    return 0;
}


static struct sk_buff *sclp_gso_segment(struct sk_buff *skb,
					int features)
{
    struct sk_buff *segs;
    struct sclphdr *sclph;
    unsigned int rem;
    unsigned int mss;
    off_t offset;

    segs = ERR_PTR(-EINVAL);

    if (! pskb_may_pull(skb, sizeof(struct sclphdr))) {
	goto out;
    }

    sclph = sclp_hdr(skb);

    __skb_pull(skb, sizeof(struct sclphdr));

    mss = skb_shinfo(skb)->gso_size;

    if (unlikely(skb->len <= mss)) {
	goto out;
    }

    rem = skb->len - mss;

    sclph->id &= htonl(SCLP_ID_MASK);

    /* Do segmentation */
    segs = skb_segment(skb, features);
    if (IS_ERR(segs)) {
	goto out;
    }

    skb = segs;

    /* Set the first flag */
    sclp_set_first_segment(sclp_hdr(skb));

    while (skb) {
	sclph        = sclp_hdr(skb);
	sclph->rem   = htons(rem);
	sclph->check = 0;

	offset = skb_transport_offset(skb);

	/* Calculate the checksum */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
#if 0
	    skb->csum_start  = skb_headroom(skb) + offset;
	    skb->csum_offset = offsetof(struct sclphdr, check);
#else
	    sclph->check = csum_fold(skb_checksum(skb, offset, skb->len - offset, 0));
	    skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif
	} else if (skb->ip_summed == CHECKSUM_NONE) {
	    sclph->check = csum_fold(skb_checksum(skb, offset, skb->len - offset, 0));
	    skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	if (rem >= mss) {
	    rem -= mss;
	} else {
	    rem = 0;
	}

	skb = skb->next;
    }

out:
    return segs;
}


struct sk_buff **sclp_gro_receive_impl(struct sk_buff **head, struct sk_buff *skb)
{
    struct sk_buff **ppskb;
    struct sk_buff *pskb;
    struct sclphdr *sclph;
    struct sclphdr *sclph2;
    unsigned int len;
    unsigned int mss;
    unsigned int hlen;
    unsigned int offset;
    unsigned short int rem;
    int flush;

    ppskb = NULL;

    offset = skb_gro_offset(skb);
    hlen = offset + sizeof(struct sclphdr);

    sclph = skb_gro_header_fast(skb, offset);
    if (skb_gro_header_hard(skb, hlen)) {
	sclph = skb_gro_header_slow(skb, hlen, offset);
	if (unlikely(! sclph)) {
	    flush = 1;
	    goto out;
	}
    }

    skb_gro_pull(skb, sizeof(struct sclphdr));

    len = skb_gro_len(skb);
    rem = sclph->rem;

    for (; (pskb = *head); head = &pskb->next) {
	if (! NAPI_GRO_CB(pskb)->same_flow) {
	    continue;
	}

	sclph2 = sclp_hdr(pskb);

	if (*(u32*)&sclph->source != *(u32*)&sclph2->source) {
	    NAPI_GRO_CB(pskb)->same_flow = 0;
	    continue;
	}
	goto found;
    }
    mss = 1;
    goto out_check_final;

found:
    flush = NAPI_GRO_CB(pskb)->flush;
    flush |= (sclph->id ^ sclph2->id) & htonl(SCLP_ID_MASK);

    mss = skb_shinfo(pskb)->gso_size;

    flush |= (len - 1) >= mss;
    flush |= (ntohs(sclph->rem) + skb_gro_len(skb)) ^ ntohs(sclph2->rem);

    if (flush || skb_gro_receive(head, skb)) {
	mss = 1;
	goto out_check_final;
    }

    pskb = *head;
    sclph2 = sclp_hdr(pskb);
    sclph2->rem = rem;

out_check_final:
    flush = len < mss;

    if (pskb && (! NAPI_GRO_CB(skb)->same_flow || flush)) {
	ppskb = head;
    }

out:
    NAPI_GRO_CB(skb)->flush |= flush;

    return ppskb;
}


struct sk_buff **sclp_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
    __sum16 sum;

    switch (skb->ip_summed) {
    case CHECKSUM_COMPLETE:
	sum = csum_fold(skb->csum);
	if (sum != 0) {
	    goto flush;
	}
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	break;
    case CHECKSUM_NONE:
	sum = csum_fold(skb_checksum(skb, skb_gro_offset(skb), skb_gro_len(skb), 0));
	if (sum != 0) {
	    goto flush;
	}
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	break;
    default:
	break;
    }

    return sclp_gro_receive_impl(head, skb);

flush:
    NAPI_GRO_CB(skb)->flush = 1;
    return NULL;
}


int sclp_gro_complete(struct sk_buff *skb)
{
    struct sclphdr *sclph;

    sclph = sclp_hdr(skb);

    sclph->check = 0;

    skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;

    skb->csum_start  = skb_transport_header(skb) - skb->head;
    skb->csum_offset = offsetof(struct sclphdr, check);
    skb->ip_summed   = CHECKSUM_PARTIAL;

    skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

    return 0;
}


static const struct net_offload sclp_offload = {
    .gso_send_check = sclp_gso_send_check,
    .gso_segment    = sclp_gso_segment,
    .gro_receive    = sclp_gro_receive,
    .gro_complete   = sclp_gro_complete,
};


int __init sclp_offload_init(void)
{
    if (inet_add_offload(&sclp_offload, IPPROTO_SCLP) != 0)
	goto err;

    pr_info("[sclp] GSO/GRO support\n");

    return 0;

err:
    return -EAGAIN;
}


void __exit sclp_offload_exit(void)
{
    inet_del_offload(&sclp_offload, IPPROTO_SCLP);
}

#ifdef SCLP_OFFLOAD_MODULE
module_init(sclp_offload_init);
module_exit(sclp_offload_exit);

MODULE_DESCRIPTION("SCLP offloading (GSO/GRO)");
MODULE_AUTHOR("Ryota Kawashima (kawa1983@ieee.org)");
MODULE_LICENSE("GPL");
#endif
