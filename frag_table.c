/*
 * frag_table.c : A fragment table for Rx pprocessing
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

#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/hashtable.h>
#include "frag_table.h"

static DEFINE_HASHTABLE(fraginfo_hash, 16);


struct sclp_fraginfo *find_fraginfo(__u32 key, __u32 id)
{
    struct sclp_fraginfo *frag;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    struct hlist_node *node;

    hash_for_each_possible(fraginfo_hash, frag, node, list, key) {
        if (likely(frag->id == id))
            return frag;
    }
#else
    hash_for_each_possible(fraginfo_hash, frag, list, key) {
        if (likely(frag->id == id))
            return frag;
    }
#endif
    return NULL;
}


void add_fraginfo(struct sclp_fraginfo *frag, __u32 key)
{
    struct hlist_node *old_node;

    old_node = fraginfo_hash[hash_min(key, HASH_BITS(fraginfo_hash))].first;

    if (unlikely(old_node))
        delete_fraginfo(old_node);

    hash_add(fraginfo_hash, &frag->list, key);
}


void delete_fraginfo(struct hlist_node *node)
{
    struct sclp_fraginfo *frag;

    frag = container_of(node, struct sclp_fraginfo, list);
    if (likely(frag->skb)) {
        kfree_skb(frag->skb);
        frag->skb = NULL;
    }
    hash_del(node);
    kfree(frag);
}


void delete_all_fraginfo(void)
{
    int i;
    for (i = 0; i < HASH_SIZE(fraginfo_hash); i++) {
        struct hlist_node *node = fraginfo_hash[i].first;

        if (node)
            delete_fraginfo(node);
    }
}
