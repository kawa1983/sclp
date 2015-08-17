/*
 * frag_table.h : A fragment table definition for Rx pprocessing
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

#ifndef __SCLP_FRAG_TABLE_H
#define __SCLP_FRAG_TABLE_H

struct sk_buff;
struct hlist_node;

struct sclp_fraginfo
{
    __be32            id;
    off_t             next_idx;
    size_t            payload_len;
    struct sk_buff   *skb;
    struct hlist_node list;
};


extern struct sclp_fraginfo *find_fraginfo(__u32 key, __u32 id);
extern void add_fraginfo(struct sclp_fraginfo *frag, __u32 key);
extern void delete_fraginfo(struct hlist_node *node);
extern void delete_all_fraginfo(void);

#endif /* __SCLP_FRAG_TABLE_H */
