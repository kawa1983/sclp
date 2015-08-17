/*
 * sclp.h : SCLP header definition
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

#ifndef _UAPI_LINUX_SCLP_H
#define _UAPI_LINUX_SCLP_H
 
#include <linux/types.h>
#include <asm/byteorder.h>

#ifndef IPPROTO_SCLP
#define IPPROTO_SCLP        234
#endif

#ifndef NEXTHDR_SCLP
#define NEXTHDR_SCLP        234
#endif

#ifndef SOL_SCLP
#define SOL_SCLP            234
#endif

#ifndef SOCK_SCLP
#define SOCK_SCLP           7
#endif

#define SCLP_ID_MASK        0xFFFFFFFE


struct sclphdr
{
    __be16 source;          /* Source port */
    __be16 dest;            /* Destination port */
    __be32 id;              /* Payload identifier */
    __be16 rem;             /* Remaining length */
    __be16 check;           /* Checksum */
} __attribute__ ((packed));


static inline void sclp_set_first_segment(struct sclphdr *sclp)
{
    sclp->id |= htonl(~SCLP_ID_MASK);
}

static inline bool sclp_is_first_segment(const struct sclphdr *sclp)
{
    return (sclp->id & htonl(~SCLP_ID_MASK));
}

#endif /* _UAPI_LINUX_SCLP_H */

