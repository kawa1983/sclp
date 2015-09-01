/*
 * compat.h : Compatibility
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

#ifndef __COMPAT_H
#define __COMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define compat_rt_dst(rt)	(rt->u.dst)
#else
#define compat_rt_dst(rt)	(rt->dst)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define compat_inet_daddr(sk)		(inet_sk(sk)->daddr)
#define compat_inet_rcv_saddr(sk)	(inet_sk(sk)->rcv_saddr)
#define compat_inet_dport(sk)		(inet_sk(sk)->dport)
#define compat_inet_sport(sk)		(inet_sk(sk)->sport)
#else
#define compat_inet_daddr(sk)		(inet_sk(sk)->inet_daddr)
#define compat_inet_rcv_saddr(sk)	(inet_sk(sk)->inet_rcv_saddr)
#define compat_inet_dport(sk)		(inet_sk(sk)->inet_dport)
#define compat_inet_sport(sk)		(inet_sk(sk)->inet_sport)
#endif

#endif /* compat.h */
