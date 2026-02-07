/* Copyright (C) 2019-present, Facebook, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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

#ifndef __DECAP_CONSTS_H
#define __DECAP_CONSTS_H

/*
 * Constants extracted from katran balancer_consts.h, plus kernel #define
 * constants that are NOT present in vmlinux.h (which only has enums/structs).
 */

// --- TC action constants (from <linux/pkt_cls.h>, not in vmlinux.h) ---
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_SHOT 2

// --- Ethernet protocol types in network byte order (pre-computed BE) ---
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

// --- GUE constants ---
#define GUEV1_IPV6MASK 0x30

// --- Packet processing return codes ---
#define FURTHER_PROCESSING -1

// --- Fragmentation ---
#define PCKT_FRAGMENTED 65343

// --- Header lengths ---
#define IPV4_HDR_LEN_NO_OPT 20

// --- Map flags ---
#define NO_FLAGS 0

// --- Map sizes ---
#define MAX_VIPS 512

// --- GUE port ---
#define GUE_DPORT 6080

// --- Source address indices ---
#define V4_SRC_INDEX 0
#define V6_SRC_INDEX 1

// --- Packet description flags ---
#define F_ICMP (1 << 0)
#define F_SYN_SET (1 << 1)
#define F_RST_SET (1 << 2)

// --- TPR (TCP Per-packet Routing) constants ---
#if defined(INLINE_DECAP_GUE) || defined(DECAP_TPR_STATS)
#define TCP_HDR_OPT_KIND_TPR 0xB7
#define TCP_HDR_OPT_LEN_TPR 6
#define TCP_HDR_OPT_MAX_OPT_CHECKS 15
#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#endif

// --- memcpy for vmlinux.h-based BPF programs ---
#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif // __DECAP_CONSTS_H
