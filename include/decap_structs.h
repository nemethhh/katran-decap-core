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

#ifndef __DECAP_STRUCTS_H
#define __DECAP_STRUCTS_H

/*
 * Structs extracted from katran balancer_structs.h.
 * Types (__be32, __u32, __u16, __u8) come from vmlinux.h which is
 * always included first in every BPF compilation unit.
 */

struct flow_key {
  union {
    __be32 src;
    __be32 srcv6[4];
  };
  union {
    __be32 dst;
    __be32 dstv6[4];
  };
  union {
    __u32 ports;
    __u16 port16[2];
  };
  __u8 proto;
};

struct packet_description {
  struct flow_key flow;
  __u32 real_index;
  __u8 flags;
  __u8 tos;
};

#ifdef DECAP_STRICT_DESTINATION
struct real_definition {
  union {
    __be32 dst;
    __be32 dstv6[4];
  };
  __u8 flags;
};
#endif

#endif // __DECAP_STRUCTS_H
