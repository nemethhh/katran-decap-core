/* Copyright (C) 2018-present, Facebook, Inc.
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

#ifndef __PCKT_ENCAP_H
#define __PCKT_ENCAP_H

/*
 * XDP decapsulation routines extracted from katran pckt_encap.h.
 * Only decap functions are included; encap functions are balancer-only.
 *
 * Kernel structs (ethhdr, iphdr, ipv6hdr, udphdr, xdp_md) come from
 * vmlinux.h which is included first by the .c compilation units.
 */

#include <bpf/bpf_helpers.h>

#include "decap_consts.h"

/* RECORD_GUE_ROUTE is a no-op in decap-only mode.
 * In katran's flow_debug.h, this expands to {} when RECORD_FLOW_INFO
 * is not defined. */
#ifndef RECORD_GUE_ROUTE
#define RECORD_GUE_ROUTE(...) {}
#endif

// before calling decap helper apropriate checks for data_end - data must be
// done. otherwise verifier wont like it
__attribute__((__always_inline__)) static inline bool
decap_v6(struct xdp_md* xdp, void** data, void** data_end, bool inner_v4) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  if (inner_v4) {
    new_eth->h_proto = BE_ETH_P_IP;
  } else {
    new_eth->h_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct ipv6hdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(xdp, (int)sizeof(struct iphdr))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

#ifdef INLINE_DECAP_GUE

__attribute__((__always_inline__)) static inline bool
gue_decap_v4(struct xdp_md* xdp, void** data, void** data_end) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
  RECORD_GUE_ROUTE(old_eth, new_eth, *data_end, true, true);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  new_eth->h_proto = BE_ETH_P_IP;
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}

__attribute__((__always_inline__)) static inline bool
gue_decap_v6(struct xdp_md* xdp, void** data, void** data_end, bool inner_v4) {
  struct ethhdr* new_eth;
  struct ethhdr* old_eth;
  old_eth = *data;
  new_eth = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
  RECORD_GUE_ROUTE(old_eth, new_eth, *data_end, false, inner_v4);
  memcpy(new_eth->h_source, old_eth->h_source, 6);
  memcpy(new_eth->h_dest, old_eth->h_dest, 6);
  if (inner_v4) {
    new_eth->h_proto = BE_ETH_P_IP;
  } else {
    new_eth->h_proto = BE_ETH_P_IPV6;
  }
  if (bpf_xdp_adjust_head(
          xdp, (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr)))) {
    return false;
  }
  *data = (void*)(long)xdp->data;
  *data_end = (void*)(long)xdp->data_end;
  return true;
}
#endif // INLINE_DECAP_GUE

#endif // __PCKT_ENCAP_H
