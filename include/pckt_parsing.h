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

#ifndef __PCKT_PARSING_H
#define __PCKT_PARSING_H

/*
 * Generic packet parsing routines (TCP/UDP header parsing, TPR option lookup).
 * Extracted from katran pckt_parsing.h for decap-only use.
 *
 * Kernel structs (ethhdr, iphdr, ipv6hdr, tcphdr, udphdr, icmphdr, icmp6hdr,
 * xdp_md, __sk_buff) and protocol enums (IPPROTO_*) come from vmlinux.h,
 * which is included first by the .c compilation units.
 */

#include <bpf/bpf_helpers.h>

#include "decap_consts.h"
#include "decap_structs.h"

__attribute__((__always_inline__)) static inline __u64 calc_offset(
    bool is_ipv6,
    bool is_icmp) {
  __u64 off = sizeof(struct ethhdr);
  if (is_ipv6) {
    off += sizeof(struct ipv6hdr);
    if (is_icmp) {
      off += (sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
    }
  } else {
    off += sizeof(struct iphdr);
    if (is_icmp) {
      off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
    }
  }
  return off;
}

__attribute__((__always_inline__)) static inline bool parse_udp(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt) {
  bool is_icmp = !((pckt->flags & F_ICMP) == 0);
  __u64 off = calc_offset(is_ipv6, is_icmp);
  struct udphdr* udp;
  udp = data + off;

  if (udp + 1 > data_end) {
    return false;
  }

  if (!is_icmp) {
    pckt->flow.port16[0] = udp->source;
    pckt->flow.port16[1] = udp->dest;
  } else {
    // packet_description was created from icmp "packet too big". hence
    // we need to invert src/dst ports
    pckt->flow.port16[0] = udp->dest;
    pckt->flow.port16[1] = udp->source;
  }
  return true;
}

__attribute__((__always_inline__)) static inline bool parse_tcp(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt) {
  bool is_icmp = !((pckt->flags & F_ICMP) == 0);
  __u64 off = calc_offset(is_ipv6, is_icmp);
  struct tcphdr* tcp;
  tcp = data + off;

  if (tcp + 1 > data_end) {
    return false;
  }

  if (tcp->syn) {
    pckt->flags |= F_SYN_SET;
  }

  if (tcp->rst) {
    pckt->flags |= F_RST_SET;
  }

  if (!is_icmp) {
    pckt->flow.port16[0] = tcp->source;
    pckt->flow.port16[1] = tcp->dest;
  } else {
    // packet_description was created from icmp "packet too big". hence
    // we need to invert src/dst ports
    pckt->flow.port16[0] = tcp->dest;
    pckt->flow.port16[1] = tcp->source;
  }
  return true;
}

struct hdr_opt_state {
  __u32 server_id;
  __u8 byte_offset;
  __u8 hdr_bytes_remaining;
};

#if defined(INLINE_DECAP_GUE) || defined(DECAP_TPR_STATS)
__attribute__((__always_inline__)) int parse_hdr_opt_raw(
    const void* data,
    const void* data_end,
    struct hdr_opt_state* state) {
  __u8 *tcp_opt, kind, hdr_len;

  // Need this check to satisify the verifier
  if (!state) {
    return -1;
  }

  tcp_opt = (__u8*)(data + state->byte_offset);
  if (tcp_opt + 1 > data_end) {
    return -1;
  }

  kind = tcp_opt[0];
  if (kind == TCP_OPT_EOL) {
    return -1;
  }

  if (kind == TCP_OPT_NOP) {
    state->hdr_bytes_remaining--;
    state->byte_offset++;
    return 0;
  }

  if (state->hdr_bytes_remaining < 2 ||
      tcp_opt + sizeof(__u8) + sizeof(__u8) > data_end) {
    return -1;
  }

  hdr_len = tcp_opt[1];
  if (hdr_len > state->hdr_bytes_remaining) {
    return -1;
  }

  if (kind == TCP_HDR_OPT_KIND_TPR) {
    if (hdr_len != TCP_HDR_OPT_LEN_TPR) {
      return -1;
    }

    if (tcp_opt + TCP_HDR_OPT_LEN_TPR > data_end) {
      return -1;
    }

    state->server_id = *(__u32*)&tcp_opt[2];
    return 1;
  }

  state->hdr_bytes_remaining -= hdr_len;
  state->byte_offset += hdr_len;
  return 0;
}

/* MUST remain noinline - BPF verifier stack depth limit (512 bytes).
 * The noinline boundary creates a BPF-to-BPF function call that resets
 * stack accounting for the TPR option parsing loop. */
__attribute__((noinline)) int parse_hdr_opt(
    const struct xdp_md* xdp,
    struct hdr_opt_state* state) {
  __u8 *tcp_opt, kind, hdr_len;

  const void* data = (void*)(long)xdp->data;
  const void* data_end = (void*)(long)xdp->data_end;
  return parse_hdr_opt_raw(data, data_end, state);
}

/* MUST remain noinline - same stack depth reason as parse_hdr_opt(). */
int parse_hdr_opt_skb(
    const struct __sk_buff* skb,
    struct hdr_opt_state* state) {
  __u8 *tcp_opt, kind, hdr_len;

  const void* data = (void*)(long)skb->data;
  const void* data_end = (void*)(long)skb->data_end;
  return parse_hdr_opt_raw(data, data_end, state);
}

__attribute__((__always_inline__)) static inline int
tcp_hdr_opt_lookup_server_id(
    const struct xdp_md* xdp,
    bool is_ipv6,
    __u32* server_id) {
  const void* data = (void*)(long)xdp->data;
  const void* data_end = (void*)(long)xdp->data_end;
  struct tcphdr* tcp_hdr;
  __u8 tcp_hdr_opt_len = 0;
  __u64 tcp_offset = 0;
  struct hdr_opt_state opt_state = {};
  int err = 0;

  tcp_offset = calc_offset(is_ipv6, false /* is_icmp */);
  tcp_hdr = (struct tcphdr*)(data + tcp_offset);
  if (tcp_hdr + 1 > data_end) {
    return FURTHER_PROCESSING;
  }
  tcp_hdr_opt_len = (tcp_hdr->doff * 4) - sizeof(struct tcphdr);
  if (tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
    return FURTHER_PROCESSING;
  }

  opt_state.hdr_bytes_remaining = tcp_hdr_opt_len;
  opt_state.byte_offset = sizeof(struct tcphdr) + tcp_offset;
  for (int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
    err = parse_hdr_opt(xdp, &opt_state);
    if (err || !opt_state.hdr_bytes_remaining) {
      break;
    }
  }
  if (!opt_state.server_id) {
    return FURTHER_PROCESSING;
  }
  *server_id = opt_state.server_id;
  return 0;
}

__attribute__((__always_inline__)) static inline int
tcp_hdr_opt_lookup_server_id_skb(
    const struct __sk_buff* skb,
    bool is_ipv6,
    __u32* server_id) {
  const void* data = (void*)(long)skb->data;
  const void* data_end = (void*)(long)skb->data_end;
  struct tcphdr* tcp_hdr;
  __u8 tcp_hdr_opt_len = 0;
  __u64 tcp_offset = 0;
  struct hdr_opt_state opt_state = {};
  int err = 0;

  tcp_offset = calc_offset(is_ipv6, false /* is_icmp */);
  tcp_hdr = (struct tcphdr*)(data + tcp_offset);
  if (tcp_hdr + 1 > data_end) {
    return FURTHER_PROCESSING;
  }
  tcp_hdr_opt_len = (tcp_hdr->doff * 4) - sizeof(struct tcphdr);
  if (tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
    return FURTHER_PROCESSING;
  }

  opt_state.hdr_bytes_remaining = tcp_hdr_opt_len;
  opt_state.byte_offset = sizeof(struct tcphdr) + tcp_offset;
  for (int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
    err = parse_hdr_opt_skb(skb, &opt_state);
    if (err || !opt_state.hdr_bytes_remaining) {
      break;
    }
  }
  if (!opt_state.server_id) {
    return FURTHER_PROCESSING;
  }
  *server_id = opt_state.server_id;
  return 0;
}
#endif // INLINE_DECAP_GUE || DECAP_TPR_STATS

#endif // __PCKT_PARSING_H
