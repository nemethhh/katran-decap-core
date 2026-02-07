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

#ifndef __DECAP_INFO_MAPS_H
#define __DECAP_INFO_MAPS_H

/*
 * This file contains definition of maps used by the TC decap info program.
 */

#include <bpf/bpf_helpers.h>

#include "../include/decap_consts.h"
#include "../include/decap_structs.h"

#ifndef PCKT_INFO_MAP_SIZE
#define PCKT_INFO_MAP_SIZE 100000
#endif

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct flow_key);
  __type(value, struct flow_key);
  __uint(max_entries, PCKT_INFO_MAP_SIZE);
  __uint(map_flags, NO_FLAGS);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_encap_info SEC(".maps");

#endif // of __DECAP_INFO_MAPS_H
