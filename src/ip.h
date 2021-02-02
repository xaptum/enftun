/*
 * Copyright 2018-2019 Xaptum, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifndef ENFTUN_IP_H
#define ENFTUN_IP_H

#include <stdint.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "packet.h"

#ifndef IPV6_VERSION
#define IPV6_VERSION 0x60
#define IPV6_VERSION_MASK 0xf0
#endif

extern const struct in6_addr ip6_all_nodes;
extern const struct in6_addr ip6_all_routers;
extern const struct in6_addr ip6_default;
extern const struct in6_addr ip6_all_dhcp_relay_agents_and_servers;
extern const struct in6_addr ip6_self;

/**
 * Computes the checksum for common transport (layer 3) protocols like
 * TCP, UDP, and ICMPv6.
 */
uint16_t
ip6_l3_cksum(struct ip6_hdr* nh, void* payload);

static inline int
ipv6_equal(const struct in6_addr* a, const struct in6_addr* b)
{
    return memcmp(a, b, sizeof(struct in6_addr)) == 0;
}

int
ip6_prefix_str(const struct in6_addr* addr,
               const int prefix,
               char* dst,
               size_t size);

int
ip6_prefix(const char* str, struct in6_addr* prefix, uint8_t* prefixlen);

static inline void
enftun_ip6_reserve(struct enftun_packet* pkt)
{
    enftun_packet_reserve_head(pkt, sizeof(struct ip6_hdr));
}

static inline void
enftun_udp6_reserve(struct enftun_packet* pkt)
{
    enftun_ip6_reserve(pkt);
    enftun_packet_reserve_head(pkt, sizeof(struct udphdr));
}

struct ip6_hdr*
enftun_ip6_header(struct enftun_packet* pkt,
                  uint8_t nxt,
                  uint8_t hops,
                  const struct in6_addr* src,
                  const struct in6_addr* dst);

struct ip6_hdr*
enftun_udp6_header(struct enftun_packet* pkt,
                   uint8_t hops,
                   const struct in6_addr* src,
                   const struct in6_addr* dst,
                   uint16_t sport,
                   uint16_t dport);

struct ip6_hdr*
enftun_ip6_pull(struct enftun_packet* pkt);

struct ip6_hdr*
enftun_ip6_pull_if_dest(struct enftun_packet* pkt, const struct in6_addr* dst);

struct ip6_hdr*
enftun_udp6_pull(struct enftun_packet* pkt);

struct ip6_hdr*
enftun_udp6_pull_if_dest(struct enftun_packet* pkt,
                         const struct in6_addr* dst,
                         uint16_t sport,
                         uint16_t dport);

#endif // ENFTUN_IP_H
