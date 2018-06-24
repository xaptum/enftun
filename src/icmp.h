/*
 * Copyright 2018 Xaptum, Inc.
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

#ifndef ENFTUN_ICMP_H
#define ENFTUN_ICMP_H

#include "ip.h"

enum icmpv6_type_type
{
    enftun_icmpv6_echo_request         = 128,
    enftun_icmpv6_echo_reply           = 129,
    enftun_icmpv6_router_solicitation  = 133,
    enftun_icmpv6_router_advertisement = 134
};

#pragma pack(push, 1)
struct icmp6_hdr
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

/**
 * ICMP6 Router Solitication
 */
struct icmp6_rs
{
    struct icmp6_hdr header;
    uint32_t reserved;
};

/**
 * ICMP6 Router Advertisement
 */
struct icmp6_ra
{
    uint8_t  cur_hop_limit;
    uint8_t  cfg_reserved : 2,
             cfg_proxy    : 1,
             cfg_prf      : 2,
             cfg_home     : 1,
             cfg_other    : 1,
             cfg_managed  : 1;
    uint16_t router_lifetime;
    uint32_t reachable_time;
    uint32_t retrans_timer;
};

struct icmp6_opt_hdr
{
    uint8_t type;
    uint8_t length;
};

struct icmp6_opt_mtu
{
    uint16_t reserved;
    uint32_t mtu;
};

struct icmp6_opt_prefix
{
    uint8_t  prefix_length;
    uint8_t  flags_reserved   : 5,
             flags_router     : 1,
             flags_autoconfig : 1,
             flags_onlink     : 1;
    uint32_t valid_lifetime;
    uint32_t preferred_lifetime;
    uint32_t reserved;
    struct in6_addr prefix;
};

#pragma pack(pop)

#include "log.h"

static
void
icmp6_set_checksum(struct enftun_ipv6_header* iphdr, struct icmp6_hdr* icmp)
{
    uint32_t  sum = 0;
    uint16_t* w;
    int i;

    icmp->checksum = 0;

    // IPv6 pseudo-header
    //   - src and dst
    w = (uint16_t*) &iphdr->src;
    for (i = 0; i < 16; ++i)
        sum += *w++;
    //   - length
    sum += iphdr->payload_length;
    //   - next header
    sum += htons(58);

    // ICMP payload
    w = (uint16_t*) icmp;
    for (i = ntohs(iphdr->payload_length); i > 1; i -= 2)
    {
        sum += *w++;
    }

    if (i == 1)
        sum += (uint16_t) *(uint8_t*)w;

    sum += sum >> 16;

    icmp->checksum = (uint16_t) ~sum;
}

/**
static
void
icmp6_build_ra(struct enftun_packet* pkt)
{
    struct enftun_ipv6_header* iphdr;
    struct icmp6_hdr* icmphdr;
    struct icmp6_ra*  icmpra;

    struct icmp6_opt_hdr* opthdr;
    struct icmp6_opt_mtu* optmtu;
    struct icmp6_opt_prefix* optprefix;

    enftun_packet_reset(pkt);
    enftun_packet_reserve_head(pkt, sizeof(*iphdr));

    icmphdr = enftun_packet_insert_tail(pkt, sizeof(*icmphdr));
    icmphdr->type = 134;
    icmphdr->code = 0;

    icmpra = enftun_packet_insert_tail(pkt, sizeof(*icmpra));
    icmpra->cur_hop_limit = 64;
    icmpra->cfg_managed = 0;
    icmpra->cfg_other = 0;
    icmpra->cfg_prf = 1;
    icmpra->router_lifetime = htons(1800);
    icmpra->reachable_time = 0;
    icmpra->retrans_timer = 0;

    opthdr = enftun_packet_insert_tail(pkt, sizeof(*opthdr));
    opthdr->type = 5;
    opthdr->length = 1;

    optmtu = enftun_packet_insert_tail(pkt, sizeof(*optmtu));
    optmtu->mtu = htonl(1280);

    opthdr = enftun_packet_insert_tail(pkt, sizeof(*opthdr));
    opthdr->type = 3;
    opthdr->length = 4;

    optprefix = enftun_packet_insert_tail(pkt, sizeof(*optprefix));
    optprefix->prefix_length = 64;
    optprefix->flags_onlink = 1;
    optprefix->flags_autoconfig = 1;
    optprefix->flags_router = 1;
    optprefix->valid_lifetime = -1;
    optprefix->preferred_lifetime = -1;
    inet_pton(AF_INET6, "2607:8f80:1234::1111", &optprefix->prefix);

    size_t payload_len = pkt.size;

    iphdr = enftun_packet_insert_head(pkt, sizeof(*iphdr));
    iphdr = (struct enftun_ipv6_header*) pkt.data;
    iphdr->version = 6;
    iphdr->payload_length = htons(payload_len);
    iphdr->next_header = 58;
    iphdr->hop_limit = 255;
    inet_pton(AF_INET6, "fe80::1111:2222:3333:4444", &iphdr->src);
    inet_pton(AF_INET6, "ff02::1", &iphdr->dst);

    icmp6_set_checksum(iphdr, icmphdr);
}
*/

#endif // ENFTUN_ICMP_H
