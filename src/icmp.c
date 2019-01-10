/*
 * Copyright 2019 Xaptum, Inc.
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

#include "icmp.h"

#include "ip.h"
#include "log.h"

static
uint16_t
icmp6_cksum(struct ip6_hdr* nh, struct icmp6_hdr* th)
{
    uint32_t sum = 0;
    uint16_t* w;
    int i;

    // IPv6 pseudo-header
    //   - src and dst
    w = (uint16_t*) &nh->ip6_src;
    for (i = 0; i < 16; ++i)
        sum += *w++;
    sum += nh->ip6_plen;
    sum += htons(nh->ip6_nxt);

    // ICMP payload
    w = (uint16_t*) th;
    for (i = ntohs(nh->ip6_plen); i > 1; i -= 2)
    {
        sum += *w++;
    }

    if (i == 1)
        sum += (uint16_t) *(uint8_t*)w;

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return (uint16_t) ~sum;
}

bool
icmp6_is_nd_rs(struct enftun_packet* pkt)
{
    struct rs {
        struct ip6_hdr ip6;
        struct nd_router_solicit icmp6;
    } *rs = (struct rs*) pkt->data;

    // Start with cheap and easy checks first
    if (sizeof(rs) > pkt->size)                                return false;
    if (sizeof(rs->icmp6) > ntohs(rs->ip6.ip6_plen))           return false;

    if (IPV6_VERSION != (rs->ip6.ip6_vfc & IPV6_VERSION_MASK)) return false;

    if (IPPROTO_ICMPV6 != rs->ip6.ip6_nxt)                     return false;
    if (ND_ROUTER_SOLICIT != rs->icmp6.nd_rs_type)             return false;
    if (0 != rs->icmp6.nd_rs_code)                             return false;

    if (0 != memcmp(&rs->ip6.ip6_dst,
                    &ip6_all_routers,
                    sizeof(ip6_all_routers)))                  return false;

    if (0 != icmp6_cksum(&rs->ip6, &rs->icmp6.nd_rs_hdr))      return false;

    return true;
}

int
icmp6_make_nd_ra(struct enftun_packet* pkt,
                 const struct in6_addr* src,
                 const struct in6_addr* dst,
                 const char** routes,
                 int lifetime)
{
    struct ip6_hdr* nh = enftun_packet_insert_tail(pkt, sizeof(*nh));
    if (!nh)
        goto err;

    nh->ip6_vfc = IPV6_VERSION;
    nh->ip6_plen = 0; // computed below
    nh->ip6_nxt = IPPROTO_ICMPV6;
    nh->ip6_hlim = 255;
    nh->ip6_src = *src;
    nh->ip6_dst = *dst;

    struct nd_router_advert* th = enftun_packet_insert_tail(pkt, sizeof(*th));
    if (!th)
        goto err;

    th->nd_ra_type = ND_ROUTER_ADVERT;
    th->nd_ra_code = 0;
    th->nd_ra_cksum = 0; // computed below
    th->nd_ra_curhoplimit = 0; // unspecified by this router
    th->nd_ra_flags_reserved = ND_RA_FLAG_PRF_HIGH | ND_RA_FLAG_MANAGED;
    th->nd_ra_router_lifetime = htonl(0); // not a default router
    th->nd_ra_reachable = htonl(0); // unspecified by this router
    th->nd_ra_retransmit = htonl(0); // unspecified by this router

    struct nd_opt_mtu* mh = enftun_packet_insert_tail(pkt, sizeof(*mh));
    if (!mh)
        goto err;
    mh->nd_opt_mtu_type = ND_OPT_MTU;
    mh->nd_opt_mtu_len = 1;
    mh->nd_opt_mtu_reserved = 0;
    mh->nd_opt_mtu_mtu = htonl(1280);

    const char* route;
    for (route=*routes; route!=NULL; route=*++routes)
    {
        struct in6_addr prefix;
        uint8_t prefixlen;

        if (0 != ip6_prefix(route, &prefix, &prefixlen))
        {
            enftun_log_warn("ndp: skipping invalid route %s\n", route);
            continue;
        }

        struct nd_opt_route_info* rh = enftun_packet_insert_tail(pkt, sizeof(*rh));
        if (!rh)
        {
            enftun_log_warn("ndp: router advertisment full, "
                            "skipping remaining routes\n");
            break;
        }

        uint8_t* rh_prefix = enftun_packet_insert_tail(pkt, 16);
        if (!rh_prefix)
        {
            enftun_log_warn("ndp: router advertisment full, "
                            "skipping route: %s\n", route);
            enftun_packet_remove_tail(pkt, sizeof(*rh));
            continue;
        }

        rh->nd_opt_rti_type = ND_OPT_ROUTE_INFO;
        rh->nd_opt_rti_len = 3;
        rh->nd_opt_rti_prefixlen = prefixlen;
        rh->nd_opt_rti_flags = ND_RA_FLAG_PRF_HIGH;
        rh->nd_opt_rti_lifetime = htonl(lifetime);
        memcpy(rh_prefix, &prefix, 16);
    }

    // update packet length
    nh->ip6_plen = htons(pkt->size - sizeof(*nh));

    // update checksum
    th->nd_ra_cksum = icmp6_cksum(nh, &th->nd_ra_hdr);

    return 0;

 err:
    return -1;
}
