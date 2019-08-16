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

#include <stdint.h>

#include <netinet/in.h>

#include "cksum.h"
#include "ip.h"
#include "log.h"
#include "packet.h"

#define ECHO_ID 0x4e45
#define ECHO_SEQ 0x5446

struct nd_router_solicit*
enftun_icmp6_nd_rs_pull(struct enftun_packet* pkt, struct ip6_hdr* iph)
{
    ENFTUN_SAVE_INIT(pkt);

    if (IPPROTO_ICMPV6 != iph->ip6_nxt)
        goto err;

    struct nd_router_solicit* rs = enftun_packet_remove_head(pkt, sizeof(*rs));
    if (!rs)
        goto err;

    if (ND_ROUTER_SOLICIT != rs->nd_rs_type)
        goto err;

    if (0 != rs->nd_rs_code)
        goto err;

    if (0 != ip6_l3_cksum(iph, &rs->nd_rs_hdr))
        goto err;

    return rs;

err:
    ENFTUN_RESTORE(pkt);
    return NULL;
}

struct nd_opt_mtu*
enftun_icmp6_nd_mtu(struct enftun_packet* pkt)
{
    struct nd_opt_mtu* mh = enftun_packet_insert_tail(pkt, sizeof(*mh));
    if (!mh)
        return NULL;

    mh->nd_opt_mtu_type     = ND_OPT_MTU;
    mh->nd_opt_mtu_len      = 1;
    mh->nd_opt_mtu_reserved = 0;
    mh->nd_opt_mtu_mtu      = htonl(1280);

    return mh;
}

struct nd_opt_route_info*
enftun_icmp6_nd_route_info(struct enftun_packet* pkt,
                           const struct in6_addr* pfx,
                           uint8_t pfxlen,
                           uint32_t lifetime)
{
    ENFTUN_SAVE_INIT(pkt);

    struct nd_opt_route_info* ri = enftun_packet_insert_tail(pkt, sizeof(*ri));
    if (!ri)
        goto err;

    uint8_t* ri_pfx = enftun_packet_insert_tail(pkt, 16);
    if (!ri_pfx)
        goto err;

    ri->nd_opt_rti_type      = ND_OPT_ROUTE_INFO;
    ri->nd_opt_rti_len       = 3;
    ri->nd_opt_rti_prefixlen = pfxlen;
    ri->nd_opt_rti_flags     = ND_RA_FLAG_PRF_HIGH;
    ri->nd_opt_rti_lifetime  = htonl(lifetime);
    memcpy(ri_pfx, pfx, 16);

    return ri;

err:
    ENFTUN_RESTORE(pkt);
    return NULL;
}

struct nd_router_advert*
enftun_icmp6_nd_ra(struct enftun_packet* pkt,
                   const struct in6_addr* src,
                   const struct in6_addr* dst,
                   const struct in6_addr* network,
                   uint16_t prefix,
                   const char** other_routes)
{
    enftun_ip6_reserve(pkt);

    struct nd_router_advert* ra = enftun_packet_insert_tail(pkt, sizeof(*ra));
    if (!ra)
        goto err;

    ra->nd_ra_type            = ND_ROUTER_ADVERT;
    ra->nd_ra_code            = 0;
    ra->nd_ra_cksum           = 0; // computed below
    ra->nd_ra_curhoplimit     = 0; // unspecified by this router
    ra->nd_ra_flags_reserved  = ND_RA_FLAG_PRF_HIGH | ND_RA_FLAG_MANAGED;
    ra->nd_ra_router_lifetime = htons(0); // will be set later if default router
    ra->nd_ra_reachable       = htonl(0); // unspecified by this router
    ra->nd_ra_retransmit      = htonl(0); // unspecified by this router

    struct nd_opt_mtu* mh = enftun_icmp6_nd_mtu(pkt);
    if (!mh)
        goto err;

    if (NULL == enftun_icmp6_nd_route_info(pkt, network, prefix, 0xffffffff))
        goto err;

    const char* route;
    for (route = *other_routes; route != NULL; route = *++other_routes)
    {
        struct in6_addr prefix;
        uint8_t prefixlen;

        if (0 != ip6_prefix(route, &prefix, &prefixlen))
        {
            enftun_log_warn("ndp: skipping invalid route %s\n", route);
            continue;
        }

        switch (prefixlen)
        {
        case 0:
            // default route
            ra->nd_ra_router_lifetime = htons(9000); // max allowed by RFC4861
            break;
        default:
            if (NULL ==
                enftun_icmp6_nd_route_info(pkt, &prefix, prefixlen, 0xffffffff))
            {
                enftun_log_warn("ndp: router advertisment full, "
                                "skipping route\n");
                continue;
            }
            break;
        }
    }

    struct ip6_hdr* nh = enftun_ip6_header(pkt, IPPROTO_ICMPV6, 255, src, dst);
    ra->nd_ra_cksum    = ip6_l3_cksum(nh, &ra->nd_ra_hdr);

    return ra;

err:
    return NULL;
}

struct icmp6_hdr*
enftun_icmp6_echo_reply_pull(struct enftun_packet* pkt, struct ip6_hdr* iph)
{
    ENFTUN_SAVE_INIT(pkt);

    if (IPPROTO_ICMPV6 != iph->ip6_nxt)
        goto err;

    struct icmp6_hdr* echo = enftun_packet_remove_head(pkt, sizeof(*echo));
    if (!echo)
        goto err;

    if (ICMP6_ECHO_REPLY != echo->icmp6_type)
        goto err;

    if (0 != echo->icmp6_code)
        goto err;

    if (ECHO_ID != echo->icmp6_id)
        goto err;

    if (ECHO_SEQ != echo->icmp6_seq)
        goto err;

    return echo;

err:
    ENFTUN_RESTORE(pkt);
    return NULL;
}

struct icmp6_hdr*
enftun_icmp6_echo_request(struct enftun_packet* pkt,
                          const struct in6_addr* src,
                          const struct in6_addr* dest)
{
    enftun_packet_reserve_head(pkt, sizeof(struct ip6_hdr));

    struct icmp6_hdr* req =
        enftun_packet_insert_tail(pkt, sizeof(struct icmp6_hdr));
    if (!req)
        goto err;

    req->icmp6_type = ICMP6_ECHO_REQUEST;
    req->icmp6_code = 0;
    req->icmp6_id   = ECHO_ID;
    req->icmp6_seq  = ECHO_SEQ;
    struct ip6_hdr* hdr =
        enftun_ip6_header(pkt, IPPROTO_ICMPV6, 255, src, dest);
    req->icmp6_cksum = ip6_l3_cksum(hdr, &req);

    return req;

err:
    return NULL;
}
