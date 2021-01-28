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

#include <arpa/inet.h>

#include "filter.h"
#include "ip.h"
#include "log.h"

#define IP4_HEADER(hdr, pkt) struct iphdr* hdr = (struct iphdr*) pkt->data
#define IP6_HEADER(hdr, pkt) struct ip6_hdr* hdr = (struct ip6_hdr*) pkt->data

int
enftun_is_ipv4(struct enftun_packet* pkt)
{
    IP4_HEADER(hdr, pkt);

    if (pkt->size < sizeof(struct iphdr))
      {
        enftun_log_debug("enftun_is_ipv4: packet smaller than IPv4 header (%d < %d)\n",
                         pkt->size, sizeof(struct iphdr));
        return 0;
      }

    if (hdr->version != IPVERSION)
      {
        enftun_log_debug("enftun_is_ipv4: header version is not 4 (%d != %d)\n",
                         (hdr->version), IPVERSION);
        return 0;
      }

    if (ntohs(hdr->tot_len) != pkt->size)
    {
        enftun_log_debug("enftun_is_ipv4: payload length does not match "
                         "received (%d != %d)\n",
                         ntohs(hdr->tot_len), pkt->size);
        return 0;
    }

    return 1;
}

int
enftun_is_ipv6(struct enftun_packet* pkt)
{
    IP6_HEADER(hdr, pkt);

    if (pkt->size < sizeof(struct ip6_hdr))
    {
        enftun_log_debug(
            "enftun_is_ipv6: packet smaller than IPv6 header (%d < %d)\n",
            pkt->size, sizeof(struct ip6_hdr));
        return 0;
    }

    if ((hdr->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
    {
        enftun_log_debug("enftun_is_ipv6: header version is not 6 (%d != %d)\n",
                         (hdr->ip6_vfc >> 4), 6);
        return 0;
    }

    if (ntohs(hdr->ip6_plen) != pkt->size - sizeof(*hdr))
    {
        enftun_log_debug("enftun_is_ipv6: payload length does not match "
                         "received (%d != %d)\n",
                         ntohs(hdr->ip6_plen), pkt->size - sizeof(*hdr));
        return 0;
    }

    return 1;
}

int
enftun_has_src_ip(struct enftun_packet* pkt, struct in6_addr* addr)
{
    IP6_HEADER(hdr, pkt);

    if (!ipv6_equal(&hdr->ip6_src, addr))
    {
        char actual[45], expected[45];
        inet_ntop(AF_INET6, addr, expected, sizeof(expected));
        inet_ntop(AF_INET6, &hdr->ip6_src, actual, sizeof(actual));

        enftun_log_debug("enftun_has_src_ip: %s != %s\n", expected, actual);
        return 0;
    }

    return 1;
}

int
enftun_has_dst_ip(struct enftun_packet* pkt, struct in6_addr* addr)
{
    IP6_HEADER(hdr, pkt);
    return ipv6_equal(&hdr->ip6_dst, addr);
}
