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

#include "filter.h"
#include "ip.h"


#define IPV6_HEADER_INIT(header, packet) \
    struct ipv6_header* header = (struct ipv6_header*) packet->data

int
enftun_is_ipv6(struct enftun_packet* pkt)
{
    IPV6_HEADER_INIT(hdr, pkt);
    uint16_t payload_length;

    if (pkt->size < sizeof(struct ipv6_header))
        return 0;

    if (hdr->version != 6)
        return 0;

    if (ntohs(hdr->payload_length) != pkt->size - sizeof(*hdr))
        return 0;

    return 1;
}

int
enftun_has_src_ip(struct enftun_packet* pkt, struct in6_addr* addr)
{
    IPV6_HEADER_INIT(hdr, pkt);
    return ipv6_equal(&hdr->src, addr);
}

int
enftun_has_dst_ip(struct enftun_packet* pkt, struct in6_addr* addr)
{
    IPV6_HEADER_INIT(hdr, pkt);
    return ipv6_equal(&hdr->dst, addr);
}
