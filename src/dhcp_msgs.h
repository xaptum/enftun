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

#pragma once

#ifndef ENFTUN_DHCP6_MSGS_H
#define ENFTUN_DHCP6_MSGS_H

#include <stdint.h>

#include "dhcp6_types.h"
#include "packet.h"

struct enftun_dhcp6_context
{
    struct in6_addr* lladdr;

    uint8_t* xid;

    uint8_t* cid;
    uint16_t cidlen;

    uint8_t* sid;
    uint16_t sidlen;

    uint32_t iaid;
};

struct dhcp6_msg*
enftun_dhcp6_parse(struct enftun_packet* pkt, struct enftun_dhcp6_context* ctx);

struct dhcp6_msg*
enftun_dhcp6_advertise(struct enftun_packet* pkt,
                       struct enftun_dhcp6_context* ctx,
                       const struct in6_addr* caddr);

struct dhcp6_msg*
enftun_dhcp6_reply(struct enftun_packet* pkt,
                   struct enftun_dhcp6_context* ctx,
                   const struct in6_addr* caddr);

struct dhcp6_msg*
enftun_dhcp6_msg(struct enftun_packet* pkt, uint8_t type, const uint8_t* xid);

struct dhcp6_option*
enftun_dhcp6_clientid(struct enftun_packet* pkt,
                      const uint8_t* duid,
                      size_t duidlen);

struct dhcp6_option*
enftun_dhcp6_serverid(struct enftun_packet* pkt,
                      const uint8_t* duid,
                      size_t duidlen);

struct dhcp6_option*
enftun_dhcp6_ia_na_start(struct enftun_packet* pkt,
                         uint32_t iaid,
                         uint32_t t1,
                         uint32_t t2);

static inline void
enftun_dhcp6_ia_na_finish(struct enftun_packet* pkt, struct dhcp6_option* opt)
{
    opt->len = htons((void*) pkt->tail - (void*) opt - sizeof(*opt));
}

struct dhcp6_option*
enftun_dhcp6_iaaddr_start(struct enftun_packet* pkt,
                          const struct in6_addr* addr,
                          uint32_t pltime,
                          uint32_t vltime);

static inline void
enftun_dhcp6_iaaddr_finish(struct enftun_packet* pkt, struct dhcp6_option* opt)
{
    opt->len = htons((void*) pkt->tail - (void*) opt - sizeof(*opt));
}

struct dhcp6_option*
enftun_dhcp6_status_code(struct enftun_packet* pkt, uint16_t code);

#endif // ENFTUN_DHCP6_MSGS_H
