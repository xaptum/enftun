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

#ifndef ENFTUN_ICMP_H
#define ENFTUN_ICMP_H

#include <stdbool.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "packet.h"

#ifndef ND_RA_FLAG_PRF_HIGH
#define ND_RA_FLAG_PRF_HIGH 0x08
#define ND_RA_FLAG_PRF_MEDIUM 0x00
#define ND_RA_FLAG_PRF_LOW 0x18
#endif

#ifndef ND_OPT_ROUTE_INFO
#define ND_OPT_ROUTE_INFO 24

struct nd_opt_route_info {/* route info */
    u_int8_t    nd_opt_rti_type;
    u_int8_t    nd_opt_rti_len;
    u_int8_t    nd_opt_rti_prefixlen;
    u_int8_t    nd_opt_rti_flags;
    u_int32_t   nd_opt_rti_lifetime;
    /* prefix follows */
} __packed;
#endif

bool
icmp6_is_nd_rs(struct enftun_packet* pkt);

int
icmp6_make_nd_ra(struct enftun_packet* pkt,
                 const struct in6_addr* src,
                 const struct in6_addr* dst,
                 const char** routes,
                 int lifetime);

#endif // ENFTUN_ICMP_H
