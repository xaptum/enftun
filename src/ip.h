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

#include <netinet/ip6.h>
#include <stdint.h>
#include <string.h>

#ifndef IPV6_VERSION
#define IPV6_VERSION 0x60
#define IPV6_VERSION_MASK 0xf0
#endif

extern const struct in6_addr ip6_all_nodes;
extern const struct in6_addr ip6_all_routers;
extern const struct in6_addr ip6_default;

extern const struct in6_addr ip6_self;

static inline
int ipv6_equal(const struct in6_addr* a, const struct in6_addr* b)
{
    return memcmp(a, b, sizeof(struct in6_addr)) == 0;
}

int ip6_prefix_str(const struct in6_addr* addr,
                   const int prefix, char* dst,
                   size_t size);

int ip6_prefix(const char* str,
               struct in6_addr* prefix,
               uint8_t* prefixlen);

#endif // ENFTUN_IP_H
