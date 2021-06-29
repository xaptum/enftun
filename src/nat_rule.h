/*
 * Copyright 2021 Xaptum, Inc.
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

#ifndef ENFTUN_NAT_RULE_H
#define ENFTUN_NAT_RULE_H

#include <netinet/ip6.h>
#include <stdint.h>

#include "ip6.h"
#include "packet.h"

struct enftun_nat_addr
{
    struct in6_addr addr;
    uint16_t port;
};

struct enftun_nat_tuple
{
    struct enftun_nat_addr src;
    struct enftun_nat_addr dst;
};

struct enftun_nat_rule
{
    uint8_t proto;

    struct enftun_nat_tuple match;
    struct enftun_nat_tuple trans;
};

int
enftun_nat_rule_normalize(struct enftun_nat_rule* rule,
                          const struct in6_addr* self);

void
enftun_nat_rule_reverse(const struct enftun_nat_rule* rule,
                        struct enftun_nat_rule* reversed);

int
enftun_nat_rule_apply(const struct enftun_nat_rule* rule,
                      struct ip6_hdr* nh,
                      void* payload,
                      size_t payload_len);

#endif
