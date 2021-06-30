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

#ifndef ENFTUN_NAT_H
#define ENFTUN_NAT_H

#include <netinet/ip6.h>
#include <stdint.h>

#include "nat_rule.h"

struct enftun_nat
{
    size_t rules_len;
    struct enftun_nat_rule* rules_forward;
    struct enftun_nat_rule* rules_reverse;

    const struct in6_addr* self;
};

int
enftun_nat_init(struct enftun_nat* nat,
                struct enftun_nat_rule* rules,
                size_t len,
                const struct in6_addr* self);

int
enftun_nat_free(struct enftun_nat* nat);

int
enftun_nat_ingress(struct enftun_nat* nat, struct enftun_packet* pkt);

int
enftun_nat_egress(struct enftun_nat* nat, struct enftun_packet* pkt);

#endif
