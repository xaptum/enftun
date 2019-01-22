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

#ifndef ENFTUN_DHCP_H
#define ENFTUN_DHCP_H

#include <stdbool.h>

#include <netinet/in.h>

#include "channel.h"
#include "packet.h"

struct enftun_dhcp
{
    struct enftun_channel* chan;

    uint8_t duid[16];

    struct in6_addr ipv6;

    struct enftun_packet pkt;
    struct enftun_crb crb;

    bool inflight;
};

int
enftun_dhcp_init(struct enftun_dhcp* dchp,
                 struct enftun_channel *chan,
                 const struct in6_addr* ipv6);

int
enftun_dhcp_free(struct enftun_dhcp* dhcp);

int
enftun_dhcp_handle_packet(struct enftun_dhcp* dhcp,
                          struct enftun_packet* pkt);

#endif // ENFTUN_DHCP_H
