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

#pragma once

#ifndef ENFTUN_TUN_H
#define ENFTUN_TUN_H

#include <stdint.h>

#include "channel.h"
#include "packet.h"

struct enftun_tun
{
    int fd;     // file descriptor for TUN device
    char* name; // name of the TUN dev, including unit number if any
};

extern struct enftun_channel_ops enftun_tun_ops;

int
enftun_tun_init(struct enftun_tun* tun);

int
enftun_tun_free(struct enftun_tun* tun);

int
enftun_tun_open(struct enftun_tun* tun, const char* dev, const char* dev_node);

int
enftun_tun_close(struct enftun_tun* tun);

int
enftun_tun_set_ip6(struct enftun_tun* tun,
                   const char* ip_path,
                   const struct in6_addr* ip6);

int
enftun_tun_read(struct enftun_tun* tun, uint8_t* buf, size_t len);

int
enftun_tun_write(struct enftun_tun* tun, uint8_t* buf, size_t len);

int
enftun_tun_read_packet(struct enftun_tun* tun, struct enftun_packet* pkt);

int
enftun_tun_write_packet(struct enftun_tun* tun, struct enftun_packet* pkt);

#endif // ENFTUN_TUN_H
