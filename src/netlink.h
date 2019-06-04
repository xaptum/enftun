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

#ifndef ENFTUN_NETLINK_H
#define ENFTUN_NETLINK_H

#include <linux/rtnetlink.h>
#include <sys/socket.h>

#include <uv.h>

struct enftun_netlink;

typedef void (*enftun_netlink_on_change)(struct enftun_netlink* nl);

struct enftun_netlink
{
    int fd;
    uv_poll_t poll;

    struct sockaddr_nl sock_addr;

    int tcp_fd;
    struct addrinfo local_addr;

    void* data;
    enftun_netlink_on_change on_network_change;

    int (*on_poll)(void* netlink);
};

int
enftun_netlink_connect(struct enftun_netlink* nl, void* ctx);

int
enftun_netlink_close(struct enftun_netlink* nl);

int
enftun_netlink_init();

int
enftun_netlink_free();

int
enftun_netlink_start(struct enftun_netlink* nl,
                     enftun_netlink_on_change on_change);

int
enftun_netlink_stop(struct enftun_netlink* nl);

#endif // ENFTUN_NETLINK_H
