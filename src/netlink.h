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

struct enftun_netlink
{
    int fd;
    struct sockaddr_nl sock_addr;
};

int
enftun_netlink_connect(struct enftun_netlink* nl);

int
enftun_netlink_close(struct enftun_netlink* nl);


#endif // ENFTUN_NETLINK_H
