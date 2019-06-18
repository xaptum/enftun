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

#ifndef ENFTUN_UDP_H
#define ENFTUN_UDP_H

#include <netinet/in.h>

#define MAX_SOCKADDR_LEN    sizeof(struct sockaddr_in6)

struct enftun_udp
{
    int fd; // file descriptor for the underlying UDP socket
    union {
        struct sockaddr local_addr;
        char _local_addr_pad[MAX_SOCKADDR_LEN];
    };

    union {
        struct sockaddr remote_addr;
        char _remote_addr_pad[MAX_SOCKADDR_LEN];
    };
};

int
enftun_udp_connect_addr(struct enftun_udp* udp, struct sockaddr* addr);

int
enftun_udp_close(struct enftun_udp* udp);

#endif //ENFTUN_UDP_H
