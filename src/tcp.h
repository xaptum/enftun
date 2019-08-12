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

#ifndef ENFTUN_TCP_H
#define ENFTUN_TCP_H

#include <netinet/in.h>

#define MAX_SOCKADDR_LEN sizeof(struct sockaddr_in6)

struct enftun_tcp_ops
{
    int (*connect)(void* ctx, const char* host, const char* port);
    int (*connect_any)(void* ctx, const char** host, const char* port);
    void (*close)(void* ctx);
};

struct enftun_tcp
{
    int fd; // file descriptor for the underlying TCP socket
    union {
        struct sockaddr local_addr;
        char _local_addr_pad[MAX_SOCKADDR_LEN];
    };

    union {
        struct sockaddr remote_addr;
        char _remote_addr_pad[MAX_SOCKADDR_LEN];
    };

    struct enftun_tcp_ops ops;
};

struct enftun_tcp_native
{
    struct enftun_tcp socket;
    int fwmark;
};

void
enftun_tcp_native_init(struct enftun_tcp_native* ctx,
                       struct enftun_tcp* sock,
                       int mark);

int
enftun_tcp_native_connect(struct enftun_tcp_native* tcp,
                          const char* host,
                          const char* port);

int
enftun_tcp_native_connect_any(struct enftun_tcp_native* tcp,
                              const char** hosts,
                              const char* port);

void
enftun_tcp_native_close(struct enftun_tcp_native* tcp);

#endif
