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

// Defines the type of TCP sockets which can be used
enum enftun_tcp_type
{
    ENFTUN_TCP_NATIVE,
    ENFTUN_TCP_SCM,
    ENFTUN_TCP_NONE,
    ENFTUN_TCP_MAX
};

struct enftun_tcp;

struct enftun_tcp_ops
{
    int (*connect)(struct enftun_tcp* sock,
                   const char* host,
                   const char* port,
                   int fwmark);
    int (*connect_any)(struct enftun_tcp* sock,
                       const char** host,
                       const char* port,
                       int fwmark);
    void (*close)(struct enftun_tcp* sock);
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

    enum enftun_tcp_type type;

    struct enftun_tcp_ops ops;
};

// Native TCP specific functions

void
enftun_tcp_native_init(struct enftun_tcp* ctx);

int
enftun_tcp_connect_any(struct enftun_tcp* tcp,
                       const char** hosts,
                       const char* port,
                       int fwmark);

void
enftun_tcp_close(struct enftun_tcp* tcp);

#endif
