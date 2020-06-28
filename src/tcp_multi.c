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

#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"
#include "tcp.h"
#include "tcp_multi.h"
#ifdef USE_HSS
#include "tcp_hss.h"
#endif

static int
enftun_tcp_multi_connect_any(struct enftun_tcp* tcp,
                             const char** hosts,
                             const char* port,
                             int fwmark);

/**
 * This is a pseudo-type that acts as a multiplexer of the below types and,
 * upon a connection call, will try each one in order and return the first
 * successful type.
 */
typedef void (*enftun_multi_init_type)(struct enftun_tcp* tcp);
static enftun_multi_init_type enftun_multi_init_types[] = {
    enftun_tcp_native_init,
#ifdef USE_HSS
    enftun_tcp_hss_init,
#endif
};
static const int enftun_tcp_ops_size =
    sizeof(enftun_multi_init_types) / sizeof(enftun_multi_init_types[0]);

int
enftun_tcp_multi_connect(struct enftun_tcp* tcp,
                         const char* host,
                         const char* port,
                         int fwmark)
{
    int i;
    int rc;

    for (i = 0; i < enftun_tcp_ops_size; i++)
    {
        enftun_multi_init_types[i](tcp);
        rc = tcp->ops.connect(tcp, host, port, fwmark);
        if (!rc)
            break;
        tcp->ops.close(tcp);
    }

    // If all ops failed revert back to multi type
    if (rc)
        enftun_tcp_multi_init(tcp);

    return rc;
}

/**
 * This procedure tries every protocol in order, trying every address once
 * with the procol before moving on.
 */
static int
enftun_tcp_multi_connect_any(struct enftun_tcp* tcp,
                             const char** hosts,
                             const char* port,
                             int fwmark)
{
    int i;
    int rc = 0;

    for (i = 0; i < enftun_tcp_ops_size; i++)
    {
        enftun_multi_init_types[i](tcp);
        rc = tcp->ops.connect_any(tcp, hosts, port, fwmark);
        if (!rc)
            break;
        tcp->ops.close(tcp);
    }

    // If all ops failed revert back to multi type
    if (rc)
        enftun_tcp_multi_init(tcp);

    return rc;
}

void
enftun_tcp_multi_close(struct enftun_tcp* tcp)
{
    (void) tcp;
}

static struct enftun_tcp_ops enftun_tcp_multi_ops = {
    .connect =
        (int (*)(struct enftun_tcp*, const char* host, const char*, int fwmark))
            enftun_tcp_multi_connect,
    .connect_any = enftun_tcp_multi_connect_any,
    .close       = enftun_tcp_multi_close};

void
enftun_tcp_multi_init(struct enftun_tcp* tcp)
{
    tcp->ops  = enftun_tcp_multi_ops;
    tcp->type = ENFTUN_TCP_NONE;
}
