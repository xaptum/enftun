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
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"
#include "tcp.h"

#define get_sin_addr(addr) (&((struct sockaddr_in*) addr->ai_addr)->sin_addr)

#define get_sin_port(addr) (((struct sockaddr_in*) addr->ai_addr)->sin_port)

void
enftun_tcp_native_init(struct enftun_tcp_native* ctx,
                       struct enftun_tcp* sock,
                       int mark)
{
    ctx->socket = *sock;

    ctx->socket.ops.connect     = (int (*)(void*, const char* host,
                                       const char*)) enftun_tcp_native_connect;
    ctx->socket.ops.connect_any = (int (*)(
        void*, const char** host, const char*)) enftun_tcp_native_connect_any;
    ctx->socket.ops.close       = (void (*)(void*)) enftun_tcp_native_close;

    ctx->fwmark = mark;
}

static int
do_connect(struct enftun_tcp* tcp, int mark, struct addrinfo* addr)
{
    char ip[45];
    int opt, port;
    int rc;

    inet_ntop(addr->ai_family, get_sin_addr(addr), ip, sizeof(ip));
    port = ntohs(get_sin_port(addr));

    enftun_log_debug("TCP: connecting to [%s]:%d\n", ip, port);

    if ((tcp->fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol)) < 0)
    {
        enftun_log_error("TCP: Failed to create socket: %s\n", strerror(errno));
        rc = -errno;
        goto out;
    }

    if (mark > 0)
    {
        if ((rc = setsockopt(tcp->fd, SOL_SOCKET, SO_MARK, &mark,
                             sizeof(mark))) < 0)
        {
            enftun_log_error("TCP: Failed to set mark %d: %s\n", mark,
                             strerror(errno));
            rc = -errno;
            goto close_fd;
        }
    }

    opt = 1;
    if ((rc = setsockopt(tcp->fd, SOL_SOCKET, SO_KEEPALIVE, &opt,
                         sizeof(opt))) < 0)
    {
        enftun_log_error("TCP: Failed to enable keepalives: %s\n",
                         strerror(errno));
        rc = -errno;
        goto close_fd;
    }

    opt = 5 * 60;
    if ((rc = setsockopt(tcp->fd, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt))) <
        0)
    {
        enftun_log_error("TCP: Failed to enable keepalive time: %s\n",
                         strerror(errno));
        rc = -errno;
        goto close_fd;
    }

    opt = 6;
    if ((rc = setsockopt(tcp->fd, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt))) < 0)
    {
        enftun_log_error("TCP: Failed to enable keepalive probes: %s\n",
                         strerror(errno));
        rc = -errno;
        goto close_fd;
    }

    opt = 10;
    if ((rc = setsockopt(tcp->fd, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt))) <
        0)
    {
        enftun_log_error("TCP: Failed to enable keepalive interval: %s\n",
                         strerror(errno));
        rc = -errno;
        goto close_fd;
    }

    if ((rc = connect(tcp->fd, addr->ai_addr, addr->ai_addrlen)) < 0)
    {
        enftun_log_error("TCP: Failed to connect to [%s]:%d: %s\n", ip, port,
                         strerror(errno));
        rc = -errno;
        goto close_fd;
    }

    enftun_log_info("TCP: Connected to [%s]:%d\n", ip, port);
    goto out;

close_fd:
    close(tcp->fd);
    tcp->fd = 0;

out:
    return rc;
}

int
enftun_tcp_native_connect(struct enftun_tcp_native* ctx,
                          const char* host,
                          const char* port)
{
    int rc;
    struct addrinfo *addr_h, *addr, hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    rc = getaddrinfo(host, port, &hints, &addr_h);
    if (rc < 0)
    {
        enftun_log_error("TCP: Cannot resolve %s:%s: %s\n", host, port,
                         gai_strerror(rc));
        rc = -1;
        goto out;
    }

    for (addr = addr_h; addr != NULL; addr = addr->ai_next)
    {
        rc = do_connect(&ctx->socket, ctx->fwmark, addr);
        if (rc == 0)
            break;
    }

    if (addr != NULL)
    {
        socklen_t length = MAX_SOCKADDR_LEN;
        getsockname(ctx->socket.fd, &ctx->socket.local_addr, &length);
        getpeername(ctx->socket.fd, &ctx->socket.remote_addr, &length);
    }

    freeaddrinfo(addr_h);

out:
    return rc;
}

int
enftun_tcp_native_connect_any(struct enftun_tcp_native* ctx,
                              const char** hosts,
                              const char* port)
{
    int rc = 0;
    const char* host;

    for (host = *hosts; host != NULL; host = *++hosts)
    {
        rc = enftun_tcp_native_connect(ctx, host, port);
        if (rc == 0)
            break;
    }

    return rc;
}

void
enftun_tcp_native_close(struct enftun_tcp_native* ctx)
{
    if (ctx->socket.fd)
        close(ctx->socket.fd);
    ctx->socket.fd = 0;
}
