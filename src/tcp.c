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
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"
#include "tcp.h"

#define get_sin_addr(addr) \
    (&((struct sockaddr_in*)addr->ai_addr)->sin_addr)

#define get_sin_port(addr) \
    (((struct sockaddr_in*)addr->ai_addr)->sin_port)

static
int
do_connect(struct enftun_tcp* tcp, int mark,
           struct addrinfo* addr)
{
    char ip[45];
    int port;
    int rc;

    inet_ntop(addr->ai_family, get_sin_addr(addr), ip, sizeof(ip));
    port = get_sin_port(addr);

    enftun_log_debug("TCP: connecting to [%s]:%d\n", ip, port);

    if ((tcp->fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol)) < 0)
    {
        enftun_log_debug("TCP: Failed to create socket: %s\n", strerror(errno));
        rc = -errno;
        goto out;
    }

    if (mark > 0)
    {
        if ((rc = setsockopt(tcp->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) < 0)
        {
            enftun_log_debug("TCP: Failed to set mark %d: %s\n", mark, strerror(errno));
            rc = -errno;
            goto close_fd;
        }
    }

    if ((rc = connect(tcp->fd, addr->ai_addr, addr->ai_addrlen)) < 0)
    {
        enftun_log_debug("TCP: Failed to connect to [%s]:%d: %s\n",
                         ip, port, strerror(errno));
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
enftun_tcp_connect(struct enftun_tcp* tcp,
                   int mark, const char* host, const char *port)
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
        enftun_log_error("TCP: Cannot resolve %s:%s: %s\n",
                         host, port, gai_strerror(rc));
        rc = -1;
        goto out;
    }

    for (addr=addr_h; addr!=NULL; addr=addr->ai_next)
    {
        rc = do_connect(tcp, mark, addr);
        if (rc == 0)
            break;
    }

    freeaddrinfo(addr_h);

 out:
    return rc;
}

int
enftun_tcp_connect_any(struct enftun_tcp* tcp,
                       int mark,
                       const char** hosts, const char *port)
{
    int rc;
    const char* host;

    for (host=*hosts; host!=NULL; host=*++hosts)
    {
        rc = enftun_tcp_connect(tcp, mark, host, port);
        if (rc == 0)
            break;
    }

    return rc;
}

void
enftun_tcp_close(struct enftun_tcp* tcp)
{
    if (tcp->fd)
        close(tcp->fd);
    tcp->fd = 0;
}
