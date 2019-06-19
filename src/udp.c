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

#include "udp.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"

int
enftun_udp_connect_addr(struct enftun_udp* udp, struct sockaddr* connect_addr)
{
    int rc = 0;

    udp->fd = socket(connect_addr->sa_family, SOCK_DGRAM, 0);

    if (udp->fd < 0) {
        enftun_log_error("UDP: Failed to create socket: %s\n", strerror(errno));
    }

    rc = connect(udp->fd, connect_addr, sizeof(struct sockaddr));
    if (0 != rc){
        enftun_log_error("UDP: Failed to connect: \n", strerror(errno));
        close(udp->fd);
        return rc;
    }

    socklen_t length = sizeof(struct sockaddr);
    rc = getsockname(udp->fd, &udp->local_addr, &length);
    if (0 != rc){
        close(udp->fd);
        return rc;
    }

    rc = getpeername(udp->fd, &udp->remote_addr, &length);
    if (0 != rc){
        close(udp->fd);
        return rc;
    }

    return rc;
}

int
enftun_udp_close(struct enftun_udp* udp)
{
    close(udp->fd);
    return 0;
}

int
enftun_sockaddr_compare(struct sockaddr* local_udp, struct sockaddr* local_tcp)
{
    if (local_udp->sa_family != local_tcp->sa_family)
        return -1;

    if (local_udp->sa_family == AF_INET) {
        struct sockaddr_in *udp_in = (struct sockaddr_in*)local_udp;
        struct sockaddr_in *tcp_in = (struct sockaddr_in*)local_tcp;

        if (ntohl(udp_in->sin_addr.s_addr) != ntohl(tcp_in->sin_addr.s_addr))
            return -1;

    } else if (local_udp->sa_family == AF_INET6) {
        struct sockaddr_in6 *udp_in6 = (struct sockaddr_in6*)local_udp;
        struct sockaddr_in6 *tcp_in6 = (struct sockaddr_in6*)local_tcp;

        int rc = memcmp(udp_in6->sin6_addr.s6_addr, tcp_in6->sin6_addr.s6_addr, sizeof(udp_in6->sin6_addr.s6_addr));
        if (rc != 0)
            return -1;
    }

    return 0;
}
