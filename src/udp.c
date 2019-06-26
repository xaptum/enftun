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
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"

int
enftun_udp_connect_addr(struct enftun_udp* udp,
                        int mark,
                        struct sockaddr* connect_addr)
{
    int rc = 0;

    udp->fd = socket(connect_addr->sa_family, SOCK_DGRAM, 0);
    if (udp->fd < 0)
    {
        enftun_log_error("UDP: Failed to create socket: %s\n", strerror(errno));
        rc = -errno;
        goto out;
    }

    if (mark > 0)
    {
        if ((rc = setsockopt(udp->fd, SOL_SOCKET, SO_MARK, &mark,
                             sizeof(mark))) < 0)
        {
            enftun_log_error("UDP: Failed to set mark %d: %s\n", mark,
                             strerror(errno));
            rc = -errno;
            goto close_fd;
        }
    }

    rc = connect(udp->fd, connect_addr, sizeof(struct sockaddr));
    if (0 != rc)
    {
        enftun_log_error("UDP: Failed to connect: %s\n", strerror(errno));
        goto close_fd;
    }

    socklen_t length = MAX_SOCKADDR_LEN;
    rc               = getsockname(udp->fd, &udp->local_addr, &length);
    if (0 != rc)
        goto close_fd;

    rc = getpeername(udp->fd, &udp->remote_addr, &length);
    if (0 != rc)
        goto close_fd;

    goto out;

close_fd:
    close(udp->fd);
    udp->fd = 0;

out:
    return rc;
}

int
enftun_udp_close(struct enftun_udp* udp)
{
    close(udp->fd);
    return 0;
}
