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

#include "netlink.h"

#include <net/if.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "conn_state.h"

static
int
udp_check(struct enftun_netlink* nl)
{
    char udp_address[45];
    connect_udp_socket(udp_address, sizeof(udp_address), &nl->local_addr);

    struct sockaddr_in local_copy_addr;
    socklen_t copy_addr_len = sizeof(struct sockaddr_in);

    memset(&local_copy_addr, 0, copy_addr_len);
    local_copy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_copy_addr.sin_port = htons(0);
    local_copy_addr.sin_family = AF_INET;

    char local_ip[45];
    getsockname(nl->tcp_fd, (struct sockaddr*)&local_copy_addr, &copy_addr_len);
    inet_ntop(AF_INET, (struct sockaddr_in*)&local_copy_addr.sin_addr, local_ip, sizeof(local_ip));

    if (0 == strcmp(udp_address, local_ip)) {
        return 0;
    }
    else {
        enftun_log_info("UDP detected a higher priority route.\n");
        nl->on_network_change(nl);
    }

    return 0;
}

int
enftun_netlink_connect(struct enftun_netlink* nl, void* ctx)
{
    nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl->fd < 0) {
        return -1;
    }

    nl->sock_addr.nl_family = AF_NETLINK;
    nl->sock_addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
    nl->sock_addr.nl_pid = getpid();

    nl->on_poll = (int (*)(void*))udp_check;

    if (bind(nl->fd, (struct sockaddr*)&nl->sock_addr, sizeof(struct sockaddr_nl)) < 0) {
        close(nl->fd);
        return -1;
    }

    nl->data = ctx;

    nl->poll.data = nl;
    int rc = 0;

    return rc;
}

int
enftun_netlink_close(struct enftun_netlink* nl)
{
    close(nl->fd);
    return 0;
}


int
enftun_netlink_init()
{
    return 0;
}

int
enftun_netlink_free()
{
    return 0;
}

int
enftun_netlink_start(struct enftun_netlink* nl, enftun_netlink_on_change on_network_change)
{
    nl->on_network_change = on_network_change;

    return 0;
}

int
enftun_netlink_stop(struct enftun_netlink* nl)
{
    (void) nl;
    return 0;
}
