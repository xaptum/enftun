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
#include <unistd.h>

int
enftun_netlink_connect(struct enftun_netlink* nl)
{
    nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl->fd < 0) {
        return -1;
    }

    nl->sock_addr.nl_family = AF_NETLINK;
    nl->sock_addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE;
    nl->sock_addr.nl_pid = getpid();

    if (bind(nl->fd, (struct sockaddr*)&nl->sock_addr, sizeof(struct sockaddr_nl)) < 0) {
        close(nl->fd);
        return -1;
    }

    return 0;
}

int
enftun_netlink_close(struct enftun_netlink* nl)
{
    close(nl->fd);
    return 0;
}
