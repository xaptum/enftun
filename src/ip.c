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

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "ip.h"

const struct in6_addr ip6_all_nodes = {
    .s6_addr = { // ff02::1
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};

const struct in6_addr ip6_all_routers = {
    .s6_addr = { // fe02::2
        0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    }
};

const struct in6_addr ip6_default = {
    .s6_addr = { // ::
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
};

const struct in6_addr ip6_self = {
    .s6_addr = { // fe80::1
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};

int ip6_prefix_str(const struct in6_addr* addr,
                   const int prefix, char* dst,
                   size_t size)
{
    int rc;

    /* Print the IP address */
    if (inet_ntop(AF_INET6, addr, dst, size) == NULL)
        return -1;

    int len = strlen(dst);
    size -= len; dst += len;

    /* Print the slash */
    if (size < 2)
        return -1;

    dst[0] = '/';
    dst[1] = '\0';
    size -= 1; dst += 1;

    /* Print the prefix */
    rc = snprintf(dst, size, "%d", prefix);
    if ((rc < 0) || ((size_t) rc >= size))
        return -1;

    return 0;
}
