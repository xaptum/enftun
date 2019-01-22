/*
 * Copyright 2018-2019 Xaptum, Inc.
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

#include "ip.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

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

int
ip6_prefix(const char* str,
           struct in6_addr* prefix,
           uint8_t* prefixlen)
{
    // Handle the special string "default"
    if (0 == strcmp(str, "default"))
    {
        *prefix = ip6_default;
        *prefixlen = 0;
        return 0;
    }

    // Parse an actual IPv6 prefix
    char buf[65];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[64] = 0; // null terminator

    // Parse characters after slash as prefixlen.
    // If no slash, use 128.
    char *slash = strchr(buf, '/');
    if ( slash )
    {
        *slash = 0;

        char *beg = slash + 1;
        char *end = NULL;
        errno = 0;
        long val = strtol(beg, &end, 10);
        if (*beg != 0 && *end == 0 && errno != ERANGE &&
            val >= 0 && val <= 128)
            *prefixlen = val;
        else
            return -1;
    } else
    {
        *prefixlen = 128;
    }

    if (!inet_pton(AF_INET6, buf, prefix))
        return -1;

    return 0;
}
