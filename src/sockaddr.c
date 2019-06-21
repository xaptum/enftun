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

#include "sockaddr.h"

#include <string.h>

int
enftun_sockaddr_equal(struct sockaddr* a, struct sockaddr* b)
{
    if (a->sa_family != b->sa_family)
        return -1;

    switch (a->sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *ina = (struct sockaddr_in*)a;
            struct sockaddr_in *inb = (struct sockaddr_in*)b;

            if (ina->sin_addr.s_addr != inb->sin_addr.s_addr)
                return -1;
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *in6a = (struct sockaddr_in6*)a;
            struct sockaddr_in6 *in6b = (struct sockaddr_in6*)b;

            int rc = memcmp(in6a->sin6_addr.s6_addr, in6b->sin6_addr.s6_addr, sizeof(in6a->sin6_addr.s6_addr));
            if (rc != 0)
                return -1;
            break;
        }
        default:
            return -1;
            break;
    }

    return 0;
}
