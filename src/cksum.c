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

#include "cksum.h"

uint16_t
in_cksum(const void* buf, size_t len)
{
    uint32_t sum = 0;
    uint16_t* w;
    size_t i;

    w = (uint16_t*) buf;
    for (i = len; i > 1; i -= 2)
        sum += *w++;

    if (i == 1)
        sum += (uint16_t) * (uint8_t*) w;

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return (uint16_t) ~sum;
}
