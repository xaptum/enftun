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

#pragma once

#ifndef ENFTUN_MEM_H
#define ENFTUN_MEM_H

#include <stdbool.h>
#include <string.h>

/*
 * Clear a struct.
 *
 * This could be optimized away. Do not use to clear secrets.
 */
#define CLEAR(s) memset(&(s), 0, sizeof(s))

/*
 * https://github.com/rustyrussell/ccan/blob/master/ccan/mem/mem.c
 * License: CC0 (Public domain)
 */
static inline bool
memeq(const void* data, size_t length, unsigned char val)
{
    const unsigned char* p = data;
    size_t len;

    /* Check first 16 bytes manually */
    for (len = 0; len < 16; len++)
    {
        if (!length)
            return true;
        if (*p != val)
            return false;
        p++;
        length--;
    }

    /* Now we know that's all equal, memcmp with self. */
    return memcmp(data, p, length) == 0;
}

static inline bool
memeqzero(const void* data, size_t length)
{
    return memeq(data, length, 0x00);
}

#endif // ENFTUN_MEM_H
