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
#include <stdlib.h>

#include "log.h"
#include "memory.h"
#include "packet.h"

const size_t enftun_packet_max_size = ENFTUN_PACKET_MAX_SIZE;

void
enftun_packet_reset(struct enftun_packet* pkt)
{
    CLEAR(pkt->head);
    pkt->end  = pkt->head + sizeof(pkt->head);
    pkt->data = pkt->head;
    pkt->tail = pkt->data;

    pkt->size = 0;

    enftun_packet_reserve_head(pkt, 4); // space for stream header while staying word aligned
}

void
enftun_packet_reserve_head(struct enftun_packet* pkt, size_t len)
{
    if (pkt->size != 0)
    {
        enftun_log_error("enftun_packet_reserve_head: pkt must be empty\n");
        exit(-EINVAL);
    }

    if (len > enftun_packet_max_size)
    {
        enftun_log_error(
            "enftun_packet_reserve_head: len greater than available space\n");
        exit(-EINVAL);
    }

    pkt->data += len;
    pkt->tail += len;
}

void*
enftun_packet_insert_head(struct enftun_packet* pkt, size_t len)
{
    if (len > enftun_packet_headroom(pkt))
        return NULL;

    pkt->data -= len;
    pkt->size += len;

    return pkt->data;
}

void*
enftun_packet_insert_tail(struct enftun_packet* pkt, size_t len)
{
    if (len > enftun_packet_tailroom(pkt))
        return NULL;

    void* old = pkt->tail;

    pkt->tail += len;
    pkt->size += len;

    return old;
}

void*
enftun_packet_remove_head(struct enftun_packet* pkt, size_t len)
{
    if (len > pkt->size)
        return NULL;

    void* old = pkt->data;

    pkt->data += len;
    pkt->size -= len;

    return old;
}

void*
enftun_packet_remove_tail(struct enftun_packet* pkt, size_t len)
{
    if (len > pkt->size)
        return NULL;

    pkt->tail -= len;
    pkt->size -= len;

    return pkt->tail;
}

void
enftun_packet_save(struct enftun_packet* pkt, struct enftun_packet_state* st)
{
    st->data = pkt->data;
    st->tail = pkt->tail;
}

void
enftun_packet_restore(struct enftun_packet* pkt, struct enftun_packet_state* st)
{
    if (st->data < pkt->head || st->data > pkt->end || st->tail < pkt->head ||
        st->tail > pkt->end || st->data > st->tail)
    {
        enftun_log_error("enftun_packet_restore: invalid packet state\n");
        exit(-EINVAL);
    }

    pkt->data = st->data;
    pkt->tail = st->tail;

    pkt->size = pkt->tail - pkt->data;
}
