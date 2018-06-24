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

#ifndef ENFTUN_PACKET_H
#define ENFTUN_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define ENFTUN_PACKET_MAX_SIZE 1504

extern const size_t enftun_packet_max_size;

struct enftun_packet
{
    uint8_t  head[ENFTUN_PACKET_MAX_SIZE];
    uint8_t* end;

    uint8_t* data;
    uint8_t* tail;

    size_t size;
};

static inline
size_t
enftun_packet_headroom(struct enftun_packet* pkt)
{
    return (pkt->data - pkt->head);
}

static inline
size_t
enftun_packet_tailroom(struct enftun_packet* pkt)
{
    return (pkt->end - pkt->tail);
}

void
enftun_packet_reset(struct enftun_packet* pkt);

void
enftun_packet_reserve_head(struct enftun_packet* pkt, size_t len);

void*
enftun_packet_insert_head(struct enftun_packet* pkt, size_t len);

void*
enftun_packet_insert_tail(struct enftun_packet* pkt, size_t len);

void
enftun_packet_remove_head(struct enftun_packet* pkt, size_t len);

void
enftun_packet_remove_tail(struct enftun_packet* pkt, size_t len);


#endif // ENFTUN_PACKET_H
