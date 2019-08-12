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

#pragma once

#ifndef ENFTUN_HEARTBEAT_H
#define ENFTUN_HEARTBEAT_H

#include <stdbool.h>
#include <time.h>
#include <uv.h>

#include "channel.h"
#include "packet.h"

struct enftun_heartbeat
{
    struct enftun_channel* chan;

    const struct in6_addr* source_addr;
    const struct in6_addr* dest_addr;

    struct enftun_packet reply_pkt;
    struct enftun_crb reply_crb;

    uv_timer_t request_timer;
    int heartbeat_period;

    uv_timer_t reply_timer;
    int heartbeat_timeout;

    bool hb_inflight;
    bool hb_scheduled;

    void (*on_timeout)(void* data);
    void* data;
};

void
enftun_heartbeat_send_request(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_handle_packet(struct enftun_heartbeat* heartbeat,
                               struct enftun_packet* pkt);

int
enftun_heartbeat_init(struct enftun_heartbeat* heartbeat,
                      uv_loop_t* loop,
                      struct enftun_channel* chan,
                      const struct in6_addr* source,
                      const struct in6_addr* dest,
                      void (*on_timeout)(void* data),
                      void* cb_ctx,
                      int hb_period,
                      int hb_timeout);

int
enftun_heartbeat_free(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_start(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_stop(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_restart(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_now(struct enftun_heartbeat* heartbeat);

#endif // ENFTUN_HEARTBEAT_H
