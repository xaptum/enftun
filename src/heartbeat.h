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

typedef int (*enftun_heartbeat_timeout)(struct enftun_heartbeat hb);

struct enftun_heartbeat
{
    struct enftun_channel* chan;

    const struct in6_addr* source_addr;
    const struct in6_addr* dest_addr;

    struct enftun_packet req_pkt;
    struct enftun_crb req_crb;

    uv_timer_t req_timer;
    int req_period;

    uv_timer_t reply_timer;
    int reply_timeout;

    bool req_scheduled;
    bool req_sending;
    bool req_inflight;

    enftun_heartbeat_timeout timeout_cb;
    void* data; // data for timeout callback
};

void
enftun_heartbeat_send_request(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_handle_packet(struct enftun_heartbeat* heartbeat,
                               struct enftun_packet* pkt);

int
enftun_heartbeat_init(struct enftun_heartbeat* heartbeat,
                      int hb_period,
                      int hb_timeout,
                      uv_loop_t* loop,
                      struct enftun_channel* chan,
                      const struct in6_addr* source,
                      const struct in6_addr* dest,
                      enftun_heartbeat_timeout cb,
                      void* data);

int
enftun_heartbeat_free(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_start(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_stop(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_reset(struct enftun_heartbeat* heartbeat);

int
enftun_heartbeat_now(struct enftun_heartbeat* heartbeat);

#endif // ENFTUN_HEARTBEAT_H
