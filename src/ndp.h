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

#ifndef ENFTUN_NDP_H
#define ENFTUN_NDP_H

#include <stdbool.h>

#include <uv.h>

#include "channel.h"
#include "packet.h"

struct enftun_ndp
{
    struct enftun_channel* chan;
    const char** routes;
    int ra_period;

    uv_timer_t timer;

    struct enftun_packet ra_pkt;
    struct enftun_crb ra_crb;

    bool ra_inflight;
    bool ra_scheduled;
};

int
enftun_ndp_init(struct enftun_ndp* ndp,
                struct enftun_channel *chan,
                uv_loop_t* loop,
                const char** routes,
                int ra_period);

int
enftun_ndp_free(struct enftun_ndp* ndp);

int
enftun_ndp_start(struct enftun_ndp* ndp);

int
enftun_ndp_stop(struct enftun_ndp* ndp);

int
enftun_ndp_handle_rs(struct enftun_ndp* ndp, struct enftun_packet* pkt);

#endif // ENFTUN_NDP_H
