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

#ifndef ENFTUN_CHANNEL_H
#define ENFTUN_CHANNEL_H

#include <uv.h>

#include "list.h"
#include "packet.h"

struct enftun_crb;
struct enftun_channel;

typedef void (*enftun_crb_complete)(struct enftun_crb*);

struct enftun_crb
{
    struct enftun_list entry; /* to store in list */

    struct enftun_packet* packet; /* associated packet buffer */

    struct enftun_channel* channel; /* active channel */

    void* context;                /* context for completion */
    enftun_crb_complete complete; /* completion route */

    int status; /* status code after completion */
};

struct enftun_channel_ops
{
    int (*fd)(void* ctx);
    int (*read)(void* ctx, struct enftun_packet* pkt);
    int (*write)(void* ctx, struct enftun_packet* pkt);
    void (*prepare)(void* ctx, struct enftun_packet* pkt);
    int (*pending)(void* ctx);
};

struct enftun_channel
{
    struct enftun_channel_ops* ops;
    void* ops_context;

    int events;
    uv_poll_t poll;

    struct enftun_list rxqueue;
    struct enftun_list txqueue;
};

int
enftun_channel_init(struct enftun_channel* chan,
                    struct enftun_channel_ops* ops,
                    void* ops_context,
                    uv_loop_t* loop);

int
enftun_channel_free(struct enftun_channel* chan);

void
enftun_crb_read(struct enftun_crb* crb, struct enftun_channel* chan);

void
enftun_crb_write(struct enftun_crb* crb, struct enftun_channel* chan);

void
enftun_crb_cancel(struct enftun_crb* crb);

#endif // ENFTUN_CHANNEL_H
