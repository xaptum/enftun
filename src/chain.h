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

#ifndef ENFTUN_CHAIN_H
#define ENFTUN_CHAIN_H

#include <uv.h>

#include "channel.h"
#include "packet.h"

struct enftun_chain;

enum enftun_chain_state
{
    enftun_chain_reading,
    enftun_chain_writing
};

typedef int (*enftun_chain_filter)(struct enftun_chain* chain,
                                   struct enftun_packet* packet);

typedef void (*enftun_chain_complete)(struct enftun_chain* chain, int status);

struct enftun_chain
{
    struct enftun_channel* input;
    struct enftun_channel* output;

    struct enftun_packet packet;
    struct enftun_crb crb;

    enum enftun_chain_state state;

    void* data;

    enftun_chain_filter filter;
    enftun_chain_complete complete;
};

int
enftun_chain_init(struct enftun_chain* chain,
                  struct enftun_channel* input,
                  struct enftun_channel* output,
                  void* data,
                  enftun_chain_filter filter);

int
enftun_chain_free(struct enftun_chain* chain);

int
enftun_chain_start(struct enftun_chain* chain, enftun_chain_complete complete);

int
enftun_chain_stop(struct enftun_chain* chain);

#endif // ENFTUN_CHAIN_H
