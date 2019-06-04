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

#ifndef ENFTUN_CONNECTION_STATE_H
#define ENFTUN_CONNECTION_STATE_H

#include "netlink.h"

#include <uv.h>

struct enftun_conn_state;

typedef void (*enftun_conn_state_reconnect)(struct enftun_conn_state* conn_state);

struct enftun_conn_state
{
    uv_poll_t poll;
    void* data;
    struct enftun_netlink nl;
    enftun_conn_state_reconnect reconnect;
};

int
enftun_conn_state_start(struct enftun_conn_state* conn_state,
                        enftun_conn_state_reconnect trigger_reconnect,
                        uv_loop_t* loop,
                        void* ctx);

int
enftun_conn_state_close(struct enftun_conn_state* conn_state);

int
enftun_conn_state_stop(struct enftun_conn_state* conn_state);

#endif //ENFTUN_CONNECTION_STATE_H
