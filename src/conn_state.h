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

#include "heartbeat.h"
#include "netlink.h"
#include "tls.h"
#include "udp.h"

#include <uv.h>

struct enftun_conn_state;

typedef void (*enftun_conn_state_reconnect)(
    struct enftun_conn_state* conn_state);

struct enftun_conn_state
{
    enftun_conn_state_reconnect reconnect_cb;
    void* data; // data for reconnect callback

    uv_poll_t poll;
    struct enftun_netlink nl;
    struct enftun_udp udp;
    struct enftun_heartbeat hb;

    struct enftun_tls* conn;

    int mark; // mark to apply to tunnel packets. 0 to disable
};

int
enftun_conn_state_start(struct enftun_conn_state* conn_state,
                        struct enftun_tls* tls_conn);

int
enftun_conn_state_stop(struct enftun_conn_state* conn_state);

int
enftun_conn_state_init(struct enftun_conn_state* conn_state,
                       uv_loop_t* loop,
                       int mark,
                       int hb_period,
                       int hb_timeout,
                       struct enftun_channel* chan,
                       const struct in6_addr* saddr,
                       const struct in6_addr* daddr,
                       enftun_conn_state_reconnect cb,
                       void* data);

int
enftun_conn_state_free(struct enftun_conn_state* conn_state);

#endif // ENFTUN_CONNECTION_STATE_H
