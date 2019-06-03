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

#include <uv.h>

struct enftun_nl_conn_state
{
    uv_poll_t poll;
    int (*handle_change)(void* nl);
    void* nl;
};

int
enftun_conn_state_init(struct enftun_nl_conn_state* nl_conn_state,
                       uv_loop_t* loop,
                       int fd,
                       void* nl,
                       int (*handle_nl_change)(void* netlink));

int
enftun_conn_state_free(struct enftun_nl_conn_state* conn_state);

int
enftun_conn_state_start(struct enftun_nl_conn_state* conn_state);

int
enftun_conn_state_stop(struct enftun_nl_conn_state* conn_state);

#endif // ENFTUN_CONNECTION_STATE_H
