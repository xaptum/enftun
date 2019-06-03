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

#include "conn_state.h"
#include "log.h"


static
void
on_poll(uv_poll_t* handle, int status, int events)
{
    (void) events;
    struct enftun_nl_conn_state* conn_state = handle->data;

    if (status < 0)
        return;
    if (0 == status)
        conn_state->handle_change(conn_state->nl);
}

int
enftun_conn_state_init(struct enftun_nl_conn_state* nl_conn_state,
                       uv_loop_t* loop,
                       int fd,
                       void* nl,
                       int (*handle_nl_change)(void* netlink))
{
    int rc;
    nl_conn_state->poll.data = nl_conn_state;
    nl_conn_state->nl = nl;
    nl_conn_state->handle_change = handle_nl_change;
    rc = uv_poll_init(loop, &nl_conn_state->poll, fd);

    return rc;
}

int
enftun_conn_state_free(struct enftun_nl_conn_state* conn_state)
{
    (void) conn_state;
    return 0;
}

int
enftun_conn_state_start(struct enftun_nl_conn_state* conn_state)
{
    int rc = uv_poll_start(&conn_state->poll, UV_READABLE, on_poll);
    return rc;
}

int
enftun_conn_state_stop(struct enftun_nl_conn_state* conn_state)
{
    int rc = uv_poll_stop(&conn_state->poll);
    return rc;
}
