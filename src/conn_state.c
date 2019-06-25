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

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "log.h"
#include "sockaddr.h"
#include "udp.h"

static int
check_preferred_route(struct enftun_conn_state* conn_state)
{
    int rc = enftun_udp_connect_addr(&conn_state->udp, conn_state->mark,
                                     &conn_state->conn->sock.remote_addr);
    if (0 != rc)
        return rc;

    enftun_udp_close(&conn_state->udp);

    rc = enftun_sockaddr_equal(&conn_state->udp.local_addr,
                               &conn_state->conn->sock.local_addr);
    if (0 != rc)
        conn_state->reconnect_cb(conn_state);

    return rc;
}

static void
on_poll(uv_poll_t* handle, int status, int events)
{
    (void) events;
    struct enftun_conn_state* conn_state = handle->data;

    char msg_buf[8192];

    if (status < 0)
        return;

    enftun_netlink_read_message(&conn_state->nl, msg_buf, sizeof(msg_buf));
    check_preferred_route(conn_state);
}

int
enftun_conn_state_start(struct enftun_conn_state* conn_state,
                        struct enftun_tls* tls_conn)
{
    conn_state->conn = tls_conn;
    int rc           = uv_poll_start(&conn_state->poll, UV_READABLE, on_poll);
    return rc;
}

int
enftun_conn_state_stop(struct enftun_conn_state* conn_state)
{
    return uv_poll_stop(&conn_state->poll);
}

int
enftun_conn_state_prepare(struct enftun_conn_state* conn_state,
                          uv_loop_t* loop,
                          enftun_conn_state_reconnect cb,
                          void* cb_ctx,
                          int mark)
{
    conn_state->poll.data    = conn_state;
    conn_state->reconnect_cb = cb;
    conn_state->data         = cb_ctx;
    conn_state->mark         = mark;

    enftun_netlink_connect(&conn_state->nl);

    int rc = uv_poll_init(loop, &conn_state->poll, conn_state->nl.fd);
    if (0 != rc)
        return rc;

    return 0;
}

int
enftun_conn_state_close(struct enftun_conn_state* conn_state)
{
    return enftun_netlink_close(&conn_state->nl);
}

int
enftun_conn_state_init(struct enftun_conn_state* conn_state)
{
    (void) conn_state;
    return 0;
}

int
enftun_conn_state_free(struct enftun_conn_state* conn_state)
{
    (void) conn_state;
    return 0;
}
