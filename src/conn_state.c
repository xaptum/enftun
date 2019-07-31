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

#define NEED_PING 1

static int
check_preferred_route(struct enftun_conn_state* conn_state)
{
    int rc = enftun_udp_connect_addr(&conn_state->udp, conn_state->mark,
                                     &conn_state->conn->sock->remote_addr);
    if (0 != rc)
        return rc;

    enftun_udp_close(&conn_state->udp);

    rc = enftun_sockaddr_equal(&conn_state->udp.local_addr,
                               &conn_state->conn->sock->local_addr);

    return rc;
}

static int
get_if_status(struct nlmsghdr* nl_message)
{
    struct ifinfomsg* if_info;

    if_info = (struct ifinfomsg*) NLMSG_DATA(nl_message);

    if (if_info->ifi_flags & IFF_UP & IFF_RUNNING)
        return 0;
    else
        return -1;
}

static void
reset_io_vector(struct enftun_netlink* nl)
{
    nl->io_vector.iov_base = NULL;
    nl->io_vector.iov_len  = 0;
}

static int
parse_netlink_message(struct enftun_netlink* nl, int bytes_in_msg)
{
    int rc = 0;

    struct nlmsghdr* nl_message;
    nl_message = (struct nlmsghdr*) nl->io_vector.iov_base;

    while (bytes_in_msg >= (ssize_t) sizeof(*nl_message))
    {
        int length_msghdr = nl_message->nlmsg_len;
        int length_msg    = length_msghdr - sizeof(*nl_message);

        if ((length_msg < 0) || (length_msghdr > bytes_in_msg))
        {
            enftun_log_error("Invalid message length: %i\n", length_msghdr);
            continue;
        }

        if (nl_message->nlmsg_type == RTM_NEWADDR)
        {
            rc = NEED_PING;
        }
        else if (nl_message->nlmsg_type == RTM_NEWLINK &&
                 0 == get_if_status(nl_message))
        {
            rc = NEED_PING;
        }

        bytes_in_msg -= NLMSG_ALIGN(length_msghdr);

        nl_message = (struct nlmsghdr*) ((char*) nl_message +
                                         NLMSG_ALIGN(length_msghdr));
    }

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

    int bytes =
        enftun_netlink_read_message(&conn_state->nl, msg_buf, sizeof(msg_buf));
    int rc = check_preferred_route(conn_state);
    if (0 != rc)
        conn_state->reconnect_cb(conn_state->data);
    else
    {
        rc = parse_netlink_message(&conn_state->nl, bytes);
        if (NEED_PING == rc)
            enftun_heartbeat_now(&conn_state->heartbeat);
    }

    reset_io_vector(&conn_state->nl);
    return;
}

int
enftun_conn_state_start(struct enftun_conn_state* conn_state,
                        struct enftun_tls* tls_conn)
{
    conn_state->conn = tls_conn;

    int rc = enftun_heartbeat_start(&conn_state->heartbeat);
    if (0 != rc)
        return rc;

    rc = uv_poll_start(&conn_state->poll, UV_READABLE, on_poll);
    return rc;
}

int
enftun_conn_state_stop(struct enftun_conn_state* conn_state)
{
    int rc = uv_poll_stop(&conn_state->poll);
    if (0 != rc)
        return rc;

    rc = enftun_heartbeat_stop(&conn_state->heartbeat);
    return rc;
}

int
enftun_conn_state_prepare(struct enftun_conn_state* conn_state,
                          uv_loop_t* loop,
                          void (*cb)(void* data),
                          void* cb_ctx,
                          int mark,
                          struct enftun_channel* chan,
                          struct in6_addr* ipv6,
                          int hb_period,
                          int hb_timeout)
{
    conn_state->poll.data    = conn_state;
    conn_state->reconnect_cb = cb;
    conn_state->data         = cb_ctx;
    conn_state->mark         = mark;

    enftun_netlink_connect(&conn_state->nl);

    enftun_heartbeat_init(&conn_state->heartbeat, loop, chan, ipv6, cb, cb_ctx,
                          hb_period, hb_timeout);

    int rc = uv_poll_init(loop, &conn_state->poll, conn_state->nl.fd);
    if (0 != rc)
        return rc;

    return 0;
}

int
enftun_conn_state_close(struct enftun_conn_state* conn_state)
{
    int rc = enftun_heartbeat_free(&conn_state->heartbeat);
    if (0 != rc)
        return rc;

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
