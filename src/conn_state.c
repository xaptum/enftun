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

#include "context.h"
#include "log.h"

static
int
connect_udp_socket(char* udp_address, int udp_length, struct addrinfo* connect_addr)
{
    int rc = 0;
    struct sockaddr_in udp_sock_addr;
    int udp_sockfd = -1;

    switch(connect_addr->ai_family){
        case AF_INET:
            udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            break;
        case AF_INET6:
            udp_sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
            break;
    }

    if (udp_sockfd < 0) {
        enftun_log_error("UDP: Failed to create socket: %s\n", strerror(errno));
    }

    socklen_t udp_addr_len = sizeof(struct sockaddr_in);

    memset(&udp_sock_addr, 0, udp_addr_len);
    udp_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_sock_addr.sin_port = htons(0);
    udp_sock_addr.sin_family = connect_addr->ai_family;

    rc = connect(udp_sockfd, connect_addr->ai_addr, connect_addr->ai_addrlen);
    if (0 != rc){
        close(udp_sockfd);
        return -1;
    }

    rc = getsockname(udp_sockfd, (struct sockaddr*)&udp_sock_addr, &udp_addr_len);
    if (0 != rc){
        close(udp_sockfd);
        return -1;
    }

    inet_ntop(connect_addr->ai_family, (struct sockaddr_in*)&udp_sock_addr.sin_addr, udp_address, udp_length);

    close(udp_sockfd);

    return 0;
}

static
int
udp_check(struct enftun_conn_state* conn_state)
{
    struct enftun_context* ctx = (struct enftun_context*)conn_state->data;
    char udp_address[45];
    connect_udp_socket(udp_address, sizeof(udp_address), &ctx->tls.sock.local_addr);

    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    memset(&local_addr, 0, addr_len);
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(0);
    local_addr.sin_family = ctx->tls.sock.local_addr.ai_family;

    char local_ip[45];
    getsockname(ctx->tls.sock.fd, (struct sockaddr*)&local_addr, &addr_len);
    inet_ntop(ctx->tls.sock.local_addr.ai_family, (struct sockaddr_in*)&local_addr.sin_addr, local_ip, sizeof(local_ip));

    if (0 == strcmp(udp_address, local_ip)) {
        return 0;
    }
    else {
        enftun_log_info("UDP check found a higher priority route. Reconnecting...\n");
        return -1;
    }

    return 0;
}

static
void
check_conn_state(struct enftun_conn_state* conn_state)
{
    int rc = udp_check(conn_state);
    if (0 != rc) {
        conn_state->reconnect(conn_state);
    }
}

static
void
on_poll(uv_poll_t* handle, int status, int events)
{
    (void) events;
    struct enftun_conn_state* conn_state = handle->data;

    if (status < 0)
        return;
    if (0 == status)
        check_conn_state(conn_state);
}

int
enftun_conn_state_start(struct enftun_conn_state* conn_state,
                        enftun_conn_state_reconnect trigger_reconnect,
                        uv_loop_t* loop, void* ctx)
{
    conn_state->poll.data = conn_state;
    conn_state->reconnect = trigger_reconnect;
    conn_state->data = ctx;

    enftun_netlink_connect(&conn_state->nl);

    int rc = uv_poll_init(loop, &conn_state->poll, conn_state->nl.fd);
    if (0 != rc)
        return rc;

    rc = uv_poll_start(&conn_state->poll, UV_READABLE, on_poll);

    return rc;
}

int
enftun_conn_state_close(struct enftun_conn_state* conn_state)
{
    return enftun_netlink_close(&conn_state->nl);
}

int
enftun_conn_state_stop(struct enftun_conn_state* conn_state)
{
    return uv_poll_stop(&conn_state->poll);
}
