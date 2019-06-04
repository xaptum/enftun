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
        enftun_log_error("Could not create UDP socket. \n");
    }

    socklen_t udp_addr_len = sizeof(struct sockaddr_in);

    memset(&udp_sock_addr, 0, udp_addr_len);
    udp_sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_sock_addr.sin_port = htons(0);
    udp_sock_addr.sin_family = AF_INET;

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

    inet_ntop(AF_INET, (struct sockaddr_in*)&udp_sock_addr.sin_addr, udp_address, udp_length);

    close(udp_sockfd);

    return 0;

}

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
