/*
 * Copyright 2018-2021 Xaptum, Inc.
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

#ifndef ENFTUN_CONTEXT_H
#define ENFTUN_CONTEXT_H

#include <netinet/in.h>
#include <uv.h>

#include "chain.h"
#include "channel.h"
#include "config.h"
#include "conn_state.h"
#include "dhcp.h"
#include "ndp.h"
#include "options.h"
#include "tls.h"
#include "tun.h"

/**
 * The state for one tunnel.
 */
struct enftun_context
{
    // Global context
    uv_loop_t loop;

    struct enftun_options options;
    struct enftun_config config;

    // Run context
    struct enftun_conn_state conn_state;

    struct enftun_tls tls;

    struct enftun_tun tun;

    // Tunnel context
    struct
    {
        struct enftun_channel remote;
        struct enftun_channel local;
    } channels;

    struct
    {
        struct enftun_chain ingress;
        struct enftun_chain egress;
    } chains;

    // Services
    struct
    {
        struct enftun_dhcp dhcp;
        struct enftun_ndp ndp;
    } services;

    struct in6_addr ipv6;
    char ipv6_str[45];
};

int
enftun_context_global_init(struct enftun_context* ctx);

int
enftun_context_global_free(struct enftun_context* ctx);

int
enftun_context_run_init(struct enftun_context* ctx,
                        enftun_conn_state_reconnect cb);

int
enftun_context_run_free(struct enftun_context* ctx);

int
enftun_context_tunnel_init(struct enftun_context* ctx,
                           enftun_chain_filter ingress,
                           enftun_chain_filter egress);

int
enftun_context_tunnel_free(struct enftun_context* ctx);

int
enftun_context_ipv6_from_cert(struct enftun_context* ctx, const char* cert);

int
enftun_context_ipv6_write_to_file(struct enftun_context* ctx, const char* file);

#endif // ENFTUN_CONTEXT_H
