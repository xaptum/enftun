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

#ifndef ENFTUN_CONTEXT_H
#define ENFTUN_CONTEXT_H

#include <netinet/in.h>
#include <uv.h>

#include "chain.h"
#include "channel.h"
#include "config.h"
#include "ndp.h"
#include "options.h"
#include "tls.h"
#include "tun.h"

/**
 * The state for one tunnel.
 */
struct enftun_context
{
    struct enftun_options options;
    struct enftun_config config;

    struct enftun_tls tls;
    struct enftun_tun tun;

    struct enftun_channel tlschan;
    struct enftun_channel tunchan;

    struct enftun_chain ingress;
    struct enftun_chain egress;

    struct enftun_ndp ndp;

    uv_loop_t loop;

    struct in6_addr ipv6;
    char ipv6_str[45];
};

int
enftun_context_init(struct enftun_context* ctx);

int
enftun_context_free(struct enftun_context* ctx);

int
enftun_context_ipv6_from_cert(struct enftun_context* ctx, const char* cert);


#endif // ENFTUN_CONTEXT_H
