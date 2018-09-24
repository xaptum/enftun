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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cert.h"
#include "channel.h"
#include "enftun.h"
#include "filter.h"
#include "log.h"

int
enftun_context_init(struct enftun_context* ctx)
{
    int rc;

    rc = enftun_options_init(&ctx->options);
    if (rc < 0)
        goto err;

    rc = enftun_tls_init(&ctx->tls);
    if (rc < 0)
        goto free_options;

    rc = enftun_tun_init(&ctx->tun);
    if (rc < 0)
        goto free_tls;

    rc = uv_loop_init(&ctx->loop);
    if (rc < 0)
        goto free_tun;

    memset(ctx->ipv6_str, 0, sizeof(ctx->ipv6_str));

    return 0;

 free_tun:
    enftun_tun_free(&ctx->tun);

 free_tls:
    enftun_tls_free(&ctx->tls);

 free_options:
    enftun_options_free(&ctx->options);

 err:
    return rc;
}

int
enftun_context_free(struct enftun_context* ctx)
{
    uv_loop_close(&ctx->loop);

    enftun_tun_free(&ctx->tun);
    enftun_tls_free(&ctx->tls);

    enftun_options_free(&ctx->options);
}

/**
 * Adds missing colons back into IPv6 string.
 */
static
void
fix_ipv6_string(char *ipv6_str)
{
    int i, c;
    for (i = 28, c = 7; i >= 0; i = i - 4, c = c - 1)
    {
        memcpy(ipv6_str + i + c, ipv6_str + i, 4);
        if (i > 0)
            *(ipv6_str + i + c - 1) = ':';
    }
}

int
enftun_context_ipv6_from_cert(struct enftun_context* ctx, const char* file)
{
    int rc;

    if ((rc = enftun_cert_common_name_file(ctx->options.cert_file,
                                           ctx->ipv6_str,
                                           sizeof(ctx->ipv6_str))) < 0)
    {
        enftun_log_error("Failed to read IPv6 address from cert %s\n", file);
        goto out;
    }

    fix_ipv6_string(ctx->ipv6_str);

    if (inet_pton(AF_INET6, ctx->ipv6_str, &ctx->ipv6) != 1)
    {
        enftun_log_error("Invalid IPv6 address (%s) in cert %s\n", ctx->ipv6_str);
        rc = -1;
        goto out;
    }

 out:
    return rc;
}

static void chain_complete(struct enftun_chain* chain, int status);

static
void
start_all(struct enftun_context* ctx)
{
    enftun_chain_start(&ctx->ingress, chain_complete);
    enftun_chain_start(&ctx->egress, chain_complete);

    enftun_log_info("Started.\n");
}

static
void
stop_all(struct enftun_context* ctx)
{
    enftun_chain_stop(&ctx->ingress);
    enftun_chain_stop(&ctx->egress);

    enftun_log_info("Stopped.\n");
}

static
void
chain_complete(struct enftun_chain* chain, int status)
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;
    stop_all(ctx);
}

static
int
chain_ingress_filter(struct enftun_chain* chain,
                     struct enftun_packet* pkt)
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;
    char addr[INET6_ADDRSTRLEN];

    if (!enftun_is_ipv6(pkt))
    {
        enftun_log_debug("DROP [ingress]: invalid IPv6 packet\n");
        return 1;
    }

    if (!enftun_has_dst_ip(pkt, &ctx->ipv6))
    {
        enftun_log_debug("DROP [ingress]: invalid dst IP\n");
        return 1;
    }

    return 0;
}

static
int
chain_egress_filter(struct enftun_chain* chain,
                    struct enftun_packet* pkt)
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;

    if (!enftun_is_ipv6(pkt))
    {
        enftun_log_debug("DROP [ egress]: invalid IPv6 packet\n");
        return 1;
    }

    if (!enftun_has_src_ip(pkt, &ctx->ipv6))
    {
        enftun_log_debug("DROP [ egress]: invalid src IP\n");
        return 1;
    }

    return 0;
}

static
int
enftun_tunnel(struct enftun_context* ctx)
{
    int rc;

    rc = enftun_channel_init(&ctx->tlschan, &enftun_tls_ops, &ctx->tls,
                             &ctx->loop, ctx->tls.fd);
    if (rc < 0)
        goto out;

    rc = enftun_channel_init(&ctx->tunchan, &enftun_tun_ops, &ctx->tun,
                             &ctx->loop, ctx->tun.fd);
    if (rc < 0)
        goto free_tlschan;

    rc = enftun_chain_init(&ctx->ingress, &ctx->tlschan, &ctx->tunchan, ctx,
                           chain_ingress_filter);
    if (rc < 0)
        goto free_tunchan;

    rc = enftun_chain_init(&ctx->egress, &ctx->tunchan, &ctx->tlschan, ctx,
                           chain_egress_filter);
    if (rc <0)
        goto free_ingress;

    start_all(ctx);

    uv_run(&ctx->loop, UV_RUN_DEFAULT);

 free_egress:
    enftun_chain_free(&ctx->egress);

 free_ingress:
    enftun_chain_free(&ctx->ingress);

 free_tunchan:
    enftun_channel_free(&ctx->tunchan);

 free_tlschan:
    enftun_channel_free(&ctx->tlschan);

 out:
    return rc;
}

static
int
enftun_connect(struct enftun_context* ctx)
{
    int rc;

    // enftun_xtt_handshake();

    if ((rc = enftun_context_ipv6_from_cert(ctx, ctx->options.cert_file)) < 0)
        goto out;

    if ((rc = enftun_tls_connect(&ctx->tls,
                                 ctx->options.remote_host,
                                 ctx->options.remote_port,
                                 ctx->options.remote_ca_cert_file,
                                 ctx->options.cert_file,
                                 ctx->options.key_file)) < 0)
        goto out;

    if ((rc = enftun_tun_open(&ctx->tun, ctx->options.dev,
                              ctx->options.dev_node)) < 0)
        goto close_tls;

    rc = enftun_tunnel(ctx);

    enftun_tun_close(&ctx->tun);

 close_tls:
    enftun_tls_disconnect(&ctx->tls);

 out:
    return rc;
}

static
int
enftun_main(int argc, char *argv[])
{
    struct enftun_context ctx;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    if ((rc = enftun_context_init(&ctx)) < 0)
        goto out;

    if ((rc = enftun_options_parse_argv(&ctx.options, argc, argv)) < 0)
        goto free_context;

    if ((rc = enftun_options_parse_conf(&ctx.options) < 0))
        goto free_context;

    while (1)
    {
        rc = enftun_connect(&ctx);
        sleep(1);
    }

 free_context:
    enftun_context_free(&ctx);

 out:
    return rc;
}

int
main(int argc, char *argv[])
{
  return enftun_main(argc, argv);
}