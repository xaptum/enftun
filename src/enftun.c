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
#include <unistd.h>

#include "channel.h"
#include "context.h"
#include "filter.h"
#include "log.h"
#include "ndp.h"
#include "tls.h"
#ifdef USE_XTT
#include "xtt.h"
#endif

static void chain_complete(struct enftun_chain* chain, int status);

static
void
start_all(struct enftun_context* ctx)
{
    enftun_chain_start(&ctx->ingress, chain_complete);
    enftun_chain_start(&ctx->egress, chain_complete);
    enftun_ndp_start(&ctx->ndp);

    enftun_log_info("Started.\n");
}

static
void
stop_all(struct enftun_context* ctx)
{
    enftun_ndp_stop(&ctx->ndp);
    enftun_chain_stop(&ctx->ingress);
    enftun_chain_stop(&ctx->egress);

    enftun_log_info("Stopped.\n");
}

static
void
chain_complete(struct enftun_chain* chain, int status __attribute__((unused)))
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

    if (enftun_ndp_handle_rs(&ctx->ndp, pkt))
        return 1;

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
                             &ctx->loop, ctx->tls.sock.fd);
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
    if (rc < 0)
        goto free_ingress;

    rc = enftun_ndp_init(&ctx->ndp, &ctx->tunchan, &ctx->loop,
                         ctx->config.prefixes, ctx->config.ra_period);
    if (rc < 0)
        goto free_egress;

    start_all(ctx);

    uv_run(&ctx->loop, UV_RUN_DEFAULT);

    enftun_ndp_free(&ctx->ndp);

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
enftun_provision(struct enftun_context* ctx)
{
    (void) ctx;
#ifdef USE_XTT
    struct enftun_xtt xtt;
    int rc = enftun_xtt_init(&xtt);
    if (0 != rc)
    {
        goto err;
    }

    rc = enftun_xtt_handshake(ctx->config.remote_hosts,
                              ctx->config.xtt_remote_port,
                              ctx->config.fwmark,
                              ctx->config.xtt_tcti,
                              ctx->config.xtt_device,
                              ctx->config.cert_file,
                              ctx->config.key_file,
                              ctx->config.xtt_socket_host,
                              ctx->config.xtt_socket_port,
                              ctx->config.remote_ca_cert_file,
                              ctx->config.xtt_basename,
                              &xtt);

    if (0 != rc)
    {
        enftun_log_error("XTT handshake failed\n");
        goto out;
    }
 out:
    enftun_xtt_free(&xtt);
    ctx->tls.need_provision = 0;
 err:
    return rc;
#else
    return 0;
#endif
}

static
int
enftun_connect(struct enftun_context* ctx)
{
    int rc = 0;
    if ((rc = enftun_context_ipv6_from_cert(ctx, ctx->config.cert_file)) < 0)
        goto out;

    if ((rc = enftun_tls_connect(&ctx->tls,
                                 ctx->config.fwmark,
                                 ctx->config.remote_hosts,
                                 ctx->config.remote_port)) < 0)
        goto out;

    if ((rc = enftun_tun_open(&ctx->tun, ctx->config.dev,
                              ctx->config.dev_node)) < 0)
        goto close_tls;

    if (ctx->config.ip_set && (rc = enftun_tun_set_ip6(&ctx->tun,
                                 ctx->config.ip_path, &ctx->ipv6)) < 0)
        goto close_tun;

    rc = enftun_tunnel(ctx);

 close_tun:
    enftun_tun_close(&ctx->tun);

 close_tls:
    enftun_tls_disconnect(&ctx->tls);

 out:
    return rc;
}

static
int enftun_print(struct enftun_context* ctx)
{
    return enftun_config_print(&ctx->config, ctx->options.print_arg);
}

static
int enftun_run(struct enftun_context* ctx)
{
    int rc = 0;

    while (1)
    {
        // Sets tls.need_provision if the certs don't exist yet
        rc = enftun_tls_load_credentials(&ctx->tls, ctx->config.remote_ca_cert_file,
                                         ctx->config.cert_file, ctx->config.key_file);

        if (ctx->tls.need_provision && ctx->config.xtt_enable)
        {
            rc = enftun_provision(ctx);
            continue;
        }

        // Sets tls.need_provision if the certs might be bad, i.e.,
        // the SSL handshake fails
        if (0 == rc)
            rc = enftun_connect(ctx);

        sleep(1);
    }

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

    if ((rc = enftun_config_parse(&ctx.config, ctx.options.conf_file) < 0))
        goto free_context;

    switch (ctx.options.action)
    {
    case ENFTUN_ACTION_PRINT:
        rc = enftun_print(&ctx);
        break;
    case ENFTUN_ACTION_RUN:
    default:
        rc = enftun_run(&ctx);
        break;
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
