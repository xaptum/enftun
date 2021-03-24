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
#include "conn_state.h"
#include "context.h"
#include "dhcp.h"
#include "filter.h"
#include "log.h"
#include "ndp.h"
#include "tls.h"
#ifdef USE_XTT
#include "xtt.h"
#endif

static void
chain_complete(struct enftun_chain* chain, int status);
static void
trigger_reconnect(struct enftun_conn_state* conn_state);

static void
start_all(struct enftun_context* ctx)
{
    if (ctx->tls.sock.type == ENFTUN_TCP_NATIVE)
        enftun_conn_state_start(&ctx->conn_state, &ctx->tls);

    enftun_chain_start(&ctx->ingress, chain_complete);
    enftun_chain_start(&ctx->egress, chain_complete);
    enftun_ndp_start(&ctx->ndp);

    enftun_log_info("Started.\n");
}

static void
stop_all(struct enftun_context* ctx)
{
    enftun_ndp_stop(&ctx->ndp);
    enftun_chain_stop(&ctx->ingress);
    enftun_chain_stop(&ctx->egress);

    if (ctx->tls.sock.type == ENFTUN_TCP_NATIVE)
        enftun_conn_state_stop(&ctx->conn_state);

    enftun_log_info("Stopped.\n");
}

static void
chain_complete(struct enftun_chain* chain, int status __attribute__((unused)))
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;
    stop_all(ctx);
}

static void
trigger_reconnect(struct enftun_conn_state* conn_state)
{
    struct enftun_context* ctx = (struct enftun_context*) conn_state->data;
    stop_all(ctx);
}

static int
chain_ingress_filter(struct enftun_chain* chain, struct enftun_packet* pkt)
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;

    // -------------------------- IPv4 --------------------------
    if (enftun_is_ipv4(pkt))
    {
        if (!ctx->config.allow_ipv4)
        {
            enftun_log_debug("DROP [ingress]: route.allow_ipv4 = false\n");
            return 1; // DROP
        }

        return 0; // ACCEPT
    }

    // -------------------------- IPv6 --------------------------
    if (enftun_is_ipv6(pkt))
    {
        // Check dst IP is us
        if (!enftun_has_dst_ip(pkt, &ctx->ipv6))
        {
            enftun_log_debug("DROP [ingress]: invalid dst IP\n");
            return 1; // DROP
        }

        return 0; // ACCEPT
    }

    // -------------------------- Other --------------------------
    return 1; // DROP
}

static int
chain_egress_filter(struct enftun_chain* chain, struct enftun_packet* pkt)
{
    struct enftun_context* ctx = (struct enftun_context*) chain->data;

    // -------------------------- Handlers --------------------------
    if (enftun_ndp_handle_packet(&ctx->ndp, pkt))
        return 1; // STOLEN

    if (enftun_dhcp_handle_packet(&ctx->dhcp, pkt))
        return 1; // STOLEN

    // -------------------------- IPv4 --------------------------
    if (enftun_is_ipv4(pkt))
    {
        if (!ctx->config.allow_ipv4)
        {
            enftun_log_debug("DROP [ egress]: route.allow_ipv4 = false\n");
            return 1; // DROP
        }

        return 0; // ACCEPT
    }

    // -------------------------- IPv6 --------------------------
    if (enftun_is_ipv6(pkt))
    {
        // Check src IP is us
        if (!enftun_has_src_ip(pkt, &ctx->ipv6))
        {
            enftun_log_debug("DROP [ egress]: invalid src IP\n");
            return 1; // DROP
        }

        return 0; // ACCEPT
    }

    // -------------------------- Other --------------------------
    return 1; // DROP
}

static int
enftun_tunnel(struct enftun_context* ctx)
{
    int rc;

    rc = enftun_context_tunnel_init(ctx, chain_ingress_filter,
                                    chain_egress_filter);
    if (rc < 0)
        goto out;

    start_all(ctx);
    uv_run(&ctx->loop, UV_RUN_DEFAULT);

    enftun_context_tunnel_free(ctx);

out:
    return rc;
}

static int
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

    rc = enftun_xtt_handshake(
        ctx->config.remote_hosts, ctx->config.xtt_remote_port,
        ctx->config.fwmark, ctx->config.tpm_tcti, ctx->config.tpm_device,
        ctx->config.cert_file, ctx->config.key_file,
        ctx->config.tpm_socket_host, ctx->config.tpm_socket_port,
        ctx->config.remote_ca_cert_file, ctx->config.xtt_basename,
        ctx->config.tpm_hierarchy, ctx->config.tpm_password,
        ctx->config.tpm_parent, &xtt);

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

static int
enftun_connect(struct enftun_context* ctx)
{
    int rc = 0;

    if ((rc = enftun_context_ipv6_from_cert(ctx, ctx->config.cert_file)) < 0)
        goto out;

    if (ctx->config.ip_file)
    {
        if ((rc = enftun_context_ipv6_write_to_file(ctx, ctx->config.ip_file)) <
            0)
            goto out;
    }

    /* Always init conn_state */
    if ((rc = enftun_conn_state_prepare(&ctx->conn_state, &ctx->loop,
                                        trigger_reconnect, (void*) ctx,
                                        ctx->config.fwmark)) < 0)
        goto out;

    if ((rc = enftun_tls_connect(&ctx->tls, ctx->config.remote_hosts,
                                 ctx->config.remote_port)) < 0)
        goto close_conn_state;

    if ((rc = enftun_tun_open(&ctx->tun, ctx->config.dev,
                              ctx->config.dev_node)) < 0)
        goto close_tls;

    if (ctx->config.ip_set &&
        (rc = enftun_tun_set_ip6(&ctx->tun, ctx->config.ip_path, &ctx->ipv6)) <
            0)
        goto close_tun;

    rc = enftun_tunnel(ctx);

close_tun:
    enftun_tun_close(&ctx->tun);

close_tls:
    enftun_tls_disconnect(&ctx->tls);

close_conn_state:
    enftun_conn_state_close(&ctx->conn_state);

out:
    return rc;
}

static int
enftun_print(struct enftun_context* ctx)
{
    return enftun_config_print(&ctx->config, ctx->options.print_arg);
}

static int
enftun_run(struct enftun_context* ctx)
{
    int rc = 0;

    if ((rc = enftun_context_run_init(ctx)) < 0)
        goto out;

    while (1)
    {
        // Sets tls.need_provision if the certs don't exist yet
        rc = enftun_tls_load_credentials(
            &ctx->tls, ctx->config.remote_ca_cert_file, ctx->config.cert_file,
            ctx->config.key_file, ctx->config.tpm_tcti, ctx->config.tpm_device,
            ctx->config.tpm_socket_host, ctx->config.tpm_socket_port);

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

out:
    enftun_context_run_free(ctx);

    return rc;
}

static int
enftun_main(int argc, char* argv[])
{
    struct enftun_context ctx;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    if ((rc = enftun_context_global_init(&ctx)) < 0)
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
    enftun_context_global_free(&ctx);

out:
    return rc;
}

int
main(int argc, char* argv[])
{
    return enftun_main(argc, argv);
}
