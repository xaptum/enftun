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

#include "context.h"

#include <stdio.h>
#include <string.h>

#include "cert.h"
#include "conn_state.h"
#include "ip.h"
#include "log.h"

/**
 * Adds missing colons back into IPv6 string.
 */
static void
fix_ipv6_string(char* ipv6_str)
{
    int i, c;
    for (i = 0; i < 5; i++)
    {
        if (ipv6_str[i] == ':')
            return;
    }

    for (i = 28, c = 7; i >= 0; i = i - 4, c = c - 1)
    {
        memcpy(ipv6_str + i + c, ipv6_str + i, 4);
        if (i > 0)
            *(ipv6_str + i + c - 1) = ':';
    }
}

int
enftun_context_global_init(struct enftun_context* ctx)
{
    int rc;

    memset(ctx->ipv6_str, 0, sizeof(ctx->ipv6_str));

    rc = enftun_options_init(&ctx->options);
    if (rc < 0)
        goto err;

    rc = enftun_config_init(&ctx->config);
    if (rc < 0)
        goto free_options;

    rc = uv_loop_init(&ctx->loop);
    if (rc < 0)
        goto free_config;

    return 0;

free_config:
    enftun_options_free(&ctx->options);

free_options:
    enftun_options_free(&ctx->options);

err:
    return rc;
}

int
enftun_context_global_free(struct enftun_context* ctx)
{
    uv_loop_close(&ctx->loop);
    enftun_config_free(&ctx->config);
    enftun_options_free(&ctx->options);

    return 0;
}

int
enftun_context_run_init(struct enftun_context* ctx,
                        enftun_conn_state_reconnect cb)

{
    int rc;

    rc = enftun_conn_state_init(
        &ctx->conn_state, &ctx->loop, ctx->config.fwmark,
        ctx->config.heartbeat_period, ctx->config.heartbeat_timeout,
        &ctx->tlschan, &ctx->ipv6, &ip6_enf_router, cb, ctx);
    if (rc < 0)
        goto err;

    rc = enftun_tls_init(&ctx->tls, ctx->config.fwmark);
    if (rc < 0)
        goto free_conn_state;

    rc = enftun_tun_init(&ctx->tun);
    if (rc < 0)
        goto free_tls;

    return 0;

free_tls:
    enftun_tls_free(&ctx->tls);

free_conn_state:
    enftun_conn_state_free(&ctx->conn_state);

err:
    return rc;
}

int
enftun_context_run_free(struct enftun_context* ctx)
{
    enftun_tun_free(&ctx->tun);
    enftun_tls_free(&ctx->tls);
    enftun_conn_state_free(&ctx->conn_state);

    return 0;
}

int
enftun_context_tunnel_init(struct enftun_context* ctx,
                           enftun_chain_filter ingress,
                           enftun_chain_filter egress)
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
                           ingress);
    if (rc < 0)
        goto free_tunchan;

    rc = enftun_chain_init(&ctx->egress, &ctx->tunchan, &ctx->tlschan, ctx,
                           egress);
    if (rc < 0)
        goto free_ingress;

    rc = enftun_ndp_init(&ctx->ndp, &ctx->tunchan, &ctx->loop, &ctx->ipv6,
                         ctx->config.prefixes, ctx->config.ra_period);
    if (rc < 0)
        goto free_egress;

    rc = enftun_dhcp_init(&ctx->dhcp, &ctx->tunchan, &ctx->ipv6);
    if (rc < 0)
        goto free_ndp;

    return 0;

free_ndp:
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

int
enftun_context_tunnel_free(struct enftun_context* ctx)
{
    enftun_dhcp_free(&ctx->dhcp);
    enftun_ndp_free(&ctx->ndp);
    enftun_chain_free(&ctx->egress);
    enftun_chain_free(&ctx->ingress);
    enftun_channel_free(&ctx->tunchan);
    enftun_channel_free(&ctx->tlschan);

    return 0;
}

int
enftun_context_ipv6_from_cert(struct enftun_context* ctx, const char* file)
{
    int rc;

    memset(ctx->ipv6_str, 0, sizeof(ctx->ipv6_str));

    if ((rc = enftun_cert_common_name_file(ctx->config.cert_file, ctx->ipv6_str,
                                           sizeof(ctx->ipv6_str))) < 0)
    {
        enftun_log_error("Failed to read IPv6 address from cert %s\n", file);
        goto out;
    }

    fix_ipv6_string(ctx->ipv6_str);

    if (inet_pton(AF_INET6, ctx->ipv6_str, &ctx->ipv6) != 1)
    {
        enftun_log_error("Invalid IPv6 address (%s) in cert %s\n",
                         ctx->ipv6_str);
        rc = -1;
        goto out;
    }

out:
    return rc;
}

int
enftun_context_ipv6_write_to_file(struct enftun_context* ctx, const char* file)
{
    int rc;

    FILE* f = fopen(file, "w");
    if (NULL == f)
    {
        enftun_log_warn("Unable to open file %s\n", file);
        rc = -1;
        goto out;
    }

    if (fputs(ctx->ipv6_str, f) == EOF)
    {
        enftun_log_warn("Failed to write to file %s\n", file);
        rc = -1;
        goto out;
    }

    if (fputs("\n", f) == EOF)
    {
        enftun_log_warn("Failed to write to file %s\n", file);
        rc = -1;
        goto out;
    }

    fclose(f);
    rc = 0;

out:
    return rc;
}
