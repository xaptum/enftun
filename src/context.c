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

#include <string.h>

#include "context.h"
#include "cert.h"
#include "log.h"

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
enftun_context_init(struct enftun_context* ctx)
{
    int rc;

    rc = enftun_options_init(&ctx->options);
    if (rc < 0)
        goto err;

    rc = enftun_config_init(&ctx->config);
    if (rc < 0)
        goto free_options;

    rc = enftun_tls_init(&ctx->tls);
    if (rc < 0)
        goto free_config;

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

 free_config:
    enftun_config_free(&ctx->config);

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

    enftun_config_free(&ctx->config);
    enftun_options_free(&ctx->options);

    return 0;
}

int
enftun_context_ipv6_from_cert(struct enftun_context* ctx, const char* file)
{
    int rc;

    if ((rc = enftun_cert_common_name_file(ctx->config.cert_file,
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
