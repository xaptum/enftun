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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>

#include "log.h"
#include "memory.h"
#include "config.h"

int
enftun_config_init(struct enftun_config* config)
{
    CLEAR(*config);

    config_init(&config->cfg);

    config->ip_path = "/bin/ip";

    config->dev = "enf0";
    config->dev_node = "/dev/net/tun";

    config->remote_host = "23.147.128.112";
    config->remote_port = "443";

    config->fwmark = 363;

    return 0;
}

int
enftun_config_free(struct enftun_config* config)
{
    config_destroy(&config->cfg);

    CLEAR(*config);

    return 0;
}

static
void
log_config_read_error(struct enftun_config* config, const char* file)
{
    config_t *cfg = &config->cfg;

    if (!config_error_line(cfg))
    {
        enftun_log_error("Cannot open config file %s\n", file);
    }
    else
    {
        enftun_log_error("Cannot parse config file %s at line %d - %s\n",
                         file,
                         config_error_line(cfg),
                         config_error_text(cfg));
    }
}

int
enftun_config_parse(struct enftun_config* config, const char* file)
{
    config_t *cfg = &config->cfg;

    if (!file)
        return 0;

    if (!config_read_file(cfg, file))
    {
        log_config_read_error(config, file);
        return -EINVAL;
    }

    /* Platform settings */
    config_lookup_string(cfg, "tun.ip_path", &config->ip_path);

    /* TUN settings */
    config_lookup_string(cfg, "tun.dev", &config->dev);
    config_lookup_string(cfg, "tun.dev_node", &config->dev_node);

    /* Remote settings */
    config_lookup_string(cfg, "remote.host", &config->remote_host);
    config_lookup_string(cfg, "remote.port", &config->remote_port);
    config_lookup_string(cfg, "remote.ca_cert_file", &config->remote_ca_cert_file);

    /* Route settings */
    config_lookup_int(cfg, "route.fwmark", &config->fwmark);

    /* Identity settings */
    config_lookup_string(cfg, "identity.cert_file", &config->cert_file);
    config_lookup_string(cfg, "identity.key_file", &config->key_file);

    return 0;
}
