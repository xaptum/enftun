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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libconfig.h>

#include "log.h"
#include "memory.h"
#include "options.h"

static
void print_usage()
{
    puts("usage: enftun [-h] [-c conf_file]");
}

int
enftun_options_init(struct enftun_options* opts)
{
    CLEAR(*opts);

    config_init(&opts->cfg);

    opts->conf_file = "";

    opts->dev = "enf0";
    opts->dev_node = "/dev/net/tun";

    opts->remote_host = "23.147.128.112";
    opts->remote_port = "443";

    opts->fwmark = 363;

    return 0;
}

int
enftun_options_free(struct enftun_options* opts)
{
    config_destroy(&opts->cfg);

    CLEAR(*opts);

    return 0;
}

int
enftun_options_parse_argv(struct enftun_options* opts,
                          const int argc,
                          char *argv[])
{
    int c;
    while ((c = getopt(argc, argv, "hc:")) != -1)
    {
        switch (c)
        {
        case 'h':
            print_usage();
            return -EINVAL;
        case 'c':
            opts->conf_file = optarg;
            break;
        default:
            print_usage();
            return -EINVAL;
        }
    }

    return 0;
}

static
void
log_config_read_error(struct enftun_options* opts)
{
    config_t *cfg = &opts->cfg;

    if (!config_error_line(cfg))
    {
        enftun_log_error("Cannot open config file %s\n",
                         opts->conf_file);
    }
    else
    {
        enftun_log_error("Cannot parse config file %s at line %d - %s\n",
                         opts->conf_file,
                         config_error_line(cfg),
                         config_error_text(cfg));
    }
}

int
enftun_options_parse_conf(struct enftun_options* opts)
{
    config_t *cfg = &opts->cfg;

    if (!opts->conf_file)
        return 0;

    if (!config_read_file(cfg, opts->conf_file))
    {
        log_config_read_error(opts);
        return -EINVAL;
    }

    /* Platform settings */
    config_lookup_string(cfg, "tun.ip_path", &opts->ip_path);

    /* TUN settings */
    config_lookup_string(cfg, "tun.dev", &opts->dev);
    config_lookup_string(cfg, "tun.dev_node", &opts->dev_node);

    /* Remote settings */
    config_lookup_string(cfg, "remote.host", &opts->remote_host);
    config_lookup_string(cfg, "remote.port", &opts->remote_port);
    config_lookup_string(cfg, "remote.ca_cert_file", &opts->remote_ca_cert_file);

    /* Route settings */
    config_lookup_int(cfg, "route.fwmark", &opts->fwmark);

    /* Identity settings */
    config_lookup_string(cfg, "identity.cert_file", &opts->cert_file);
    config_lookup_string(cfg, "identity.key_file", &opts->key_file);

    return 0;
}
