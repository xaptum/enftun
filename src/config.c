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

/**
 * Joins a null-terminated array of strings with the specified
 * separator and prints to stdout.
 */
static
void
print_joined(const char** strs, const char* sep)
{
    while (*strs != NULL)
    {
        fprintf(stdout, "%s", *strs);
        strs++;
        if (*strs != NULL)
            fprintf(stdout, "%s", sep);
    }
    fprintf(stdout, "\n");
}

/**
 * Looks up the value of string array in the configuration config
 * specified by the path path. It stores the values in a
 * null-terminated array at value.
 *
 * The caller is responsible for free-ing value.  If value was
 * non-NULL when called, this method will free it.
 */
static
void
lookup_string_array(config_t* cfg, const char* path, const char*** value)
{
    config_setting_t* s = config_lookup(cfg, path);
    if (!s || !config_setting_is_array(s))
        return;

    int cnt = config_setting_length(s);

    if (*value) free(*value);
    *value = calloc(cnt + 1, sizeof(char*));
    for (int i = 0; i < cnt; i++)
    {
        (*value)[i] = config_setting_get_string_elem(s, i);
    }
}

int
enftun_config_init(struct enftun_config* config)
{
    CLEAR(*config);

    config_init(&config->cfg);

    config->ip_path = "/bin/ip";
    config->ip_set = 1; // true

    config->dev = "enf0";
    config->dev_node = "/dev/net/tun";

    config->remote_hosts = calloc(3, sizeof(char*));
    config->remote_hosts[0] = "23.147.128.112";
    config->remote_hosts[1] = "2607:8f80:ffff::1";
    config->remote_port = "443";
    config->remote_ca_cert_file = "/etc/enftun/enf.cacert.pem";

    config->fwmark = 363;
    config->table = 2097;

    config->prefixes = calloc(2, sizeof(char*));
    config->prefixes[0] = "default";

    config->trusted_ifaces = calloc(2, sizeof(char*));

    config->ra_period = 10 * 60 * 1000; // milliseconds

    config->xtt_enable = 0;
    config->xtt_remote_port = "444";
    config->xtt_tcti = "device";
    config->xtt_device = "/dev/tpm0";
    config->xtt_socket_host = "localhost";
    config->xtt_socket_port = "2321";
    config->xtt_basename = NULL;

    return 0;
}

int
enftun_config_free(struct enftun_config* config)
{
    free(config->trusted_ifaces);
    free(config->prefixes);
    free(config->remote_hosts);
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
    config_lookup_bool(cfg, "tun.ip_set", &config->ip_set);

    /* TUN settings */
    config_lookup_string(cfg, "tun.dev", &config->dev);
    config_lookup_string(cfg, "tun.dev_node", &config->dev_node);

    /* Remote settings */
    lookup_string_array(cfg, "remote.hosts", &config->remote_hosts);
    config_lookup_string(cfg, "remote.port", &config->remote_port);
    config_lookup_string(cfg, "remote.ca_cert_file", &config->remote_ca_cert_file);

    /* Route settings */
    config_lookup_int(cfg, "route.fwmark", &config->fwmark);
    config_lookup_int(cfg, "route.table", &config->table);
    lookup_string_array(cfg, "route.prefixes", &config->prefixes);
    lookup_string_array(cfg, "route.trusted_interfaces", &config->trusted_ifaces);
    config_lookup_int(cfg, "route.ra_period", &config->ra_period);

    /* Identity settings */
    config_lookup_string(cfg, "identity.cert_file", &config->cert_file);
    config_lookup_string(cfg, "identity.key_file", &config->key_file);

    /* XTT settings */
    if (NULL != config_lookup(cfg, "identity.xtt"))
    {
        config->xtt_enable = 1;
        config_lookup_string(cfg, "identity.xtt.remote_port", &config->xtt_remote_port);
        config_lookup_string(cfg, "identity.xtt.tcti", &config->xtt_tcti);
        config_lookup_string(cfg, "identity.xtt.device", &config->xtt_device);
        config_lookup_string(cfg, "identity.xtt.socket_host", &config->xtt_socket_host);
        config_lookup_string(cfg, "identity.xtt.socket_port", &config->xtt_socket_port);
        config_lookup_string(cfg, "identity.xtt.basename", &config->xtt_basename);
    }

    return 0;
}

int
enftun_config_print(struct enftun_config* config, const char* key)
{
    /* Platform settings */
    if (strcmp(key, "tun.ip_path") == 0)
        fprintf(stdout, "%s\n", config->ip_path);
    else if (strcmp(key, "tun.ip_set") == 0)
        fprintf(stdout, "%s\n", config->ip_set ? "true" : "false");
    /* TUN settings */
    else if (strcmp(key, "tun.dev") == 0)
        fprintf(stdout, "%s\n", config->dev);
    else if (strcmp(key, "tun.dev_node") == 0)
        fprintf(stdout, "%s\n", config->dev_node);
    /* Remote settings */
    else if (strcmp(key, "remote.hosts") == 0)
        print_joined(config->remote_hosts, " ");
    else if (strcmp(key, "remote.port") == 0)
        fprintf(stdout, "%s\n", config->remote_port);
    else if (strcmp(key, "remote.port") == 0)
        fprintf(stdout, "%s\n", config->remote_port);
    else if (strcmp(key, "remote.ca_cert_file") == 0)
        fprintf(stdout, "%s\n", config->remote_ca_cert_file);
    /* Route settings */
    else if (strcmp(key, "route.fwmark") == 0)
        fprintf(stdout, "%d\n", config->fwmark);
    else if (strcmp(key, "route.table") == 0)
        fprintf(stdout, "%d\n", config->table);
    else if (strcmp(key, "route.prefixes") == 0)
        print_joined(config->prefixes, " ");
    else if (strcmp(key, "route.trusted_interfaces") == 0)
        print_joined(config->trusted_ifaces, " ");
    else if (strcmp(key, "route.ra_period") == 0)
        fprintf(stdout, "%d\n", config->ra_period);
    /* Identity settings */
    else if (strcmp(key, "identity.cert_file") == 0)
        fprintf(stdout, "%s\n", config->cert_file);
    else if (strcmp(key, "identity.key_file") == 0)
        fprintf(stdout, "%s\n", config->key_file);
    /* XTT settings */
    else if (strcmp(key, "identity.xtt.enable") == 0)
        fprintf(stdout, "%d\n", config->xtt_enable);
    else if (strcmp(key, "identity.xtt.remote_port") == 0)
        fprintf(stdout, "%s\n", config->xtt_remote_port);
    else if (strcmp(key, "identity.xtt.tcti") == 0)
        fprintf(stdout, "%s\n", config->xtt_tcti);
    else if (strcmp(key, "identity.xtt.device") == 0)
        fprintf(stdout, "%s\n", config->xtt_device);
    else if (strcmp(key, "identity.xtt.socket_host") == 0)
        fprintf(stdout, "%s\n", config->xtt_socket_host);
    else if (strcmp(key, "identity.xtt.socket_port") == 0)
        fprintf(stdout, "%s\n", config->xtt_socket_port);
    else if (strcmp(key, "identity.xtt.basename") == 0)
        fprintf(stdout, "%s\n", config->xtt_basename);
    else
    {
        fprintf(stderr, "%s not found\n", key);
        return -1;
    }

    return 0;
}
