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

#include "config.h"
#include "log.h"
#include "memory.h"

/**
 * Joins a null-terminated array of strings with the specified
 * separator and prints to stdout.
 */
static void
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
static void
lookup_string_array(config_t* cfg, const char* path, const char*** value)
{
    config_setting_t* s = config_lookup(cfg, path);
    if (!s || !config_setting_is_array(s))
        return;

    int cnt = config_setting_length(s);

    if (*value)
        free(*value);
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

    config->slirp_enable = 0;

    config->tun_ip_path = "/bin/ip";
    config->tun_ip_set  = 1; // true

    config->tun_dev      = "enf0";
    config->tun_dev_node = "/dev/net/tun";

    config->remote_hosts        = calloc(2, sizeof(char*));
    config->remote_hosts[0]     = "23.147.128.112";
    config->remote_port         = "443";
    config->remote_ca_cert_file = "/etc/enftun/enf.cacert.pem";

    config->ip_file = NULL;

    config->fwmark = 363;
    config->table  = 2097;

    config->prefixes    = calloc(2, sizeof(char*));
    config->prefixes[0] = "default";

    config->trusted_ifaces = calloc(2, sizeof(char*));

    config->allow_ipv4 = 0; // false

    config->ra_period         = 10 * 60 * 1000; // milliseconds
    config->heartbeat_period  = 5 * 60 * 1000;
    config->heartbeat_timeout = 10 * 1000;

    config->xtt_enable      = 0;
    config->xtt_remote_port = "444";
    config->xtt_basename    = NULL;

    config->tpm_tcti        = "device";
    config->tpm_device      = "/dev/tpm0";
    config->tpm_socket_host = "localhost";
    config->tpm_socket_port = "2321";
    config->tpm_hierarchy   = 0;
    config->tpm_password    = NULL;
    config->tpm_parent      = 0;

    config->trace_enable    = 0;
    config->trace_pcap_file = NULL;

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

static void
log_config_read_error(struct enftun_config* config, const char* file)
{
    config_t* cfg = &config->cfg;

    if (!config_error_line(cfg))
    {
        enftun_log_error("Cannot open config file %s\n", file);
    }
    else
    {
        enftun_log_error("Cannot parse config file %s at line %d - %s\n", file,
                         config_error_line(cfg), config_error_text(cfg));
    }
}

int
enftun_config_parse(struct enftun_config* config, const char* file)
{
    config_t* cfg = &config->cfg;

    if (!file)
        return 0;

    if (!config_read_file(cfg, file))
    {
        log_config_read_error(config, file);
        return -EINVAL;
    }

    /* Slirp settings */
    if (NULL != config_lookup(cfg, "slirp"))
    {
        config->slirp_enable = 1;
    }

    /* TUN settings */
    config_lookup_string(cfg, "tun.ip_path", &config->tun_ip_path);
    config_lookup_bool(cfg, "tun.ip_set", &config->tun_ip_set);
    config_lookup_string(cfg, "tun.dev", &config->tun_dev);
    config_lookup_string(cfg, "tun.dev_node", &config->tun_dev_node);

    /* Remote settings */
    lookup_string_array(cfg, "remote.hosts", &config->remote_hosts);
    config_lookup_string(cfg, "remote.port", &config->remote_port);
    config_lookup_string(cfg, "remote.ca_cert_file",
                         &config->remote_ca_cert_file);
    config_lookup_int(cfg, "remote.heartbeat_period",
                      &config->heartbeat_period);
    config_lookup_int(cfg, "remote.heartbeat_timeout",
                      &config->heartbeat_timeout);

    /* Route settings */
    config_lookup_int(cfg, "route.fwmark", &config->fwmark);
    config_lookup_int(cfg, "route.table", &config->table);
    lookup_string_array(cfg, "route.prefixes", &config->prefixes);
    lookup_string_array(cfg, "route.trusted_interfaces",
                        &config->trusted_ifaces);
    config_lookup_bool(cfg, "route.allow_ipv4", &config->allow_ipv4);
    config_lookup_int(cfg, "route.ra_period", &config->ra_period);

    /* Identity settings */
    config_lookup_string(cfg, "identity.cert_file", &config->cert_file);
    config_lookup_string(cfg, "identity.key_file", &config->key_file);
    config_lookup_string(cfg, "identity.ip_file", &config->ip_file);

    /* XTT settings */
    if (NULL != config_lookup(cfg, "identity.xtt"))
    {
        config->xtt_enable = 1;
        config_lookup_string(cfg, "identity.xtt.remote_port",
                             &config->xtt_remote_port);
        config_lookup_string(cfg, "identity.xtt.basename",
                             &config->xtt_basename);
    }

    /* TPM settings */
    if (NULL != config_lookup(cfg, "identity.tpm"))
    {
        config->tpm_enable = 1;
        config_lookup_string(cfg, "identity.tpm.tcti", &config->tpm_tcti);
        config_lookup_string(cfg, "identity.tpm.device", &config->tpm_device);
        config_lookup_string(cfg, "identity.tpm.socket_host",
                             &config->tpm_socket_host);
        config_lookup_string(cfg, "identity.tpm.socket_port",
                             &config->tpm_socket_port);
        config_lookup_int(cfg, "identity.tpm.hierarchy",
                          &config->tpm_hierarchy);
        config_lookup_string(cfg, "identity.tpm.password",
                             &config->tpm_password);
        config_lookup_int(cfg, "identity.tpm.parent", &config->tpm_parent);
    }

    /* Trace settings */
    if (NULL != config_lookup(cfg, "trace"))
    {
        config->trace_enable = 1;
        config_lookup_string(cfg, "trace.pcap_file", &config->trace_pcap_file);
    }

    return 0;
}

int
enftun_config_print(struct enftun_config* config, const char* key)
{
    /* TUN settings */
    if (strcmp(key, "tun.ip_path") == 0)
        fprintf(stdout, "%s\n", config->tun_ip_path);
    else if (strcmp(key, "tun.ip_set") == 0)
        fprintf(stdout, "%s\n", config->tun_ip_set ? "true" : "false");
    else if (strcmp(key, "tun.dev") == 0)
        fprintf(stdout, "%s\n", config->tun_dev);
    else if (strcmp(key, "tun.dev_node") == 0)
        fprintf(stdout, "%s\n", config->tun_dev_node);
    /* Remote settings */
    else if (strcmp(key, "remote.hosts") == 0)
        print_joined(config->remote_hosts, " ");
    else if (strcmp(key, "remote.port") == 0)
        fprintf(stdout, "%s\n", config->remote_port);
    else if (strcmp(key, "remote.port") == 0)
        fprintf(stdout, "%s\n", config->remote_port);
    else if (strcmp(key, "remote.ca_cert_file") == 0)
        fprintf(stdout, "%s\n", config->remote_ca_cert_file);
    else if (strcmp(key, "remote.heartbeat_period") == 0)
        fprintf(stdout, "%d\n", config->heartbeat_period);
    else if (strcmp(key, "remote.heartbeat_timeout") == 0)
        fprintf(stdout, "%d\n", config->heartbeat_timeout);
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
    else if (strcmp(key, "identity.ip_file") == 0)
        fprintf(stdout, "%s\n", config->ip_file);
    /* XTT settings */
    else if (strcmp(key, "identity.xtt.enable") == 0)
        fprintf(stdout, "%d\n", config->xtt_enable);
    else if (strcmp(key, "identity.xtt.remote_port") == 0)
        fprintf(stdout, "%s\n", config->xtt_remote_port);
    else if (strcmp(key, "identity.xtt.basename") == 0)
        fprintf(stdout, "%s\n", config->xtt_basename);
    else if (strcmp(key, "identity.tpm.enable") == 0)
        fprintf(stdout, "%d\n", config->tpm_enable);
    else if (strcmp(key, "identity.tpm.tcti") == 0)
        fprintf(stdout, "%s\n", config->tpm_tcti);
    else if (strcmp(key, "identity.tpm.device") == 0)
        fprintf(stdout, "%s\n", config->tpm_device);
    else if (strcmp(key, "identity.tpm.socket_host") == 0)
        fprintf(stdout, "%s\n", config->tpm_socket_host);
    else if (strcmp(key, "identity.tpm.socket_port") == 0)
        fprintf(stdout, "%s\n", config->tpm_socket_port);
    else if (strcmp(key, "identity.tpm.hierarchy") == 0)
        fprintf(stdout, "%d\n", config->tpm_hierarchy);
    else if (strcmp(key, "identity.tpm.password") == 0)
        fprintf(stdout, "%s\n", config->tpm_password);
    else if (strcmp(key, "identity.tpm.parent") == 0)
        fprintf(stdout, "%d\n", config->tpm_parent);
    else if (strcmp(key, "trace.pcap_file") == 0)
        fprintf(stdout, "%s\n", config->trace_pcap_file);
    else
    {
        fprintf(stderr, "%s not found\n", key);
        return -1;
    }

    return 0;
}
