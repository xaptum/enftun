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

#ifndef ENFTUN_CONFIG_H
#define ENFTUN_CONFIG_H

#include <netinet/in.h>

#include <libconfig.h>

struct enftun_config
{
    config_t cfg;

    const char* conf_file;

    const char* ip_path;
    int ip_set;

    const char* dev;
    const char* dev_node;

    const char** remote_hosts;
    const char* remote_port;
    const char* remote_ca_cert_file;

    const char* cert_file;
    const char* key_file;

    int fwmark;
    int table;
    const char** prefixes;
    const char** trusted_ifaces;

    int ra_period; /* router advertisement period in ms */

    int xtt_enable;
    const char* xtt_remote_port;
    const char* xtt_tcti;
    const char* xtt_device;
    const char* xtt_socket_host;
    const char* xtt_socket_port;
    const char* xtt_basename;

};

int
enftun_config_init(struct enftun_config* config);

int
enftun_config_free(struct enftun_config* config);

int
enftun_config_parse(struct enftun_config* config, const char* file);

int
enftun_config_print(struct enftun_config* config, const char* key);

#endif // ENFTUN_OPTIONS_H
