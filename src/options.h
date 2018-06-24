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

#ifndef ENFTUN_OPTIONS_H
#define ENFTUN_OPTIONS_H

#include <netinet/in.h>

#include <libconfig.h>

struct enftun_options
{
    config_t cfg;

    const char* conf_file;

    const char* dev;
    const char* dev_node;

    const char* remote_host;
    const char* remote_port;
    const char* remote_ca_cert_file;

    const char* cert_file;
    const char* key_file;
};

int
enftun_options_init(struct enftun_options* opts);

int
enftun_options_free(struct enftun_options* opts);

int
enftun_options_parse_argv(struct enftun_options* opts,
                          const int argc,
                          char *argv[]);

int
enftun_options_parse_conf(struct enftun_options* opts);

#endif // ENFTUN_OPTIONS_H
