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

#ifndef ENFTUN_XTT_H
#define ENFTUN_XTT_H

#include <xtt.h>

#include "channel.h"
#include "packet.h"

struct enftun_xtt
{
    const char *suitespec;
    struct xtt_tpm_context tpm_ctx;
    struct xtt_tpm_params tpm_params;
};

int
enftun_xtt_init(struct enftun_xtt* xtt);

int
enftun_xtt_free(struct enftun_xtt* xtt);

int
enftun_xtt_handshake(const char *server_host,
                     const char *server_port,
                     int mark,
                     const char *tcti,
                     const char *device,
                     const char *longterm_cert_file,
                     const char *longterm_key_file,
                     const char *socket_host,
                     const char *socket_port,
                     const char *ca_cert_file,
                     const char *basename,
                     struct enftun_xtt* xtt);

#endif // ENFTUN_XTT_H
