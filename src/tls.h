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

#ifndef ENFTUN_TLS_H
#define ENFTUN_TLS_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "channel.h"
#include "packet.h"
#include "tcp.h"

struct enftun_tls
{
    struct enftun_tcp* sock; // the underlying TCP socket
    struct enftun_tcp_native tcp_ctx;

    int mark; // mark to apply to tunnel packets. 0 to disable

    SSL_CTX* ctx; // the openSSL context
    SSL* ssl;     // the openSSL connection

    BIO* bio; // openSSL BIO socket wrapper

    int need_provision; // Whether or not XTT provisioning is required
};

extern struct enftun_channel_ops enftun_tls_ops;

int
enftun_tls_init(struct enftun_tls* tls, int mark);

int
enftun_tls_free(struct enftun_tls* tls);

int
enftun_tls_load_credentials(struct enftun_tls* tls,
                            const char* cacert_file,
                            const char* cert_file,
                            const char* key_file);

int
enftun_tls_connect(struct enftun_tls* tls,
                   const char** hosts,
                   const char* port);

int
enftun_tls_disconnect(struct enftun_tls* tls);

int
enftun_tls_read(struct enftun_tls* tls, uint8_t* buf, size_t len);

int
enftun_tls_write(struct enftun_tls* tls, uint8_t* buf, size_t len);

int
enftun_tls_pending(struct enftun_tls* tls);

int
enftun_tls_read_packet(struct enftun_tls* tls, struct enftun_packet* pkt);

void
enftun_tls_prepare_packet(struct enftun_tls* tls, struct enftun_packet* pkt);

int
enftun_tls_write_packet(struct enftun_tls* tls, struct enftun_packet* pkt);

#endif // ENFTUN_TLS_H
