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

#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "memory.h"
#include "tcp_multi.h"
#include "tls.h"
#include "tls_tpm.h"

struct enftun_channel_ops enftun_tls_ops = {
    .read  = (int (*)(void*, struct enftun_packet*)) enftun_tls_read_packet,
    .write = (int (*)(void*, struct enftun_packet*)) enftun_tls_write_packet,
    .prepare =
        (void (*)(void*, struct enftun_packet*)) enftun_tls_prepare_packet,
    .pending = (int (*)(void*)) enftun_tls_pending};

int
enftun_tls_init(struct enftun_tls* tls, int mark)
{
    int rc = 0;

    CLEAR(*tls);

#if OPENSSL_VERSION_NUMBER < 0x10100000
    SSL_library_init();
    SSL_load_error_strings();
    ERR_clear_error();
    tls->ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
    ERR_clear_error();
    tls->ctx = SSL_CTX_new(TLS_client_method());
#endif
    if (!tls->ctx)
    {
        enftun_log_ssl_error("Cannot allocate SSL_CTX structure:");
        rc = -1;
        goto out;
    }

    tls->mark           = mark;
    tls->need_provision = 0;

    enftun_tcp_multi_init(&tls->sock);

out:
    return rc;
}

int
enftun_tls_free(struct enftun_tls* tls)
{
    SSL_CTX_free(tls->ctx);
    CLEAR(*tls);
    return 0;
}

int
enftun_tls_load_credentials(struct enftun_tls* tls,
                            const char* cacert_file,
                            const char* cert_file,
                            const char* key_file,
                            const char* tcti,
                            const char* device,
                            const char* socket_host,
                            const char* socket_port)
{
    ERR_clear_error();
    if (!SSL_CTX_load_verify_locations(tls->ctx, cacert_file, NULL))
    {
        enftun_log_ssl_error("Failed to load server TLS certificate %s:",
                             cacert_file);
        goto err;
    }
    enftun_log_debug("Loaded server TLS certificate %s\n", cacert_file);

    ERR_clear_error();
    if (!(SSL_CTX_use_certificate_file(tls->ctx, cert_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_certificate_file(tls->ctx, cert_file, SSL_FILETYPE_ASN1)))
    {
        enftun_log_ssl_error("Failed to load client TLS certificate %s:",
                             cert_file);
        goto err;
    }
    enftun_log_debug("Loaded client TLS certificate %s\n", cert_file);

    ERR_clear_error();
    if (!(SSL_CTX_use_PrivateKey_file(tls->ctx, key_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_PrivateKey_file(tls->ctx, key_file, SSL_FILETYPE_ASN1) ||
          enftun_tls_tpm_use_key(tls, key_file, tcti, device, socket_host,
                                 socket_port)))
    {
        enftun_log_ssl_error("Failed to load client TLS key %s:", key_file);
        goto err;
    }

    enftun_log_debug("Loaded client TLS private key %s\n", key_file);

    ERR_clear_error();
    if (!SSL_CTX_check_private_key(tls->ctx))
    {
        enftun_log_ssl_error(
            "Failed to validate client TLS cert and private key:");
        goto err;
    }

    enftun_log_debug("Validated client TLS cert and private key\n");
    return 0;

err:
    tls->need_provision = 1;
    return -1;
}

static int
enftun_tls_handshake(struct enftun_tls* tls)
{
    int rc;

    ERR_clear_error();
    tls->ssl = SSL_new(tls->ctx);
    if (!tls->ssl)
    {
        enftun_log_ssl_error("Failed to allocate SSL structure:");
        goto err;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000
    SSL_set_options(tls->ssl, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                  SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#else
    ERR_clear_error();
    if (SSL_set_min_proto_version(tls->ssl, TLS1_2_VERSION) != 1)
    {
        enftun_log_ssl_error("Cannot set min proto version:");
        goto free_ssl;
    }
#endif

    ERR_clear_error();
    if (SSL_set_fd(tls->ssl, tls->sock.fd) != 1)
    {
        enftun_log_ssl_error("Failed to set SSL file descriptor (%d):",
                             tls->sock.fd);
        goto free_ssl;
    }

    SSL_set_connect_state(tls->ssl);
    SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);

    /*
     * Set this regardless of whether the handshake succeeds or
     * fails.
     *
     * Failure might be due to bad credentials, so rerun
     * provisioning.
     *
     * Success doesn't yet indicate that the credentials were
     * accepted. The ENF doesn't check the certificate until after the
     * SSL handshake is complete.  It will then close the TCP socket
     * if the certificate checks fail. So set :need_provision: here,
     * and then clear it on the first successful read.
     */
    tls->need_provision = 1;

    ERR_clear_error();
    rc = SSL_do_handshake(tls->ssl);
    if (rc != 1)
    {
        enftun_log_ssl_error("Failed to do TLS handshake:");
        goto free_ssl;
    }

    enftun_log_info("Completed TLS handshake\n");
    goto out;

free_ssl:
    SSL_free(tls->ssl);

err:
    rc = -1;

out:
    return rc;
}

int
enftun_tls_connect(struct enftun_tls* tls, const char** hosts, const char* port)
{
    int rc;

    /* Attempt a connection */
    rc = tls->sock.ops.connect_any(&tls->sock, hosts, port, tls->mark);

    if (rc < 0)
    {
        enftun_log_error("TLS could not connect\n");
        goto out;
    }

    rc = enftun_tls_handshake(tls);
    if (rc < 0)
        tls->sock.ops.close(&tls->sock);

out:
    return rc;
}

int
enftun_tls_disconnect(struct enftun_tls* tls)
{
    int rc;

    if (tls->ssl)
    {
        ERR_clear_error();
        rc = SSL_shutdown(tls->ssl);

        if (rc == 0)
        {
            ERR_clear_error();
            rc = SSL_shutdown(tls->ssl);
        }

        if (rc < 0)
        {
            enftun_log_ssl_error("Failed to shutdown TLS connection:");
        }
    }

    tls->sock.ops.close(&tls->sock);
    SSL_free(tls->ssl);

    return 0;
}

int
enftun_tls_read(struct enftun_tls* tls, uint8_t* buf, size_t len)
{
    int err, rc;

    ERR_clear_error();
    if ((rc = SSL_read(tls->ssl, buf, len)) >= 0)
    {
        if (tls->need_provision)
            tls->need_provision = 0;
        goto out;
    }

    err = SSL_get_error(tls->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        rc = -EAGAIN;
        goto out;
    }

    enftun_log_ssl_error("Failed to read:");

out:
    return rc;
}

int
enftun_tls_write(struct enftun_tls* tls, uint8_t* buf, size_t len)
{
    int err, rc;

    ERR_clear_error();
    if ((rc = SSL_write(tls->ssl, buf, len)) >= 0)
        goto out;

    err = SSL_get_error(tls->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    {
        rc = -EAGAIN;
        goto out;
    }

    enftun_log_ssl_error("Failed to write:");

out:
    return rc;
}

static size_t
size_to_read(struct enftun_packet* pkt)
{
    /* read header */
    if (pkt->size < 2)
        return 2 - pkt->size;

    /* read body */
    return ntohs(*(uint16_t*) pkt->data) - (pkt->size - 2);
}

int
enftun_tls_pending(struct enftun_tls* tls)
{
    return SSL_pending(tls->ssl);
}

int
enftun_tls_read_packet(struct enftun_tls* tls, struct enftun_packet* pkt)
{
    int rc;
    size_t len;

    /*
     * If starting to read a new packet, ensure the TLS stream header
     * is half-word aligned so that the actual packet paylaod will be
     * word aligned.
     */
    if (pkt->size == 0)
    {
        enftun_packet_reserve_head(pkt, 2);
    }

    len = size_to_read(pkt);
    if (len > enftun_packet_tailroom(pkt))
    {
        rc = -EINVAL;
        goto out;
    }

    rc = enftun_tls_read(tls, pkt->tail, len);
    if (rc < 0)
        goto out;

    if (rc == 0)
    {
        rc = -ENOTCONN;
        goto out;
    }

    enftun_packet_insert_tail(pkt, rc);

    if (size_to_read(pkt) > 0)
    {
        rc = -EAGAIN;
        goto out;
    }

    enftun_packet_remove_head(pkt, 2);
    rc = 0;

out:
    return rc;
}

void
enftun_tls_prepare_packet(struct enftun_tls* tls __attribute__((unused)),
                          struct enftun_packet* pkt)
{
    enftun_packet_insert_head(pkt, 2);
    *(uint16_t*) (pkt->data) = htons(pkt->size - 2);
}

int
enftun_tls_write_packet(struct enftun_tls* tls, struct enftun_packet* pkt)
{
    int rc;

    rc = enftun_tls_write(tls, pkt->data, pkt->size);
    if (rc < 0)
        goto out;
    enftun_packet_remove_head(pkt, rc);

    if (pkt->size > 0)
    {
        rc = -EAGAIN;
        goto out;
    }

    rc = 0;

out:
    return rc;
}
