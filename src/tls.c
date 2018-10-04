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

#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "log.h"
#include "tls.h"

#define get_sin_addr(addr) \
    (&((struct sockaddr_in*)addr->ai_addr)->sin_addr)

struct enftun_channel_ops enftun_tls_ops =
{
   .read    = (int  (*)(void*, struct enftun_packet*)) enftun_tls_read_packet,
   .write   = (int  (*)(void*, struct enftun_packet*)) enftun_tls_write_packet,
   .prepare = (void (*)(void*, struct enftun_packet*)) enftun_tls_prepare_packet
};

int
enftun_tls_init(struct enftun_tls* tls)
{
    int rc = 0;

    tls->ctx = SSL_CTX_new(TLS_client_method());
    if (!tls->ctx)
    {
        enftun_log_ssl_error("Cannot allocate SSL_CTX structure:");
        rc = -1;
        goto out;
    }

 out:
    return rc;
}

int
enftun_tls_free(struct enftun_tls* tls)
{
    SSL_CTX_free(tls->ctx);
    return 0;
}

static
int
enftun_tls_handshake(struct enftun_tls* tls,
                     const char* cacert_file,
                     const char* cert_file, const char* key_file)
{
    int rc;

    if (SSL_CTX_set_min_proto_version(tls->ctx, TLS1_2_VERSION) < 0)
    {
        enftun_log_ssl_error("Cannot set min proto version:");
        goto err;
    }

    if (!SSL_CTX_load_verify_locations(tls->ctx, cacert_file, NULL))
    {
        enftun_log_ssl_error("Failed to load server TLS certificate %s", cacert_file);
        goto err;
    }

    if (!(SSL_CTX_use_certificate_file(tls->ctx, cert_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_certificate_file(tls->ctx, cert_file, SSL_FILETYPE_ASN1)))
    {
        enftun_log_ssl_error("Failed to load client TLS certificate %s:", cert_file);
        goto err;
    }
    enftun_log_debug("Loaded client TLS certificate %s\n", cert_file);

    if (!(SSL_CTX_use_PrivateKey_file(tls->ctx, key_file, SSL_FILETYPE_PEM) ||
          SSL_CTX_use_PrivateKey_file(tls->ctx, key_file, SSL_FILETYPE_ASN1)))
    {
        enftun_log_ssl_error("Failed to load client TLS key %s:", key_file);
        goto err;
    }
    enftun_log_debug("Loaded client TLS private key %s\n", key_file);

    if (!SSL_CTX_check_private_key(tls->ctx))
    {
        enftun_log_ssl_error("Failed to validate client TLS cert and private key:");
        goto err;
    }
    enftun_log_debug("Validated client TLS cert and private key\n");

    tls->ssl = SSL_new(tls->ctx);
    if (!tls->ssl)
    {
        enftun_log_ssl_error("Failed to allocate SSL structure:");
        goto err;
    }

    if (!SSL_set_fd(tls->ssl, tls->fd))
    {
        enftun_log_ssl_error("Failed to set SSL file descriptor (%d):", tls->fd);
        goto err;
    }

    SSL_set_connect_state(tls->ssl);
    SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, NULL);

    if ((rc = SSL_do_handshake(tls->ssl)) != 1)
    {
        enftun_log_ssl_error("Failed to do TLS handshake: ");
        goto err;
    }

    enftun_log_info("Completed TLS handshake\n");
    goto out;

 err:
    rc = -1;

 out:
    return rc;
}

int
enftun_tls_connect(struct enftun_tls* tls, int mark,
                   const char* host, const char *port,
                   const char* cacert_file,
                   const char* cert_file, const char* key_file)
{
    struct addrinfo *addr_h, *addr, hints;
    char ip[45];
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    if ((rc = getaddrinfo(host, port, &hints, &addr_h)) < 0)
    {
        enftun_log_error("Cannot resolve %s:%s: %s\n", host, port, gai_strerror(rc));
        goto out;
    }

    for (addr=addr_h; addr!=NULL; addr=addr->ai_next)
    {
        inet_ntop(addr->ai_family, get_sin_addr(addr), ip, sizeof(ip));

        enftun_log_debug("Attempting to connect to %s at [%s]:%s\n", host, ip, port);

        if ((tls->fd = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol)) < 0)
        {
            enftun_log_debug("Failed to create socket: %s\n", strerror(errno));
            rc = -errno;
            continue;
        }

        if (mark > 0)
        {
            if ((rc = setsockopt(tls->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) < 0)
            {
                enftun_log_debug("Failed to set mark %d: %s\n", mark, strerror(errno));
                rc = -errno;
                continue;
            }
        }

        if ((rc = connect(tls->fd, addr->ai_addr, addr->ai_addrlen)) < 0)
        {
            enftun_log_debug("Failed to connect to [%s]:%s: %s\n",
                             ip, port, strerror(errno));
            rc = -errno;
            goto close_fd;
        }

        enftun_log_info("Connected to [%s]:%s\n", ip, port);
        break;

    close_fd:
            close(tls->fd);
            tls->fd = 0;
    }

    if (rc == 0)
        rc = enftun_tls_handshake(tls, cacert_file, cert_file, key_file);

 out:
    freeaddrinfo(addr_h);
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
            enftun_log_ssl_error("Failed to shutdown TLS connection");
        }
    }

    if (tls->fd)
        close(tls->fd);

    return 0;
}

int
enftun_tls_read(struct enftun_tls* tls, uint8_t* buf, size_t len)
{
    int err, rc;

    ERR_clear_error();
    if ((rc = SSL_read(tls->ssl, buf, len)) >= 0)
        goto out;

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

    enftun_log_ssl_error("Failed to write");

 out:
        return rc;
}

static
size_t
size_to_read(struct enftun_packet* pkt)
{
    /* read header */
    if (pkt->size < 2)
        return 2 - pkt->size;

    /* read body */
    return ntohs(*(uint16_t*)pkt->data) - (pkt->size - 2);
}

int
enftun_tls_read_packet(struct enftun_tls* tls, struct enftun_packet* pkt)
{
    int rc;
    size_t len;

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
    *(uint16_t*)(pkt->data) = htons(pkt->size - 2);
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
