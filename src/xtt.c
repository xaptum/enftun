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
#include <assert.h>
#include <netdb.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <tss2/tss2_sys.h>
#include <unistd.h>
#include <xaptum-tpm/nvram.h>
#include <xtt.h>
#include <xtt/tpm/context.h>

#include "log.h"
#include "tcp_multi.h"
#include "tls.h"
#include "xtt.h"

int
enftun_xtt_init(struct enftun_xtt* xtt)
{
    int ret = xtt_crypto_initialize_crypto();
    if (0 != ret)
    {
        enftun_log_error("Error initializing cryptography library: %d\n", ret);
        return -1;
    }

    xtt->suitespec = "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512";

    return 0;
}

int
enftun_xtt_free(struct enftun_xtt* xtt)
{
    (void) xtt;
    return 0;
}

static int
initialize_certs(struct xtt_server_root_certificate_context* saved_cert,
                 xtt_certificate_root_id* saved_root_id,
                 xtt_root_certificate* root_certificate);

static int
initialize_daa(struct xtt_client_group_context* group_ctx,
               unsigned char* basename,
               uint16_t basename_len,
               xtt_daa_group_pub_key_lrsw* gpk,
               xtt_daa_credential_lrsw* cred,
               struct xtt_tpm_context* tpm_ctx,
               const char* basename_in);

static int
read_in_from_TPM(struct xtt_tpm_context* tpm_ctx,
                 unsigned char* basename,
                 uint16_t* basename_len,
                 xtt_daa_group_pub_key_lrsw* gpk,
                 xtt_daa_credential_lrsw* cred,
                 xtt_root_certificate* root_certificate,
                 unsigned char* tls_root_cert,
                 uint16_t* tls_len);

static int
do_handshake_client(int socket,
                    xtt_identity_type* requested_client_id,
                    struct xtt_client_group_context* group_ctx,
                    struct xtt_client_handshake_context* ctx,
                    xtt_certificate_root_id* saved_root_id,
                    struct xtt_server_root_certificate_context* saved_cert);

static int
save_credentials(struct xtt_client_handshake_context* ctx,
                 const char* longterm_cert_out_file,
                 const char* longterm_private_key_out_file,
                 struct xtt_tpm_context* tpm_ctx);

int
enftun_xtt_handshake(const char** server_hosts,
                     const char* server_port,
                     int mark,
                     const char* tcti,
                     const char* dev_file,
                     const char* longterm_cert_out_file,
                     const char* longterm_private_key_out_file,
                     const char* tpm_hostname,
                     const char* tpm_port,
                     const char* ca_cert_file,
                     const char* basename_in,
                     int tpm_hierarchy,
                     const char* tpm_password,
                     int tpm_password_len,
                     int tpm_parent,
                     struct enftun_xtt* xtt)
{
    struct enftun_tcp sock = {0};

    int init_daa_ret = -1;
    int ret          = 0;

    xtt_certificate_root_id saved_root_id = {.data = {0}};
    struct xtt_server_root_certificate_context saved_cert;

    setbuf(stdout, NULL);

    xtt_identity_type requested_client_id = {.data = {0}};
    requested_client_id                   = xtt_null_identity;

    // Set suite spec from command line args
    xtt_suite_spec suite_spec = 0;
    if (0 ==
        strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512"))
    {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512;
    }
    else if (0 == strcmp(xtt->suitespec,
                         "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B"))
    {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B;
    }
    else if (0 ==
             strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_SHA512"))
    {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512;
    }
    else if (0 ==
             strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B"))
    {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B;
    }
    else
    {
        enftun_log_error("Unknown suite_spec '%s'\n", xtt->suitespec);
        exit(1);
    }

    // Set TCTI from command line args
    if (0 == strcmp(tcti, "device"))
    {
        xtt->tpm_params.tcti = XTT_TCTI_DEVICE;
    }
    else if (0 == strcmp(tcti, "socket"))
    {
        xtt->tpm_params.tcti = XTT_TCTI_SOCKET;
    }
    else
    {
        enftun_log_error("Unknown tcti_type '%s'\n", tcti);
        exit(1);
    }

    xtt->tpm_params.dev_file = dev_file;
    xtt->tpm_params.hostname = tpm_hostname;
    xtt->tpm_params.port     = tpm_port;

    // Set TCTI device file from command line args
    if (NULL == dev_file && xtt->tpm_params.tcti == XTT_TCTI_DEVICE)
    {
        enftun_log_error("Not given a device file for TCTI\n");
        exit(1);
    }

    int tpm_ctx_ret = SUCCESS;
    tpm_ctx_ret     = xtt_init_tpm_context(&xtt->tpm_ctx, &xtt->tpm_params);
    if (SUCCESS != tpm_ctx_ret)
    {
        fprintf(stderr, "Error initializing TPM context: %d\n", tpm_ctx_ret);
        return tpm_ctx_ret;
    }

    // 1) Setup the needed XTT contexts (from files/TPM).
    // 1i) Read in DAA data from the TPm or from files

    xtt_daa_group_pub_key_lrsw gpk        = {.data = {0}};
    xtt_daa_credential_lrsw cred          = {.data = {0}};
    xtt_root_certificate root_certificate = {.data = {0}};
    unsigned char basename[1024]          = {0};
    uint16_t basename_len                 = sizeof(basename);
    unsigned char tls_root_cert[1024]     = {0};
    uint16_t tls_len                      = sizeof(tls_root_cert);

    ret = read_in_from_TPM(&xtt->tpm_ctx, basename, &basename_len, &gpk, &cred,
                           &root_certificate, tls_root_cert, &tls_len);
    if (0 != ret)
    {
        enftun_log_error("Error reading data from TPM\n");
        goto finish;
    }

    ret = xtt_save_cert_to_file(tls_root_cert, tls_len, ca_cert_file);
    if (ret < 0)
    {
        return SAVE_TO_FILE_ERROR;
    }

    // 1ii) Initialize DAA
    struct xtt_client_group_context group_ctx;
    init_daa_ret = initialize_daa(&group_ctx, basename, basename_len, &gpk,
                                  &cred, &xtt->tpm_ctx, basename_in);
    ret          = init_daa_ret;
    if (0 != init_daa_ret)
    {
        enftun_log_error("Error initializing DAA context\n");
        goto finish;
    }
    // 1iii) Initialize Certificates
    ret = initialize_certs(&saved_cert, &saved_root_id, &root_certificate);
    if (0 != ret)
    {
        enftun_log_error(
            "Error initializing server/root certificate contexts\n");
        goto finish;
    }

    // 2) Make network connection
    enftun_tcp_multi_init(&sock);
    ret = sock.ops.connect_any(&sock, server_hosts, (char*) server_port, mark);

    if (ret < 0)
    {
        enftun_log_error("XTT Handshake: Connection failed\n");
        ret = 1;
        goto finish;
    }

    // 3) Initialize XTT handshake context
    // (will be populated with useful information after a successful handshake).
    enftun_log_debug("Using suite_spec = %d\n", suite_spec);

    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH]  = {0};
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH] = {0};
    struct xtt_client_handshake_context ctx;
    xtt_return_code_type rc = xtt_initialize_client_handshake_context_TPM(
        &ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer),
        XTT_VERSION_ONE, suite_spec, tpm_hierarchy, tpm_password,
        tpm_password_len, tpm_parent, xtt->tpm_ctx.tcti_context);
    if (XTT_RETURN_SUCCESS != rc)
    {
        ret = 1;
        enftun_log_error("Error initializing client handshake context: %d\n",
                         rc);
        goto finish;
    }

    // 4) Run the identity-provisioning handshake with the server.
    ret = do_handshake_client(sock.fd, &requested_client_id, &group_ctx, &ctx,
                              &saved_root_id, &saved_cert);
    if (0 == ret)
    {
        // 6) Save the results (what we and the server now agree on
        // post-handshake)
        ret = save_credentials(&ctx, longterm_cert_out_file,
                               longterm_private_key_out_file, &xtt->tpm_ctx);
        if (0 != ret)
            goto finish;
    }
    else
    {
        enftun_log_error("Handshake failed!\n");
        goto finish;
    }

finish:
    sock.ops.close(&sock);
    xtt_free_tpm_context(&xtt->tpm_ctx);
    if (0 == ret)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

static int
read_in_from_TPM(struct xtt_tpm_context* tpm_ctx,
                 unsigned char* basename,
                 uint16_t* basename_len,
                 xtt_daa_group_pub_key_lrsw* gpk,
                 xtt_daa_credential_lrsw* cred,
                 xtt_root_certificate* root_certificate,
                 unsigned char* tls_root_cert,
                 uint16_t* tls_len)
{
    uint16_t length_read = 0;

    int nvram_ret = xtpm_read_object(basename, *basename_len, &length_read,
                                     XTPM_BASENAME, tpm_ctx->sapi_context);
    if (0 != nvram_ret)
    {
        enftun_log_error("Error reading basename from TPM NVRAM\n");
        goto finish;
    }
    *basename_len = length_read;

    length_read = 0;
    nvram_ret = xtpm_read_object(gpk->data, sizeof(xtt_daa_group_pub_key_lrsw),
                                 &length_read, XTPM_GROUP_PUBLIC_KEY,
                                 tpm_ctx->sapi_context);
    if (0 != nvram_ret)
    {
        enftun_log_error("Error reading GPK from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

    length_read = 0;
    nvram_ret =
        xtpm_read_object(cred->data, sizeof(xtt_daa_credential_lrsw),
                         &length_read, XTPM_CREDENTIAL, tpm_ctx->sapi_context);
    if (0 != nvram_ret)
    {
        enftun_log_error("Error reading credential from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

    length_read = 0;
    nvram_ret   = xtpm_read_object(
        root_certificate->data, sizeof(xtt_root_certificate), &length_read,
        XTPM_ROOT_XTT_CERTIFICATE, tpm_ctx->sapi_context);
    if (0 != nvram_ret)
    {
        enftun_log_error("Error reading root's certificate from TPM NVRAM");
        nvram_ret = TPM_ERROR;
        goto finish;
    }

    nvram_ret =
        xtpm_read_object(tls_root_cert, *tls_len, &length_read,
                         XTPM_ROOT_ASN1_CERTIFICATE, tpm_ctx->sapi_context);
    if (0 != nvram_ret)
    {
        enftun_log_error("Error reading tls root from TPM NVRAM\n");
        nvram_ret = TPM_ERROR;
        goto finish;
    }
    *tls_len = length_read;

finish:
    return nvram_ret;
}

static int
initialize_daa(struct xtt_client_group_context* group_ctx,
               unsigned char* basename,
               uint16_t basename_len,
               xtt_daa_group_pub_key_lrsw* gpk,
               xtt_daa_credential_lrsw* cred,
               struct xtt_tpm_context* tpm_ctx,
               const char* basename_in)
{
    xtt_return_code_type rc = 0;

    // 1) Change the basename if requested
    if (basename_in)
    {
        basename_len = strlen(basename_in);
        if (basename_len > 1024)
            return CLIENT_ERROR;
        memcpy(basename, basename_in, basename_len);
    }

    // 2) Generate gid from gpk (gid = SHA-256(gpk | basename))
    xtt_group_id gid = {.data = {0}};

    crypto_hash_sha256_state hash_state;
    int hash_ret = crypto_hash_sha256_init(&hash_state);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, gpk->data, sizeof(*gpk));
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, basename, basename_len);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_final(&hash_state, gid.data);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;

    // 3) Initialize DAA context using the above information
    rc = xtt_initialize_client_group_context_lrswTPM(
        group_ctx, &gid, cred, basename, basename_len, XTPM_ECDAA_KEY_HANDLE,
        NULL, 0, tpm_ctx->tcti_context);

    return rc;
}

static int
initialize_certs(struct xtt_server_root_certificate_context* saved_cert,
                 xtt_certificate_root_id* saved_root_id,
                 xtt_root_certificate* root_certificate)
{
    xtt_return_code_type rc               = 0;
    xtt_certificate_root_id root_id       = {.data = {0}};
    xtt_ecdsap256_pub_key root_public_key = {.data = {0}};

    // Initialize stored data
    xtt_deserialize_root_certificate(&root_public_key, &root_id,
                                     root_certificate);

    memcpy(saved_root_id, root_id.data, sizeof(xtt_certificate_root_id));
    rc = xtt_initialize_server_root_certificate_context_ecdsap256(
        saved_cert, &root_id, &root_public_key);
    if (XTT_RETURN_SUCCESS != rc)
        return CLIENT_ERROR;

    return 0;
}

static int
do_handshake_client(int socket,
                    xtt_identity_type* requested_client_id,
                    struct xtt_client_group_context* group_ctx,
                    struct xtt_client_handshake_context* ctx,
                    xtt_certificate_root_id* saved_root_id,
                    struct xtt_server_root_certificate_context* saved_cert)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;
    (void) saved_root_id;

    uint16_t bytes_requested                = 0;
    unsigned char* io_ptr                   = NULL;
    xtt_certificate_root_id claimed_root_id = {.data = {0}};
    rc = xtt_handshake_client_start(&bytes_requested, &io_ptr, ctx);
    while (XTT_RETURN_HANDSHAKE_FINISHED != rc)
    {
        switch (rc)
        {
        case XTT_RETURN_WANT_WRITE:
        {
            int write_ret = write(socket, io_ptr, bytes_requested);
            if (write_ret <= 0)
            {
                enftun_log_error("Error sending to server\n");
                return -1;
            }

            rc = xtt_handshake_client_handle_io((uint16_t) write_ret,
                                                0, // 0 bytes read
                                                &bytes_requested, &io_ptr, ctx);

            break;
        }
        case XTT_RETURN_WANT_READ:
        {
            int read_ret = read(socket, io_ptr, bytes_requested);
            if (read_ret <= 0)
            {
                enftun_log_error("Error receiving from server\n");
                return -1;
            }

            rc = xtt_handshake_client_handle_io(0, // 0 bytes written
                                                (uint16_t) read_ret,
                                                &bytes_requested, &io_ptr, ctx);
            break;
        }
        case XTT_RETURN_WANT_PREPARSESERVERATTEST:
        {
            rc = xtt_handshake_client_preparse_serverattest(
                &claimed_root_id, &bytes_requested, &io_ptr, ctx);
            break;
        }
        case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
        {
            struct xtt_server_root_certificate_context* server_cert;
            server_cert = saved_cert;
            if (NULL == server_cert)
            {
                (void) xtt_client_build_error_msg(&bytes_requested, &io_ptr,
                                                  ctx);
                int write_ret = write(socket, io_ptr, bytes_requested);
                if (write_ret > 0)
                {
                }
                return -1;
            }
            rc = xtt_handshake_client_build_idclientattest(
                &bytes_requested, &io_ptr, server_cert, requested_client_id,
                group_ctx, ctx);

            break;
        }
        case XTT_RETURN_WANT_PARSEIDSERVERFINISHED:
        {
            rc = xtt_handshake_client_parse_idserverfinished(&bytes_requested,
                                                             &io_ptr, ctx);
            break;
        }
        case XTT_RETURN_HANDSHAKE_FINISHED:
            break;
        case XTT_RETURN_RECEIVED_ERROR_MSG:
            enftun_log_error("Received error message from server\n");
            return -1;
        default:
            enftun_log_debug(
                "Encountered error during client handshake: %s (%d)\n",
                xtt_strerror(rc), rc);
            unsigned char err_buffer[16];
            (void) xtt_client_build_error_msg(&bytes_requested, &io_ptr, ctx);
            int write_ret = write(socket, err_buffer, bytes_requested);
            if (write_ret > 0)
            {
            }
            return -1;
        }
    }

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc)
    {
        enftun_log_info("Handshake completed successfully!\n");
        return 0;
    }
    else
    {
        return CLIENT_ERROR;
    }
}

static int
save_credentials(struct xtt_client_handshake_context* ctx,
                 const char* longterm_cert_out_file,
                 const char* longterm_private_key_out_file,
                 struct xtt_tpm_context* tpm_ctx)
{
    int write_ret = 0;

    // 1) Get assigned ID
    xtt_identity_type my_assigned_id = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_identity(&my_assigned_id, ctx))
    {
        enftun_log_error("Error getting my assigned client id!\n");
        return 1;
    }

    // 2) Get longterm public key
    xtt_ecdsap256_pub_key my_longterm_key = {.data = {0}};
    if (XTT_RETURN_SUCCESS !=
        xtt_get_my_longterm_key_ecdsap256(&my_longterm_key, ctx))
    {
        enftun_log_error("Error getting longterm key!\n");
        return 1;
    }

    // 3) Save longterm keypair as X509 certificate
    //  and PEM-encoded TPM-loadable private key blob
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH] = {0};
    if (0 != xtt_x509_from_ecdsap256_TPM(&my_longterm_key,
                                         &ctx->longterm_private_key_tpm,
                                         tpm_ctx->tcti_context, &my_assigned_id,
                 cert_buf, sizeof(cert_buf)))
    {
        enftun_log_error("Error creating X509 certificate\n");
        return CERT_CREATION_ERROR;
    }
    write_ret = xtt_save_to_file(cert_buf, sizeof(cert_buf),
                                 longterm_cert_out_file, 0644);
    if (write_ret < 0)
    {
        enftun_log_error("Error saving X509 certificate\n");
        return SAVE_TO_FILE_ERROR;
    }

    if (TSS2_RC_SUCCESS != xtpm_write_key(&ctx->longterm_private_key_tpm,
                                          longterm_private_key_out_file))
    {
        enftun_log_error("Error saving private key blob\n");
        return 1;
    }

    return 0;
}
