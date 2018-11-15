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
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <xtt.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_socket.h>
#include <tss2/tss2_tcti_device.h>

#include "xtt.h"
#include "log.h"
#include "tls.h"

#define TLS_ROOT_CERT_HANDLE 0x1410005
#define XTT_ROOT_CERT_HANDLE 0x1410009

int
enftun_xtt_init(struct enftun_xtt* xtt)
{
    int ret = xtt_crypto_initialize_crypto();
    if (0 != ret) {
        enftun_log_error("Error initializing cryptography library: %d\n", ret);
        return -1;
    }

    xtt->tcti_context_buffer_s_len = 256;
    xtt->tcti_context_buffer_s = malloc(sizeof(unsigned char)*xtt->tcti_context_buffer_s_len);
    xtt->suitespec = "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512";

    return 0;
}

int
enftun_xtt_free(struct enftun_xtt* xtt)
{
    if (xtt->tcti_context_buffer_s)
        free(xtt->tcti_context_buffer_s);
    return 0;
}

static int initialize_tcti(TSS2_TCTI_CONTEXT **tcti_context, xtt_tcti_type tcti_type, const char *dev_file,
                           const char *tpm_hostname_g, const char *tpm_port_g, unsigned char* tcti_context_buffer_s,
                           unsigned int tcti_context_buffer_s_len);

static int connect_to_server(const char *ip, char *port, int mark);

static int initialize_server_id(xtt_identity_type *intended_server_id,
                                TSS2_TCTI_CONTEXT *tcti_context);

static int initialize_certs(TSS2_TCTI_CONTEXT *tcti_context,
                            xtt_certificate_root_id* saved_root_id,
                            struct xtt_server_root_certificate_context* saved_cert,
                            xtt_root_certificate* root_certificate);

static int initialize_daa(struct xtt_client_group_context *group_ctx, TSS2_TCTI_CONTEXT *tcti_context);

static int
read_nvram(unsigned char *out,
           uint16_t length,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context);

static int do_handshake_client(int socket,
                               xtt_identity_type *requested_client_id,
                               xtt_identity_type *intended_server_id,
                               struct xtt_client_group_context *group_ctx,
                               struct xtt_client_handshake_context *ctx,
                               xtt_certificate_root_id *saved_root_id,
                               struct xtt_server_root_certificate_context *saved_cert);

static int save_credentials(struct xtt_client_handshake_context *ctx,
                            const char* longterm_cert_out_file,
                            const char* longterm_private_key_out_file);

static int read_tls_root_cert(TSS2_TCTI_CONTEXT *tcti_context, const char* ca_cert_file);

int
enftun_xtt_handshake(const char *server_ip,
                     const char *server_port,
                     int mark,
                     const char *tcti,
                     const char *dev_file,
                     const char *longterm_cert_out_file,
                     const char *longterm_private_key_out_file,
                     const char *tpm_hostname_g,
                     const char *tpm_port_g,
                     const char *ca_cert_file,
                     struct enftun_xtt* xtt)
{
    int init_daa_ret = -1;
    int socket = -1;
    int ret = 0;

    xtt_certificate_root_id saved_root_id = {.data = {0}};
    struct xtt_server_root_certificate_context saved_cert;

    setbuf(stdout, NULL);

    xtt_identity_type requested_client_id = {.data = {0}};
    requested_client_id = xtt_null_identity;

    //Set suite spec from command line args
    xtt_suite_spec suite_spec = 0;
    if (0 == strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512;
    } else if (0 == strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_BLAKE2B;
    } else if (0 == strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_SHA512")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_SHA512;
    } else if (0 == strcmp(xtt->suitespec, "X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B")) {
        suite_spec = XTT_X25519_LRSW_ECDSAP256_AES256GCM_BLAKE2B;
    } else {
        enftun_log_error("Unknown suite_spec '%s'\n", xtt->suitespec);
        exit(1);
    }

    //Set TCTI from command line args
    xtt_tcti_type tcti_type;
    if (0 == strcmp(tcti, "device")) {
        tcti_type = XTT_TCTI_DEVICE;
    } else if (0 == strcmp(tcti, "socket")) {
        tcti_type = XTT_TCTI_SOCKET;
    } else {
        enftun_log_error("Unknown tcti_type '%s'\n", tcti);
        exit(1);
    }

    //Set TCTI device file from command line args
    if(NULL == dev_file && tcti_type == XTT_TCTI_DEVICE)
    {
        enftun_log_error("Not given a device file for TCTI\n");
        exit(1);
    }

    // 1) Setup the needed XTT contexts (from files).
    // 1i) Setup TPM TCTI
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    int init_tcti_ret = 0;
    init_tcti_ret = initialize_tcti(&tcti_context, tcti_type, dev_file, tpm_hostname_g, tpm_port_g, xtt->tcti_context_buffer_s, xtt->tcti_context_buffer_s_len);
    if (0 != init_tcti_ret) {
        enftun_log_error("Error initializing TPM TCTI context\n");
        goto finish;
    }

    ret = read_tls_root_cert(tcti_context, ca_cert_file);
    if (0 != ret) {
        goto finish;
    }

    // 1ii) Initialize DAA
    struct xtt_client_group_context group_ctx;
    init_daa_ret = initialize_daa(&group_ctx, tcti_context);
    ret = init_daa_ret;
    if (0 != init_daa_ret) {
        enftun_log_error("Error initializing DAA context\n");
        goto finish;
    }
    // 1iii) Initialize Certificates
    xtt_root_certificate root_certificate;
    ret = initialize_certs(tcti_context, &saved_root_id, &saved_cert, &root_certificate);
    if (0 != ret) {
        enftun_log_error("Error initializing server/root certificate contexts\n");
        goto finish;
    }

    // 2) Set the intended server id.
    xtt_identity_type intended_server_id = {.data = {0}};
    ret = initialize_server_id(&intended_server_id, tcti_context);
    if(0 != ret) {
        enftun_log_error("Error setting XTT server ID!\n");
        goto finish;
    }

    // 3) Make TCP connection to server.
    enftun_log_info("Connecting to server at %s:%s ...\n", server_ip, server_port);
    socket = connect_to_server(server_ip, (char*)server_port, mark);
    if (socket < 0) {
        ret = 1;
        goto finish;
    }

    // 4) Initialize XTT handshake context
    // (will be populated with useful information after a successful handshake).
    enftun_log_debug("Using suite_spec = %d\n", suite_spec);
    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH] = {0};
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH] = {0};
    struct xtt_client_handshake_context ctx;
    xtt_return_code_type rc = xtt_initialize_client_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer), XTT_VERSION_ONE, suite_spec);
    if (XTT_RETURN_SUCCESS != rc) {
        ret = 1;
        enftun_log_error("Error initializing client handshake context: %d\n", rc);
        goto finish;
    }

    // 5) Run the identity-provisioning handshake with the server.
    ret = do_handshake_client(socket,
                              &requested_client_id,
                              &intended_server_id,
                              &group_ctx,
                              &ctx,
                              &saved_root_id,
                              &saved_cert);
    if (0 == ret) {
    // 6) Save the results (what we and the server now agree on post-handshake)
        ret = save_credentials(&ctx, longterm_cert_out_file, longterm_private_key_out_file);
        if (0 != ret)
            goto finish;
    } else {
        enftun_log_error("Handshake failed!\n");
        goto finish;
    }

finish:
    if (socket > 0)
        close(socket);
    if (0==init_tcti_ret) {
        tss2_tcti_finalize(tcti_context);
    }
    if (0 == ret) {
        return 0;
    } else {
        return 1;
    }
}

static int read_tls_root_cert(TSS2_TCTI_CONTEXT *tcti_context, const char* ca_cert_file)
{
    //read in TLS root cert from TPM
    unsigned char tls_root_cert[461];
    int nvram_ret = read_nvram(tls_root_cert,
                               461,
                               TLS_ROOT_CERT_HANDLE,
                               tcti_context);
    if (0 != nvram_ret) {
        fprintf(stderr, "Error reading tls root from TPM NVRAM\n");
        return TPM_ERROR;
    }
    //write TLS root cert to ca_cert_file
    int ret = xtt_save_to_file(tls_root_cert, 461, ca_cert_file);
    if (ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}


static
int connect_to_server(const char *server_host, char *port, int mark)
{
    struct addrinfo *serverinfo;
    struct addrinfo hints = {.ai_protocol = IPPROTO_TCP};

    if (0 != getaddrinfo(server_host, port, &hints, &serverinfo)) {
        enftun_log_error("Error resolving server host '%s:%s'\n", server_host, port);
        return -1;
    }

    struct addrinfo *addr = NULL;
    int sock_ret = -1;
    for (addr=serverinfo; addr!=NULL; addr=addr->ai_next) {
        sock_ret = socket(addr->ai_family, SOCK_STREAM, addr->ai_protocol);
        if (sock_ret == -1) {
            enftun_log_debug("Error opening client socket, trying next address\n");
            continue;
        }

        if (mark > 0)
        {
            if (setsockopt(sock_ret, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
            {
                enftun_log_debug("Failed to set mark %d: %s\n", mark, strerror(errno));
                close(sock_ret);
                continue;
            }
        }


        if (connect(sock_ret, addr->ai_addr, addr->ai_addrlen) < 0) {
            enftun_log_debug("Error connecting to server, trying next address\n");
            close(sock_ret);
            continue;
        }

        break;
    }

    freeaddrinfo(serverinfo);

    if (NULL == addr) {
        enftun_log_error("Unable to connect to server\n");
        return -1;
    }

    return sock_ret;
}

int initialize_tcti(TSS2_TCTI_CONTEXT **tcti_context, xtt_tcti_type tcti_type, const char *dev_file, const char *tpm_hostname_g,
                    const char *tpm_port_g, unsigned char* tcti_context_buffer_s, unsigned int tcti_context_buffer_s_len)
{
    *tcti_context = (TSS2_TCTI_CONTEXT*)tcti_context_buffer_s;
    switch (tcti_type) {
        case XTT_TCTI_SOCKET:
            assert(tss2_tcti_getsize_socket() < tcti_context_buffer_s_len);
            if (TSS2_RC_SUCCESS != tss2_tcti_init_socket(tpm_hostname_g, tpm_port_g, *tcti_context)) {
                enftun_log_error("Error: Unable to initialize socket TCTI context\n");
                return TPM_ERROR;
            }
            break;
        case XTT_TCTI_DEVICE:
            assert(tss2_tcti_getsize_device() < tcti_context_buffer_s_len);
            if (TSS2_RC_SUCCESS != tss2_tcti_init_device(dev_file, strlen(dev_file), *tcti_context)) {
                enftun_log_error("Error: Unable to initialize device TCTI context\n");
                return TPM_ERROR;
            }
            break;
    }

    return 0;
}

static
int initialize_server_id(xtt_identity_type *intended_server_id,
                         TSS2_TCTI_CONTEXT *tcti_context)
{
    // Set server's id from file/NVRAM
    int nvram_ret = 0;
    nvram_ret = read_nvram(intended_server_id->data,
                           sizeof(xtt_identity_type),
                           XTT_SERVER_ID_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error( "Error reading server id from TPM NVRAM\n");
        return TPM_ERROR;
    }

    return 0;
}

static
int initialize_daa(struct xtt_client_group_context *group_ctx, TSS2_TCTI_CONTEXT *tcti_context)
{
    xtt_return_code_type rc = 0;

    // 1) Read DAA-related things in from file/TPM-NVRAM
    xtt_daa_group_pub_key_lrsw gpk = {.data = {0}};
    xtt_daa_credential_lrsw cred = {.data = {0}};
    unsigned char basename[1024] = {0};
    uint16_t basename_len = 0;
    int nvram_ret = 0;
    uint8_t basename_len_from_tpm = 0;
    nvram_ret = read_nvram((unsigned char*)&basename_len_from_tpm,
                           1,
                           XTT_BASENAME_SIZE_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error( "Error reading basename size from TPM NVRAM\n");
        return TPM_ERROR;
    }
    basename_len = basename_len_from_tpm;
    nvram_ret = read_nvram(basename,
                           basename_len,
                           XTT_BASENAME_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error("Error reading basename from TPM NVRAM\n");
        return TPM_ERROR;
    }

    nvram_ret = read_nvram(gpk.data,
                           sizeof(xtt_daa_group_pub_key_lrsw),
                           XTT_GPK_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error("Error reading GPK from TPM NVRAM\n");
        return TPM_ERROR;
    }

    nvram_ret = read_nvram(cred.data,
                           sizeof(xtt_daa_credential_lrsw),
                           XTT_CRED_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error("Error reading credential from TPM NVRAM\n");
        return TPM_ERROR;
    }

    // 2) Generate gid from gpk (gid = SHA-256(gpk | basename))
    xtt_group_id gid = {.data = {0}};

    crypto_hash_sha256_state hash_state;
    int hash_ret = crypto_hash_sha256_init(&hash_state);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, gpk.data, sizeof(gpk));
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_update(&hash_state, basename, basename_len);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;
    hash_ret = crypto_hash_sha256_final(&hash_state, gid.data);
    if (0 != hash_ret)
        return CRYPTO_HASH_ERROR;

    // 3) Initialize DAA context using the above information
    rc = xtt_initialize_client_group_context_lrswTPM(group_ctx,
                                                     &gid,
                                                     &cred,
                                                     (unsigned char*)basename,
                                                     basename_len,
                                                     XTT_KEY_HANDLE,
                                                     NULL,
                                                     0,
                                                     tcti_context);

    return rc;
}

static
int initialize_certs(TSS2_TCTI_CONTEXT *tcti_context,
                     xtt_certificate_root_id* saved_root_id,
                     struct xtt_server_root_certificate_context* saved_cert,
                     xtt_root_certificate* root_certificate)
{
    xtt_return_code_type rc = 0;
    // 1) Read root id ang pubkey in from buffer
    xtt_certificate_root_id root_id = {.data = {0}};
    xtt_ecdsap256_pub_key root_public_key = {.data = {0}};

    int nvram_ret;
    nvram_ret = read_nvram(root_certificate->data,
                           sizeof(xtt_root_certificate),
                           XTT_ROOT_CERT_HANDLE,
                           tcti_context);
    if (0 != nvram_ret) {
        enftun_log_error("Error reading root's certificate from TPM NVRAM\n");
        return TPM_ERROR;
    }

    // 2) Initialize stored data
    xtt_deserialize_root_certificate(&root_public_key, &root_id, root_certificate);

    memcpy(saved_root_id, root_id.data, sizeof(xtt_certificate_root_id));
    rc = xtt_initialize_server_root_certificate_context_ecdsap256(saved_cert,
                                                                  &root_id,
                                                                  &root_public_key);
    if (XTT_RETURN_SUCCESS != rc)
        return CLIENT_ERROR;

    return 0;
}

static
int do_handshake_client(int socket,
                        xtt_identity_type *requested_client_id,
                        xtt_identity_type *intended_server_id,
                        struct xtt_client_group_context *group_ctx,
                        struct xtt_client_handshake_context *ctx,
                        xtt_certificate_root_id* saved_root_id,
                        struct xtt_server_root_certificate_context *saved_cert)
{
    xtt_return_code_type rc = XTT_RETURN_SUCCESS;
    (void) saved_root_id;

    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;
    xtt_certificate_root_id claimed_root_id = {.data = {0}};
    rc = xtt_handshake_client_start(&bytes_requested,
                                    &io_ptr,
                                    ctx);
    while (XTT_RETURN_HANDSHAKE_FINISHED != rc) {
        switch (rc) {
            case XTT_RETURN_WANT_WRITE:
                {
                    int write_ret = write(socket, io_ptr, bytes_requested);
                    if (write_ret <= 0) {
                        enftun_log_error("Error sending to server\n");
                        return -1;
                    }

                    rc = xtt_handshake_client_handle_io((uint16_t)write_ret,
                                                        0,  // 0 bytes read
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        ctx);

                    break;
                }
            case XTT_RETURN_WANT_READ:
                {
                    int read_ret = read(socket, io_ptr, bytes_requested);
                    if (read_ret <= 0) {
                        enftun_log_error("Error receiving from server\n");
                        return -1;
                    }

                    rc = xtt_handshake_client_handle_io(0,  // 0 bytes written
                                                        (uint16_t)read_ret,
                                                        &bytes_requested,
                                                        &io_ptr,
                                                        ctx);
                    break;
                }
            case XTT_RETURN_WANT_PREPARSESERVERATTEST:
                {
                    rc = xtt_handshake_client_preparse_serverattest(&claimed_root_id,
                                                                    &bytes_requested,
                                                                    &io_ptr,
                                                                    ctx);
                    break;
                }
            case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
                {
                    struct xtt_server_root_certificate_context *server_cert;
                    server_cert = saved_cert;
                    if (NULL == server_cert) {
                        (void)xtt_client_build_error_msg(&bytes_requested, &io_ptr, ctx);
                        int write_ret = write(socket, io_ptr, bytes_requested);
                        if (write_ret > 0) {
                        }
                        return -1;
                    }
                    rc = xtt_handshake_client_build_idclientattest(&bytes_requested,
                                                                   &io_ptr,
                                                                   server_cert,
                                                                   requested_client_id,
                                                                   intended_server_id,
                                                                   group_ctx,
                                                                   ctx);

                    break;
                }
            case XTT_RETURN_WANT_PARSEIDSERVERFINISHED:
                {
                    rc = xtt_handshake_client_parse_idserverfinished(&bytes_requested,
                                                                     &io_ptr,
                                                                     ctx);
                    break;
                }
            case XTT_RETURN_HANDSHAKE_FINISHED:
                break;
            case XTT_RETURN_RECEIVED_ERROR_MSG:
                enftun_log_error("Received error message from server\n");
                return -1;
            default:
                enftun_log_debug("Encountered error during client handshake: %s (%d)\n", xtt_strerror(rc), rc);
                unsigned char err_buffer[16];
                (void)xtt_client_build_error_msg(&bytes_requested, &io_ptr, ctx);
                int write_ret = write(socket, err_buffer, bytes_requested);
                if (write_ret > 0) {
                }
                return -1;
        }
    }

    if (XTT_RETURN_HANDSHAKE_FINISHED == rc) {
        enftun_log_info("Handshake completed successfully!\n");
        return 0;
    } else {
        return CLIENT_ERROR;
    }
}

static
int save_credentials(struct xtt_client_handshake_context *ctx,
                     const char* longterm_cert_out_file,
                     const char* longterm_private_key_out_file)
{
    int write_ret = 0;

    // 1) Get assigned ID
    xtt_identity_type my_assigned_id = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_identity(&my_assigned_id, ctx)) {
        enftun_log_error("Error getting my assigned client id!\n");
        return 1;
    }

    // 2) Get longterm keypair
    xtt_ecdsap256_pub_key my_longterm_key = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_key_ecdsap256(&my_longterm_key, ctx)) {
        enftun_log_error("Error getting longterm key!\n");
        return 1;
    }

    xtt_ecdsap256_priv_key my_longterm_private_key = {.data = {0}};
    if (XTT_RETURN_SUCCESS != xtt_get_my_longterm_private_key_ecdsap256(&my_longterm_private_key, ctx)) {
        enftun_log_error("Error getting longterm private key!\n");
        return 1;
    }

    // 3) Save longterm keypair as X509 certificate and ASN.1-encoded private key
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH] = {0};
    if (0 != xtt_x509_from_ecdsap256_keypair(&my_longterm_key, &my_longterm_private_key, &my_assigned_id, cert_buf, sizeof(cert_buf))) {
        enftun_log_error("Error creating X509 certificate\n");
        return CERT_CREATION_ERROR;
    }
    write_ret = xtt_save_to_file(cert_buf, sizeof(cert_buf), longterm_cert_out_file);
    if(write_ret < 0){
        return SAVE_TO_FILE_ERROR;
    }

    unsigned char asn1_priv_buf[XTT_ASN1_PRIVATE_KEY_LENGTH] = {0};
    if (0 != xtt_asn1_from_ecdsap256_private_key(&my_longterm_private_key, &my_longterm_key, asn1_priv_buf, sizeof(asn1_priv_buf))) {
        enftun_log_error("Error creating ASN.1 private key\n");
        return 1;
    }
    write_ret = xtt_save_to_file(asn1_priv_buf, sizeof(asn1_priv_buf), longterm_private_key_out_file);
    if(write_ret < 0) {
        return SAVE_TO_FILE_ERROR;
    }

    return 0;
}

static int
read_nvram(unsigned char *out,
           uint16_t size,
           TPM_HANDLE index,
           TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_RC ret = TSS2_RC_SUCCESS;

    size_t sapi_ctx_size = Tss2_Sys_GetContextSize(0);
    TSS2_SYS_CONTEXT *sapi_context = malloc(sapi_ctx_size);
    if (NULL == sapi_context) {
        enftun_log_error("Error allocating memory for TPM SAPI context\n");
        return TPM_ERROR;
    }

    TSS2_ABI_VERSION abi_version = TSS2_ABI_CURRENT_VERSION;
    ret = Tss2_Sys_Initialize(sapi_context,
                              sapi_ctx_size,
                              tcti_context,
                              &abi_version);
    if (TSS2_RC_SUCCESS != ret) {
        enftun_log_error("Error initializing TPM SAPI context\n");
        goto finish;
    }

    TPMS_AUTH_COMMAND session_data = {
        .sessionHandle = TPM_RS_PW,
        .sessionAttributes = {0},
    };
    TPMS_AUTH_RESPONSE sessionDataOut = {{0}, {0}, {0}};
    (void)sessionDataOut;
    TSS2_SYS_CMD_AUTHS sessionsData;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &session_data;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsData.cmdAuths = &sessionDataArray[0];
    sessionsDataOut.rspAuthsCount = 1;
    sessionsData.cmdAuthsCount = 1;
    sessionsData.cmdAuths[0] = &session_data;

    uint16_t data_offset = 0;

    while (size > 0) {
        uint16_t bytes_to_read = size;

        TPM2B_MAX_NV_BUFFER nv_data = {.size=0};

        ret = Tss2_Sys_NV_Read(sapi_context,
                               index,
                               index,
                               &sessionsData,
                               bytes_to_read,
                               data_offset,
                               &nv_data,
                               &sessionsDataOut);

        if (ret != TSS2_RC_SUCCESS) {
            enftun_log_error("Error reading from NVRAM\n");
            goto finish;
        }

        size -= nv_data.size;

        memcpy(out + data_offset, nv_data.buffer, nv_data.size);
        data_offset += nv_data.size;
    }

finish:
    Tss2_Sys_Finalize(sapi_context);
    free(sapi_context);

    if (ret == TSS2_RC_SUCCESS) {
        return 0;
    } else {
        return TPM_ERROR;
    }
}
