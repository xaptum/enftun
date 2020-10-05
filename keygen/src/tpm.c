#ifdef KEYGEN_USE_TPM

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/ui.h>

#include <tss2/tss2_tcti_mssim.h>
#include <tss2/tss2_tcti_device.h>

#include "enftun/log.h"
#include "enftun/tls_tpm.h"

#include "tpm.h"

int
tpm_key_to_pkey(EVP_PKEY **pkey_out, const char *key_filename,
                const char* tcti,
                const char* device,
                const char* socket_host,
                const char* socket_port)
{
    int ret = 1;

    ENGINE* e = enftun_tls_tpm_engine_init(tcti, device, socket_host, socket_port);
    if (!e)
    {
        enftun_log_error("Failed to load engine tpm2tss");
        ret = 0;
        goto out;
    }

    UI_METHOD* meth = enftun_tls_tpm_ssl_ui_passthrough();
    if (!meth)
    {
        enftun_log_error("Failed to load passthrough UI");
        ret = 0;
        goto cleanup_engine;
    }

    *pkey_out = ENGINE_load_private_key(e, key_filename, meth, "");
    if (!*pkey_out)
    {
        enftun_log_ssl_error("Failed to load TSS2 key from file %s", key_filename);
        ret = 0;
        goto cleanup_method;
    }

cleanup_method:
    if (meth)
        UI_destroy_method(meth);
cleanup_engine:
    ENGINE_finish(e);
    ENGINE_free(e);
out:
    return ret;
}

int
init_tcti(TSS2_TCTI_CONTEXT **tcti_ctx,
          const char* tcti,
          const char* device,
          const char* socket_host,
          const char* socket_port)
{
    if (0 == strcmp(tcti, "device"))
    {
        size_t tcti_ctx_size;
        if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(NULL, &tcti_ctx_size, device)) {
            return 0;
        }
        *tcti_ctx = calloc(tcti_ctx_size, 1);
        if (NULL == tcti_ctx)
            return 0;

        if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(*tcti_ctx, &tcti_ctx_size, device)) {
            return 0;
        }
    }
    else if (0 == strcmp(tcti, "socket"))
    {
        size_t tcti_ctx_size;
        char config_string[64];
        size_t ret = snprintf(config_string, sizeof(config_string), "host=%s,port=%s", socket_host, socket_port);
        if (ret >= sizeof(config_string)) {
            return 0;
        }
        if (TSS2_RC_SUCCESS != Tss2_Tcti_Mssim_Init(NULL, &tcti_ctx_size, config_string)) {
            return 0;
        }
        *tcti_ctx = calloc(tcti_ctx_size, 1);
        if (NULL == tcti_ctx)
            return 0;

        if (TSS2_RC_SUCCESS != Tss2_Tcti_Mssim_Init(*tcti_ctx, &tcti_ctx_size, config_string)) {
            return 0;
        }
    }

    return 1;
}

void
free_tcti(TSS2_TCTI_CONTEXT *tcti_ctx)
{
    if (tcti_ctx) {
        Tss2_Tcti_Finalize(tcti_ctx);
        free(tcti_ctx);
    }
}

#endif
