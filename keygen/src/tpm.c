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

#include "tpm.h"

static ENGINE*
enftun_tls_tpm_engine_init()
{
    ENGINE* eng                = NULL;
    const char* engine_names[] = {"tpm2tss", "tpm2"};
    size_t engine_index;

    /* Init the engine */
    ENGINE_load_builtin_engines();

    for (engine_index = 0;
         engine_index < sizeof(engine_names) / sizeof(engine_names[0]);
         engine_index++)
    {
        eng = ENGINE_by_id(engine_names[engine_index]);
        if (eng)
        {
            enftun_log_info("INFO: Using engine %s\n",
                            engine_names[engine_index]);
            break;
        }
    }
    if (!eng)
    {
        enftun_log_error("Could not find a TSS engine\n");
        goto out;
    }

    if (!ENGINE_init(eng))
    {
        enftun_log_ssl_error("Could not init engine %s",
                             engine_names[engine_index]);
        ENGINE_free(eng);
        goto out;
    }

    if (!ENGINE_set_default_RAND(eng))
    {
        enftun_log_ssl_error("Could not set %s as default RAND engine",
                             engine_names[engine_index]);
    }

out:
    return eng;
}

/* Define a boilerplate passthrough UI where all writes will be populated with
 * user_data unless user_data is NULL.  On user_data==NULL the default UI
 * will be used.
 */
static int
enftun_tls_tpm_ui_open(UI* ui)
{
    return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int
enftun_tls_tpm_ui_read(UI* ui, UI_STRING* uis)
{
    const char* password;
    int string_type;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
        UI_get0_user_data(ui))
    {
        string_type = UI_get_string_type(uis);
        if (string_type == UIT_PROMPT || string_type == UIT_VERIFY)
        {
            password = (const char*) UI_get0_user_data(ui);
            if (password)
            {
                UI_set_result(ui, uis, password);
                return 1;
            }
        }
    }
    return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int
enftun_tls_tpm_ui_write(UI* ui, UI_STRING* uis)
{
    const char* password;
    int string_type;

    if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD &&
        UI_get0_user_data(ui))
    {
        string_type = UI_get_string_type(uis);
        if (string_type == UIT_PROMPT || string_type == UIT_VERIFY)
        {
            password = (const char*) UI_get0_user_data(ui);
            if (password && password[0] != '\0')
                return 1;
        }
    }
    return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int
enftun_tls_tpm_ui_close(UI* ui)
{
    return UI_method_get_closer(UI_OpenSSL())(ui);
}

static UI_METHOD*
enftun_tls_tpm_ssl_ui_passthrough(void)
{
    UI_METHOD* ui_method = NULL;

    ui_method = UI_create_method("Static password UI");

    UI_method_set_opener(ui_method, enftun_tls_tpm_ui_open);
    UI_method_set_reader(ui_method, enftun_tls_tpm_ui_read);
    UI_method_set_writer(ui_method, enftun_tls_tpm_ui_write);
    UI_method_set_closer(ui_method, enftun_tls_tpm_ui_close);

    return ui_method;
}

int
tpm_key_to_pkey(EVP_PKEY **pkey_out, const char *key_filename)
{
    int ret = 1;

    ENGINE* e = enftun_tls_tpm_engine_init();
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
init_tcti(TSS2_TCTI_CONTEXT **tcti_ctx)
{
    size_t ctx_size;
    if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(NULL, &ctx_size, NULL))
        return 0;

    *tcti_ctx = calloc(ctx_size, 1);
    if (NULL == tcti_ctx)
        return 0;

    // Nb. NULL means to use default device
    if (TSS2_RC_SUCCESS != Tss2_Tcti_Device_Init(*tcti_ctx, &ctx_size, NULL))
        return 0;

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
