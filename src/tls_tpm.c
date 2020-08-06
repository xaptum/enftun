/*
 * Copyright 2020 Xaptum, Inc.
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

#include "tls_tpm.h"
#include "log.h"
#include "tls.h"
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/ui.h>
#include <stdio.h>
#include <string.h>

/* Forward declarations */
static UI_METHOD*
enftun_tls_tpm_ssl_ui_passthrough(void);

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
            enftun_log_info("INFO: Using engine %s",
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

int
enftun_tls_tpm_use_key(struct enftun_tls* tls, const char* key_file)
{
    ENGINE* e;
    EVP_PKEY* key   = NULL;
    UI_METHOD* meth = NULL;
    int ret         = 0;

    /* Only continue if the key is a TSS key */
    if (!enftun_tls_tpm_is_tpm_key(key_file))
    {
        goto out;
    }
/* Having XTT enabled causes library conflicts due to xaptum-tpm */
#ifdef USE_XTT
    enftun_log_error("TPM key not supported when XTT is enabled.");
    goto out;
#endif

    e = enftun_tls_tpm_engine_init();
    if (!e)
    {
        enftun_log_error("Failed to load engine tpm2tss");
        goto out;
    }

    meth = enftun_tls_tpm_ssl_ui_passthrough();
    if (!meth)
    {
        enftun_log_error("Failed to load passthrough UI");
        goto cleanup_engine;
    }

    key = ENGINE_load_private_key(e, key_file, meth, "");
    if (!key)
    {
        enftun_log_ssl_error("Failed to load TSS2 key from file %s", key_file);
        goto cleanup_method;
    }

    if (!SSL_CTX_use_PrivateKey(tls->ctx, key))
    {
        enftun_log_ssl_error("Failed to apply client TSS key %s:", key_file);
        goto free_key;
    }

    /* Success */
    ret = 1;

free_key:
    EVP_PKEY_free(key);
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
enftun_tls_tpm_is_tpm_key(const char* key_file)
{
    FILE* f;
    char buf[256];
    int ret = 0;

    f = fopen(key_file, "r");

    if (f)
    {
        buf[255] = 0;
        while (fgets(buf, 255, f))
        {
            if (!strcmp(buf, "-----BEGIN TSS2 KEY BLOB-----\n") ||
                !strcmp(buf, "-----BEGIN TSS2 PRIVATE KEY-----\n"))
            {
                ret = 1;
                break;
            }
        }
        fclose(f);
    }

    return ret;
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
