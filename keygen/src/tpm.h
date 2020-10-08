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

#ifndef _TPM_H
#define _TPM_H
#pragma once

#include <tss2/tss2_tcti.h>

#include <openssl/evp.h>

#include "ssl.h"

int
init_tcti(TSS2_TCTI_CONTEXT **tcti_ctx);

void
free_tcti(TSS2_TCTI_CONTEXT *tcti_ctx);

int
tpm_key_to_pkey(EVP_PKEY **pkey_out, const char *key_filename);

#endif
