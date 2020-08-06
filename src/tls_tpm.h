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

#include "tls.h"
#include <openssl/ui.h>

#ifndef TLS_TPM_H
#define TLS_TPM_H

int
enftun_tls_tpm_use_key(struct enftun_tls* tls, const char* key_file);

int
enftun_tls_tpm_is_tpm_key(const char* key_file);
#endif // TLS_TPM_H
