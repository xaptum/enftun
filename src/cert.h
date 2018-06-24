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

#ifndef ENFTUN_CERT_H
#define ENFTUN_CERT_H

#include <netinet/in.h>
#include <openssl/x509.h>

int
enftun_cert_common_name_X509(X509 *cert, char* out, size_t out_len);

int
enftun_cert_common_name_file(const char *file, char* out, size_t out_len);

#endif // ENFTUN_CERT_H
