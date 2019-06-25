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

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

#include <openssl/err.h>

void
enftun_log(const char* format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    vfprintf(stderr, format, arglist);
    va_end(arglist);
}

void
enftun_log_ssl(unsigned long err, const char* format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    enftun_log(format, arglist);
    va_end(arglist);

    enftun_log("%d:%s:%s:%s\n", err, ERR_lib_error_string(err),
               ERR_func_error_string(err), ERR_reason_error_string(err));
}
