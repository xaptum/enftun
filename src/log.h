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

#ifndef ENFTUN_LOG_H
#define ENFTUN_LOG_H

void
enftun_log(const char* format, ...);

#define enftun_log_debug(format, ...) enftun_log("<7>" format, ##__VA_ARGS__)
#define enftun_log_info(format, ...)  enftun_log("<6>" format, ##__VA_ARGS__)
#define enftun_log_warn(format, ...)  enftun_log("<4>" format, ##__VA_ARGS__)
#define enftun_log_error(format, ...) enftun_log("<3>" format, ##__VA_ARGS__)

void
enftun_log_ssl(unsigned long err, const char* format, ...);

#define __enftun_log_ssl(format, ...) enftun_log_ssl(ERR_get_error(), format, ##__VA_ARGS__)

#define enftun_log_ssl_debug(format, ...) __enftun_log_ssl("<7>" format, ##__VA_ARGS__)
#define enftun_log_ssl_info(format, ...)  __enftun_log_ssl("<6>" format, ##__VA_ARGS__)
#define enftun_log_ssl_warn(format, ...)  __enftun_log_ssl("<4>" format, ##__VA_ARGS__)
#define enftun_log_ssl_error(format, ...) __enftun_log_ssl("<3>" format, ##__VA_ARGS__)

#endif // ENFTUN_LOG_H
