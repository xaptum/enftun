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

#ifndef ENFTUN_SCM_H
#define ENFTUN_SCM_H

#include "tcp.h"

struct enftun_tcp_scm
{
    struct enftun_tcp base;
};

void
enftun_tcp_scm_init(struct enftun_tcp_scm* scm);

int
enftun_tcp_scm_connect(struct enftun_tcp* scm,
                       const char* host,
                       const char* port);

#endif
