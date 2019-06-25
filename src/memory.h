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

#ifndef ENFTUN_MEM_H
#define ENFTUN_MEM_H

#include <string.h>

/*
 * Clear a struct.
 *
 * This could be optimized away. Do not use to clear secrets.
 */
#define CLEAR(s) memset(&(s), 0, sizeof(s))

#endif // ENFTUN_MEM_H
