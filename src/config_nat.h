/*
 * Copyright 2018-2021 Xaptum, Inc.
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

#ifndef ENFTUN_CONFIG_NAT_H
#define ENFTUN_CONFIG_NAT_H

void
lookup_nat_rule_list(config_t* cfg,
                     const char* path,
                     struct enftun_nat_rule** value,
                     size_t* len);

#endif
