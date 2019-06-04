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

#ifndef ENFTUN_TCP_H
#define ENFTUN_TCP_H

struct enftun_tcp
{
    int fd; // file descriptor for the underlying TCP socket
    struct addrinfo local_addr;
};


int
enftun_tcp_connect(struct enftun_tcp* tcp,
                   int mark, const char* host, const char *port);

int
enftun_tcp_connect_any(struct enftun_tcp* tcp,
                       int mark,
                       const char** hosts, const char *port);

void
enftun_tcp_close(struct enftun_tcp* tcp);

#endif
