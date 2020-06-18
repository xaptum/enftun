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

#ifndef _AUTH_H
#define _AUTH_H

#include <jansson.h>

struct auth_login {
    char *username;
    char *password;
};

struct auth_credentials {
    char username[255];
    char token[255];
    json_int_t user_id;
    char type[255];
    json_int_t domain_id;
    char domain_network[255];
};

struct auth_page {
    json_int_t curr;
    json_int_t next;
    json_int_t prev;
};

struct auth_resp {
    struct auth_credentials *data;
    int data_cnt;
    struct auth_page *page;
};

int
auth_send_login(struct auth_login *req, struct auth_credentials *creds);
void
auth_resp_destroy(struct auth_resp *auth);
void auth_login_destroy(struct auth_login *login);

#endif // ENFTUN_XCR_COMM_H
