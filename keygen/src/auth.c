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

#include <string.h>
#include <jansson.h>
#include "auth.h"
#include "curl.h"
#include "json_tools.h"

#ifndef XAP_AUTH_URL
#define XAP_AUTH_URL "https://xaptum.io/api/xcr/v2/"
#endif

static const char * AUTH_XAUTH_URL = XAP_AUTH_URL "xauth";
/**
 * auth_login_marshal() - Create AUTH login
 * @login: The login user and password (key)
 *
 * Returns a JSON object representing the payload of an AUTH authentication
 * request with the username and password copied from login.
 *
 * Return: A pointer to the JSON data
 */
char *auth_login_marshal(struct auth_login *login)
{
    json_t *root = json_object();
    int ret = 0;
    char *ret_str = NULL;

    ret |= json_object_set_new(root, "username", json_string(login->username));
    ret |= json_object_set_new(root, "token", json_string(login->password));

    /* If any of the set operations failed, abort */
    if (ret == -1)
        goto out;

    /* Generate a string from the json object */
    ret_str = json_dumps(root, 0);

out:
    json_decref(root);
    return ret_str;
}

/**
 * auth_login_json_destroy() - Create AUTH login
 * @login: The json login request to free
 *
 * Return: None
 */
void auth_login_json_destroy(json_t *login)
{
    json_decref(login);
}

/**
 * auth_resp_unmarshal() - Process AUTH auth response.
 * @auth: A JSON string containing AUTHs authorization response
 * @resp: The memory to write the response into
 *
 * Marshals AUTH's Authentication JSON into struct auth_auth.
 * The returned structure data must be destroyted with auth_resp_destroy
 *
 * Return: 1 on success, 0 on failure
 */
static int auth_resp_unmarshal(char *auth, struct auth_resp * resp)
{
    json_error_t jerror;
    json_t *root;
    json_t *data;
    json_t *page;
    int ret = 0;

    /* Zero out the return struct to make bad input distinct from allocated pointers on error */
    memset(resp, 0, sizeof(*resp));

    /* Process the main elements */
    root = json_loads(auth, 0, &jerror);
    data = json_array_get(json_object_get(root, "data"), 0);
    page = json_object_get(root, "page");

    if (!root) {
        fprintf(stderr, "%s ERR: Could not parse JSON string error %s",
                __func__, jerror.text);
       goto cleanup_err;
    } else if (!data || !page) {
        fprintf(stderr, "%s missing data or page. This usually means an error was returned by the API.", __func__);
        goto cleanup_err;
    }

    resp->data = malloc(sizeof(*resp->data));
    resp->page = malloc(sizeof(*resp->page));
    if(!resp->data || !resp->page)
        goto cleanup_err;

    resp->data_cnt = 1;

    /* Extract the json elements in data */
    copy_json_str(resp->data->username, json_object_get(data, "username"), sizeof(resp->data->username));
    copy_json_str(resp->data->token, json_object_get(data, "token"), sizeof(resp->data->token));
    resp->data->user_id = json_integer_value(json_object_get(data, "user_id"));
    copy_json_str(resp->data->type, json_object_get(data, "type"), sizeof(resp->data->type));
    resp->data->domain_id = json_integer_value(json_object_get(data, "domain_id"));
    copy_json_str(resp->data->domain_network, json_object_get(data, "domain_network"), sizeof(resp->data->domain_network));

    /* Extract the page data */
    resp->page->curr = json_integer_value(json_object_get(page, "curr"));
    resp->page->next = json_integer_value(json_object_get(page, "next"));
    resp->page->prev = json_integer_value(json_object_get(page, "prev"));

    /* Success */
    ret = 1;
    goto out;

cleanup_err:
    ret = 0;
    free(resp->data);
    free(resp->page);
out:
    if(root)
        json_decref(root);
    return ret;
}

/**
 * auth_resp_destroy() - Destroy an auth_resp structure
 * @auth: The object to be destroyed
 *
 * Return: None
 */
void auth_resp_destroy(struct auth_resp *auth)
{
    if (auth) {
        free(auth->data);
        free(auth->page);
    }
}

/**
 * auth_login_destroy() - Destroy an auth_login structure
 * @login: The object to be destroyed
 *
 * Return: None
 */
void auth_login_destroy(struct auth_login *login)
{
    if (login) {
        free(login->username);
        free(login->password);
    }
}

/**
 * auth_send_login() - Send an Auth request to AUTH
 * @req: The credentials to log in with
 * @creds: The credentials to return from the API call
 *
 * Log in to AUTH and populates creds with the return information.
 * @creds does not need to be freed with any special functions.
 *
 * Return: 1 on success, 0 on failure
 */
int auth_send_login(struct auth_login *req, struct auth_credentials *creds)
{
    struct enftun_req api_req = {0};
    char *post_text = NULL;
    char *response_text = NULL;
    int ret = 1;

    /* Prepare the request */
    enftun_curl_init(&api_req);
    post_text = auth_login_marshal(req);
    if (!post_text) {
        fprintf(stderr, "%s Coult not parse request JSON\n", __func__);
        goto cleanup;
    }

    /* Send the request */
    response_text = enftun_curl_send(&api_req, AUTH_XAUTH_URL, post_text);

    if (response_text) {
        struct auth_resp resp = {0};
        ret = auth_resp_unmarshal(response_text, &resp);

        if (ret) {
            memcpy(creds, resp.data, sizeof(*creds));
            auth_resp_destroy(&resp);
        } else {
            fprintf(stderr, "%s unable to marshal response: %s\n", __func__,
                    response_text);
            ret = 0;
        }
    } else {
        ret = 0;
        fprintf(stderr, "%s No response received\n", __func__);
    }

cleanup:
    free(response_text);
    free(post_text);
    enftun_curl_destroy(&api_req);
    return ret;
}