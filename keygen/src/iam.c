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
#include <curl/curl.h>
#include "iam.h"
#include "auth.h"
#include "curl.h"

static const char *XAP_XIAM_URL = "https://xaptum.io/api/xiam/v1/";
static const char *XIAM_FUNC_EP_AUTH = "endpoints";

/* TODO Factor these functions */
static void ep_copy_json_str(char *dst, json_t *j_str)
{
    char *src = json_string_value(j_str);
    int len = strlen(src);
    strcpy(dst, src);
}

/**
 * ep_auth_marshal() - Create XCR login
 * @auth: The login user and password (key)
 *
 * Returns a JSON object representing the payload of an XCR authentication
 * request with the username and password copied from login.
 *
 * Return: A pointer to the JSON data
 */
json_t *ep_auth_marshal(struct iam_create_endpoint_request*auth)
{
    json_t *new_endpoint_auth = json_object();
    json_t *new_credential = json_object();
    json_t *address_request = json_object();

    json_object_set_new(new_credential, "type", json_string(auth->ecdsa_credential.type));
    json_object_set_new(new_credential, "key", json_string(auth->ecdsa_credential.key));
    json_object_set_new(address_request, "network", json_string(auth->endpoint.network));

    json_object_set_new(new_endpoint_auth, "ecdsa_credential", new_credential);
    json_object_set_new(new_endpoint_auth, "address_request", address_request);

    return new_endpoint_auth;
}

json_t *
iam_send_create_endpoint_request(struct iam_create_endpoint_request*auth, struct xcr_session *sess)
{
    json_t *xcr_proc_auth_resp = NULL;
    struct xcr_auth *auth_resp;
    CURL *curl;
    struct curl_slist *chunk = NULL;
    struct MemoryStruct target;
    char *url;
    CURLcode res;
    json_error_t jerror;


    /* Assemble the URL */
    url = malloc(strlen(XAP_XIAM_URL) + strlen(XIAM_FUNC_EP_AUTH) + 1);
    strcpy(url, XAP_XIAM_URL);
    memcpy(url + strlen(url), XIAM_FUNC_EP_AUTH, strlen(XIAM_FUNC_EP_AUTH) + 1);
    printf("Sending to URL %s\n", url);

    /* Set up a request to send to the API */
    curl = curl_easy_init();
    set_std_curl_opts(curl, chunk, sess, url, json_dumps(ep_auth_marshal(auth), 0));

    /* Send the request and check for errors */
    res = curl_easy_perform(curl);
    if(res == CURLE_OK)
    {
        printf("ENDPOINT RESP\n");
        printf("%s", target.memory);
        /* Process the response into a JSON object */
        //xcr_proc_auth_resp = json_loads(target.memory, 0, &jerror);

        /* Process the JSON object into our data structure */
        //auth_resp = xcr_auth_marshal(xcr_proc_auth_resp);

        /* Copy the token into the session handler */
        //strcpy(session->token, auth_resp->data[0].token);
    }
    else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    /* Clean up */
    curl_easy_cleanup(curl);
    curl_slist_free_all(chunk);

    return auth_resp;
}