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
#include <arpa/inet.h>
#include "iam.h"
#include "curl.h"
#include "json_tools.h"

#ifndef XAP_XIAM_URL
#define XAP_XIAM_URL "https://xaptum.io/api/xiam/v1/"
#endif

static const char *XIAM_FUNC_EP_AUTH = XAP_XIAM_URL "endpoints";


/* Structure for XIAM internal errors */
struct iam_error {
    int error;
    int http_error;
    char *reason;
};

/**
 * iam_error_unmarshall() - Marshall an error response from XIAM
 * @str: The JSON string to marshall
 * @out: A structure to write the return data into
 *
 * Return: 1 on success, 0 if structure cannot be read
 */
static int iam_error_unmarshall(char *str, struct iam_error *out) {
    json_t *root = NULL;
    struct iam_error error = {-1, -1, ""};
    int ret = 1;

    root = json_loads(str, 0, NULL);

    /* Validate the object */
    if (!root || !json_object_get(root, "xiam_error") || !json_object_get(root, "http_error") ||
        !json_object_get(root, "reason")) {
        ret = 0;
        goto out;
    }

    error.error = json_integer_value(json_object_get(root, "xiam_error"));
    error.http_error = json_integer_value(json_object_get(root, "http_error"));
    error.reason = new_json_str(json_object_get(root, "reason"));

    *out = error;

out:
    return ret;
}

static void iam_error_free(struct iam_error *err)
{
    if(err->reason)
        free(err->reason);
    err->reason = NULL;
}
/**
 * ep_auth_marshal() - Generate a JSON object to send to IAM endpoints API
 * @auth: The login user and password (key)
 *
 * Return: The new JSON data
 */
char *ep_auth_marshal(struct iam_create_endpoint_request *auth)
{
    json_t *new_endpoint_auth = json_object();
    json_t *new_credential = json_object();
    json_t *address_request = json_object();
    char *auth_str = NULL;
    const char *endpoint_name = auth->type == NETWORK ? "network" : "address";
    int ret = 0;

    /* No specific memory has to be freed so it only needs to be known if any of them failed */
    ret |= json_object_set_new(new_credential, "type", json_string(auth->ecdsa_credential.type));
    ret |= json_object_set_new(new_credential, "key", json_string(auth->ecdsa_credential.key));
    ret |= json_object_set_new(address_request, endpoint_name, json_string(auth->endpoint));

    ret |= json_object_set_new(new_endpoint_auth, "ecdsa_credential", new_credential);
    ret |= json_object_set_new(new_endpoint_auth, "address_request", address_request);

    /* Do not generate the string if any of them failed */
    if (ret)
        goto cleanup;

    /* Copy the assembled object to a new stirng */
    auth_str = json_dumps(new_endpoint_auth, 0);

cleanup:
    json_decref(new_endpoint_auth);

    return auth_str;
}

/**
 * ep_auth_resp_set_common() - Helper function to ep_auth_resp_unmarshal
 * @active_credentials: The active credentials portion of XIAMs return
 * @ep_ret: The return data structure
 *
 * Return: None
 */
static void ep_auth_resp_set_common(json_t *root, struct iam_endpoint *ep_ret)
{
    copy_json_str(ep_ret->address, json_object_get(root, "address"), sizeof(ep_ret->address));
    copy_json_str(ep_ret->network, json_object_get(root, "network"), sizeof(ep_ret->network));
    ep_ret->creation_timestamp = new_json_str(json_object_get(root, "creation_timestamp"));
    ep_ret->modification_timestamp = new_json_str(json_object_get(root, "modification_timestamp"));
}

/**
 * ep_auth_resp_set_daa() - Helper function to ep_auth_resp_unmarshal
 * @active_credentials: The active credentials portion of XIAMs return
 * @ep_ret: The return data structure
 *
 * Return: None
 */
static void ep_auth_resp_set_daa(json_t *active_credentials, struct iam_endpoint *ep_ret)
{
    ep_ret->type = EP_DAA;
    strcpy(ep_ret->active_credentials.daa.type, type_daa_lrsw_bn256);
    copy_json_str(
            ep_ret->active_credentials.daa.group_id,
            json_object_get(active_credentials, "group_id"),
            sizeof(ep_ret->active_credentials.daa.group_id));
    ep_ret->active_credentials.daa.pseudonym = new_json_str(json_object_get(active_credentials, "pseudonym"));
    ep_ret->active_credentials.daa.creation_timestamp =
            new_json_str(json_object_get(active_credentials, "creation_timestamp"));
}

/**
 * ep_auth_resp_set_ecdsa() - Helper function to ep_auth_resp_unmarshal
 * @active_credentials: The active credentials portion of XIAMs return
 * @ep_ret: The return data structure
 *
 * Return: None
 */
static void ep_auth_resp_set_ecdsa(json_t *active_credentials, struct iam_endpoint *ep_ret)
{
    ep_ret->type = EP_ECDSA;
    strcpy(ep_ret->active_credentials.ecdsa.type, type_ecdsa_p256);
    ep_ret->active_credentials.ecdsa.key = new_json_str(json_object_get(active_credentials, "key"));
    ep_ret->active_credentials.ecdsa.creation_timestamp =
            new_json_str(json_object_get(active_credentials, "creation_timestamp"));
}

/**
 * ep_auth_resp_unmarshal() - Process the response from IAM endpoints API
 * @ep: The JSON string represneing a xiam.ENDPOINT object
 * @ep_ret: A structure to write the return data into
 *
 * Return: The new endpoint
 */
int ep_auth_resp_unmarshal(char *ep, struct iam_endpoint *ep_ret)
{
    /* Json holders */
    json_error_t jerror;
    json_t *root = NULL;
    json_t *active_credentials = NULL;
    int ret = 0;

    /* Zero out the return struct to make bad input distinct from allocated pointers on error */
    memset(ep_ret, 0, sizeof(*ep_ret));

    root = json_loads(ep, 0, &jerror);
    if (!root) {
        goto cleanup_err;
    }

    /* Determine if an active credntial was returned and abort if nothing is given */
    active_credentials = json_object_get(root, "active_credentials");
    active_credentials = json_array_get(json_object_get(active_credentials, "body"), 0);
    if (!active_credentials) {
        goto cleanup_err;
    }

    /* Copy common elements */
    ep_auth_resp_set_common(root, ep_ret);

    /* Copy active credentials */
    if(strcmp(type_daa_lrsw_bn256, json_string_value(json_object_get(active_credentials, "type"))) == 0)
        ep_auth_resp_set_daa(active_credentials, ep_ret);
    else if (strcmp(type_ecdsa_p256, json_string_value(json_object_get(active_credentials, "type"))) == 0)
        ep_auth_resp_set_ecdsa(active_credentials, ep_ret);
    else
        goto cleanup_err;

    /* See if the necessary values are all present */

    /* Common fields */
    if(!ep_ret->creation_timestamp || !ep_ret->modification_timestamp)
        goto out;

    /* Active credential types */
    if (ep_ret->type != EP_DAA && ep_ret->type != EP_ECDSA)
            goto cleanup_err;
    else if (ep_ret->type == EP_DAA && (!ep_ret->active_credentials.daa.creation_timestamp || !ep_ret->active_credentials.daa.pseudonym))
        goto cleanup_err;
    else if (ep_ret->type == EP_ECDSA && (!ep_ret->active_credentials.ecdsa.creation_timestamp || !ep_ret->active_credentials.ecdsa.key))
        goto cleanup_err;

    /* Success */
    ret = 1;
    goto out;

cleanup_err:
    ret = 0;
    ep_auth_resp_destroy(ep_ret);

out:
    if (root)
        json_decref(root);
    return ret;
}

/**
 * ep_auth_resp_destroy() - Destroys an iam_endpoint object
 * @ep: The object to be destroyed
 *
 * Return: None
 */
void ep_auth_resp_destroy(struct iam_endpoint *ep)
{
    free(ep->creation_timestamp);
    free(ep->modification_timestamp);

    /* Free active credential items where applicable */
    if (ep->type == EP_DAA) {
        free(ep->active_credentials.daa.pseudonym);
        free(ep->active_credentials.daa.creation_timestamp);
    } else if (ep->type == EP_ECDSA) {
        free(ep->active_credentials.ecdsa.key);
        free(ep->active_credentials.ecdsa.creation_timestamp);
    }
}

/**
 * iam_create_endpoint_request_destroy() - Destroys an iam_create_endpoint_request object
 * @req: The object to be destroyed
 *
 * Return: None
 */
void iam_create_endpoint_request_destroy(struct iam_create_endpoint_request *req)
{
    free(req->ecdsa_credential.key);
}


/**
 * countZeroBytes() - Counts the number of sequential zero bytes at the end of a buffer
 * @buf: The buffer to count
 * @size: The number of bytes in the buffer
 *
 * Returns the number of 0x00 bytes at the end (least signifiant) portion of a network order byte sequence.
 * This function does not count bits in a partially zero byte.
 *
 * Return: The number of zero bytes found
 */
static int countZeroBytes(const char *buf, int size)
{
    int ret = 0;

    /* Count the number of sequential sero bytes at the end */
    for (; size>0 && !buf[size-1]; size--)
        ret++;

    return ret;
}

/**
 * ip_version() - Determines if given "network" is a network, address or invalid
 * @src: The IPv6 address or network as a string
 *
 * Takes an IPv6 address or subnet (including /128 subnets) and returns what type
 * of format the address is to XIAM. /64 subnets are validated that the address doesn't
 * supply too many bits.
 *
 * Return: NETWORK if
 */
static enum addr_type ip_version(const char *src) {
    char buf[16] = {0};
    char *ip_str = NULL;
    int ip_valid = 0;
    int ret = TYPE_NONE;
    char *subnet;

    /* Copy the IP as we can modify it */
    ip_str = malloc(strlen(src) + 1);
    if (!ip_str) {
        fprintf(stderr, "%s ERR: Memory error\n", __func__);
        goto out;
    }
    strcpy(ip_str, src);

    /* Seperate the subnet specifier */
    subnet = strchr(ip_str, '/');
    if (subnet)
        *(subnet++) = '\0';

    /* Parse the IP address portion */
    ip_valid = inet_pton(AF_INET6, ip_str, buf);

    /* Check for a ::/128 */
    if (ip_valid && subnet && strcmp(subnet, "64") == 0 && countZeroBytes(buf, sizeof(buf)) >= 8) {
        ret = TYPE_IPV6_NETWORK;
    }

    /* A full address can be a ::/128 network or no subnet specified. */
    if (ip_valid && inet_pton(AF_INET6, ip_str, buf) && (!subnet || strcmp(subnet,"128")==0)) {
        ret = TYPE_IPV6_ADDR;
    }

    free(ip_str);

out:
    return ret;
}

/**
 * iam_new_ep_auth_network() - Created a new request for XIAM endpoint request
 * @network: The IPv6 subnet being requested
 * @key: The x9.62-encoded public key
 * @req Address to write the returned data into
 *
 * Returned value must be freed with iam_destroy
 *
 * Return: 1 on success, 0 on failure
 */
int iam_new_ep_auth_network_request(char *network, char *key, struct iam_create_endpoint_request *request)
{
    int ret = 1;
    enum addr_type addr_type;

    /* Avoid an overcopy error */
    if (strlen(network) + 1 > sizeof(request->endpoint)) {
        fprintf(stderr, "Error: Endpoint address too long.");
        ret = 0;
        goto out;
    }

    /* Allocate and copy the key */
    request->ecdsa_credential.key = malloc(strlen(key) + 1);
    if (!request->ecdsa_credential.key) {
        fprintf(stderr, "%s ERR: Memory alloc failed for key.", __func__);
        ret = 0;
        goto cleanup;
    }
    strcpy(request->ecdsa_credential.key, key);
    strcpy(request->ecdsa_credential.type, type_ecdsa_p256);
    strcpy(request->endpoint, network);


    addr_type = ip_version(network);
    if (addr_type == TYPE_IPV6_NETWORK) {
        request->type = NETWORK;
    } else if(addr_type == TYPE_IPV6_ADDR) {
        request->type = ADDRESS;

        /* Note: The API does not accept ::/128 at this time so convert this "subnet" to a regular address */
        char * slash;
        slash = strchr(request->endpoint, '/');
        if (slash)
            *slash = '\0';
    } else {
        fprintf(stderr, "Error: Cannot parse address as an IPv6 address or ::/64 network.\n");
        ret = 0;
        goto cleanup;
    }
    /* Success */
    goto out;

cleanup:
    free(request->ecdsa_credential.key);
    request->ecdsa_credential.key = NULL;
out:
    return ret;
}

/**
 * iam_send_ep_auth() - sends an endpoint request to XIAM
 * @auth: The endpoint authorization parameters to send (see xiam.NEW_ENDPOINT_AUTH)
 * @token: The session token provided by XCR
 * @ep_resp: A continer to populate with the reponse data
 *
 * @ep_resp must be freed with ep_auth_resp_destroy
 *
 * Return: 1 on success, 0 on failure
 */
int iam_send_ep_auth(struct iam_create_endpoint_request *auth, char *token, struct iam_endpoint *ep_resp)
{
    struct enftun_req api_req = {0};
    char *send_post = NULL;
    char *response = NULL;
    int ret = 1;

    /* Prepare the request */
    ret = enftun_curl_init(&api_req);
    if (!ret) {
        ret = 0;
        fprintf(stderr, "%s CURL init failed.\n", __func__);
        goto cleanup;
    }
    enftun_req_set_auth(&api_req, token);

    /* Turn the request into JSON */
    send_post = ep_auth_marshal(auth);
    if (!send_post) {
        ret = 0;
        fprintf(stderr, "%s Could not marshal request.\n", __func__);
        goto cleanup;
    }

    /* Actually send the request */
    response = enftun_curl_send(&api_req, XIAM_FUNC_EP_AUTH, send_post);

    if (response) {
        ret = ep_auth_resp_unmarshal(response, ep_resp);
        if (!ret) {
            /* try to figure out the error */
            struct iam_error emsg = {0};
            iam_error_unmarshall(response, &emsg);

            if(emsg.error == 500)
                fprintf(stderr, "A server error occured. Please check input parameters.\n");
            else if(emsg.error == 403)
                fprintf(stderr, "An authorization error occured. Please check input parameters.\n");
            else
                fprintf(stderr, "An unknown error occured (%d, %d, %s)\n", emsg.error, emsg.http_error, emsg.reason);

            iam_error_free(&emsg);

            ret = 0;
        }
    } else {
        ret = 0;
        fprintf(stderr, "%s No response received\n", __func__);
    }

cleanup:
    free(response);
    free(send_post);
    enftun_curl_destroy(&api_req);

    return ret;
}
