#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "curl.h"

static size_t curl_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}


/**
 * get_auth_str() - Creates a new string with the HTTP authorization header line
 * @token: The token to append
 *
 * Return value must be freed by caller
 *
 * Return: A new buffer containing the HTTP header line for authorization
 */
static char *get_auth_str(char *token)
{
    const char *auth_start = "authorization: Bearer ";
    char *auth_str = malloc(strlen(auth_start) + strlen(token) + 1);
    strcpy(auth_str, auth_start);
    strcpy(auth_str+strlen(auth_start), token);
    return auth_str;
}

/**
 * set_std_curl_opts() - Set common CURL parameters
 * @req: The request instance to set
 *
 * This is a helper function that sets common parameters for xending to Xaptum APIs
 *
 * Return: None
 */
static void set_common_curl_opts(struct enftun_req *req)
{
    req->headers = curl_slist_append(req->headers, "Accept: application/json");
    req->headers = curl_slist_append(req->headers, "Content-Type: application/json");

    curl_easy_setopt(req->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(req->curl, CURLOPT_HTTPHEADER, req->headers);
    curl_easy_setopt(req->curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(req->curl, CURLOPT_WRITEFUNCTION, curl_cb);
    curl_easy_setopt(req->curl, CURLOPT_WRITEDATA, (void *)&req->target);
}

/**
 * copy_ret_str() - Copies the response from a MemoryStruct
 * @req: The memory struct to read
 *
 * MemoryStruct must contain a null terminated string.
 * Caller must free returned buffer.
 *
 * Return: A new buffer containing the MemoryStruct response
 */
static char *copy_ret_str(const struct MemoryStruct *mem)
{
    char *ret = malloc(mem->size + 1);
    /* Note: curl_cb guarentees a terminal /0 in allocated memory */
    strcpy(ret, mem->memory);
    return ret;
}

/**
 * enftun_curl_init() Create a request to send to a Xaptum API
 * @req: The request instance to set
 *
 * Return value must be freed by caller with enftun_curl_destroy()
 *
 * Return: A new request
 */
int enftun_curl_init(struct enftun_req *req)
{
    int ret = 1;

    /* Initialize CURL */
    req->curl = curl_easy_init();
    if (!req->curl) {
        ret = 0;
        goto out;
    }

    /* Initialize the memory buffer to place the read content */
    req->target.memory = calloc(1, 1);
    if (!req->target.memory) {
        ret = 0;
        curl_easy_cleanup(req->curl);
        goto out;
    }

    out:
    return ret;
}

/**
 * enftun_req_set_auth() Set HTTP auth to Bearer {token}
 * @req The enftun request to modify
 * @token: The value for the Bearer header
 *
 * The value of @token should be the token returned by XCR login
 *
 * Return: None
 */
void enftun_req_set_auth(struct enftun_req *req, char *token)
{
    char *auth_str = get_auth_str(token);
    req->headers = curl_slist_append(req->headers, auth_str);
    free(auth_str);
}

/**
 * enftun_curl_destroy() Tear down an enftun curl request
 * @req The enftun request to destroy
 *
 * Return: None
 */
void enftun_curl_destroy(struct enftun_req *req)
{
    curl_easy_cleanup(req->curl);
    curl_slist_free_all(req->headers);
    if (req->target.memory)
        free(req->target.memory);
}

/**
 * enftun_curl_send() Send an enftun curl request
 * @req The enftun request to send
 * @url: The URL to send the request to
 * @post_data: The POST data to send
 *
 * Returned buffer must be freed by caller
 *
 * Return: A new string containing the response, or NULL on error
 */
char *enftun_curl_send(struct enftun_req *req, const char *url, char *post_data)
{
    int curl_result;
    char *ret = NULL;

    curl_easy_setopt(req->curl, CURLOPT_URL, url);
    curl_easy_setopt(req->curl, CURLOPT_POSTFIELDS, post_data);
    set_common_curl_opts(req);
    curl_result = curl_easy_perform(req->curl);

    if(curl_result == CURLE_OK) {
        ret = copy_ret_str(&req->target);
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(curl_result));
    }
    return ret;
}