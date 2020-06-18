#ifndef ENFTUN_CURL_H
#define ENFTUN_CURL_H

#include <curl/curl.h>
#include "auth.h"

struct MemoryStruct {
    char *memory;
    size_t size;
};

struct enftun_req {
    CURL *curl;
    struct curl_slist *headers;
    struct MemoryStruct target;
};

int enftun_curl_init(struct enftun_req *req);
void enftun_req_set_auth(struct enftun_req *req, char *token);
void enftun_curl_destroy(struct enftun_req *req);
char *enftun_curl_send(struct enftun_req *req, const char *url, char *post_data);

#endif // ENFTUN_CURL_H
