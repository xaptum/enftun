#ifndef _IAM_H
#define _IAM_H

#include "auth.h"

static const char *type_ecdsa_p256 = {"ecdsa_p256"};
static const char *type_daa_lrsw_bn256 = {"daa_lrsw_bn256"};

struct iam_new_credential_ECDSA
{
    char type[11];
    char *key;
};

struct iam_create_endpoint_request
{
    struct iam_new_credential_ECDSA ecdsa_credential;
    enum {ADDRESS, NETWORK} type;
    char endpoint[44]; //Holds either a IPv6 address or subnet, depending on `type`
};

struct credential_daa
{
    char type[sizeof(type_daa_lrsw_bn256) + 1];
    char group_id[64];
    char *pseudonym;
    char *creation_timestamp;
};

struct credential_ecdsa
{
    char type[sizeof(type_ecdsa_p256) + 1];
    char *key;
    char *creation_timestamp;
};
struct iam_endpoint
{
    char address[40];
    char network[43];
    enum {EP_NONE=0, EP_DAA, EP_ECDSA} type;
    union
    {
        struct credential_daa daa;
        struct credential_ecdsa ecdsa;
    } active_credentials;
    char *creation_timestamp;
    char *modification_timestamp;
};

int iam_send_ep_auth(struct iam_create_endpoint_request *auth, char *token, struct iam_endpoint *ep_resp);
int iam_new_ep_auth_network_request(char *network, char *key, struct iam_create_endpoint_request *request);
void ep_auth_resp_destroy(struct iam_endpoint *ep);
void iam_create_endpoint_request_destroy(struct iam_create_endpoint_request *req);

#endif