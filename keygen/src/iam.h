#include "auth.h"

static const char *type_ecdsa_p256 = {"ecdsa_p256"};

union iam_endpoint_request
{
    char address[40];
    char network[43]; // Longest IPv6 addr with subnet specifier
};

struct iam_new_credential_ECDSA
{
    char type[11];
    char *key;
};

struct iam_create_endpoint_request
{
    struct iam_new_credential_ECDSA ecdsa_credential;
    union iam_endpoint_request endpoint;
};

json_t *
iam_send_create_endpoint_request(struct iam_create_endpoint_request*auth, struct xcr_session *sess);