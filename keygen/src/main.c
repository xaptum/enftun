#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "json_model.h"

const char *TEST_RESP_STR = "{\"data\": [{\"username\": \"<YOUR_USERNAME>\",\"token\": \"1jadsfk834==jkasdIK9234=jl;99903\",\"user_id\": 24,\"type\": \"DOMAIN_USER\",\"domain_id\": 6,\"domain_network\": \"fd00:8f80:0000::/48\"}],\"page\": {\"curr\": -1,\"next\": -1,\"prev\": -1}}";

int main(int argc, char **argv)
{
	json_t *root;
    json_error_t jerror;
	struct xcr_auth *auth;

	root = json_loads(TEST_RESP_STR, 0, &jerror);
	auth = xcr_proc_auth(root);

	printf("username=%s\ntoken=%s\nuser_id=%lld\ntype=%s\ndomain_id=%lld\ndomain_network=%s",
			auth->data[0].username,
			auth->data[0].token,
			auth->data[0].user_id,
			auth->data[0].type,
			auth->data[0].domain_id,
			auth->data[0].domain_network);
}
