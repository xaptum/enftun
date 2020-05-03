//
// Created by dan on 4/30/20.
//

#ifndef ENFTUN_SSL_H
#define ENFTUN_SSL_H
#include <openssl/evp.h>

struct key {
    EVP_PKEY *pkey;
    char *hex_str;
};

int
gen_key(struct key *key_out);

void
destroy_key(struct key *key_in);

int write_key(struct key *key_in, const char *fname);

int write_cert(const struct key *key_in, const char *cn, const char *fname);

#endif // ENFTUN_SSL_H