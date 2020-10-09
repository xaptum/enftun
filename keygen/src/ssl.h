//
// Created by dan on 4/30/20.
//

#ifndef ENFTUN_SSL_H
#define ENFTUN_SSL_H
#include <openssl/evp.h>

#ifdef USE_TPM
#include <tss2/tss2_sys.h>
#endif

struct key {
    EVP_PKEY *pkey;
    char *hex_str;
};

int
gen_key(struct key *key_out);

#ifdef USE_TPM
int
gen_and_save_tpm_key(struct key *key_out, const char *key_filename,
                     const char* tcti,
                     const char* device,
                     const char* socket_host,
                     const char* socket_port,
                     TPM2_HANDLE parent_handle,
                     TPMI_RH_HIERARCHY hierarchy,
                     const char *hierarchy_password,
                     size_t hierarchy_password_length);
#endif

void
destroy_key(struct key *key_in);

int write_key(struct key *key_in, const char *fname);

int write_cert(const struct key *key_in, const char *cn, const char *fname);

#endif // ENFTUN_SSL_H
