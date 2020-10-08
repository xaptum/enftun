/*
 * Copyright 2018 Xaptum, Inc.
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

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <sodium.h>
#include <errno.h>

#ifdef KEYGEN_USE_TPM
#include <xaptum-tpm/keys.h>

#include "tpm.h"
#endif

#include "ssl.h"
#include "enftun/config.h"

/**
 * public_key_encode_x962() - Encode a public key from an EVP_PKEY structure
 *
 * Caller must free the returned buffer
 *
 * Return: A new buffer containing the x9.62-encoded string
 */
static char *public_key_encode_x962(EC_KEY *key)
{
    const EC_POINT * point = NULL;
    char *hex = NULL;

    if (!key) {
        printf("%s Could not get EC_KEY from pkey", __func__);
        goto out;
    }

    point = EC_KEY_get0_public_key(key);
    if (!point) {
        printf("%s Could not get point from EC_KEY", __func__);
        goto out;
    }

    hex = EC_POINT_point2hex(EC_KEY_get0_group(key), point, POINT_CONVERSION_UNCOMPRESSED, NULL);

out:
    return hex;
}

/**
 * gen_EC_PKEY() - Generate an Elliptic Curve key (NID_X9_62_prime256v1)
 *
 * Return: A pointer to a new EC_KEY instance or NULL on failure
 */
int gen_key(struct key *key_out)
{
    int ret = 0;
    EC_KEY * ec_key = NULL;

    ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        fprintf(stderr, "%s ERR: Could not generate EC_KEY", __func__);
        ret = 0;
        goto out;
    }

    key_out->pkey = EVP_PKEY_new();
    if (!key_out->pkey) {
        fprintf(stderr, "%s ERR: Could not generate PKEY", __func__);
        ret = 0;
        goto cleanup_ec_key;
    }

    ret = EC_KEY_generate_key(ec_key);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could not generate EC_KEY", __func__);
        ret = 0;
        goto cleanup_ec_key;
    }

    if (!EVP_PKEY_assign_EC_KEY(key_out->pkey, ec_key)) {
        fprintf(stderr, "%s ERR: Could not assign EC_KEY to PKEY", __func__);
        ret = 0;
        goto cleanup_ec_key;
    }

    key_out->hex_str = public_key_encode_x962(ec_key);
    if (!key_out->hex_str) {
        fprintf(stderr, "%s ERR: Could not generate x862 public key from PKEY", __func__);
        ret = 0;
        /* Because EVP_PKEY_assign_EC_KEY succeeded both items will be freed when EC_KEY_free is run */
        goto cleanup;
    }

    /* Success */
    ret = 1;
    goto out;

cleanup_ec_key:
    if (ec_key)
        EC_KEY_free(ec_key);
cleanup:
    destroy_key(key_out);

out:
    return ret;
}

#ifdef KEYGEN_USE_TPM
int
gen_and_save_tpm_key(struct key *key_out, const char *key_filename,
                     TPM2_HANDLE parent_handle,
                     TPMI_RH_HIERARCHY hierarchy,
                     const char *hierarchy_password,
                     size_t hierarchy_password_length)
{
    struct xtpm_key tpm_key = {};
    int ret = 1;
    TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

    ret = init_tcti(&tcti_ctx);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could not initialize TPM TCTI context\n", __func__);
        ret = 0;
        goto out;
    }

    if (TSS2_RC_SUCCESS != xtpm_gen_key(tcti_ctx, parent_handle, hierarchy, hierarchy_password, hierarchy_password_length, &tpm_key)) {
        fprintf(stderr, "%s ERR: Could not generate key on TPM\n", __func__);
        ret = 0;
        goto out;
    }

    if (TSS2_RC_SUCCESS != xtpm_write_key(&tpm_key, key_filename)) {
        fprintf(stderr, "%s ERR: Could not write tpm key to %s\n", __func__, key_filename);
        ret = 0;
        goto out;
    }

    ret = tpm_key_to_pkey(&key_out->pkey, key_filename);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could not convert xtpm key to EVP_PKEY\n", __func__);
        ret = 0;
        goto out;
    }

    key_out->hex_str = public_key_encode_x962(EVP_PKEY_get1_EC_KEY(key_out->pkey));
    if (!key_out->hex_str) {
        fprintf(stderr, "%s ERR: Could not generate x862 public key from PKEY", __func__);
        ret = 0;
        goto out;
    }

out:
    free_tcti(tcti_ctx);

    return ret;
}
#endif

/**
 * destroy_key() - Deallocate a key
 *
 * Return: None
 */
void destroy_key(struct key *key_in)
{
    EVP_PKEY_free(key_in->pkey);
    OPENSSL_free(key_in->hex_str);

    key_in->pkey = NULL;
    key_in->hex_str = NULL;
}

/**
 * gen_rand_serial() - Returns a random serial number
 *
 * Returns a random 19-byte  serial number as an ASN1_INTEGER
 *
 * Return: A new ASN1_INTEGER on success or NULL on failure
 */
static ASN1_INTEGER *gen_rand_serial()
{
    unsigned char buffer[19];    // to hold a random number up to 2**152
    BIGNUM *bignum;
    ASN1_INTEGER *ret = NULL;

    randombytes_buf(buffer, sizeof(buffer));
    bignum = BN_bin2bn(buffer, sizeof(buffer), NULL);

    if (!bignum) {
        ret = NULL;
        fprintf(stderr, "%s ERR: Could not generate serial number", __func__);
        goto out;
    }

    ret = BN_to_ASN1_INTEGER(bignum, NULL);
    if (!ret) {
        ret = 0;
        fprintf(stderr, "%s ERR: Could not convert BN to ASN1 (memory error)", __func__);
        goto cleanup;
    }

cleanup:
    BN_free(bignum);
out:
    return ret;
}

static X509 *new_cert_1year()
{
    X509 *x509 = X509_new();
    if(!x509)
        goto out;

    /* This certificate is valid from now until exactly 365 days from now */
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 31536000L);

out:
    return x509;
}

static int x509_set_rand_serial(X509 *x509)
{
    int ret = 0;
    ASN1_INTEGER *serial;

    serial = gen_rand_serial();
    if (!serial) {
        ret = 0;
        goto out;
    }

    ret = X509_set_serialNumber(x509, serial);
    ASN1_STRING_free(serial);
out:
    return ret;
}

/**
 * gen_signed_cert() - Generate an X509 cert with a public key
 * @pkey: The public key to certify as an EVP_PKEY*
 * @cn: The IPv6 address (as a string) to assign to CN
 *
 * Caller must free returned buffer with destroy_signed_cert
 *
 * Return: A new x509 certificate or NULL on error
 */
static X509 *gen_signed_cert(EVP_PKEY *pkey, const char *cn)
{
    X509 *x509;
    int ret;

    x509 = new_cert_1year();
    if (!x509) {
        fprintf(stderr, "%s ERR: Could generate new cert", __func__);
       goto out;
    }

    /* Set the public key for our certificate. */
    ret = X509_set_pubkey(x509, pkey);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could add public key to cert", __func__);
        goto cleanup_err;
    }

    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);

    /* Set the common name. */
    ret = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could not add CN", __func__);
        goto cleanup_err;
    }

    /* Set the issuer name to the same value as the subject name */
    ret = X509_set_issuer_name(x509, name);
    if (!ret) {
        fprintf(stderr, "%s ERR: Could not add name", __func__);
        goto cleanup_err;
    }

    /* Set the serial number to a random value */
    x509_set_rand_serial(x509);

    /* Sign the cert */
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "%s ERR: Could not sign key", __func__);
        goto cleanup_err;
    }
    /* Success! */
    goto out;

cleanup_err:
    if (x509)
        X509_free(x509);
    x509 = NULL;
out:
    return x509;
}

/**
 * write_x509_cert() - Write an X509 cert to a file
 * @cert: The certificate to write
 * @fname: A string containing the name of the file to write into
 *
 * Return: None
 */
int write_cert(const struct key *key_in, const char *cn, const char *fname)
{
    X509 *cert = NULL;
    FILE *f = NULL;
    int ret = 0;

    cert = gen_signed_cert(key_in->pkey, cn);
    if (!cert) {
        fprintf(stderr, "%s generate signed cert", __func__);
        ret = 0;
        goto out;
    }

    f = fopen(fname, "w");
    if (!f) {
        fprintf(stderr, "%s could not open %s, fopen error=%d", __func__, fname, errno);
        ret = 0;
        goto cleanup;
    }

    ret = PEM_write_X509(f, cert);
    if (!ret) {
        fprintf(stderr, "%s could not write x509 cert to %s", __func__, fname);
    }

cleanup:
    if (f)
        fclose(f);
    if (cert)
        X509_free(cert);
out:
    return ret;
}

/**
 * write_EC_private_key() - Write a puiblic and private key in PEM format
 * @ec_key: The key to be written
 * @fname: A string containing the name of the file to write into
 *
 * Return: 1 on success or 0 on failure
 */
int write_key(struct key *key_in, const char *fname)
{
    FILE *f;
    int ret;

    /* Open the file for writing */
    f = fopen(fname, "w");
    if(!f) {
        fprintf(stderr, "%s could not open %s, fopen error=%d", __func__, fname, errno);
        ret = 0;
        goto out;
    }

    /* Write the private key to the file */
    ret = PEM_write_PKCS8PrivateKey(f, key_in->pkey, NULL,NULL,0,NULL,NULL);
    if (!ret) {
        fprintf(stderr, "%s could not write private key to %s", __func__, fname);
    }

    fclose(f);
out:
    return ret;
}
