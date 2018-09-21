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

#include <openssl/asn1.h>
#include <openssl/pem.h>

#include "cert.h"
#include "log.h"

static
int
asn1_extract(ASN1_STRING* asn1, char* out, size_t out_len)
{
    unsigned char* utf8;
    int len;

    if ((len = ASN1_STRING_to_UTF8(&utf8, asn1)) < 0)
        goto out;

    if (len > out_len)
    {
        len = -1;
        goto free;
    }

    memcpy(out, utf8, len);

 free:
    OPENSSL_free(utf8);

 out:
    return len;
}

int
enftun_cert_common_name_X509(X509 *cert, char* out, size_t out_len)
{
    X509_NAME *subject_name;
    X509_NAME_ENTRY *cn_entry;
    ASN1_STRING *cn_asn1;
    unsigned char* cn;
    int len, pos;

    subject_name = X509_get_subject_name(cert);
    if (!subject_name)
    {
        enftun_log_error("Failed to get subject name\n");
        goto err;
    }

    pos = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
    if (pos < 0)
    {
        enftun_log_error("Failed to find common name\n");
        goto err;
    }

    cn_entry = X509_NAME_get_entry(subject_name, pos);
    if (!cn_entry)
    {
        enftun_log_error("Failed to get common name\n");
        goto err;
    }

    cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (!cn_asn1)
    {
        enftun_log_error("Failed to decode common name\n");
        goto err;
    }


    len = asn1_extract(cn_asn1, out, out_len);
    if (len < 0)
    {
        goto err;
    }

    return len;

 err:
    return -1;
}

int
enftun_cert_common_name_file(const char *file, char* out, size_t out_len)
{
    FILE* fp;
    X509 *cert;
    int len;

    // Try to open cert as PEM format
    fp = fopen(file, "r");
    if (!fp)
    {
        enftun_log_error("Failed to open cert %s\n", file);
        len = -1;
        goto out;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    // If not PEM, try to open cert as DER format
    if (!cert)
    {
        fp = fopen(file, "r");
        if (!fp)
        {
            enftun_log_error("Failed to open cert %s\n", file);
            len = -1;
            goto out;
        }
        cert = d2i_X509_fp(fp, NULL);
        fclose(fp);
    }

    if (!cert)
    {
        enftun_log_error("Failed to parse cert %s\n", file);
        len = -1;
    }

    len = enftun_cert_common_name_X509(cert, out, out_len);
    if (len < 0)
        enftun_log_error("Failed to get common name from cert %s\n", file);

    X509_free(cert);

 out:
    return len;
}
