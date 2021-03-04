 #include <openssl/ec.h>/*
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include <ctype.h>
#include <errno.h>
#include <sodium.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>

#include "auth.h"
#include "iam.h"
#include "ssl.h"
#include "enftun/config.h"

/* limts.h is allowed to specify a PASS_MAX, but GNU implementations don't */
#ifndef PASS_MAX
#define PASS_MAX INT_MAX
#endif
/**
 * print_usage_msg() - Print usage message
 * @name: The name of the program
 *
 * Prints usage message detailing parameters and usage
 *
 * Return: None
 */
static void print_usage_msg(char *name)
{
    const char *help_msg =
            "Provision and register credentials (key and cert) for enftun to connect.\n"
            "\n"
            "Usage: %s -c CONF_FILE -a ADDRESS -u USERNAME [-e /etc/enftun/]\n"
            "CONF_FILE: Path to the config file for the enftun instance (/etc/enftun/enf0.conf)\n"
            "ADDRESS: The IPv6 address to provision credentials for. If a ::/64 network is provided, a new, randomly generated IPv6 address in the network will created.\n"
            "USERNAME: Your ENF API username.\n"
            "\n"
            "This program will prompt for your password.\n";
        printf(help_msg, name);
}

/**
 * parse_args() - Parse input parameters
 * @argc: The argumnet count provided by main
 * @argv: The argument vector provided by main
 * @ipv6_network: The IPv6 network name to return
 * @enftun_cfg_file: The enftun config filename to return
 * @api_email: The email to use for authorization (return)
 *
 * Parses input parameters and sets ipv6_network, enftun_cfg_file and api_email to
 * newly allocated char pointers. If a parameter is not found the respective return
 * value will not be written to.
 *
 * Return: 1 on success (all required parameters found) and 0 on failure
 */
static int parse_args(int argc, char **argv, char **ipv6_network, char **enftun_cfg_file, char **api_email, char **enftun_path)
{
    int c;
    const char *enftun_def_path = "/etc/enftun/";

    opterr = 0;
    while ((c = getopt (argc, argv, "a:c:u:e:")) != -1)
        switch (c)
        {
        case 'a':
            *ipv6_network = malloc(strlen(optarg) + 1);
            strcpy(*ipv6_network, optarg);
            break;
        case 'c':
            *enftun_cfg_file = malloc(strlen(optarg) + 1);
            strcpy(*enftun_cfg_file, optarg);
            break;
        case 'u':
            *api_email = malloc(strlen(optarg) + 1);
            strcpy(*api_email, optarg);
            break;
        case 'e':
            *enftun_path = malloc(strlen(optarg) + 1);
            strcpy(*enftun_path, optarg);
            break;
        case '?':
            if (optopt == 'a' || optopt == 'c' || optopt == 'u')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            /* Fall through */
        default:
            return 1;
        }

    /* Use the default enftun path if none is set */
    if (!*enftun_path) {
        *enftun_path = malloc(strlen(enftun_def_path) + 1);
        strcpy(*enftun_path, enftun_def_path);
    }

    return *ipv6_network && *enftun_cfg_file && *api_email && *enftun_path;
}

/**
 * get_pass() - Print usage message
 * @password: Where to write the given password
 *
 * Prompts the user via stdin and copies the pointer to password.
 *
 * Return: 1 on success and 0 on failure
 */
static void get_pass(char **password)
{
    /* Prompt the user for the password */
    *password = getpass("Enter API Password: ");

    if(strlen(*password) == PASS_MAX)
        printf("WARNING: Password truncated at %d characters.", PASS_MAX);
}

/**
 * prompt_user() - Helper subroutine to get user confirmation before beginning the process
 * @username: The given usename
 * @network: The given network
 * @cfg: The enftun config file path
 * @cert: The cert file path
 * @key The key file path
 *
 * Prints a summary of the changes about to be made and prompts the user for a `y/n` answer.
 *
 * Return: 1 if user replies 'y', 1 otherwise
 */
static int prompt_user(const char *username, const char *network, const char *cfg, const char *cert, const char *key)
{
    char ch;
    printf("ENFTUN KEYGEN\n");
    printf("Login Email: %s\n", username);
    printf("IP Network: %s\n", network);
    printf("Enftun Config: %s\n", cfg);
    printf("Cert target file: %s\n", cert);
    printf("Key target file: %s\n", key);

    printf("Enter y to continue, n to exit: ");
    fflush(stdout);
    if (scanf("%c",&ch) < 0) {
        return 0;
    }

    printf("\n");
    if (ch != 'y' && ch != 'Y') {
        return 0;
    }

    return 1;
}


/**
 * start_sodium() - Helper function to start sodium
 *
 * Return: 1 on success, 0 on failure
 */
static int start_sodium()
{
#if defined(__linux__) && defined(RNDGETENTCNT)
    int rand_fd;
    int ent_count;

    if ((rand_fd = open("/dev/random", O_RDONLY)) != -1) {
        if (ioctl(rand_fd, RNDGETENTCNT, &ent_count) == 0 && ent_count < 160) {
            return 0;
        }

        (void) close(rand_fd);
    }
#endif

    return (sodium_init() != -1);
}

/* Turn relative paths from the enftun config into absolute ones */
static void make_cfg_path_absolute(const char *enftun_path_prefix, const char *cert_file, const char *key_file, char **full_cert_path, char **full_key_path)
{
    if (cert_file[0] != '/') {
        *full_cert_path = malloc(strlen(enftun_path_prefix) + strlen(cert_file) + 2);
        memcpy(*full_cert_path, enftun_path_prefix, strlen(enftun_path_prefix));
        (*full_cert_path)[strlen(enftun_path_prefix)] = '/';
        strcpy(*full_cert_path + strlen(enftun_path_prefix) + 1, cert_file);
    } else {
        *full_cert_path = malloc(strlen(cert_file) + 1);
        strcpy(*full_cert_path, cert_file);
    }

    if (key_file[0] != '/') {
        *full_key_path = malloc(strlen(enftun_path_prefix) + strlen(key_file) + 2);
        memcpy(*full_key_path, enftun_path_prefix, strlen(enftun_path_prefix));
        (*full_key_path)[strlen(enftun_path_prefix)] = '/';
        strcpy(*full_key_path + strlen(enftun_path_prefix) + 1, key_file);
    } else {
        *full_key_path = malloc(strlen(key_file) + 1);
        strcpy(*full_key_path, key_file);
    }
}

int main(int argc, char **argv)
{
    struct key key = {0};
    struct auth_login login = {0};
    struct iam_endpoint ep_resp = {0};
    struct auth_credentials auth_creds = {0};
    struct enftun_config cfg = {0};
    struct iam_create_endpoint_request ep_req = {0};
    char *enftun_cfg_file = NULL;
    char *ipv6_network = NULL;
    char *full_cert_path = NULL;
    char *full_key_path = NULL;
    char *enftun_path = NULL;
    int ret = 0;

    /* Start OpenSSL */
    #if OPENSSL_VERSION_NUMBER < 0x10100000
    SSL_library_init();
    #endif

    /* Start Sodium */
    ret = start_sodium();
    if (!ret) {
        printf("Libsodium init failed. Exiting.\n");
        goto cleanup;
    }

    /* Process input parameters */
    parse_args(argc, argv, &ipv6_network, &enftun_cfg_file, &login.username, &enftun_path);

    /* Only continue if all required parameters have been given */
    if (!ipv6_network || !enftun_cfg_file || !login.username) {
        print_usage_msg(argv[0]);
        goto cleanup;
    }

    /* Prompt the user for a password */
    get_pass(&login.password);

    /* Get the enftun config */
    enftun_config_init(&cfg);
    enftun_config_parse(&cfg, enftun_cfg_file);

    /* Turn relative paths into absolute */
    make_cfg_path_absolute(enftun_path, cfg.cert_file, cfg.key_file, &full_cert_path, &full_key_path);

    /* Get the final OK from the user before continuing */
    if (!prompt_user(login.username, ipv6_network, enftun_cfg_file, full_cert_path, full_key_path)) {
        printf("Aborting...\n");
        goto cleanup;
    }

    /* Log in with XCR */
    printf("Logging in... ");
    ret = auth_send_login(&login, &auth_creds);
    if (!ret) {
        printf("Failed. Exiting.\n");
        goto cleanup;
    }
    printf("Successful.\n");

    /* Generate a key (and save it to file) to send to IAM */
    if (cfg.tpm_enable) {
#ifdef USE_TPM
        printf("Generating TPM Key and saving it to file... ");
        ret = gen_and_save_tpm_key(&key, full_key_path,
                cfg.tpm_tcti,
                cfg.tpm_device,
                cfg.tpm_socket_host,
                cfg.tpm_socket_port,
                cfg.tpm_parent,
                cfg.tpm_hierarchy,
                cfg.tpm_password,
                cfg.tpm_password ? strlen(cfg.tpm_password) : 0);
        if (!ret) {
            printf("Failed. Exiting.\n");
            goto cleanup;
        }
#else
    fprintf(stderr, "Attempted to use a TPM, but not built with TPM enabled!\n");
    goto cleanup;
#endif
    } else {
        printf("Generating Key... ");
        ret = gen_key(&key);
        if (!ret) {
            printf("Failed. Exiting.\n");
            goto cleanup;
        }

        printf("Saving private key... ");
        ret = write_key(&key, full_key_path);
        if (!ret) {
            printf("Failed. Exiting.\n");
            goto cleanup;
        }
    }
    printf("Key saved to %s\n", full_key_path);

    /* Create a request to have IAM create a new endpoint */
    printf("Preparing IAM request... ");
    ret = iam_new_ep_auth_network_request(ipv6_network, key.hex_str, &ep_req);
    if (!ret) {
        printf("Failed. Exiting.\n");
        goto cleanup;
    }
    printf("Successful.\n");

    /* Send the request to IAM */
    printf("Requesting IP address... ");
    ret = iam_send_ep_auth(&ep_req, auth_creds.token, &ep_resp);
    if (!ret) {
        printf("Failed. Exiting.\n");
        goto cleanup;
    }
    printf("Successful. (%s)\n", ep_resp.address);

    /* Generate the certificate with the returned address */
    printf("Creating signed cert... ");
    ret = write_cert(&key, ep_resp.address, full_cert_path);
    if (!ret) {
        printf("Failed. Exiting.\n");

        /* TODO Unprovision */
        printf("Warning: IP Address %s is still provisioned.\n", ep_resp.address);
        goto cleanup;
    }
    printf("Successful.\n");
    printf("Note: Cert saved to %s\n", full_cert_path);

    printf("All operations were successful.\n");

    /* Clean up */
cleanup:
    destroy_key(&key);
    auth_login_destroy(&login);
    iam_create_endpoint_request_destroy(&ep_req);
    free(ipv6_network);
    free(enftun_cfg_file);
    enftun_config_free(&cfg);
    ep_auth_resp_destroy(&ep_resp);
    free(full_cert_path);
    free(full_key_path);
    free(enftun_path);

    return 0;
}
