#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_algs.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C)
#include "mbedtls/certs.h"
#endif
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#if defined(MBEDTLS_DHM_C) && \
    (defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE))
#include "dh_prime.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#if defined(MEASUREMENT_MEASURE_C)
#include <time.h>
#endif

#if defined(MBEDTLS_DEBUG_C)
#if defined(PRINT_MSG_HEX)
/*
 *  Print for the generated inputs
 */
void print_hex(unsigned char array[], int size) {
    int i;

    for(i = 0; i < size; i++) {
        printf("%.2x ", array[i]);

        if(((i + 1) % 16) == 0) {
            printf("\n");
        }
    }
}
#endif

/*
 *  Debug callback to be used in mbedtls_ssl_conf_dbg
 */
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    const char *p, *basename;

    /* Extract basename from file */
    for(p = basename = file; *p != '\0'; p++)
        if(*p == '/' || *p == '\\')
            basename = p + 1;

    fprintf((FILE *) ctx, "%s:%04d: |%d| %s", basename, line, level, str);
    fflush((FILE *) ctx);
}
#endif /* MBEDTLS_DEBUG_C */

#if defined(USE_PSK_C)
typedef struct _psk_entry psk_entry;

struct _psk_entry {
    const char *name;
    size_t key_len;
    unsigned char key[MBEDTLS_PSK_MAX_LEN];
    psk_entry *next;
};

/*
 * Free a list of psk_entry's
 */
void psk_free(psk_entry *head) {
    psk_entry *next;

    while(head != NULL) {
        next = head->next;
        free(head);
        head = next;
    }
}

/*
 * Parse a string of pairs name1,key1[,name2,key2[,...]]
 * into a usable psk_entry list.
 *
 * Modifies the input string! This is not production quality!
 */
psk_entry *psk_parse(const unsigned char *psk, int psk_len) {
    psk_entry *cur = NULL, *new = NULL;

    if((new = (psk_entry *) calloc(1, sizeof(psk_entry))) == NULL) {
        goto error;
    }

    memset(new, 0, sizeof(psk_entry));

    new->name = CLI_ID;
    memcpy(new->key, psk, psk_len);
    new->key_len = psk_len;
    new->next = cur;
    cur = new;

    return(cur);

error:
    psk_free(new);
    psk_free(cur);

    return(NULL);
}

/*
 * PSK callback
 */
int psk_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len) {
    psk_entry *cur = (psk_entry *) p_info;

    while(cur != NULL) {
        if(name_len == strlen(cur->name) && memcmp(name, cur->name, name_len) == 0) {
            return(mbedtls_ssl_set_hs_psk(ssl, cur->key, cur->key_len));
        }

        cur = cur->next;
    }

    return(-1);
}
#endif /* USE_PSK_C */

#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
#if defined(MBEDTLS_DHM_C)
const unsigned char *prepare_dhm_primes(int sec_lvl) {
    switch(sec_lvl) {
        case 0:
            return(dhp_1024);

        case 1:
            return(dhp_2048);

        case 2:
            return(dhp_3072);

        case 3:
            return(dhp_7680);

        case 4:
            return(dhp_15360);

        default:
            return(NULL);
    }
}
#endif /* MBEDTLS_DHM_C */

#if defined(MBEDTLS_ECP_C)
mbedtls_ecp_group_id *prepare_ecdh_curve(int sec_lvl) {
    mbedtls_ecp_group_id *ret = (mbedtls_ecp_group_id *) malloc(sizeof(mbedtls_ecp_group_id));

    switch(sec_lvl) {
        case 0:
            ret[0] = MBEDTLS_ECP_DP_SECP192R1;
            break;

        case 1:
            ret[0] = MBEDTLS_ECP_DP_SECP224R1;
            break;

        case 2:
            ret[0] = MBEDTLS_ECP_DP_SECP256R1;
            break;

        case 3:
            ret[0] = MBEDTLS_ECP_DP_SECP384R1;
            break;

        case 4:
            ret[0] = MBEDTLS_ECP_DP_SECP521R1;
            break;

        default:
            ret[0] = MBEDTLS_ECP_DP_NONE;
            break;
    }

    ret[1] = MBEDTLS_ECP_DP_NONE;

    return(ret);
}
#endif /* MBEDTLS_ECP_C */
#endif

int main(int argc, char **argv) {
    // Initial setup
    mbedtls_ssl_context tls;
    mbedtls_net_context server, client;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
#if defined(CLIENT_AUTHENTICATION)
    mbedtls_x509_crt cli_cert;
#endif
#if defined(MBEDTLS_RSA_C)
    mbedtls_x509_crt rsa_cert;
    mbedtls_pk_context rsa_key;
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_x509_crt ec_cert;
    mbedtls_pk_context ec_key;
#endif
    mbedtls_ssl_config tls_conf;
#if defined(USE_PSK_C)
    psk_entry *psk_info = NULL;
#endif

    int ret, i,
        msg_size = MIN_INPUT_SIZE,
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
        max_msg_size = MAX_INPUT_SIZE,
#endif
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        starting_lvl,
        sec_lvl = MIN_SEC_LVL,
        max_sec_lvl = MAX_SEC_LVL,
#endif
#if defined(MEASUREMENT_MEASURE_C)
        n_tests = N_TESTS,
#endif
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_server generates response";
    char *p, *q;
#if defined(CLIENT_AUTHENTICATION)
    uint32_t flags;
#endif
#if defined(MEASUREMENT_MEASURE_C)
    time_t rawtime;
    struct tm *timeinfo;
#endif
#if defined(MBEDTLS_DHM_C) && \
    (defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE))
    const unsigned char dhm_g[] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;
#endif
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
    char out_buf[BUFFER_LEN]
#if defined(MBEDTLS_RSA_C)
        , rsa_path[CERT_KEY_PATH_LEN]
#endif
#if defined(MBEDTLS_ECDSA_C)
        , ec_path[CERT_KEY_PATH_LEN]
#endif
#if defined(CLIENT_AUTHENTICATION) && \
    (defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C))
        , cli_cert_path[CERT_KEY_PATH_LEN]
#endif
    ;

#if defined(CLIENT_AUTHENTICATION)
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_custom = {
    /* Only SHA-2 hashes */
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA256 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA384 ) |
    MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA512 ),
    0xFFFFFFF,  /* Any PK alg     */
    0xFFFFFFF,  /* Any curve      */
    1024        /* Min RSA keylen */
};
#endif
#endif /* MEASURE_KE || MEASURE_HANDSHAKE */

#if defined(MEASUREMENT_MEASURE_C)
    data_path = (char*) malloc(sizeof(char)*PATH_SIZE);
#endif

    // Step 1: Parse the user input
    for(i = 1; i < argc; i++) {
        p = argv[i];

        if((q = strchr(p, '=')) == NULL) {
#if defined(MBEDTLS_DEBUG_C)
            printf("To assign own variables, run with <variable>=X\n");
#endif
            return(1);
        }

        *q++ = '\0';
        if(strcmp(p, "ciphersuite") == 0) {
            if((suite_id = mbedtls_ssl_get_ciphersuite_id(q)) == 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf("%s is not an available ciphersuite\n", q);
#endif
                return(1);
            }
        }
        else if(strcmp(p, "sec_lvl") == 0) {
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
            sec_lvl = atoi(q);

            if(sec_lvl < MIN_SEC_LVL || sec_lvl > MAX_SEC_LVL) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Maximum security level must be between %d and %d\n", MIN_SEC_LVL, MAX_SEC_LVL);
#endif
                return(1);
            }
#else /* MEASURE_KE || MEASURE_HANDSHAKE */
#if defined(MBEDTLS_DEBUG_C)
            printf("Option not available. Enable MEASURE_KE or MEASURE_HANDSHAKE\n");
#endif
#endif
		}
        else if(strcmp(p, "max_sec_lvl") == 0) {
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
            max_sec_lvl = atoi(q);

            if(max_sec_lvl < MIN_SEC_LVL || max_sec_lvl > MAX_SEC_LVL) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Maximum security level must be between %d and %d\n", MIN_SEC_LVL, MAX_SEC_LVL);
#endif
                return(1);
            }
#else /* MEASURE_KE || MEASURE_HANDSHAKE */
#if defined(MBEDTLS_DEBUG_C)
            printf("Option not available. Enable MEASURE_KE or MEASURE_HANDSHAKE\n");
#endif
#endif
		}
        else if(strcmp(p, "msg_size") == 0) {
            msg_size = atoi(q);

            if(msg_size < MIN_INPUT_SIZE || msg_size > MAX_INPUT_SIZE) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Input size must be between %d and %d\n", MIN_INPUT_SIZE, MAX_INPUT_SIZE);
#endif
                return(1);
            }
        }
        else if(strcmp(p, "max_msg_size") == 0) {
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
            max_msg_size = atoi(q);

            if(max_msg_size < MIN_INPUT_SIZE || max_msg_size > MAX_INPUT_SIZE) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Maximum input size must be between %d and %d\n", MIN_INPUT_SIZE, MAX_INPUT_SIZE);
#endif
                return(1);
            }
#else /* MEASURE_CIPHER || MEASURE_MD */
#if defined(MBEDTLS_DEBUG_C)
            printf("Option not available. Enable MEASURE_CIPHER or MEASURE_MD\n");
#endif
#endif
		}
        else if(strcmp(p, "n_tests") == 0) {
#if defined(MEASUREMENT_MEASURE_C)
            n_tests = atoi(q);

            if(n_tests < 1) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Number of tests must be bigger than 1\n");
#endif
                return(1);
            }
#else /* MEASUREMENT_MEASURE_C */
#if defined(MBEDTLS_DEBUG_C)
            printf("Option not available. Enable MEASURE_CIPHER, MEASURE_MD, MEASURE_KE or MEASURE_HANDSHAKE\n");
#endif
            return(1);
#endif
		}
        else if(strcmp(p, "path") == 0) {
#if defined(MEASUREMENT_MEASURE_C)
            strcpy(data_path, FILE_PATH);
            strcat(data_path, q);
            strcat(data_path, "/");
#else /* MEASUREMENT_MEASURE_C */
#if defined(MBEDTLS_DEBUG_C)
            printf("Option not available. Enable MEASURE_CIPHER, MEASURE_MD, MEASURE_KE or MEASURE_HANDSHAKE\n");
#endif
            return(1);
#endif
        }
#if defined(MBEDTLS_DEBUG_C)
        else if(strcmp(p, "debug_lvl") == 0) {
            debug = atoi(q);
            
            if(debug < 0 || debug > 5) {
                printf("Debug level must be int between 0 and 5\n");
                return(1);
            }
        }
#endif
        else {
#if defined(MBEDTLS_DEBUG_C)
            printf("Available options are ciphersuite");
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
            printf(" ,sec_lvl, max_sec_lvl");
#endif
            printf(", msg_size");
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
            printf(", max_msg_size");
#endif
#if defined(MEASUREMENT_MEASURE_C)
            printf(", n_tests, path");
#endif
            printf(" and debug_lvl\n");
            fflush(stdout);
#endif /* MBEDTLS_DEBUG_C */
            return(1);
        }
	}

    mbedtls_ssl_init(&tls);
    mbedtls_net_init(&server);
    mbedtls_net_init(&client);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
#if defined(CLIENT_AUTHENTICATION)
    mbedtls_x509_crt_init(&cli_cert);
#endif
#if !defined(MEASURE_KE) && !defined(MEASURE_HANDSHAKE)
#if defined(MBEDTLS_RSA_C)
    mbedtls_x509_crt_init(&rsa_cert);
    mbedtls_pk_init(&rsa_key);
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_x509_crt_init(&ec_cert);
    mbedtls_pk_init(&ec_key);
#endif
    mbedtls_ssl_config_init(&tls_conf);
#endif /* !MEASURE_KE && !MEASURE_HANDSHAKE */

#if defined(MEASUREMENT_MEASURE_C)
    if(strcmp(data_path, "") == 0) {
        sprintf(data_path, "%s", FILE_PATH);
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        sprintf(data_path, "%s%02d%02d%02d.%02d%02d/", FILE_PATH, timeinfo->tm_mday, timeinfo->tm_mon + 1,
                                        timeinfo->tm_year + 1900, timeinfo->tm_hour, timeinfo->tm_min);
    }
#endif

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug);
#endif

    // Step 2: Seed the RNG
#if defined(MBEDTLS_DEBUG_C)
    printf("\nSeeding the random number generator.......");
    fflush(stdout);
#endif

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    // Step 3: Create and bind socket to pretended IP and port
    printf("\nBinding server to tcp/%s/%s......", SERVER_IP, SERVER_PORT);
    fflush(stdout);
#endif

    if((ret = mbedtls_net_bind(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_net_bind returned -0x%04x\n", -ret);
#endif
        goto exit;      
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

    // Step 4: Load CA certificate(s)
#if (defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C)) && \
    defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the ca certificate(s).............");
    fflush(stdout);
#endif

#if defined(CLIENT_AUTHENTICATION)
#if !defined(MEASURE_KE) && !defined(MEASURE_HANDSHAKE)
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C)
    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {
        if((ret = mbedtls_x509_crt_parse(&cli_cert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse_ca returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
    }
#endif
#else /* !MEASURE_KE && !MEASURE_HANDSHAKE */
    for(i = sec_lvl; i <= max_sec_lvl; i++) {
#if defined(MBEDTLS_RSA_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "RSA") != NULL) {
            sprintf(cli_cert_path, "%scli_rsa_%d.crt", CERTS_PATH, asm_key_sizes[i]);

            if((ret = mbedtls_x509_crt_parse_file(&cli_cert, cli_cert_path))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECDSA_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "ECDSA") != NULL) {
            sprintf(cli_cert_path, "%scli_ec_%d.crt", CERTS_PATH, ecc_key_sizes[i]);

            if((ret = mbedtls_x509_crt_parse_file(&cli_cert, cli_cert_path))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif /* MBEDTLS_ECDSA_C */
    }
#endif /* !MEASURE_KE && !MEASURE_HANDSHAKE */
#endif

#if (defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C)) && \
    defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
    starting_lvl = sec_lvl;

    for(; sec_lvl <= max_sec_lvl; sec_lvl++) {
#if defined(MBEDTLS_RSA_C)
        mbedtls_x509_crt_init(&rsa_cert);
        mbedtls_pk_init(&rsa_key);
        memset(rsa_path, 0, CERT_KEY_PATH_LEN);
#endif
#if defined(MBEDTLS_ECDSA_C)
        mbedtls_x509_crt_init(&ec_cert);
        mbedtls_pk_init(&ec_key);
        memset(ec_path, 0, CERT_KEY_PATH_LEN);
#endif
        mbedtls_ssl_config_init(&tls_conf);
#endif

#if defined(MBEDTLS_DEBUG_C)
        printf("\nLoading required certs and keys...........");
        fflush(stdout);
#endif

    // Step 5: Load the required key(s) and certificate(s)
#if !defined(MEASURE_KE) && !defined(MEASURE_HANDSHAKE)
#if defined(USE_PSK_C)
        if((psk_info = psk_parse(test_psk, sizeof(test_psk))) == NULL) {
#if defined(MBEDTLS_DEBUG_C)
            printf("psk_list invalid");
#endif
            ret = -1;
            goto exit;
        }
#endif /* USE_PSK_C */

#if defined(MBEDTLS_RSA_C)
        if((ret = mbedtls_x509_crt_parse(&rsa_cert, (const unsigned char *) mbedtls_test_srv_crt_rsa, mbedtls_test_srv_crt_rsa_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

        if((ret = mbedtls_pk_parse_key(&rsa_key, (const unsigned char *) mbedtls_test_srv_key_rsa, mbedtls_test_srv_key_rsa_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
#endif /* MEBDTLS_RSA_C */

#if defined(MBEDTLS_ECDSA_C)
        if((ret = mbedtls_x509_crt_parse(&ec_cert, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

        if((ret = mbedtls_pk_parse_key(&ec_key, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
#endif /* MEBDTLS_ECDSA_C */
#else /* !MEASURE_KE && !MEASURE_HANDSHAKE */
#if defined(USE_PSK_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "PSK") != NULL) {
            if((psk_info = psk_parse(test_psk, psk_key_sizes[sec_lvl])) == NULL) {
#if defined(MBEDTLS_DEBUG_C)
                printf("psk_list invalid");
#endif
                ret = -1;
                goto exit;
            }
        }
#endif /* USE_PSK_C */

#if defined(MBEDTLS_RSA_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "RSA") != NULL) {
            if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "-ECDH-") != NULL) {
                sprintf(rsa_path, "%ssrv_ec_%d.crt", CERTS_PATH, ecc_key_sizes[sec_lvl]);
            } else {
                sprintf(rsa_path, "%ssrv_rsa_%d.crt", CERTS_PATH, asm_key_sizes[sec_lvl]);
            }

            if((ret = mbedtls_x509_crt_parse_file(&rsa_cert, rsa_path))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

            if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "-ECDH-") != NULL) {
                sprintf(rsa_path, "%ssrv_ec_%d.key", CERTS_PATH, ecc_key_sizes[sec_lvl]);
            } else {
                sprintf(rsa_path, "%ssrv_rsa_%d.key", CERTS_PATH, asm_key_sizes[sec_lvl]);
            }

            if((ret = mbedtls_pk_parse_keyfile(&rsa_key, rsa_path, NULL))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif /* MEBDTLS_RSA_C */

#if defined(MBEDTLS_ECDSA_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "ECDSA") != NULL) {
            sprintf(ec_path, "%ssrv_ec_%d.crt", CERTS_PATH, ecc_key_sizes[sec_lvl]);

            if((ret = mbedtls_x509_crt_parse_file(&ec_cert, ec_path))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_x509_crt_parse_file returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

            sprintf(ec_path, "%ssrv_ec_%d.key", CERTS_PATH, ecc_key_sizes[sec_lvl]);

            if((ret = mbedtls_pk_parse_keyfile(&ec_key, ec_path, NULL))) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_pk_parse_keyfile returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif /* MBEDTLS_ECDSA_C */
#endif /* !MEASURE_KE && !MEASURE_HANDSHAKE */

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok");
#endif

    // Step 6: Setup TLS session configurations
#if defined(MBEDTLS_DEBUG_C)
        printf("\nSetting up TLS session....................");
        fflush(stdout);
#endif

        if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(CLIENT_AUTHENTICATION)
        mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
        mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#if defined(MBEDTLS_DEBUG_C)
        mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
#endif
#if defined(MBEDTLS_ARC4_C)
        mbedtls_ssl_conf_arc4_support(&tls_conf, MBEDTLS_SSL_ARC4_ENABLED);
#endif

        if(suite_id != 0) {
            mbedtls_ssl_conf_ciphersuites(&tls_conf, &suite_id);
        }

#if defined(USE_PSK_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "PSK") != NULL) {
            mbedtls_ssl_conf_psk_cb(&tls_conf, psk_callback, psk_info);
        }
#endif

#if defined(CLIENT_AUTHENTICATION)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "RSA") != NULL ||
            strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "ECDSA") != NULL) {
            mbedtls_ssl_conf_ca_chain(&tls_conf, &cli_cert, NULL);
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
            mbedtls_ssl_conf_cert_profile(&tls_conf, &mbedtls_x509_crt_profile_custom);
#endif
        }
#endif

#if defined(MBEDTLS_RSA_C)
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "RSA") != NULL) {
#endif
            if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &rsa_cert, &rsa_key)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        }
#endif
#endif

#if defined(MBEDTLS_ECDSA_C)
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "ECDSA") != NULL) {
#endif
            if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &ec_cert, &ec_key)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        }
#endif
#endif

#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
#if defined(MBEDTLS_DHM_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "DHE") != NULL) {
            if((ret = mbedtls_ssl_conf_dh_param_bin(&tls_conf,
                                prepare_dhm_primes(sec_lvl), asm_key_sizes[sec_lvl]/8, dhm_g, sizeof(dhm_g))) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_conf_dh_param_ctx returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif

#if defined(MBEDTLS_ECP_C)
        if(strstr(mbedtls_ssl_get_ciphersuite_name(suite_id), "ECDHE") != NULL) {
            mbedtls_ssl_conf_curves(&tls_conf, (const mbedtls_ecp_group_id *) prepare_ecdh_curve(sec_lvl));
        }
#endif
#endif /* MEASURE_KE || MEASURE_HANDSHAKE */

        if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

        mbedtls_ssl_set_bio(&tls, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok");
#endif

    // Step 7: Perform the TLS handshake multiple times
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        for(i = 0; i < n_tests; i++) {
        // Step 7.1: Reset the session state
#if defined(MBEDTLS_DEBUG_C)
            printf("\nResetting the connection..................");
#endif

            if((ret = mbedtls_ssl_session_reset(&tls)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_session_reset returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" ok");
#endif
#endif  /* MEASURE_KE || MEASURE_HANDSHAKE */

        // Step 7.2: Wait for and accept client connection
#if defined(MBEDTLS_DEBUG_C)
            printf("\nWaiting for client to connect.............");
            fflush(stdout);
#endif

            if((ret = mbedtls_net_accept(&server, &client, NULL, 0, NULL)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_net_accept returned -0x%04x\n", -ret);
#endif
                goto exit; 
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" ok");

        // Step 7.3: Perform the handshake protocol
            printf("\nPerforming TLS handshake..................");
            fflush(stdout);
#endif

#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
            memset(out_buf, 0, BUFFER_LEN);
            sprintf(out_buf, "%d,%d", sec_lvl, i);
            strcpy(tls.test_and_sec_lvl, out_buf);
            tls.starting_lvl = starting_lvl;
#endif

            while((ret = mbedtls_ssl_handshake(&tls)) != 0) {
                if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#if defined(MBEDTLS_DEBUG_C)
                    printf(" failed! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
#endif
                    goto exit;
                }
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" ok");
#endif

        // Step 7.4: Verify client certificate, if using client auth
#if defined(CLIENT_AUTHENTICATION)
#if defined(MBEDTLS_DEBUG_C)
            printf("\nVerifying client certificate..............");
#endif

            if((flags = mbedtls_ssl_get_verify_result(&tls)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                char vrfy_buf[512];
                mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "", flags);
                printf(" failed! mbedtls_ssl_get_verify_result returned %s\n", vrfy_buf);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" ok");
#endif
#endif /* CLIENT_AUTHENTICATION */
#if defined(MEASURE_KE) || defined(MEASURE_HANDSHAKE)
        }
    }
#endif

    // Step 8: Perform the record protocol multiple times
#if defined(MBEDTLS_DEBUG_C)
    printf("\nPerforming TLS record:");
#endif

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
    for(; msg_size <= max_msg_size; msg_size *= 2) {
#endif
        request = (unsigned char*) malloc(msg_size*sizeof(unsigned char));
        response = (unsigned char*) malloc(msg_size*sizeof(unsigned char));

        // Step 8.1: Generate server response
        memset(response, 0, msg_size);

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, response, msg_size)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
        for(i = 0; i < n_tests; i++) {
#endif
        // Step 8.2: Receive client request
#if defined(MBEDTLS_DEBUG_C)
            printf("\n  > Read from client:");
            fflush(stdout);
#endif
            memset(request, 0, msg_size);

            if((ret = mbedtls_ssl_read(&tls, request, msg_size)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_read returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
            print_hex(request, msg_size);
#endif
            fflush(stdout);

        // Step 8.3: Send server response
            printf("\n  < Write to client:");
            fflush(stdout);
#endif /* MBEDTLS_DEBUG_C */

            if((ret = mbedtls_ssl_write(&tls, response, msg_size)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! mbedtls_ssl_write returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
            print_hex(response, msg_size);
#endif
            fflush(stdout);
#endif /* MBEDTLS_DEBUG_C */
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
        }
#endif

        free(request);
        free(response);
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
    }
#endif

    // Step 9: Close the connection
#if defined(MBEDTLS_DEBUG_C)
    printf("\nClosing the connection....................");
#endif

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n",-ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

    // Step 10: Show final connection status
    printf("\n\nFinal status:");    
#if !defined(MBEDTLS_DEBUG_C)
    if(ret == 0) {
#else
        printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
#endif
        printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
#if defined(MBEDTLS_DEBUG_C)
        printf("\n  -Max record size:           %d", mbedtls_ssl_get_max_out_record_payload(&tls));
        printf("\n  -Max record expansion:      %d", mbedtls_ssl_get_record_expansion(&tls));
#else
    } else {
        printf("\n  -Return code:          -0x%04x", ret);
    }
#endif
    printf("\n");

exit:
#if defined(USE_PSK_C)
    psk_free(psk_info);
#endif
    mbedtls_ssl_config_free(&tls_conf);
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_pk_free(&ec_key);
    mbedtls_x509_crt_free(&ec_cert);
#endif
#if defined(MBEDTLS_RSA_C)
    mbedtls_pk_free(&rsa_key);
    mbedtls_x509_crt_free(&rsa_cert);
#endif
#if defined(CLIENT_AUTHENTICATION)
    mbedtls_x509_crt_free(&cli_cert);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);
    mbedtls_ssl_free(&tls);

#if defined(MEASUREMENT_MEASURE_C)
    if(data_path != NULL) {
        free(data_path);
    }
#endif

#if defined(MEASURE_CIPHER)
    if(cipher_fname != NULL) {
        free(cipher_fname);
    }
#endif

#if defined(MEASURE_MD)
    if(md_fname != NULL) {
        free(md_fname);
    }
#endif

#if defined(MEASURE_KE)
    if(ke_fname != NULL) {
        free(ke_fname);
    }
#endif

#if defined(MEASURE_HANDSHAKE)
    if(hs_fname != NULL) {
        free(hs_fname);
    }
#endif

    return(-ret);
}