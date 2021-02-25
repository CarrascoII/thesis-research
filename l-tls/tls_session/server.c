#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_session.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
#include "mbedtls/certs.h"
#endif
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#if defined(MEASURE_SESSION)
#include "measurement/measure.h"

#include <sys/stat.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server, client;
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
    mbedtls_x509_crt ca_cert;
#endif
#if defined(MBEDTLS_RSA_C)
    mbedtls_x509_crt rsa_cert;
    mbedtls_pk_context rsa_key;
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_x509_crt ec_cert;
    mbedtls_pk_context ec_key;
#endif
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;
#if defined(USE_PSK_C)
    psk_entry *psk_info = NULL;
#endif

#if defined(MEASURE_SESSION)
    measure_context_t measure;

    char path[PATH_SIZE] = FILE_PATH;
    char buffer[40];
#endif

    int ret, i,
        input_size = MAX_INPUT_SIZE,
#if defined(MEASURE_SESSION)
        n_tests = N_TESTS,
#endif
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_server generates response";
    char *p, *q;
#if defined(USE_PSK_C)
    const unsigned char test_psk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
#if MBEDTLS_PSK_MAX_LEN == 32
        ,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        ,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
#endif
    };
#endif
#if defined(MUTUAL_AUTH)
    uint32_t flags;
#endif

    for(i = 1; i < argc; i++) {
        p = argv[i];

        if((q = strchr(p, '=')) == NULL) {
#if defined(MBEDTLS_DEBUG_C)
            printf("To assign own variables, run with <variable>=X\n");
#endif
            return(1);
        }

        *q++ = '\0';
        if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);

            if(input_size < 0 || input_size > MAX_INPUT_SIZE) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Input size must be between 0 and %d\n", MAX_INPUT_SIZE);
#endif
                return(1);
            }
        }
#if defined(MEASURE_SESSION)
        else if(strcmp(p, "n_tests") == 0) {
            n_tests = atoi(q);

            if(n_tests < 1 || n_tests > N_TESTS) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Number of tests must be between 1 and %d\n", N_TESTS);
#endif
                return(1);
            }
		}
#endif /* MEASURE_SESSION */
#if defined(MBEDTLS_DEBUG_C)
        else if(strcmp(p, "debug_level") == 0) {
            debug = atoi(q);
            
            if(debug < 0 || debug > 5) {
                printf("Debug level must be int between 0 and 5\n");
                return(1);
            }
        }
#endif
        else if(strcmp(p, "ciphersuite") == 0) {
            if((suite_id = mbedtls_ssl_get_ciphersuite_id(q)) == 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf("%s is not an available ciphersuite\n", q);
#endif
                return(1);
            }
        }
        else {
#if defined(MBEDTLS_DEBUG_C)
            printf("Available options are input_size, ");
#if defined(MEASURE_SESSION)
            printf("n_tests, ");
#endif
            printf("debug_level and ciphersuite\n");
#endif /* MBEDTLS_DEBUG_C */
            return(1);
        }
	}

    mbedtls_net_init(&server);
    mbedtls_net_init(&client);
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
    mbedtls_x509_crt_init(&ca_cert);
#endif
#if defined(MBEDTLS_RSA_C)
    mbedtls_x509_crt_init(&rsa_cert);
    mbedtls_pk_init(&rsa_key);
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_x509_crt_init(&ec_cert);
    mbedtls_pk_init(&ec_key);
#endif
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

#if defined(MEASURE_SESSION)
    measure_init(&measure);
#endif

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug);
#endif

    request = (unsigned char *) malloc(input_size * sizeof(unsigned char));
    response = (unsigned char *) malloc(input_size * sizeof(unsigned char));

    // Load PSK list
#if defined(USE_PSK_C)
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the psk list......................");
    fflush(stdout);
#endif

    if((psk_info = psk_parse(test_psk, sizeof(test_psk))) == NULL) {
#if defined(MBEDTLS_DEBUG_C)
        printf("psk_list invalid");
#endif
        ret = -1;
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif /* USE_PSK_C */

    // Load CA certificate(s)
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the ca certificate(s).............");
    fflush(stdout);
#endif

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {
        if((ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse_ca returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif

    // Load server RSA certificate and key
#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the server rsa certificate........");
    fflush(stdout);
#endif

    if((ret = mbedtls_x509_crt_parse(&rsa_cert, (const unsigned char *) mbedtls_test_srv_crt_rsa, mbedtls_test_srv_crt_rsa_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    printf("\nLoading the server rsa key................");
    fflush(stdout);
#endif

    if((ret = mbedtls_pk_parse_key(&rsa_key, (const unsigned char *) mbedtls_test_srv_key_rsa, mbedtls_test_srv_key_rsa_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif /* MBEDTLS_RSA_C */

    // Load server EC certificate and key
#if defined(MBEDTLS_ECDSA_C)
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the server ec certificate.........");
    fflush(stdout);
#endif

    if((ret = mbedtls_x509_crt_parse(&ec_cert, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    printf("\nLoading the server ec key.................");
    fflush(stdout);
#endif

    if((ret = mbedtls_pk_parse_key(&ec_key, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif /* MBEDTLS_ECDSA_C */

    // Seed the RNG
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

    // Create and bind socket
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

    // Setup TLS session
    printf("\nSetting up TLS session....................");
    fflush(stdout);
#endif

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MUTUAL_AUTH)
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
    mbedtls_ssl_conf_psk_cb(&tls_conf, psk_callback, psk_info);
#endif
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
    mbedtls_ssl_conf_ca_chain(&tls_conf, &ca_cert, NULL);
#endif

#if defined(MBEDTLS_RSA_C)
    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &rsa_cert, &rsa_key)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
#endif
        goto exit;
    }
#endif

#if defined(MBEDTLS_ECDSA_C)
    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &ec_cert, &ec_key)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
#endif
        goto exit;
    }
#endif

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

    mbedtls_ssl_set_bio(&tls, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

#if defined(MEASURE_SESSION)
    if((ret = measurement_measure_config(&measure)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! measurement_measure_config returned -0x%04x\n", -ret);
#endif
        goto exit;
    }
#endif

    // Generate the response
    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, response, input_size)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

#if defined(MEASURE_SESSION)
    for(i = 0; i < n_tests; i++) {
#endif
        // Reset the connection
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

        // Create socket and await for client to connect
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

        // Handshake
        printf("\nPerforming TLS handshake..................");
        fflush(stdout);
#endif

#if defined(MEASURE_SESSION)
        if((ret = measure_get_vals(&measure, MEASURE_START)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! measure_get_vals returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
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

        // Verify client certificate
#if defined(MUTUAL_AUTH)
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
#endif

#if defined(MBEDTLS_DEBUG_C)
        printf("\nPerforming TLS record:");

        // Receive request
        printf("\n  > Read from client:");
        fflush(stdout);
#endif
        memset(request, 0, input_size);
        
        if((ret = mbedtls_ssl_read(&tls, request, input_size)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ssl_read returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(MBEDTLS_DEBUG_C)
        printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
        print_hex(request, input_size);
#endif
        fflush(stdout);

        // Send response
        printf("\n  < Write to client:");
        fflush(stdout);
#endif

        if((ret = mbedtls_ssl_write(&tls, response, input_size)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ssl_write returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(MBEDTLS_DEBUG_C)
        printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
        print_hex(response, input_size);
#endif
        fflush(stdout);
#endif

        // Close connection
#if defined(MBEDTLS_DEBUG_C)
        printf("\nClosing the connection....................");
#endif

        if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(MEASURE_SESSION)
        if((ret = measure_get_vals(&measure, MEASURE_END)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! measure_get_vals returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

        if(i == 0) {
            strcat(path, mbedtls_ssl_get_ciphersuite(&tls));
            mkdir(path, 0777);
            strcat(path, SESSION_EXTENSION);

            if((ret = measure_starts(&measure, path, "endpoint,data_size")) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! measure_starts returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }

        sprintf(buffer, "server,%d", input_size);

        if((ret = measure_finish(&measure, path, buffer)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! measure_starts returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
#endif

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok");
#endif
#if defined(MEASURE_SESSION)
    }
#endif

    // Final connection status
    printf("\n\nFinal status:");
#if defined(MBEDTLS_DEBUG_C)
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
#endif
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
#if defined(MBEDTLS_DEBUG_C)
    printf("\n  -Max record size:           %d", mbedtls_ssl_get_max_out_record_payload(&tls));
    printf("\n  -Max record expansion:      %d", mbedtls_ssl_get_record_expansion(&tls));

#if defined(MUTUAL_AUTH)
    if((ret = mbedtls_ssl_get_verify_result(&tls)) == 0) {
        char crt_buf[512];
        mbedtls_x509_crt_info(crt_buf, sizeof(crt_buf), "       ", mbedtls_ssl_get_peer_cert(&tls));
        printf("\n  -Client certificate:\n%s", crt_buf);
    }
#endif
#endif

    printf("\n");

exit:
    free(request);
    free(response);

#if defined(MEASURE_SESSION)
    measure_free(&measure);
#endif

    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#if defined(USE_PSK_C)
    psk_free(psk_info);
#endif
#if defined(MBEDTLS_ECDSA_C)
    mbedtls_pk_free(&ec_key);
    mbedtls_x509_crt_free(&ec_cert);
#endif
#if defined(MBEDTLS_RSA_C)
    mbedtls_pk_free(&rsa_key);
    mbedtls_x509_crt_free(&rsa_cert);
#endif
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
    mbedtls_x509_crt_free(&ca_cert);
#endif
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);

    return(ret);
}