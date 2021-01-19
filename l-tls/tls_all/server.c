#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_all.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
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

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
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
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED || MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED || MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server, client;
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    mbedtls_x509_crt cacert, srvcert;
    mbedtls_pk_context privkey;
#endif

    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    psk_entry *psk_info = NULL;
#endif

#if defined(MEASURE_SESSION)
    measure_context_t measure;

    char path[70] = FILE_PATH;
    char buffer[40];
#endif

    int ret,
        i, n_tests = N_TESTS,
        init_size = MIN_INPUT_SIZE,
        input_size = MAX_INPUT_SIZE,
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_server generates response";
    char *p, *q;
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    const unsigned char test_psk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
#if MBEDTLS_PSK_MAX_LEN == 32
        ,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        ,0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
#endif
    };
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
        if(strcmp(p, "n_tests") == 0) {
            n_tests = atoi(q);
            if(n_tests < 1 || n_tests > 1000) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Number of tests must be between 1 and 1000\n");
#endif
                return(1);
            }
        }
        else if(strcmp(p, "input_size") == 0) {
            init_size = atoi(q);
            if(init_size < MIN_INPUT_SIZE || init_size > MAX_INPUT_SIZE || init_size % MIN_INPUT_SIZE != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Input size must be multiple of %d, between %d and %d \n",
                       MIN_INPUT_SIZE, MIN_INPUT_SIZE, MAX_INPUT_SIZE);
#endif
                return(1);
            }
        }
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
            printf("Available options are input_size, n_tests, debug_level and ciphersuite\n");
#endif
            return(1);
        }
    }

    mbedtls_net_init(&server);
    mbedtls_net_init(&client);
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&privkey);
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

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    // Load psk list
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
#endif /* MBEDTLS_KEY_EXCHANGE_PSK_ENABLED || MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED || MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    // Load certificates and key
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the ca certificate................");
    fflush(stdout);
#endif

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {
        if((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse_ca returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    printf("\nLoading the server certificate............");
    fflush(stdout);
#endif

    if((ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt_rsa, mbedtls_test_srv_crt_rsa_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_x509_crt_parse_rsa returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    printf("\nLoading the server key....................");
    fflush(stdout);
#endif

    if((ret = mbedtls_pk_parse_key(&privkey, (const unsigned char *) mbedtls_test_srv_key_rsa, mbedtls_test_srv_key_rsa_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif /* MBEDTLS_KEY_EXCHANGE_RSA_ENABLED || MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED */

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

    // Setup ssl session
    printf("\nSetting up TLS session....................");
    fflush(stdout);
#endif

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
#endif

    if(suite_id != 0) {
        mbedtls_ssl_conf_ciphersuites(&tls_conf, &suite_id);
    }

#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    mbedtls_ssl_conf_psk_cb(&tls_conf, psk_callback, psk_info);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
#if defined(MUTUAL_AUTH)
    mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
    mbedtls_ssl_conf_ca_chain(&tls_conf, &cacert, NULL);

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &srvcert, &privkey)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
        goto exit;
    }
#endif

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MEASURE_SESSION)
    if((ret = measurement_measure_config(&measure)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! measurement_measure_config returned -0x%04x\n", -ret);
#endif
        goto exit;
    }
#endif

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

    // Listen and accept client
    for(i = 0; i < n_tests; i++) {
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

        mbedtls_ssl_set_bio(&tls, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

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

#if defined(MEASURE_SESSION)
        if(i == 0) {
            strcat(path, mbedtls_ssl_get_ciphersuite(&tls));
            mkdir(path, 0777);
            strcat(path, SESSION_EXTENSION);

            if((ret = measure_starts(&measure, path, "endpoint,min_input,max_input")) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! measure_starts returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }
#endif

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok");
        printf("\nPerforming TLS record:");
#endif

        for(input_size = init_size; input_size <= MAX_INPUT_SIZE; input_size *= 2) {
            request = (unsigned char *) malloc(input_size * sizeof(unsigned char));
            response = (unsigned char *) malloc(input_size * sizeof(unsigned char));

            // Generate the response
            memset(response, 0, input_size);

            if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, response, input_size)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
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

            free(request);
            free(response);
        }

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

        sprintf(buffer, "\nserver,%d,%d", init_size, input_size / 2);

        if((ret = measure_finish(&measure, path, buffer)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! measure_starts returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
#endif

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok\n");
#endif
    }

    // Final connection status
    printf("\n\nFinal status:");
#if defined(MBEDTLS_DEBUG_C)
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
#endif
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
#if defined(MBEDTLS_DEBUG_C)
    printf("\n  -Max record size:           %d", mbedtls_ssl_get_max_out_record_payload(&tls));
    printf("\n  -Max record expansion:      %d", mbedtls_ssl_get_record_expansion(&tls));

#if (defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)) && defined(MUTUAL_AUTH)
    ret = mbedtls_ssl_get_verify_result(&tls);
    printf("\n  -Server certificate verification:   %s", ret == 0 ? "Success" : "Failed");

    if(ret == 0) {
        char crt_buf[512];
        mbedtls_x509_crt_info(crt_buf, sizeof(crt_buf), "       ", mbedtls_ssl_get_peer_cert(&tls));
        printf("\n  -Server certificate:\n%s", crt_buf);
    }
#endif
#endif /* MBEDTLS_DEBUG_C */

    printf("\n");

exit:
#if defined(MEASURE_SESSION)
    measure_free(&measure);
#endif

    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    psk_free(psk_info);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    mbedtls_pk_free(&privkey);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
#endif
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);

    return(ret);
}