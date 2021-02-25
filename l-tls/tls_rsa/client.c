#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_rsa.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/certs.h"
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#if defined(MEASURE_KE)
#include <sys/stat.h>
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

int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server;
    mbedtls_x509_crt ca_cert;
#if defined(MUTUAL_AUTH)
    mbedtls_x509_crt cli_cert;
    mbedtls_pk_context cli_key;
#endif
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

#if defined(MEASURE_KE)
    char path[PATH_SIZE] = FILE_PATH;
    char *ke_fname;
#endif

    int ret, i,
        input_size = MIN_INPUT_SIZE,
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || defined(MEASURE_KE)
        n_tests = N_TESTS,
#endif
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_client generate request";
    char *p, *q;
    uint32_t flags;

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

            if(input_size < MIN_INPUT_SIZE || input_size > MAX_INPUT_SIZE) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Input size must be between %d and %d \n", MIN_INPUT_SIZE, MAX_INPUT_SIZE);
#endif
                return(1);
            }
        }
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || defined(MEASURE_KE)
        else if(strcmp(p, "n_tests") == 0) {
            n_tests = atoi(q);

            if(n_tests < 1 || n_tests > N_TESTS) {
#if defined(MBEDTLS_DEBUG_C)
                printf("Number of tests must be between 1 and %d\n", N_TESTS);
#endif
                return(1);
            }
		}
#endif /* MEASURE_CIPHER || MEASURE_MD || MEASURE_KE */
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
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || defined(MEASURE_KE)
            printf("n_tests, ");
#endif
            printf("debug_level and ciphersuite\n");
#endif /* MBEDTLS_DEBUG_C */
            return(1);
        }
	}

    mbedtls_net_init(&server);
    mbedtls_x509_crt_init(&ca_cert);
#if defined(MUTUAL_AUTH)
    mbedtls_x509_crt_init(&cli_cert);
    mbedtls_pk_init(&cli_key);
#endif
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug);

    // Load CA certificate(s)
    printf("\nLoading the ca certificate................");
    fflush(stdout);
#endif

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {        
        if((ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
            goto exit;
        }
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

    // Load client certificate and key
#if defined(MUTUAL_AUTH)
#if defined(MBEDTLS_DEBUG_C)
    printf("\nLoading the client certificate............");
    fflush(stdout);
#endif

    if((ret = mbedtls_x509_crt_parse(&cli_cert, (const unsigned char *) mbedtls_test_cli_crt_rsa, mbedtls_test_cli_crt_rsa_len)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");

    printf("\nLoading the client key....................");
    fflush(stdout);
#endif

    if((ret = mbedtls_pk_parse_key(&cli_key, (const unsigned char *) mbedtls_test_cli_key_rsa, mbedtls_test_cli_key_rsa_len, NULL, 0)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif
#endif /* MUTUAL_AUTH */

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

    // Setup ssl session
    printf("\nSetting up TLS session....................");
    fflush(stdout);
#endif

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

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

    mbedtls_ssl_conf_ca_chain(&tls_conf, &ca_cert, NULL);

#if defined(MUTUAL_AUTH)
    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &cli_cert, &cli_key)) != 0) {
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

    if((ret = mbedtls_ssl_set_hostname(&tls, SERVER_IP)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
        printf(" failed! mbedtls_ssl_set_hostname returned -0x%04x\n", -ret);
#endif
        goto exit;
    }

    mbedtls_ssl_set_bio(&tls, &server, mbedtls_net_send, mbedtls_net_recv, NULL);

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
#endif

#if defined(MEASURE_KE)
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
#endif
#endif /* MEASURE_KE */

        // Create socket and connect to server
#if defined(MBEDTLS_DEBUG_C)
        printf("\nConnecting client to tcp/%s/%s...", SERVER_IP, SERVER_PORT);
        fflush(stdout);
#endif

        if((ret = mbedtls_net_connect(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_net_connect returned -0x%04x\n", -ret);
#endif
            goto exit;     
        }

#if defined(MBEDTLS_DEBUG_C)
        printf(" ok");

        // Handshake
        printf("\nPerforming TLS handshake..................");
        fflush(stdout);
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

        // Verify server certificate
        printf("\nVerifying server certificate..............");
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

#if defined(MEASURE_KE)
        if(i == 0) {
            strcat(path, mbedtls_ssl_get_ciphersuite(&tls));
            mkdir(path, 0777);

            ke_fname = (char *) malloc((strlen(path) + KE_FNAME_SIZE)*sizeof(char));
            strcpy(ke_fname, path);
            strcat(ke_fname, KE_EXTENSION);

            if((ret = measure_starts(tls.ke_msr_ctx, ke_fname, "endpoint")) != 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" failed! measure_starts returned -0x%04x\n", -ret);
#endif
                goto exit;
            }
        }

        if((ret = measure_finish(tls.ke_msr_ctx, ke_fname, "client")) != 0) {
            return(ret);
        }
    }
#endif /* MEASURE_KE */

#if defined(MBEDTLS_DEBUG_C)
    printf("\nPerforming TLS record:");
#endif

    for(; input_size <= MAX_INPUT_SIZE; input_size *= 2) {
        request = (unsigned char*) malloc(input_size*sizeof(unsigned char));
        response = (unsigned char*) malloc(input_size*sizeof(unsigned char));

        // Generate the request
        memset(request, 0, input_size);

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, request, input_size)) != 0) {
#if defined(MBEDTLS_DEBUG_C)
            printf(" failed! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
#endif
            goto exit;
        }

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
        for(i = 0; i < n_tests; i++) {
#endif
            // Send request
#if defined(MBEDTLS_DEBUG_C)
            printf("\n  < Write to server:");
            fflush(stdout);
#endif

            if((ret = mbedtls_ssl_write(&tls, request, input_size)) < 0) {
#if defined(MBEDTLS_DEBUG_C)
                printf(" mbedtls_ssl_write returned -0x%04x\n", -ret);
#endif
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
            print_hex(request, input_size);
#endif
            fflush(stdout);

            // Receive response
            printf("\n  > Read from server:");
            fflush(stdout);
#endif /* MBEDTLS_DEBUG_C */

            memset(response, 0, input_size);

            if((ret = mbedtls_ssl_read(&tls, response, input_size)) < 0) {
                printf(" mbedtls_ssl_read returned -0x%04x\n", -ret);
                goto exit;
            }

#if defined(MBEDTLS_DEBUG_C)
            printf(" %d bytes\n", ret);
#if defined(PRINT_MSG_HEX)
            print_hex(response, input_size);
#endif
            fflush(stdout);
#endif /* MBEDTLS_DEBUG_C */
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
        }
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

#if defined(MBEDTLS_DEBUG_C)
    printf(" ok");
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

    if((ret = mbedtls_ssl_get_verify_result(&tls)) == 0) {
        char crt_buf[512];

        mbedtls_x509_crt_info(crt_buf, sizeof(crt_buf), "       ", mbedtls_ssl_get_peer_cert(&tls));
        printf("\n  -Server certificate:\n%s", crt_buf);
    }
#endif

    printf("\n");

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#if defined(MUTUAL_AUTH)
    mbedtls_pk_free(&cli_key);
    mbedtls_x509_crt_free(&cli_cert);
#endif
    mbedtls_x509_crt_free(&ca_cert);
    mbedtls_net_free(&server);

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

#if defined(MEASURE_KE_ROUTINES)
    if(ke_routines_fname != NULL) {
        free(ke_routines_fname);
    }
#endif

    return(ret);
}