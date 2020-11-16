#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_tls.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/debug.h"
#include "mbedtls/md_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*
 *  Print for the generated inputs
 */
void print_hex(unsigned char array[], int size) {
    int i;

    for(i = 0; i < size; i++) {
        printf("%.2x", array[i]);
    }
    printf("\n");
}

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


int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server;
    mbedtls_x509_crt cacert;
#if defined(MUTUAL_AUTH)
    mbedtls_x509_crt clicert1, clicert2;
    mbedtls_pk_context privkey, privkey2;
#endif
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

    int ret, debug = DEBUG_LEVEL,
        i, n_tests = N_TESTS,
        input_size = MIN_INPUT_SIZE;
    unsigned char *request, *response;
    const char *pers = "tls_client generate request";
    char *p, *q;
    uint32_t flags;
#if defined(USE_PAPI_TLS_CIPHER) || defined(USE_PAPI_TLS_MD)
    FILE *csv;
#endif

    for(i = 1; i < argc; i++) {
        p = argv[i];
        if((q = strchr(p, '=')) == NULL) {
            printf("To assign own variables, run with <variable>=X\n");
            return 1;
        }

        *q++ = '\0';
        if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);
            if(input_size < MIN_INPUT_SIZE || input_size > MAX_INPUT_SIZE || input_size % MIN_INPUT_SIZE != 0) {
                printf("Input size must be multiple of %d, between %d and %d \n", MIN_INPUT_SIZE, MIN_INPUT_SIZE, MAX_INPUT_SIZE);
                return 1;
            }
        } else if(strcmp(p, "debug_level") == 0) {
            debug = atoi(q);
            if(debug < 0 || debug > 5) {
                printf("Debug level must be int between 0 and 5\n");
                return 1;
            }
        } else if(strcmp(p, "n_tests") == 0) {
			n_tests = atoi(q);
            if(n_tests < 1 || n_tests > 1000) {
                printf("Number of tests must be between 1 and 1000\n");
                return 1;
            }
		} else {
			printf("Available options are input_size, key_size and n_tests\n");
			return 1;
		}
	}

    mbedtls_net_init(&server);
    mbedtls_x509_crt_init(&cacert);
#if defined(MUTUAL_AUTH)
    mbedtls_x509_crt_init(&clicert1);
    mbedtls_x509_crt_init(&clicert2);
    mbedtls_pk_init(&privkey);
    mbedtls_pk_init(&privkey2);
#endif
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

    mbedtls_debug_set_threshold(debug);

    // Load certificates and key
    printf("\nLoading the ca certificate................");
    fflush(stdout);

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {        
        if((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
            printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
            goto exit;
        }
    }

    printf(" ok");
#if defined(MUTUAL_AUTH)

    printf("\nLoading the client certificate............");
    fflush(stdout);

    if((ret = mbedtls_x509_crt_parse(&clicert1, (const unsigned char *) mbedtls_test_cli_crt_rsa, mbedtls_test_cli_crt_rsa_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_x509_crt_parse(&clicert2, (const unsigned char *) mbedtls_test_cli_crt_ec, mbedtls_test_cli_crt_ec_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");

    printf("\nLoading the client key....................");
    fflush( stdout );

    if((ret = mbedtls_pk_parse_key(&privkey, (const unsigned char *) mbedtls_test_cli_key_rsa, mbedtls_test_cli_key_rsa_len, NULL, 0)) != 0) {
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_pk_parse_key(&privkey2, (const unsigned char *) mbedtls_test_cli_key_ec, mbedtls_test_cli_key_ec_len, NULL, 0)) != 0) {
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");
#endif

    // Seed the RNG
    printf("\nSeeding the random number generator.......");
    fflush(stdout);

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
        printf(" failed! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");

    // Create socket and connect to server
    printf("\nConnecting client to tcp/%s/%s...", SERVER_IP, SERVER_PORT);
    fflush(stdout);
    
    if((ret = mbedtls_net_connect(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf(" failed! mbedtls_net_connect returned -0x%04x\n", -ret);
        goto exit;     
    }

    printf(" ok");

    // Setup ssl session
    printf("\nSetting up TLS session....................");
    fflush(stdout);

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
    mbedtls_ssl_conf_ca_chain(&tls_conf, &cacert, NULL);
#if defined(MUTUAL_AUTH)

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &clicert1, &privkey)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &clicert2, &privkey2)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
        goto exit;
    }
#endif

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
        printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_set_hostname(&tls, SERVER_IP)) != 0) {
        printf(" failed! mbedtls_ssl_set_hostname returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&tls, &server, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf(" ok");

    // Handshake
    printf("\nPerforming TLS handshake..................");
    fflush(stdout);

    while((ret = mbedtls_ssl_handshake(&tls)) != 0) {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf(" failed! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
            goto exit;
        }
    }

    printf(" ok");

    // Verify server certificate
    printf("\nVerifying server certificate..............");

    if((flags = mbedtls_ssl_get_verify_result(&tls)) != 0) {
        char vrfy_buf[512];
        
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof( vrfy_buf ), "", flags);
        printf(" failed! mbedtls_ssl_get_verify_result returned %s\n", vrfy_buf);
        goto exit;
    }

    printf(" ok");

    sleep(1); // sleep 1 sec in order to differentiate the handshake and data transmission in Wireshark
    for(; input_size <= MAX_INPUT_SIZE; input_size *= 2) {
        request = (unsigned char*) malloc(input_size*sizeof(unsigned char));
        response = (unsigned char*) malloc(input_size*sizeof(unsigned char));

        // Generate the request
        memset(request, 0, input_size);

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, request, input_size)) != 0) {
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
            goto exit;
        }

        for(i = 0; i < N_TESTS; i++) {
            // Send request
            printf("\n\n< Write to server:");
            fflush(stdout);

            if((ret = mbedtls_ssl_write(&tls, request, input_size)) < 0) {
                printf( " mbedtls_net_send returned -0x%04x\n", -ret );
                goto exit;
            }

            printf(" %d bytes\n", ret);
#if !defined(USE_PAPI_TLS_CIPHER) && !defined(USE_PAPI_TLS_MD) && !defined(USE_PAPI_TLS_MD_II)
            print_hex(request, input_size);
#endif
            fflush(stdout);

#if defined(USE_PAPI_TLS_CIPHER)
            csv = fopen(cipher_fname, "a+");    
            fprintf(csv, ",client,%d", input_size);
            fclose(csv);
#endif

#if defined(USE_PAPI_TLS_MD)
            csv = fopen(md_fname, "a+");    
            fprintf(csv, ",client,%d", input_size);
            fclose(csv);
#endif

            // Receive response
            printf("\n> Read from server:");
            fflush(stdout);

            memset(response, 0, input_size);

            if((ret = mbedtls_ssl_read(&tls, response, input_size)) < 0) {
                printf( " mbedtls_net_recv returned -0x%04x\n", -ret );
                goto exit;
            }

            printf(" %d bytes\n", ret);
#if !defined(USE_PAPI_TLS_CIPHER) && !defined(USE_PAPI_TLS_MD) && !defined(USE_PAPI_TLS_MD_II)
            print_hex(response, input_size);
#endif
            fflush(stdout);

#if defined(USE_PAPI_TLS_CIPHER)
            csv = fopen(cipher_fname, "a+");    
            fprintf(csv, ",client,%d", input_size);
            fclose(csv);
#endif

#if defined(USE_PAPI_TLS_MD)
            csv = fopen(md_fname, "a+");    
            fprintf(csv, ",client,%d", input_size);
            fclose(csv);
#endif
        }

        free(request);
        free(response);
    }

#if defined(USE_PAPI_TLS_CIPHER) || !defined(USE_PAPI_TLS_MD) || defined(USE_PAPI_TLS_MD_II)
    sleep(2);
#endif

    // Close connection
    printf("\nClosing the connection....................");

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
        printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");

#if defined(USE_PAPI_TLS_CIPHER)
    csv = fopen(cipher_fname, "a+");
    fprintf(csv, ",client,close");
    fclose(csv);
#endif

#if defined(USE_PAPI_TLS_MD)
    csv = fopen(md_fname, "a+");
    fprintf(csv, ",client,close");
    fclose(csv);
#endif

    // Final connection status
    printf("\n\nFinal status:");
    ret = mbedtls_ssl_get_verify_result(&tls);
    printf("\n  -Server certificate verification:   %s", ret == 0 ? "Success" : "Failed");

    if(ret == 0) {
        char crt_buf[512];
        mbedtls_x509_crt_info(crt_buf, sizeof(crt_buf), "       ", mbedtls_ssl_get_peer_cert(&tls));
        printf("\n  -Server certificate:\n%s", crt_buf);
    }

    printf("\n");

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
#if defined(MUTUAL_AUTH)
    mbedtls_pk_free(&privkey2);
    mbedtls_pk_free(&privkey);
    mbedtls_x509_crt_free(&clicert2);
    mbedtls_x509_crt_free(&clicert1);
#endif
    mbedtls_x509_crt_free(&cacert);
    mbedtls_net_free(&server);

    return(ret);
}