#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_psk.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
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
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

#if defined(MBEDTLS_DEBUG_C)
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
#endif

int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server;
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

    int ret, i,
        n_tests = N_TESTS,
        input_size = MIN_INPUT_SIZE,
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_client generate request",
                psk_id[] = CLI_ID;
    char *p, *q;
    const unsigned char test_psk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
#if MBEDTLS_PSK_MAX_LEN == 32
        ,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
#endif
    };

    for(i = 1; i < argc; i++) {
        p = argv[i];
        if((q = strchr(p, '=')) == NULL) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            printf("To assign own variables, run with <variable>=X\n");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
            return 1;
        }

        *q++ = '\0';
        if(strcmp(p, "n_tests") == 0) {
			n_tests = atoi(q);
            if(n_tests < 1 || n_tests > 1000) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf("Number of tests must be between 1 and 1000\n");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                return 1;
            }
		} else if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);
            if(input_size < MIN_INPUT_SIZE || input_size > MAX_INPUT_SIZE || input_size % MIN_INPUT_SIZE != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf("Input size must be multiple of %d, between %d and %d \n", MIN_INPUT_SIZE, MIN_INPUT_SIZE, MAX_INPUT_SIZE);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                return 1;
            }
        } 
#if defined(MBEDTLS_DEBUG_C) 
        else if(strcmp(p, "debug_level") == 0) {
            debug = atoi(q);
            if(debug < 0 || debug > 5) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf("Debug level must be int between 0 and 5\n");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                return 1;
            }
        }
#endif
        else if(strcmp(p, "ciphersuite") == 0) {
			if((suite_id = mbedtls_ssl_get_ciphersuite_id(q)) == 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf("%s is not an available ciphersuite\n", q);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                return 1;
            }
		} else {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
			printf("Available options are input_size, n_tests");
#if defined(MBEDTLS_DEBUG_C) 
            printf(", debug_level");
#endif
            printf(" and ciphersuite\n");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
			return 1;
		}
	}

    mbedtls_net_init(&server);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug);
#endif

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    // Seed the RNG
    printf("\nSeeding the random number generator.......");
    fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        goto exit;
    }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf(" ok");

    // Create socket and connect to server
    printf("\nConnecting client to tcp/%s/%s...", SERVER_IP, SERVER_PORT);
    fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
    
    if((ret = mbedtls_net_connect(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_net_connect returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        goto exit;     
    }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf(" ok");

    // Setup ssl session
    printf("\nSetting up TLS session....................");
    fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        goto exit;
    }

    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if(suite_id != 0) {
        mbedtls_ssl_conf_ciphersuites(&tls_conf, &suite_id);
    }
    
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
#endif
    
    if((ret = mbedtls_ssl_conf_psk(&tls_conf, test_psk, sizeof(test_psk), (const unsigned char *) psk_id, sizeof(psk_id) - 1)) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_ssl_conf_psk returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */ 
        goto exit;
    }

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        goto exit;
    }

    mbedtls_ssl_set_bio(&tls, &server, mbedtls_net_send, mbedtls_net_recv, NULL);

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf(" ok");

    // Handshake
    printf("\nPerforming TLS handshake..................");
    fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    while((ret = mbedtls_ssl_handshake(&tls)) != 0) {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            printf(" failed! mbedtls_ssl_handshake returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
            goto exit;
        }
    }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf(" ok");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    for(; input_size <= MAX_INPUT_SIZE; input_size *= 2) {
        request = (unsigned char*) malloc(input_size*sizeof(unsigned char));
        response = (unsigned char*) malloc(input_size*sizeof(unsigned char));

        // Generate the request
        memset(request, 0, input_size);

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, request, input_size)) != 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
            goto exit;
        }

        for(i = 0; i < n_tests; i++) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            // Send request
            printf("\n\n< Write to server:");
            fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

            if((ret = mbedtls_ssl_write(&tls, request, input_size)) < 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf(" mbedtls_net_send returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                goto exit;
            }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            printf(" %d bytes\n", ret);
            print_hex(request, input_size);
            fflush(stdout);

            // Receive response
            printf("\n> Read from server:");
            fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

            memset(response, 0, input_size);

            if((ret = mbedtls_ssl_read(&tls, response, input_size)) < 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
                printf(" mbedtls_net_recv returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
                goto exit;
            }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            printf(" %d bytes\n", ret);
            print_hex(response, input_size);
            fflush(stdout);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        }

        free(request);
        free(response);
    }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    // Close connection
    printf("\nClosing the connection....................");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
        printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n", -ret);
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
        goto exit;
    }

#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf(" ok");
#endif /* !MEASURE_CIPHER || !MEASURE_MD */

    // Final connection status
    printf("\n\nFinal status:");
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf("\n  -Max record size:           %d", mbedtls_ssl_get_max_out_record_payload(&tls));
    printf("\n  -Max record expansion:      %d", mbedtls_ssl_get_record_expansion(&tls));
#endif /* !MEASURE_CIPHER || !MEASURE_MD */
    printf("\n");

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
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

    return(ret);
}