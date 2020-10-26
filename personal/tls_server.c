#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(USE_PAPI)
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


int main(int argc, char **argv) {
    // Initial setup
    mbedtls_net_context server, client;
    mbedtls_x509_crt cacert, srvcert, srvcert2;
    mbedtls_pk_context privkey, privkey2;    
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

    int ret, debug = DEBUG_LEVEL,
        i, n_tests = N_TESTS,
        input_size = MIN_INPUT_SIZE;
    unsigned char *buffer;
    const char *pers = "tls_server",
               *response = "drbg generate response";
    char *p, *q;
#if defined(USE_PAPI)
    char filename[30] = "../docs/";
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

    mbedtls_debug_set_threshold(debug);

    mbedtls_net_init(&server);
    mbedtls_net_init(&client);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&privkey);
    mbedtls_x509_crt_init(&srvcert2);
    mbedtls_pk_init(&privkey2);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

    // Load certificates and key
    printf("\nLoading the ca cert....................");
    fflush(stdout);

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {        
        if((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
            printf(" failed! mbedtls_x509_crt_parse_ca returned -0x%x\n", -ret);
            goto exit;
        }
    }

    printf(" ok");

    printf("\nLoading the server cert................");
    fflush(stdout);

    if((ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt_rsa, mbedtls_test_srv_crt_rsa_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse_rsa returned -0x%x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_x509_crt_parse(&srvcert2, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse_ec returned -0x%x\n", -ret);
        goto exit;
    }

    printf(" ok");

    printf("\nLoading the server key.................");
    fflush( stdout );

    if((ret = mbedtls_pk_parse_key(&privkey, (const unsigned char *) mbedtls_test_srv_key_rsa, mbedtls_test_srv_key_rsa_len, NULL, 0)) != 0) {
        printf(" failed! mbedtls_pk_parse_key returned -0x%x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_pk_parse_key(&privkey2, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0)) != 0) {
        printf(" failed! mbedtls_pk_parse_key returned -0x%x\n", -ret);
        goto exit;
    }

    printf(" ok");

    // Create and bind socket
    printf("\nBinding server to tcp/%s/%s.....", SERVER_IP, SERVER_PORT);
    fflush(stdout);

    if((ret = mbedtls_net_bind(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf(" failed! mbedtls_net_bind returned -0x%x\n", -ret);
        goto exit;      
    }

    printf(" ok");

    // Seed the RNG
    printf("\nSeeding the random number generator....");
    fflush(stdout);

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
        printf(" failed! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }

    printf(" ok");

    // Setup ssl session
    printf("\nSetting up TLS session.................");
    fflush(stdout);

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%x\n", -ret);
        goto exit;
    }

//    mbedtls_ssl_conf_ciphersuites(&tls_conf, ciphersuites);
    mbedtls_ssl_conf_ca_chain(&tls_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &srvcert2, &privkey2)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &srvcert, &privkey)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
        printf(" failed! mbedtls_ssl_setup returned -0x%x\n", -ret);
        goto exit;
    }

    printf(" ok");

    // Listen and accept client
    printf("\nWaiting for client to connect..........");
    fflush(stdout);

    if((ret = mbedtls_net_accept(&server, &client, NULL, 0, NULL)) != 0) {
        printf(" failed! mbedtls_net_accept returned -0x%x\n", -ret);
        goto exit; 
    }

    mbedtls_ssl_set_bio(&tls, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf(" ok");

    // Handshake
    printf("\nPerforming TLS handshake...............");
    fflush(stdout);

    while((ret = mbedtls_ssl_handshake(&tls)) != 0) {
        if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf(" failed! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            goto exit;
        }
    }

    printf(" ok");

#if defined(USE_PAPI)
    // Create the csv file for symmetric cipher alg
    strcat(filename, get_cipher_name(&tls));
#if defined(MBEDTLS_AES_ENCRYPT_ALT) && defined(MBEDTLS_AES_SETKEY_ENC_ALT) && \
    defined(MBEDTLS_AES_DECRYPT_ALT) && defined(MBEDTLS_AES_SETKEY_DEC_ALT)
    strcat(filename, "-ALT.csv");
#else
    strcat(filename, ".csv");
#endif
#endif

    for(; input_size < MAX_INPUT_SIZE; input_size *= 2) {
        buffer = (unsigned char*) malloc(input_size*sizeof(unsigned char));

        // Receive request
        printf("\n\n> Read from client:");
        fflush(stdout);

        memset(buffer, 0, input_size);

        if((ret = mbedtls_ssl_read(&tls, buffer, input_size)) < 0) {
            printf(" failed! mbedtls_ssl_read returned -0x%x\n", -ret);
            goto exit;
        }

//        printf(" %d bytes\n%s\n", ret, (char *) buffer);
        printf(" %d bytes\n", ret);
        fflush(stdout);

#if defined(USE_PAPI)
        csv = fopen(filename, "a+");    
        fprintf(csv, "\nserver,%d", input_size);
        fclose(csv);
#endif

        // Generate the response
        memset(buffer, 0, input_size);

        if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) response, strlen(response))) != 0) {
                printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
                goto exit;
            }

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, buffer, input_size)) != 0) {
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
            goto exit;
        }

        // Send response
        printf("\n< Write to client:");
        fflush(stdout);

        if((ret = mbedtls_ssl_write(&tls, buffer, input_size)) < 0) {
            printf(" failed! mbedtls_ssl_write returned -0x%x\n", -ret);
            goto exit;
        }

//        printf(" %d bytes\n%s\n", ret, (char *) buffer);
        printf(" %d bytes\n", ret);
        fflush(stdout);
    }

    // Close connection
    printf("Closing the connection...");

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
        printf(" failed! mbedtls_ssl_close_notify returned -0x%x\n",-ret);
        goto exit;
    }

    printf(" ok");
    
    // Final connection status
    printf("\n\nFinal status:");
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
    printf("\n");
    
    ret = 0;

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&privkey2);
    mbedtls_x509_crt_free(&srvcert2);
    mbedtls_pk_free(&privkey);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);

    return(ret);
}