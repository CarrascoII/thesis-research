#if !defined(MBEDTLS_CONFIG_FILE)
#include "config_tls_psk.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net_sockets.h"
#if !defined(PSK_AUTH)
#include "mbedtls/certs.h"
#include "mbedtls/debug.h"
#endif
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#if !defined(PAPI_CIPHER) && !defined(PAPI_MD) && \
    !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
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

#if defined(PSK_AUTH)
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
    
    if((new = (psk_entry*) calloc(1, sizeof(psk_entry))) == NULL) {
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
#else
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
    mbedtls_net_context server, client;
#if defined(PSK_AUTH)
    const unsigned char test_psk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
#if MBEDTLS_PSK_MAX_LEN == 32
        ,0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
#endif
    };
    psk_entry *psk_info = NULL;
#else
    mbedtls_x509_crt cacert, srvcert, srvcert2;
    mbedtls_pk_context privkey, privkey2;
#endif
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

    int ret,
#if !defined(PSK_AUTH)
        debug = DEBUG_LEVEL,
#endif
        i, n_tests = N_TESTS,
        input_size = MIN_INPUT_SIZE;
    unsigned char *request, *response;
    const char *pers = "tls_server generates response";
    char *p, *q;
#if defined(PAPI_CIPHER) || defined(PAPI_MD)
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
        }
#if !defined(PSK_AUTH) 
        else if(strcmp(p, "debug_level") == 0) {
            debug = atoi(q);
            if(debug < 0 || debug > 5) {
                printf("Debug level must be int between 0 and 5\n");
                return 1;
            }
        }
#endif
        else if(strcmp(p, "n_tests") == 0) {
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
    mbedtls_net_init(&client);
#if !defined(PSK_AUTH)
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&srvcert2);
    mbedtls_pk_init(&privkey);
    mbedtls_pk_init(&privkey2);
#endif
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

#if defined(PSK_AUTH)
    // Load psk list
    printf("\nLoading the psk list......................");
    fflush(stdout);

    if((psk_info = psk_parse(test_psk, sizeof(test_psk))) == NULL) {
        printf("psk_list invalid");
        goto exit;
    }

    printf(" ok");
#else
    mbedtls_debug_set_threshold(debug);

    // Load certificates and key
    printf("\nLoading the ca certificate................");
    fflush(stdout);

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {        
        if((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
            printf(" failed! mbedtls_x509_crt_parse_ca returned -0x%04x\n", -ret);
            goto exit;
        }
    }

    printf(" ok");

    printf("\nLoading the server certificate............");
    fflush(stdout);

    if((ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt_rsa, mbedtls_test_srv_crt_rsa_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse_rsa returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_x509_crt_parse(&srvcert2, (const unsigned char *) mbedtls_test_srv_crt_ec, mbedtls_test_srv_crt_ec_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse_ec returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");

    printf("\nLoading the server key....................");
    fflush(stdout);

    if((ret = mbedtls_pk_parse_key(&privkey, (const unsigned char *) mbedtls_test_srv_key_rsa, mbedtls_test_srv_key_rsa_len, NULL, 0)) != 0) {
        printf(" failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_pk_parse_key(&privkey2, (const unsigned char *) mbedtls_test_srv_key_ec, mbedtls_test_srv_key_ec_len, NULL, 0)) != 0) {
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

    // Create and bind socket
    printf("\nBinding server to tcp/%s/%s......", SERVER_IP, SERVER_PORT);
    fflush(stdout);

    if((ret = mbedtls_net_bind(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf(" failed! mbedtls_net_bind returned -0x%04x\n", -ret);
        goto exit;      
    }

    printf(" ok");

    // Setup ssl session
    printf("\nSetting up TLS session....................");
    fflush(stdout);

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf(" failed! mbedtls_ssl_config_defaults returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(MUTUAL_AUTH)
    mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif
    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#if defined(PSK_AUTH)
    mbedtls_ssl_conf_psk_cb(&tls_conf, psk_callback, psk_info);
#else
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
    mbedtls_ssl_conf_ca_chain(&tls_conf, &cacert, NULL);

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &srvcert, &privkey)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_conf_own_cert(&tls_conf, &srvcert2, &privkey2)) != 0) {
        printf(" failed! mbedtls_ssl_conf_own_cert returned -0x%04x\n", -ret);
        goto exit;
    }
#endif

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
        printf(" failed! mbedtls_ssl_setup returned -0x%04x\n", -ret);
        goto exit;
    }

    printf(" ok");

    // Listen and accept client
    printf("\nWaiting for client to connect.............");
    fflush(stdout);

    if((ret = mbedtls_net_accept(&server, &client, NULL, 0, NULL)) != 0) {
        printf(" failed! mbedtls_net_accept returned -0x%04x\n", -ret);
        goto exit; 
    }

    mbedtls_ssl_set_bio(&tls, &client, mbedtls_net_send, mbedtls_net_recv, NULL);

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

    for(; input_size <= MAX_INPUT_SIZE; input_size *= 2) {
        request = (unsigned char*) malloc(input_size*sizeof(unsigned char));
        response = (unsigned char*) malloc(input_size*sizeof(unsigned char));

        // Generate the response
        memset(response, 0, input_size);

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, response, input_size)) != 0) {
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
            goto exit;
        }

        for(i = 0; i < n_tests; i++) {
            // Receive request
            printf("\n\n> Read from client:");
            fflush(stdout);

            memset(request, 0, input_size);

            if((ret = mbedtls_ssl_read(&tls, request, input_size)) < 0) {
                printf(" failed! mbedtls_ssl_read returned -0x%04x\n", -ret);
                goto exit;
            }

            printf(" %d bytes\n", ret);
#if !defined(PAPI_CIPHER) && !defined(PAPI_MD) && \
    !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
            print_hex(request, input_size);
#endif
            fflush(stdout);

#if defined(PAPI_CIPHER)
            csv = fopen(cipher_fname, "a+");    
            fprintf(csv, ",server,%d", input_size);
            fclose(csv);
#endif

#if defined(PAPI_MD)
            csv = fopen(md_fname, "a+");    
            fprintf(csv, ",server,%d", input_size);
            fclose(csv);
#endif

            // Send response
            printf("\n< Write to client:");
            fflush(stdout);

            if((ret = mbedtls_ssl_write(&tls, response, input_size)) < 0) {
                printf(" failed! mbedtls_ssl_write returned -0x%04x\n", -ret);
                goto exit;
            }

            printf(" %d bytes\n", ret);
#if !defined(PAPI_CIPHER) && !defined(PAPI_MD) && \
    !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
            print_hex(response, input_size);
#endif
            fflush(stdout);

#if defined(PAPI_CIPHER)
            csv = fopen(cipher_fname, "a+");    
            fprintf(csv, ",server,%d", input_size);
            fclose(csv);
#endif

#if defined(PAPI_MD)
            csv = fopen(md_fname, "a+");    
            fprintf(csv, ",server,%d", input_size);
            fclose(csv);
#endif
        }

        free(request);
        free(response);
    }

#if defined(PAPI_CIPHER) || defined(PAPI_MD)
    sleep(1);
#endif

    // Close connection
    printf("\nClosing the connection....................");

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
        printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n",-ret);
        goto exit;
    }

    printf(" ok");

#if defined(PAPI_CIPHER)
    csv = fopen(cipher_fname, "a+");
    fprintf(csv, ",server,close");
    fclose(csv);
#endif

#if defined(PAPI_MD)
    csv = fopen(md_fname, "a+");
    fprintf(csv, ",server,close");
    fclose(csv);
#endif

    // Final connection status
    printf("\n\nFinal status:");
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));

#if defined(MUTUAL_AUTH)
    ret = mbedtls_ssl_get_verify_result(&tls);
    printf("\n  -Server certificate verification:   %s", ret == 0 ? "Success" : "Failed");

    if(ret == 0) {
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
#if defined(PSK_AUTH)
    psk_free(psk_info);
#else
    mbedtls_pk_free(&privkey2);
    mbedtls_pk_free(&privkey);
    mbedtls_x509_crt_free(&srvcert2);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_x509_crt_free(&cacert);
#endif
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);

    return(ret);
}