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

#if !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
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
    mbedtls_net_context server, client;
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;
    psk_entry *psk_info = NULL;

    int ret,
        i, n_tests = N_TESTS,
        input_size = MIN_INPUT_SIZE,
#if defined(MBEDTLS_DEBUG_C)
        debug = DEBUG_LEVEL,
#endif
        suite_id = 0;
    unsigned char *request, *response;
    const char *pers = "tls_server generates response";
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
            printf("To assign own variables, run with <variable>=X\n");
            return 1;
        }

        *q++ = '\0';
        if(strcmp(p, "n_tests") == 0) {
			n_tests = atoi(q);
            if(n_tests < 1 || n_tests > 1000) {
                printf("Number of tests must be between 1 and 1000\n");
                return 1;
            }
		} else if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);
            if(input_size < MIN_INPUT_SIZE || input_size > MAX_INPUT_SIZE || input_size % MIN_INPUT_SIZE != 0) {
                printf("Input size must be multiple of %d, between %d and %d \n", MIN_INPUT_SIZE, MIN_INPUT_SIZE, MAX_INPUT_SIZE);
                return 1;
            }
        } 
#if defined(MBEDTLS_DEBUG_C) 
        else if(strcmp(p, "debug_level") == 0) {
            debug = atoi(q);
            if(debug < 0 || debug > 5) {
                printf("Debug level must be int between 0 and 5\n");
                return 1;
            }
        }
#endif
        else if(strcmp(p, "ciphersuite") == 0) {
			if((suite_id = mbedtls_ssl_get_ciphersuite_id(q)) == 0) {
                printf("%s is not an available ciphersuite\n", q);
                return 1;
            }
		} else {
			printf("Available options are input_size, n_tests");
#if defined(MBEDTLS_DEBUG_C) 
            printf(", debug_level");
#endif
            printf(" and ciphersuite\n");
			return 1;
		}
	}

    mbedtls_net_init(&server);
    mbedtls_net_init(&client);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug);
#endif

    // Load psk list
    printf("\nLoading the psk list......................");
    fflush(stdout);

    if((psk_info = psk_parse(test_psk, sizeof(test_psk))) == NULL) {
        printf("psk_list invalid");
        goto exit;
    }

    printf(" ok");
    
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

    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if(suite_id != 0) {
        mbedtls_ssl_conf_ciphersuites(&tls_conf, &suite_id);
    }
    
#if defined(MBEDTLS_DEBUG_C)
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);
#endif
    mbedtls_ssl_conf_psk_cb(&tls_conf, psk_callback, psk_info);

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

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
    printf("\nPerforming TLS record.....................");    
    fflush(stdout);
#endif

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
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
            // Receive request
            printf("\n\n> Read from client:");
            fflush(stdout);
#endif
            memset(request, 0, input_size);

            if((ret = mbedtls_ssl_read(&tls, request, input_size)) < 0) {
                printf(" failed! mbedtls_ssl_read returned -0x%04x\n", -ret);
                goto exit;
            }

#if !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
            printf(" %d bytes\n", ret);
            print_hex(request, input_size);
            fflush(stdout);

            // Send response
            printf("\n< Write to client:");
            fflush(stdout);
#endif

            if((ret = mbedtls_ssl_write(&tls, response, input_size)) < 0) {
                printf(" failed! mbedtls_ssl_write returned -0x%04x\n", -ret);
                goto exit;
            }

#if !defined(MEASURE_CIPHER) && !defined(MEASURE_MD)
            printf(" %d bytes\n", ret);
            print_hex(response, input_size);
            fflush(stdout);
#endif
        }

        free(request);
        free(response);
    }

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
    printf(" ok");
#endif

    // Close connection
    printf("\nClosing the connection....................");

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
        printf(" failed! mbedtls_ssl_close_notify returned -0x%04x\n",-ret);
        goto exit;
    }

    printf(" ok");

    // Final connection status
    printf("\n\nFinal status:");
    printf("\n  -TLS version being used:    %s", mbedtls_ssl_get_version(&tls));
    printf("\n  -Suite being used:          %s", mbedtls_ssl_get_ciphersuite(&tls));
#if !defined(MEASURE_CIPHER) || !defined(MEASURE_MD)
    printf("\n  -Max record size:           %d", mbedtls_ssl_get_max_out_record_payload(&tls));
    printf("\n  -Max record expansion:      %d", mbedtls_ssl_get_record_expansion(&tls));
#endif
    printf("\n");

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    psk_free(psk_info);
    mbedtls_net_free(&client);
    mbedtls_net_free(&server);

    return(ret);
}