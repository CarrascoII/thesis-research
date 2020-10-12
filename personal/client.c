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
#include <unistd.h>
#include <string.h>


#define SERVER_IP   "localhost"
#define SERVER_PORT "80"
#define REQUEST     "Hello Server!"
#define DEBUG_LEVEL 0

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


int main() {
    // Initial setup
    mbedtls_net_context server;
    mbedtls_x509_crt cacert, clicert;
    mbedtls_ctr_drbg_context ctr_drbg; // Deterministic Random Bit Generator using block ciphers in counter mode
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config tls_conf;
    mbedtls_ssl_context tls;

    int ret, len, i;
    unsigned char buffer[1024];
    const char *pers = "tls_client";
    uint32_t flags;

    mbedtls_debug_set_threshold( DEBUG_LEVEL );

    mbedtls_net_init(&server);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ssl_config_init(&tls_conf);
    mbedtls_ssl_init(&tls);

    // Load certificates and key
    printf("\nLoading the ca cert....................");
    fflush(stdout);

    for(i = 0; mbedtls_test_cas[i] != NULL; i++) {        
        if((ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas[i], mbedtls_test_cas_len[i])) != 0) {
            printf(" failed! mbedtls_x509_crt_parse returned %d\n", ret);
            goto exit;
        }
    }

    printf(" ok");

    printf("\nLoading the client cert................");
    fflush(stdout);

    if((ret = mbedtls_x509_crt_parse(&clicert, (const unsigned char *) mbedtls_test_cli_crt, mbedtls_test_cli_crt_len)) != 0) {
        printf(" failed! mbedtls_x509_crt_parse returned %d\n", ret);
        goto exit;
    }

    printf(" ok");

    // Create socket and connect to server
    printf("\nConnecting to tcp/%s/%s.........", SERVER_IP, SERVER_PORT );
    fflush(stdout);
    
    if((ret = mbedtls_net_connect(&server, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf(" failed! mbedtls_net_connect returned %d\n", ret);
        goto exit;     
    }

    printf(" ok");

    // Seed the RNG
    printf("\nSeeding the random number generator....");
    fflush(stdout);

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
        printf(" failed! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    printf(" ok");

    // Setup ssl session
    printf("\nSetting up TLS session.................");
    fflush(stdout);

    if((ret = mbedtls_ssl_config_defaults(&tls_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf(" failed! mbedtls_ssl_config_defaults returned %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&tls_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&tls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&tls_conf, my_debug, stdout);

    if((ret = mbedtls_ssl_setup(&tls, &tls_conf)) != 0) {
        printf(" failed! mbedtls_ssl_setup returned %d\n", ret);
        goto exit;
    }

    if((ret = mbedtls_ssl_set_hostname(&tls, SERVER_IP)) != 0) {
        printf(" failed! mbedtls_ssl_set_hostname returned %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&tls, &server, mbedtls_net_send, mbedtls_net_recv, NULL);

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

    // Verify server certificate
    printf("\nVerifying server certificate...........");

    if((flags = mbedtls_ssl_get_verify_result(&tls)) != 0) {
        char vrfy_buf[512];
        
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof( vrfy_buf ), "", flags);
        printf(" failed! mbedtls_ssl_get_verify_result returned %s\n", vrfy_buf);
        goto exit;
    }

    printf(" ok");

    sleep(1); // sleep 1 sec in order to differentiate the handshake and data transmission in Wireshark

    // Send request
    printf("\n\n< Write to server:");
    fflush(stdout);

    len = sprintf((char *) buffer, REQUEST);

    if((ret = mbedtls_ssl_write(&tls, buffer, len)) < 0) {
        printf( " mbedtls_net_send returned -0x%x\n", -ret );
        goto exit;
    }

    printf(" %d bytes\n%s\n", len, (char *) buffer);
    fflush(stdout);

    // Receive response
    printf("\n> Read from server:");
    fflush(stdout);

    len = sizeof(buffer);
    memset(buffer, 0, len);

    if((ret = mbedtls_ssl_read(&tls, buffer, len)) < 0) {
        printf( " mbedtls_net_recv returned -0x%x\n", -ret );
        goto exit;
    }

    len = ret;
    printf(" %d bytes\n%s\n\n", len, (char *) buffer);
    fflush(stdout);

    // Close connection
    printf("Closing the connection...");

    if((ret = mbedtls_ssl_close_notify(&tls)) < 0) {
        printf(" failed! mbedtls_ssl_close_notify returned %d\n", ret);
        goto exit;
    }

    printf(" ok");

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
    ret = 0;

exit:
    mbedtls_ssl_free(&tls);
    mbedtls_ssl_config_free(&tls_conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_net_free(&server);

    return(ret);
}