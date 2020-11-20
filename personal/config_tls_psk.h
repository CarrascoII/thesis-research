#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 *  mbed TLS feature support
 */
/* Protocol version */
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Key exchange algorithms */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

/**
 * mbed TLS modules
 */
/* Cipher algorithm */
// #define MBEDTLS_AES_ENCRYPT_ALT
// #define MBEDTLS_AES_SETKEY_ENC_ALT
// #define MBEDTLS_AES_DECRYPT_ALT
// #define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC

/* Message authentication algorithms */
// #define MBEDTLS_SHA256_PROCESS_ALT
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C

/* TLS protocol */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C

/* Imports */
#define MBEDTLS_NET_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* Aditional features */
#define MBEDTLS_PLATFORM_C

/**
 *  Options to reduce footprint
 */
// #define MBEDTLS_AES_ROM_TABLES              /* Save RAM at the expense of ROM */
#define MBEDTLS_PSK_MAX_LEN         16      /* 128-bits keys are generally enough */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2       /* Minimum is 2 for the entropy test suite */
#define MBEDTLS_SSL_MAX_CONTENT_LEN MAX_INPUT_SIZE + 3*16    /* The optimal size here depends on the typical size of records */

/**
 * mbed TLS ciphersuites
 */
#define MBEDTLS_SSL_CIPHERSUITES \
                MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256

#include "mbedtls/check_config.h"

/**
 * Program flags
 */
// #define PAPI_CIPHER
// #define PAPI_MD

// #define MEASURE_CIPHER
// #define MEASURE_MD

#define PSK_AUTH
// #define PRINT_HANDSHAKE_STEPS

#define SERVER_IP       "localhost"
#define SERVER_PORT     "8080"
#define CLI_ID          "Client_identity"
#define MIN_INPUT_SIZE  16
#define MAX_INPUT_SIZE  1024
#define N_TESTS         500

#if defined(PAPI_CIPHER)
extern char cipher_fname[50];
#endif
#if defined(PAPI_MD)
extern char md_fname[50];
#endif

#endif /* MBEDTLS_CONFIG_H */