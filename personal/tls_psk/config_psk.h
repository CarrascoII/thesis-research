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
#define MBEDTLS_CIPHER_C

// #define MBEDTLS_DES_C
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ENCRYPT_ALT
#define MBEDTLS_AES_SETKEY_ENC_ALT
#define MBEDTLS_AES_DECRYPT_ALT
#define MBEDTLS_AES_SETKEY_DEC_ALT
// #define MBEDTLS_ARIA_C
// #define MBEDTLS_CAMELLIA_C
// #define MBEDTLS_CHACHA20_C

#define MBEDTLS_CIPHER_MODE_CBC
// #define MBEDTLS_GCM_C
// #define MBEDTLS_CCM_C

/* Message authentication algorithms */
#define MBEDTLS_MD_C

// #define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_PROCESS_ALT
// #define MBEDTLS_SHA512_C
// #define MBEDTLS_POLY1305_C

/* AEAD algorithms */
// #define MBEDTLS_CHACHAPOLY_C

/* TLS protocol */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C

/* Imports */
#define MBEDTLS_NET_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_DEBUG_C

/* Aditional features */
#define MBEDTLS_PLATFORM_C

/**
 *  Options to reduce footprint
 */
// #define MBEDTLS_AES_ROM_TABLES              /* Save RAM at the expense of ROM */
#define MBEDTLS_PSK_MAX_LEN         16      /* 128-bits keys are generally enough */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2       /* Minimum is 2 for the entropy test suite */
// #define MBEDTLS_SSL_MAX_CONTENT_LEN MAX_INPUT_SIZE + 1024    /* The optimal size here depends on the typical size of records */

/**
 * mbed TLS ciphersuites
 */
#define MBEDTLS_SSL_CIPHERSUITES \
                 MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256        
//                 MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,          
//                 MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,           
//                 MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,           
//                 MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,        
//                 MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256,       
//                 MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384,       
//                 MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,   
//                 MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384

                // MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,        
                // MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,        
                // MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,       
                // MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,       
                // MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,   
                // MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,   
                // MBEDTLS_TLS_PSK_WITH_AES_128_CCM,               
                // MBEDTLS_TLS_PSK_WITH_AES_256_CCM,               
                // MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,             
                // MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,             
                // MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256

#include "mbedtls/check_config.h"

/**
 * Program flags
 */

#define SERVER_IP                       "localhost"
#define SERVER_PORT                     "8080"
#define CLI_ID                          "Client_identity"
#define MIN_INPUT_SIZE                  16
#define MAX_INPUT_SIZE                  8192
#define N_TESTS                         1
#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL                     1
// #define PRINT_HANDSHAKE_STEPS
// #define PRINT_MEASUREMENTS
// #define PRINT_MSG_HEX
#endif
#if MAX_INPUT_SIZE > 1024
#define MBEDTLS_CTR_DRBG_MAX_REQUEST    MAX_INPUT_SIZE
#endif

// #define MEASURE_CIPHER
// #define MEASURE_MD
// #define MEASURE_KE

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || defined(MEASURE_KE)
#define MEASURE_TIME
#define FILE_PATH           "../docs/"

#if defined(MEASURE_CIPHER)
#define CIPHER_EXTENSION    "/cipher_data.csv"
#define CIPHER_FNAME_SIZE   25 /* = len(FILE_PATH) + len(CIPHER_EXTENSION) + len("\0") */
char *cipher_fname;
#endif

#if defined(MEASURE_MD)
#define NEW_MD_HMAC_ALT
#define MD_EXTENSION        "/md_data.csv"
#define MD_FNAME_SIZE       21 /* = len(FILE_PATH) + len(MD_EXTENSION) + len("\0") */
char *md_fname;
#endif

#if defined(MEASURE_KE)
#define KE_EXTENSION        "/ke_data.csv"
#define KE_FNAME_SIZE       21 /* = len(FILE_PATH) + len(KE_EXTENSION) + len("\0") */
char *ke_fname;
#endif
#endif /* MEASURE_CIPHER || MEASURE_MD || MEASURE_KE */

#if defined(NEW_MD_HMAC_ALT) && defined(MBEDTLS_SHA256_PROCESS_ALT)
#define NEW_SHA256_PROCESS_ALT
#define SHA256_THRESHOLD    1024
#endif

#define NEW_AES_SETKEY_ENC_AND_ENCRYPT_ALT
#define NEW_AES_SETKEY_DEC_AND_DECRYPT_ALT

#endif /* MBEDTLS_CONFIG_H */