#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 *  mbed TLS feature support
 */
/* Protocol version */
#define MBEDTLS_SSL_PROTO_TLS1_2

/* Key exchange algorithms */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

/**
 * mbed TLS modules
 */
/* Key Exchange / Authentication algorithm */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
#define MBEDTLS_RSA_C

#define MBEDTLS_PKCS1_V15
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
#define MBEDTLS_DHM_C
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED    /* ca curve */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED    /* srv/cli curve */

#define MBEDTLS_ECDSA_C
#define MBEDTLS_ASN1_WRITE_C
#endif

#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_DHM_C) || defined(MBEDTLS_ECP_C)
#define MBEDTLS_BIGNUM_C
#endif

#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
#define MBEDTLS_OID_C

#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_C

#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#endif

/* Cipher algorithm */
#define MBEDTLS_CIPHER_C

#define MBEDTLS_DES_C
#define MBEDTLS_AES_C
// #define MBEDTLS_AES_ALT
// #define MBEDTLS_AES_ENCRYPT_ALT
// #define MBEDTLS_AES_SETKEY_ENC_ALT
// #define MBEDTLS_AES_DECRYPT_ALT
// #define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_ARIA_C
#define MBEDTLS_CAMELLIA_C

/* Cipher mode */
#define MBEDTLS_CIPHER_MODE_CBC

/* Message authentication algorithms */
#define MBEDTLS_MD_C

#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
// #define MBEDTLS_SHA256_PROCESS_ALT
#define MBEDTLS_SHA512_C

/* AEAD algorithms */
// #define MBEDTLS_GCM_C
// #define MBEDTLS_CCM_C
// #define MBEDTLS_CHACHA20_C
// #define MBEDTLS_POLY1305_C
// #define MBEDTLS_CHACHAPOLY_C

/* TLS protocol */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C

/* Imports */
#define MBEDTLS_NET_C
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
#define MBEDTLS_CERTS_C
#endif
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
// #define MBEDTLS_DEBUG_C

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
 * 
 * \note Supported/Total := 36/66
 */
//  #define MBEDTLS_SSL_CIPHERSUITES

            /* Regular PSK ciphersuites - 9 */
            // MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,          
            // MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,           
            // MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256        
            // MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,           
            // MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,        
            // MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256,       
            // MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384,       
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* AEAD PSK ciphersuites - 11 */
            // MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
            // MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,             
            // MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256        
            // MBEDTLS_TLS_PSK_WITH_AES_256_CCM,               
            // MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,             
            // MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,        
            // MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,       
            // MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,       
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,   
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,   
            // MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,

            /* Regular RSA_PSK ciphersuites - 9 */
            // MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* AEAD RSA_PSK ciphersuites - 7 */
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,

            /* Regular DHE_PSK ciphersuites - 9 */
            // MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* AEAD DHE_PSK ciphersuites - 11 */
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8,
            // MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256

            /* Regular ECDHE_PSK ciphersuites - 9 */
            // MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* AEAD ECDHE_PSK ciphersuites - 1 */
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,

#include "mbedtls/check_config.h"

/**
 * Server and client program flags
 */
#define SERVER_IP                       "localhost"
#define SERVER_PORT                     "8080"
#define CLI_ID                          "Client_identity"
#define MIN_INPUT_SIZE                  32
#define MAX_INPUT_SIZE                  16384
#define N_TESTS                         500
#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL                     1
// #define PRINT_HANDSHAKE_STEPS
// #define PRINT_MSG_HEX
#endif
#if MAX_INPUT_SIZE > 1024
#define MBEDTLS_CTR_DRBG_MAX_REQUEST    MAX_INPUT_SIZE
#endif

/**
 * Profiling program flags
 */
#include "measurement/config.h"

#if defined(MEASUREMENT_MEASURE_C)
#define MEASURE_CIPHER
#define MEASURE_MD
// #define MEASURE_KE
#endif

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || defined(MEASURE_KE)
#define FILE_PATH           "../docs/"
#endif

#if defined(MEASURE_CIPHER)
#define CIPHER_EXTENSION    "/cipher_data.csv"
#define CIPHER_FNAME_SIZE   17 /* = len(CIPHER_EXTENSION) + len("\0") */
char *cipher_fname;
#endif

#if defined(MEASURE_MD)
#define MD_EXTENSION        "/md_data.csv"
#define MD_FNAME_SIZE       13 /* = len(MD_EXTENSION) + len("\0") */
char *md_fname;
#endif

#if defined(MEASURE_KE)
#define KE_EXTENSION        "/ke_data.csv"
#define KE_FNAME_SIZE       13 /* = len(KE_EXTENSION) + len("\0") */
char *ke_fname;
#endif

/**
 * New alternative implementation flags
 */
#define NEW_CIPHER_ALG_ALT
#define NEW_MD_HMAC_ALT

#if defined(NEW_CIPHER_ALG_ALT) && defined(MBEDTLS_AES_ENCRYPT_ALT)
#define NEW_AES_ENCRYPT_ALT
#define AES_ENC_THRESHOLD   2048
#endif

#if defined(NEW_CIPHER_ALG_ALT) && defined(MBEDTLS_AES_SETKEY_ENC_ALT)
#define NEW_AES_SETKEY_ENC_ALT
#endif

#if defined(NEW_CIPHER_ALG_ALT) && defined(MBEDTLS_AES_DECRYPT_ALT)
#define NEW_AES_DECRYPT_ALT
#define AES_DEC_THRESHOLD   2048
#endif

#if defined(NEW_CIPHER_ALG_ALT) && defined(MBEDTLS_AES_SETKEY_DEC_ALT)
#define NEW_AES_SETKEY_DEC_ALT
#endif

#if defined(NEW_MD_HMAC_ALT) && defined(MBEDTLS_SHA256_PROCESS_ALT)
#define NEW_SHA256_PROCESS_ALT
#define SHA256_THRESHOLD    1024
#endif

#endif /* MBEDTLS_CONFIG_H */