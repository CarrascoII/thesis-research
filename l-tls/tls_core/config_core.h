#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 *  mbed TLS feature support
 */
/* Protocol version */
#define MBEDTLS_SSL_PROTO_TLS1_2
// #define MBEDTLS_SSL_ENCRYPT_THEN_MAC

/* Key exchange algorithms */
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/**
 * mbed TLS modules
 */
/* Key Exchange / Authentication algorithm */
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
#define MBEDTLS_RSA_C
//#define MBEDTLS_RSA_ALT

#define MBEDTLS_PKCS1_V15
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
#define MBEDTLS_DHM_C
//#define MBEDTLS_DHM_ALT
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
//#define MBEDTLS_ECP_ALT
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED    /* ca curve */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED    /* srv/cli curve */
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
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
#define MBEDTLS_CIPHER_NULL_CIPHER

#define MBEDTLS_ARC4_C
#define MBEDTLS_ARC4_ALT
#define MBEDTLS_DES_C
#define MBEDTLS_DES_ALT
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ALT
#define MBEDTLS_ARIA_C
#define MBEDTLS_ARIA_ALT
#define MBEDTLS_CAMELLIA_C
#define MBEDTLS_CAMELLIA_ALT

/* Cipher modes */
#define MBEDTLS_CIPHER_MODE_CBC

/* Message authentication algorithms */
#define MBEDTLS_MD_C

#define MBEDTLS_MD5_C
#define MBEDTLS_MD5_ALT
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA1_ALT
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_ALT
#define MBEDTLS_SHA512_C
#define MBEDTLS_SHA512_ALT

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
#define MBEDTLS_DEBUG_C

/* Aditional features */
#define MBEDTLS_PLATFORM_C

/**
 *  Options to reduce footprint
 */
#define MBEDTLS_PSK_MAX_LEN             32  /* 128-bits keys are generally enough */
// #define MBEDTLS_ENTROPY_MAX_SOURCES     2   /* Minimum is 2 for the entropy test suite */
#define MBEDTLS_CTR_DRBG_MAX_REQUEST    MAX_INPUT_SIZE
// #define MBEDTLS_SSL_MAX_CONTENT_LEN     MAX_INPUT_SIZE + 1024    /* The optimal size here depends on the typical size of records (does not work) */

/**
 * mbed TLS ciphersuites
 * 
 * \note Supported/Total := 125/207
 */
#define MBEDTLS_ENABLE_WEAK_CIPHERSUITES
// #define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
// #define MBEDTLS_REMOVE_3DES_CIPHERSUITES

#define MBEDTLS_SSL_CIPHERSUITES \
            MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256

            /* Regular PSK ciphersuites - 10 */
            // MBEDTLS_TLS_PSK_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA,          
            // MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA,           
            // MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA,           
            // MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384,        
            // MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256,       
            // MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384,       
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher PSK ciphersuites - 3 */
            // MBEDTLS_TLS_PSK_WITH_NULL_SHA,
            // MBEDTLS_TLS_PSK_WITH_NULL_SHA256,
            // MBEDTLS_TLS_PSK_WITH_NULL_SHA384,

            /* Regular RSA ciphersuites - 14 */
            // MBEDTLS_TLS_RSA_WITH_RC4_128_MD5,
            // MBEDTLS_TLS_RSA_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA,
            // MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA,          
            // MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,           
            // MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,        
            // MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,           
            // MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,        
            // MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256,       
            // MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,      
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,   
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,      
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,

            /* NULL cipher RSA ciphersuites - 3 */
            // MBEDTLS_TLS_RSA_WITH_NULL_MD5,
            // MBEDTLS_TLS_RSA_WITH_NULL_SHA,
            // MBEDTLS_TLS_RSA_WITH_NULL_SHA256,

            /* Regular RSA_PSK ciphersuites - 10 */
            // MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher RSA_PSK ciphersuites - 3 */
            // MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA,
            // MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384,

            /* Regular DHE_PSK ciphersuites - 10 */
            // MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher DHE_PSK ciphersuites - 3 */
            // MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA,
            // MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256,
            // MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384,

            /* Regular DHE_RSA ciphersuites - 12 */
            // MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,

            /* Regular ECDH_RSA ciphersuites - 10 */
            // MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher ECDH_RSA ciphersuites - 1 */
            // MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA,

            /* Regular ECDH_ECDSA ciphersuites - 10 */
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher ECDH_ECDSA ciphersuites - 1 */
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA,

            /* Regular ECDHE_PSK ciphersuites - 10 */
            // MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher ECDHE_PSK ciphersuites - 3 */
            // MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256,
            // MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384,

            /* Regular ECDHE_RSA ciphersuites - 10 */
            // MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher ECDHE_RSA ciphersuites - 1 */
            // MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA,

            /* Regular ECDHE_ECDSA ciphersuites - 9 */
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,

            /* NULL cipher ECDHE_ECDSA ciphersuites - 1 */
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,

#include "mbedtls/check_config.h"

/**
 * Server and client program flags
 */
#define CLI_ID                          "Client_identity"
#define SERVER_IP                       "localhost"
#define SERVER_PORT                     "8080"
#define MIN_INPUT_SIZE                  32
#define MAX_INPUT_SIZE                  16384
#define N_TESTS                         10000
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
// #define MUTUAL_AUTH
#endif
#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL                     1
// #define PRINT_HANDSHAKE_STEPS
// #define PRINT_MSG_HEX
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define USE_PSK_C
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

#if defined(MEASURE_CIPHER) || defined(MEASURE_MD) || \
    defined(MEASURE_KE)
#define FILE_PATH               "../docs/"
#define PATH_SIZE               100
#endif

#if defined(MEASURE_CIPHER)
#define CIPHER_EXTENSION        "/cipher_data.csv"
#define CIPHER_FNAME_SIZE       17 /* = len(CIPHER_EXTENSION) + len("\0") */
char *cipher_fname;
#endif

#if defined(MEASURE_MD)
#define MD_EXTENSION            "/md_data.csv"
#define MD_FNAME_SIZE           13 /* = len(MD_EXTENSION) + len("\0") */
char *md_fname;
#endif

#if defined(MEASURE_KE)
#define KE_EXTENSION            "/ke_data.csv"
#define KE_FNAME_SIZE           13 /* = len(KE_EXTENSION) + len("\0") */
#endif

#endif /* MBEDTLS_CONFIG_H */