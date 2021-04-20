#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 * Profiling program flags
 */
#include "measurement/config.h"

#if defined(MEASUREMENT_MEASURE_C)
// #define MEASURE_CIPHER
// #define MEASURE_MD
// #define MEASURE_KE
#define MEASURE_HANDSHAKE
#endif

#if defined(MEASUREMENT_MEASURE_C)
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
#define KE_EXTENTION            "/ke_data.csv"
#define KE_FNAME_SIZE           13 /* = len(KE_EXTENTION) + len("\0") */
char *ke_fname;
#endif

#if defined(MEASURE_HANDSHAKE)
#define HANDSHAKE_EXTENSION     "/handshake_data.csv"
#define HANDSHAKE_FNAME_SIZE    20 /* = len(HANDSHAKE_EXTENSION) + len("\0") */
#define MAX_SERVER_CTX          11
#define MAX_CLIENT_CTX          9
char *handshake_fname;
#endif

#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define CERTS_PATH          "../l-tls/examples/"
#define CERT_KEY_PATH_LEN   40
#define BUFFER_LEN          15
static const int psk_key_sizes[5] = {10, 14, 16, 24, 32};               /* in bytes */
static const int asm_key_sizes[5] = {1024, 2048, 3072, 7680, 15360};    /* in bits */
static const int ecc_key_sizes[5] = {192, 224, 256, 384, 521};          /* in bits */
#endif

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
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define USE_PSK_C
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
#define MBEDTLS_RSA_C

#define MBEDTLS_PKCS1_V15
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
#define MBEDTLS_DHM_C
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#endif
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED    /* srv/cli curve */
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED    /* ca curve */
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_ECDSA_C
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

#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_GENPRIME
#endif
#if defined(MBEDTLS_ECDSA_C) || defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_ASN1_WRITE_C
#endif

/* Cipher algorithm */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_NULL_CIPHER

#define MBEDTLS_ARC4_C
#define MBEDTLS_DES_C
#define MBEDTLS_AES_C
// #define MBEDTLS_AES_ALT
// #define MBEDTLS_AES_ENCRYPT_ALT
// #define MBEDTLS_AES_SETKEY_ENC_ALT
// #define MBEDTLS_AES_DECRYPT_ALT
// #define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_ARIA_C
#define MBEDTLS_CAMELLIA_C

/* Cipher modes */
#define MBEDTLS_CIPHER_MODE_CBC

/* Message authentication algorithms */
#define MBEDTLS_MD_C

#define MBEDTLS_MD5_C
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
#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_FS_IO
#define MBEDTLS_ERROR_C
#endif

/* Aditional features */
#define MBEDTLS_PLATFORM_C

/**
 *  Options to reduce footprint
 */
// #define MBEDTLS_AES_ROM_TABLES              /* Save RAM at the expense of ROM */
// #define MBEDTLS_ENTROPY_MAX_SOURCES     2   /* Minimum is 2 for the entropy test suite */
#if defined(MEASURE_CIPHER) || defined(MEASURE_MD)
#define MBEDTLS_CTR_DRBG_MAX_REQUEST    MAX_INPUT_SIZE
#elif defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_CTR_DRBG_MAX_REQUEST    MBEDTLS_MPI_MAX_SIZE
#endif
// #define MBEDTLS_SSL_MAX_CONTENT_LEN     MAX_INPUT_SIZE + 1024    /* The optimal size here depends on the typical size of records (does not work) */
#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MBEDTLS_MPI_MAX_SIZE            1920     /**< Maximum number of bytes for usable MPIs. */
#endif

/**
 * mbed TLS ciphersuites
 * 
 * \note Supported/Total := 125/207
 */
#define MBEDTLS_ENABLE_WEAK_CIPHERSUITES
// #define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
// #define MBEDTLS_REMOVE_3DES_CIPHERSUITES

#define MBEDTLS_SSL_CIPHERSUITES \
            MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA

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

            /* AEAD PSK ciphersuites - 11 */
            // MBEDTLS_TLS_PSK_WITH_AES_128_CCM,
            // MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8,             
            // MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_PSK_WITH_AES_256_CCM,               
            // MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8,             
            // MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384,        
            // MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256,       
            // MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384,       
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,   
            // MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,   
            // MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,

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

            /* AEAD RSA ciphersuites - 10 */
            // MBEDTLS_TLS_RSA_WITH_AES_128_CCM,               
            // MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8,             
            // MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,        
            // MBEDTLS_TLS_RSA_WITH_AES_256_CCM,               
            // MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8,
            // MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,        
            // MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256,       
            // MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384,       
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,   
            // MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,

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

            /* AEAD RSA_PSK ciphersuites - 7 */
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,

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
            // MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,

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

            /* AEAD DHE_RSA ciphersuites - 11 */
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8,
            // MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

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

            /* AEAD ECDH_RSA ciphersuites - 6 */
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,

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

            /* AEAD ECDH_ECDSA ciphersuites - 6 */
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,

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

            /* AEAD ECDHE_PSK ciphersuites - 1 */
            // MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,

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

            /* AEAD ECDHE_RSA ciphersuites - 7 */
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,

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

            /* AEAD ECDHE_ECDSA ciphersuites - 11 */
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,

            /* NULL cipher ECDHE_ECDSA ciphersuites - 1 */
            // MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA,

            /* AEAD ECJPAKE ciphersuites - 1 */
            // MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8,

#include "mbedtls/check_config.h"

/**
 * Server and client program flags
 */
#define SERVER_IP                       "localhost"
#define SERVER_PORT                     "8080"
#define MIN_INPUT_SIZE                  32
#define MAX_INPUT_SIZE                  1048576
#if defined(MEASURE_HANDSHAKE) || defined(MEASURE_KE)
#define MIN_SEC_LVL                     0
#define MAX_SEC_LVL                     4
#endif
#if defined(MEASUREMENT_MEASURE_C)
#define N_TESTS                         20000
#endif
#if defined(USE_PSK_C)
#define CLI_ID                          "Client_identity"
static const unsigned char test_psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
#endif
#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C)
#define MUTUAL_AUTH
#endif
#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL                     1
// #define PRINT_MSG_HEX
#else
// #define PRINT_HANDSHAKE_OPERATIONS
// #define PRINT_KEYS_OPERATIONS
#endif

/**
 * New alternative implementation flags
 */
// #define NEW_CIPHER_ALG_ALT
// #define NEW_MD_HMAC_ALT

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