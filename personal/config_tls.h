#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 * mbed TLS feature support
 */
/* Key exchange algorithms */
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED

#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_BP256R1_ENABLED
#define MBEDTLS_ECP_DP_BP384R1_ENABLED
#define MBEDTLS_ECP_DP_BP512R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_CURVE448_ENABLED

/* TLS protocol */
#define MBEDTLS_SSL_PROTO_TLS1_2


/**
 * mbed TLS modules
 */
/* Key exchange algorithms */
#define MBEDTLS_DHM_C

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C

#define MBEDTLS_OID_C
#define MBEDTLS_RSA_C

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ECDSA_C

#define MBEDTLS_PKCS1_V15

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* Cipher algorithm */
// #define MBEDTLS_AES_ENCRYPT_ALT
// #define MBEDTLS_AES_SETKEY_ENC_ALT
// #define MBEDTLS_AES_DECRYPT_ALT
// #define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC

/* Message authentication algorithms */
#define MBEDTLS_SHA1_C
// #define MBEDTLS_SHA256_PROCESS_ALT
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

/* TLS protocol */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C

/* Imports */
#define MBEDTLS_NET_C
#define MBEDTLS_CERTS_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_DEBUG_C

/* Aditional features */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_TIMING_C

/**
 * mbed TLS ciphersuites
 */
#define MBEDTLS_SSL_CIPHERSUITES                        \
        MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,    \
        MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,   \
        MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256

#include "mbedtls/check_config.h"

/**
 * Program flags
 */
// #define USE_PAPI_TLS_CIPHER
#define USE_PAPI_TLS_MD

#define SERVER_IP       "localhost"
#define SERVER_PORT     "8080"
#define DEBUG_LEVEL     0
#define MIN_INPUT_SIZE  16
#define MAX_INPUT_SIZE  16
#define N_TESTS         1
#if defined(USE_PAPI_TLS_CIPHER) || defined(USE_PAPI_TLS_MD)
#define FILENAME        "../docs/TLS-"
#endif

#endif /* MBEDTLS_CONFIG_H */