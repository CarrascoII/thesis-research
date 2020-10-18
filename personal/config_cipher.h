#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 * mbed TLS modules
 */
/* Cipher algorithm */
// #define MBEDTLS_AES_ENCRYPT_ALT
// #define MBEDTLS_AES_SETKEY_ENC_ALT
// #define MBEDTLS_AES_DECRYPT_ALT
// #define MBEDTLS_AES_SETKEY_DEC_ALT
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
// #define MBEDTLS_CIPHER_MODE_CFB
// #define MBEDTLS_CIPHER_MODE_CTR
// #define MBEDTLS_CIPHER_MODE_OFB
// #define MBEDTLS_CIPHER_MODE_XTS

/* Imports */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_PLATFORM_C

#include "mbedtls/check_config.h"

#define USE_PAPI

#endif /* MBEDTLS_CONFIG_H */