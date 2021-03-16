#ifndef MBEDTLS_RSA_ALT_H
#define MBEDTLS_RSA_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/bignum.h"

#include <stdio.h>

typedef struct mbedtls_rsa_context {
    mbedtls_mpi N;              /*!<  The public modulus. */
    mbedtls_mpi E;              /*!<  The public exponent. */
} mbedtls_rsa_context;

#endif /* MBEDTLS_RSA_ALT_H */