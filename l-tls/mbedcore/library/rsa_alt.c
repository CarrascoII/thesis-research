#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_RSA_ALT)
#include "mbedtls/rsa.h"
#include "rsa_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

int mbedtls_rsa_import( mbedtls_rsa_context *ctx,
                        const mbedtls_mpi *N,
                        const mbedtls_mpi *P, const mbedtls_mpi *Q,
                        const mbedtls_mpi *D, const mbedtls_mpi *E ) {
    return( 0 );
}

int mbedtls_rsa_import_raw( mbedtls_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len ) {
    return( 0 );
}

int mbedtls_rsa_complete( mbedtls_rsa_context *ctx ) {
    return(0);
}

void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
               int padding,
               int hash_id ) {
    return;
}

#endif /* MBEDTLS_RSA_ALT */