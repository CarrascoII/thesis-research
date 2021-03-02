#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CAMELLIA_ALT)
#include "mbedtls/camellia.h"
#include "camellia_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_camellia_init(mbedtls_camellia_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_camellia_context));
}

void mbedtls_camellia_free(mbedtls_camellia_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_camellia_context));
	}
}

int mbedtls_camellia_setkey_enc(mbedtls_camellia_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
    return(0);
}

int mbedtls_camellia_setkey_dec(mbedtls_camellia_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
    return(0);
}

int mbedtls_camellia_crypt_ecb(mbedtls_camellia_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]) {
	UNUSED(ctx); UNUSED(mode); UNUSED(input); UNUSED(output);
    return(0);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_camellia_crypt_cbc(mbedtls_camellia_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output) {
	UNUSED(ctx); UNUSED(mode); UNUSED(length); UNUSED(iv); UNUSED(input); UNUSED(output);
    return(0);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_CAMELLIA_ALT */