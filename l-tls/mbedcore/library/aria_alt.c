#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ARIA_ALT)
#include "mbedtls/aria.h"
#include "aria_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_aria_init(mbedtls_aria_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_aria_context));
}

void mbedtls_aria_free(mbedtls_aria_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_aria_context));
	}
}

int mbedtls_aria_setkey_enc(mbedtls_aria_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
    return(0);
}

int mbedtls_aria_setkey_dec(mbedtls_aria_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
    return(0);
}

int mbedtls_aria_crypt_ecb(mbedtls_aria_context *ctx, const unsigned char input[MBEDTLS_ARIA_BLOCKSIZE], unsigned char output[MBEDTLS_ARIA_BLOCKSIZE]) {
	UNUSED(ctx); UNUSED(input); UNUSED(output);
    return(0);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_aria_crypt_cbc(mbedtls_aria_context *ctx, int mode, size_t length, unsigned char iv[MBEDTLS_ARIA_BLOCKSIZE], const unsigned char *input, unsigned char *output) {
	UNUSED(ctx); UNUSED(mode); UNUSED(length); UNUSED(iv); UNUSED(input); UNUSED(output);
    return(0);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_ARIA_ALT */