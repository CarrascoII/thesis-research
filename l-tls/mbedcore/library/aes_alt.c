#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_AES_ALT)
#include "mbedtls/aes.h"
#include "aes_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_aes_init(mbedtls_aes_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_aes_context));
}

void mbedtls_aes_free(mbedtls_aes_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_aes_context));
	}
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
	return(0);
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
	UNUSED(ctx); UNUSED(key); UNUSED(keybits);
	return(0);
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]) {
	UNUSED(ctx); UNUSED(mode); UNUSED(input); UNUSED(output);
	return(0);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output) {
	UNUSED(ctx); UNUSED(mode); UNUSED(length); UNUSED(iv); UNUSED(input); UNUSED(output);
	return(0);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_AES_ALT */