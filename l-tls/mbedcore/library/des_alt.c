#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DES_ALT)
#include "mbedtls/des.h"
#include "des_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_des_init(mbedtls_des_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_des_context));
}

void mbedtls_des_free(mbedtls_des_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_des_context));
	}
}

void mbedtls_des3_init(mbedtls_des3_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_des3_context));
}

void mbedtls_des3_free(mbedtls_des3_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_des3_context));
	}
}

int mbedtls_des_setkey_enc(mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des_setkey_dec(mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des3_set2key_enc(mbedtls_des3_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des3_set2key_dec(mbedtls_des3_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des3_set3key_enc(mbedtls_des3_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des3_set3key_dec(mbedtls_des3_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3]) {
    UNUSED(ctx); UNUSED(key);
    return(0);
}

int mbedtls_des_crypt_ecb(mbedtls_des_context *ctx, const unsigned char input[8], unsigned char output[8]) {
    UNUSED(ctx); UNUSED(input); UNUSED(output);
    return(0);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_des_crypt_cbc(mbedtls_des_context *ctx, int mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output) {
    UNUSED(ctx); UNUSED(mode); UNUSED(length); UNUSED(iv); UNUSED(input); UNUSED(output);
    return(0);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

int mbedtls_des3_crypt_ecb(mbedtls_des3_context *ctx, const unsigned char input[8], unsigned char output[8]) {
    UNUSED(ctx); UNUSED(input); UNUSED(output);
    return(0);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
int mbedtls_des3_crypt_cbc(mbedtls_des3_context *ctx, int mode, size_t length, unsigned char iv[8], const unsigned char *input, unsigned char *output) {
    UNUSED(ctx); UNUSED(mode); UNUSED(length); UNUSED(iv); UNUSED(input); UNUSED(output);
    return(0);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#endif /* MBEDTLS_DES_ALT */