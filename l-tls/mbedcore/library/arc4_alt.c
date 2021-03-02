#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ARC4_ALT)
#include "mbedtls/arc4.h"
#include "arc4_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_arc4_init(mbedtls_arc4_context *ctx) {
    memset(ctx, 0, sizeof(mbedtls_arc4_context));
}

void mbedtls_arc4_free(mbedtls_arc4_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_arc4_context));
	}
}

void mbedtls_arc4_setup(mbedtls_arc4_context *ctx, const unsigned char *key, unsigned int keylen) {
	UNUSED(ctx); UNUSED(key); UNUSED(keylen);
    return;
}

/*
 * ARC4 cipher function
 */
int mbedtls_arc4_crypt(mbedtls_arc4_context *ctx, size_t length, const unsigned char *input, unsigned char *output) {
	UNUSED(ctx); UNUSED(length); UNUSED(input); UNUSED(output);
    return(0);
}

#endif /* MBEDTLS_ARC4_ALT */