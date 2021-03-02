#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA256_ALT)
#include "mbedtls/sha256.h"
#include "sha256_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_sha256_init(mbedtls_sha256_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_sha256_context));
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_sha256_context));
	}
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst, const mbedtls_sha256_context *src) {
	UNUSED(dst); UNUSED(src);
    return;
}

int mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224) {
	UNUSED(ctx); UNUSED(is224);
    return(0);
}

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx, const unsigned char data[64]) {
	UNUSED(ctx); UNUSED(data);
    return(0);
}

int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen) {
	UNUSED(ctx); UNUSED(input); UNUSED(ilen);
    return(0);
}

int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32]) {
	UNUSED(ctx);
	memcpy(output, (unsigned char[]) {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    }, 32);
	
    return(0);
}

#endif /* MBEDTLS_SHA256_ALT */