#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA512_ALT)
#include "mbedtls/sha512.h"
#include "sha512_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_sha512_init(mbedtls_sha512_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_sha512_context));
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_sha512_context));
	}
}

void mbedtls_sha512_clone(mbedtls_sha512_context *dst, const mbedtls_sha512_context *src) {
	UNUSED(dst); UNUSED(src);
    return;
}

int mbedtls_sha512_starts_ret(mbedtls_sha512_context *ctx, int is384) {
	UNUSED(ctx); UNUSED(is384);
    return(0);
}

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx, const unsigned char data[128]) {
	UNUSED(ctx); UNUSED(data);
    return(0);
}

int mbedtls_sha512_update_ret(mbedtls_sha512_context *ctx, const unsigned char *input, size_t ilen) {
	UNUSED(ctx); UNUSED(input); UNUSED(ilen);
    return(0);
}

int mbedtls_sha512_finish_ret(mbedtls_sha512_context *ctx, unsigned char output[64]) {
	UNUSED(ctx);
	memcpy(output, (unsigned char[]) {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    }, 64);

    return(0);
}

#endif /* MBEDTLS_SHA512_ALT */