#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SHA1_ALT)
#include "mbedtls/sha1.h"
#include "sha1_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_sha1_init(mbedtls_sha1_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_sha1_context));
}

void mbedtls_sha1_free(mbedtls_sha1_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_sha1_context));
	}
}

void mbedtls_sha1_clone(mbedtls_sha1_context *dst, const mbedtls_sha1_context *src) {
	UNUSED(dst); UNUSED(src);
    return;
}

int mbedtls_sha1_starts_ret(mbedtls_sha1_context *ctx) {
	UNUSED(ctx);
    return(0);
}

int mbedtls_internal_sha1_process(mbedtls_sha1_context *ctx, const unsigned char data[64]) {
	UNUSED(ctx); UNUSED(data);
    return(0);
}

int mbedtls_sha1_update_ret(mbedtls_sha1_context *ctx, const unsigned char *input, size_t ilen) {
	UNUSED(ctx); UNUSED(input); UNUSED(ilen);
    return(0);
}

int mbedtls_sha1_finish_ret(mbedtls_sha1_context *ctx, unsigned char output[20]) {
	UNUSED(ctx);
	memcpy(output, (unsigned char[]) {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13
    }, 20);

    return(0);
}

#endif /* MBEDTLS_SHA1_ALT */