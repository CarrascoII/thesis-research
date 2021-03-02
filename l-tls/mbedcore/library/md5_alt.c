#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD5_ALT)
#include "mbedtls/md5.h"
#include "md5_alt.h"

#include <string.h>

#define UNUSED(x) (void)(x)

void mbedtls_md5_init(mbedtls_md5_context *ctx) {
	memset(ctx, 0, sizeof(mbedtls_md5_context));
}

void mbedtls_md5_free(mbedtls_md5_context *ctx) {
	if(ctx != NULL) {
		memset(ctx, 0, sizeof(mbedtls_md5_context));
	}
}

void mbedtls_md5_clone(mbedtls_md5_context *dst, const mbedtls_md5_context *src) {
	UNUSED(dst); UNUSED(src);
    return;
}

int mbedtls_md5_starts_ret(mbedtls_md5_context *ctx) {
	UNUSED(ctx);
    return(0);
}

int mbedtls_internal_md5_process(mbedtls_md5_context *ctx, const unsigned char data[64]) {
	UNUSED(ctx); UNUSED(data);
    return(0);
}

int mbedtls_md5_update_ret(mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen) {
	UNUSED(ctx); UNUSED(input); UNUSED(ilen);
    return(0);
}

int mbedtls_md5_finish_ret(mbedtls_md5_context *ctx, unsigned char output[16]) {
	UNUSED(ctx);
	memcpy(output, (unsigned char[]) {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    }, 16);
	
    return(0);
}

#endif /* MBEDTLS_MD5_ALT */