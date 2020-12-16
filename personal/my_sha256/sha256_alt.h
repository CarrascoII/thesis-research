#ifndef MBEDTLS_SHA256_ALT_H
#define MBEDTLS_SHA256_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/sha256.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef unsigned int WORD;     // 32-bit word, change to "long" for 16-bit machines

#if defined(NEW_SHA256_PROCESS_ALT)
int internal_sha256_process_alt_1(mbedtls_sha256_context *ctx, const unsigned char data[64]);
#endif

#endif /* mbedtls_sha256.h */

