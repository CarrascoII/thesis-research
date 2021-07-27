#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h> 
#include <stdio.h> 
#include <wmmintrin.h> 

#include "mbedtls/aes.h"

#if defined(MBEDTLS_AES_SETKEY_ENC_ALT) || defined(MBEDTLS_AES_SETKEY_DEC_ALT)
void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key);

void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key);

void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key);
#endif

#endif /* mbedtls_aes.h */