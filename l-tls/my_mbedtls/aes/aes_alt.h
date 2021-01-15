#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/aes.h"
#include <stddef.h>

#define AES_BLOCK_SIZE 16               // AES operates on 16 bytes at a time

typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD;             // 32-bit word, change to "long" for 16-bit machines

#if defined(MBEDTLS_AES_SETKEY_ENC_ALT) || defined(MBEDTLS_AES_SETKEY_DEC_ALT)
WORD SubWord(WORD word);
#endif

#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_DECRYPT_ALT)
void AddRoundKey(BYTE state[][4], const WORD w[]);
#endif

#if defined(NEW_AES_SETKEY_ENC_ALT)
int aes_setkey_enc_alt_1(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits);
#endif

#if defined(NEW_AES_SETKEY_DEC_ALT)
int aes_setkey_dec_alt_1(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits);
#endif

#if defined(MBEDTLS_AES_ENCRYPT_ALT)
void SubBytes(BYTE state[][4]);

void ShiftRows(BYTE state[][4]);

void MixColumns(BYTE state[][4]);
#endif

#if defined(NEW_AES_ENCRYPT_ALT)
int internal_aes_encrypt_alt_1(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]);
#endif

#if defined(MBEDTLS_AES_DECRYPT_ALT)
void InvSubBytes(BYTE state[][4]);

void InvShiftRows(BYTE state[][4]);

void InvMixColumns(BYTE state[][4]);
#endif

#if defined(NEW_AES_DECRYPT_ALT)
int internal_aes_decrypt_alt_1(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]);
#endif

#endif /* mbedtls_aes.h */