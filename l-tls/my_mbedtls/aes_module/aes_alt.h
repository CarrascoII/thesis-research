#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdint.h>

#define TRUE  1
#define FALSE 0
#define AES_BLOCK_SIZE 16

typedef unsigned char BYTE;            // 8-bit byte
typedef unsigned int WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef struct mbedtls_aes_context {
    const WORD *key_schedule;
    int keysize;
} mbedtls_aes_context;

WORD SubWord(WORD word);

void aes_key_setup(const BYTE key[], WORD w[], int keysize);

void AddRoundKey(BYTE state[][4], const WORD w[]);

void SubBytes(BYTE state[][4]);

void ShiftRows(BYTE state[][4]);

void MixColumns(BYTE state[][4]);

void aes_encrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize);

void InvSubBytes(BYTE state[][4]);

void InvShiftRows(BYTE state[][4]);

void InvMixColumns(BYTE state[][4]);

void aes_decrypt(const BYTE in[], BYTE out[], const WORD key[], int keysize);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
void xor_buf(const BYTE in[], BYTE out[], size_t len);

int aes_encrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[]);

int aes_decrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[]);
#endif

#endif /* MBEDTLS_AES_ALT_H */