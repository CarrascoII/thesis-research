#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_AES_ENCRYPT_ALT) || defined(MBEDTLS_AES_SETKEY_ENC_ALT) || \
    defined(MBEDTLS_AES_DECRYPT_ALT) || defined(MBEDTLS_AES_SETKEY_DEC_ALT)
#include "aes_alt.h"
#endif

/**************************** MACROS & AUX FUNC *****************************/
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT) || defined(MBEDTLS_AES_SETKEY_DEC_ALT)
static inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2) { 
    __m128i temp3; 

    temp2 = _mm_shuffle_epi32 (temp2 ,0xff); 
    temp3 = _mm_slli_si128 (temp1, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp1 = _mm_xor_si128 (temp1, temp2); 
    
    return temp1; 
} 

void AES_128_Key_Expansion(const unsigned char *userkey, unsigned char *key) { 
    __m128i temp1, temp2; 
    __m128i *Key_Schedule = (__m128i*)key; 

    temp1 = _mm_loadu_si128((__m128i*)userkey); 
    Key_Schedule[0] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[1] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[2] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[3] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[4] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[5] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[6] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[7] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[8] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[9] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36); 
    temp1 = AES_128_ASSIST(temp1, temp2); 
    Key_Schedule[10] = temp1; 
}

static inline void KEY_192_ASSIST(__m128i* temp1, __m128i * temp2, __m128i * temp3) { 
    __m128i temp4; 

    *temp2 = _mm_shuffle_epi32 (*temp2, 0x55); 
    temp4 = _mm_slli_si128 (*temp1, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    *temp1 = _mm_xor_si128 (*temp1, *temp2); 
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff); 
    temp4 = _mm_slli_si128 (*temp3, 0x4); 
    *temp3 = _mm_xor_si128 (*temp3, temp4); 
    *temp3 = _mm_xor_si128 (*temp3, *temp2); 
} 

void AES_192_Key_Expansion(const unsigned char *userkey, unsigned char *key) { 
    __m128i temp1, temp2, temp3; 
    __m128i *Key_Schedule = (__m128i*)key; 

    temp1 = _mm_loadu_si128((__m128i*)userkey); 
    temp3 = _mm_loadu_si128((__m128i*)(userkey+16)); 
    Key_Schedule[0]=temp1; 
    Key_Schedule[1]=temp3; 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x1); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1], 
    (__m128d)temp1,0); 
    Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1); 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x2); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[3]=temp1; 
    Key_Schedule[4]=temp3; 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x4); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4], 
    (__m128d)temp1,0); 
    Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1); 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x8); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[6]=temp1; 
    Key_Schedule[7]=temp3; 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x10); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7], 
    (__m128d)temp1,0); 
    Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1); 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x20); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[9]=temp1; 
    Key_Schedule[10]=temp3; 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x40); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10], 
    (__m128d)temp1,0); 
    Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1); 
    temp2=_mm_aeskeygenassist_si128 (temp3,0x80); 
    KEY_192_ASSIST(&temp1, &temp2, &temp3); 
    Key_Schedule[12]=temp1;
}

static inline void KEY_256_ASSIST_1(__m128i* temp1, __m128i * temp2) { 
    __m128i temp4; 

    *temp2 = _mm_shuffle_epi32(*temp2, 0xff); 
    temp4 = _mm_slli_si128 (*temp1, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp1 = _mm_xor_si128 (*temp1, temp4); 
    *temp1 = _mm_xor_si128 (*temp1, *temp2); 
} 

static inline void KEY_256_ASSIST_2(__m128i* temp1, __m128i * temp3) { 
    __m128i temp2,temp4; 

    temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0); 
    temp2 = _mm_shuffle_epi32(temp4, 0xaa); 
    temp4 = _mm_slli_si128 (*temp3, 0x4); 
    *temp3 = _mm_xor_si128 (*temp3, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp3 = _mm_xor_si128 (*temp3, temp4); 
    temp4 = _mm_slli_si128 (temp4, 0x4); 
    *temp3 = _mm_xor_si128 (*temp3, temp4); 
    *temp3 = _mm_xor_si128 (*temp3, temp2); 
}

void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key) { 
    __m128i temp1, temp2, temp3; 
    __m128i *Key_Schedule = (__m128i*)key; 

    temp1 = _mm_loadu_si128((__m128i*)userkey); 
    temp3 = _mm_loadu_si128((__m128i*)(userkey+16));
    Key_Schedule[0] = temp1; 
    Key_Schedule[1] = temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x01); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[2]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[3]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x02); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[4]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[5]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x04); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[6]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[7]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x08); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[8]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[9]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x10); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[10]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[11]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x20); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[12]=temp1; 
    KEY_256_ASSIST_2(&temp1, &temp3); 
    Key_Schedule[13]=temp3; 
    temp2 = _mm_aeskeygenassist_si128 (temp3,0x40); 
    KEY_256_ASSIST_1(&temp1, &temp2); 
    Key_Schedule[14]=temp1; 
}
#endif

/**************************** ACTUAL ALT FUNCS *****************************/ 
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
#if defined(NEW_AES_SETKEY_ENC_ALT)
int aes_setkey_enc_alt_1(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
#else
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
#endif
{
    uint32_t *Rk;

    if (!ctx || !key) 
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA; 

    switch(keybits) {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    Rk = (uint32_t*) malloc(sizeof(uint32_t)*(4*(ctx->nr+1)));
   
    switch(keybits) {
        case 128: AES_128_Key_Expansion(key, (unsigned char*) Rk); break;
        case 192: AES_192_Key_Expansion(key, (unsigned char*) Rk); break;
        case 256: AES_256_Key_Expansion(key, (unsigned char*) Rk); break;
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
	
#if !defined(NEW_AES_SETKEY_ENC_ALT)
	ctx->rk = Rk;
#else
	ctx->rk_alt_1 = Rk;
#endif

	return 0;
}

#if defined(NEW_AES_SETKEY_ENC_ALT)
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
    int ret;

	if((ret = aes_setkey_enc_og(ctx, key, keybits)) != 0) {
		return ret;
	}

	if((ret = aes_setkey_enc_alt_1(ctx, key, keybits)) != 0) {
		return ret;
	}

    return ret;
}
#endif /* NEW_AES_SETKEY_ENC_ALT */
#endif /* MBEDTLS_AES_SETKEY_ENC_ALT */

#if defined(MBEDTLS_AES_SETKEY_DEC_ALT)
#if defined(NEW_AES_SETKEY_DEC_ALT)
int aes_setkey_dec_alt_1(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
#else
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
#endif
{
    int ret;
    mbedtls_aes_context temp_key;
	__m128i *Key_Schedule, *Temp_Key_Schedule;
    
    if (!key || !ctx) 
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;
    
    mbedtls_aes_init(&temp_key);

    if((ret = mbedtls_aes_setkey_enc(&temp_key, key, keybits)) != 0) 
        return ret;

    ctx->nr = temp_key.nr;
	Key_Schedule = (__m128i*) malloc(sizeof(__m128i)*(4*(ctx->nr+1)));
#if !defined(NEW_AES_SETKEY_DEC_ALT)
    Temp_Key_Schedule = (__m128i*) temp_key.rk;
#else
    Temp_Key_Schedule = (__m128i*) temp_key.rk_alt_1; 
#endif

    Key_Schedule[ctx->nr] = Temp_Key_Schedule[0];
    Key_Schedule[ctx->nr-1] = _mm_aesimc_si128(Temp_Key_Schedule[1]); 
    Key_Schedule[ctx->nr-2] = _mm_aesimc_si128(Temp_Key_Schedule[2]); 
    Key_Schedule[ctx->nr-3] = _mm_aesimc_si128(Temp_Key_Schedule[3]); 
    Key_Schedule[ctx->nr-4] = _mm_aesimc_si128(Temp_Key_Schedule[4]); 
    Key_Schedule[ctx->nr-5] = _mm_aesimc_si128(Temp_Key_Schedule[5]); 
    Key_Schedule[ctx->nr-6] = _mm_aesimc_si128(Temp_Key_Schedule[6]); 
    Key_Schedule[ctx->nr-7] = _mm_aesimc_si128(Temp_Key_Schedule[7]); 
    Key_Schedule[ctx->nr-8] = _mm_aesimc_si128(Temp_Key_Schedule[8]); 
    Key_Schedule[ctx->nr-9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);

    if(ctx->nr > 10) { 
        Key_Schedule[ctx->nr-10] = _mm_aesimc_si128(Temp_Key_Schedule[10]); 
        Key_Schedule[ctx->nr-11] = _mm_aesimc_si128(Temp_Key_Schedule[11]); 
    }

    if(ctx->nr > 12) { 
        Key_Schedule[ctx->nr-12] = _mm_aesimc_si128(Temp_Key_Schedule[12]); 
        Key_Schedule[ctx->nr-13] = _mm_aesimc_si128(Temp_Key_Schedule[13]); 
    } 

    Key_Schedule[0] = Temp_Key_Schedule[ctx->nr]; 

#if !defined(NEW_AES_SETKEY_DEC_ALT)
	ctx->rk = (uint32_t*) Key_Schedule;
#else
	ctx->rk_alt_1 = (uint32_t*) Key_Schedule;
#endif

    mbedtls_aes_free(&temp_key);

	return 0;
}

#if defined(NEW_AES_SETKEY_DEC_ALT)
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits) {
    int ret, i;

	if((ret = aes_setkey_dec_og(ctx, key, keybits)) != 0) {
		return ret;
	}

	if((ret = aes_setkey_dec_alt_1(ctx, key, keybits)) != 0) {
		return ret;
	}

    return ret;
}
#endif /* NEW_AES_SETKEY_DEC_ALT */
#endif /* MBEDTLS_AES_SETKEY_DEC_ALT */

#if defined(NEW_AES_ENCRYPT_ALT) || defined(NEW_AES_DECRYPT_ALT)
void mbedtls_aes_set_cipher_size(mbedtls_aes_context *ctx, size_t len) {
	ctx->aes_total = (uint32_t) len;
}
#endif

#if defined(MBEDTLS_AES_ENCRYPT_ALT)

#if defined(NEW_AES_ENCRYPT_ALT)
int internal_aes_encrypt_alt_1(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
#else
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
#endif
{
    int j;
    __m128i tmp; 
#if !defined(NEW_AES_SETKEY_ENC_ALT)
	char *key = (char *) ctx->rk;
#else
	char *key = (char *) ctx->rk_alt_1;
#endif
    
    tmp = _mm_loadu_si128(&((__m128i*)input)[0]); 
    tmp = _mm_xor_si128(tmp,((__m128i*)key)[0]);

    for(j=1; j < ctx->nr; j++)
        tmp = _mm_aesenc_si128(tmp,((__m128i*)key)[j]);

    tmp = _mm_aesenclast_si128(tmp,((__m128i*)key)[j]); 
    _mm_storeu_si128(&((__m128i*)output)[0],tmp); 

	return 0;
}

#if defined(NEW_AES_ENCRYPT_ALT)
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]) {
    if(ctx->aes_total <= AES_ENC_THRESHOLD) {
        return internal_aes_encrypt_og(ctx, input, output);
    } else {
    	return internal_aes_encrypt_alt_1(ctx, input, output);
    }
}
#endif
#endif /* MBEDTLS_AES_ENCRYPT_ALT */

#if defined(MBEDTLS_AES_DECRYPT_ALT)
#if defined(NEW_AES_DECRYPT_ALT)
int internal_aes_decrypt_alt_1(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
#else
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16])
#endif
{
    int j;
    __m128i tmp;
#if !defined(NEW_AES_SETKEY_DEC_ALT)
	char *key = (char *) ctx->rk;
#else
	char *key = (char *) ctx->rk_alt_1;
#endif

    tmp = _mm_loadu_si128 (&((__m128i*)input)[0]); 
    tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]); 

    for(j=1; j < ctx->nr; j++){ 
        tmp = _mm_aesdec_si128 (tmp,((__m128i*)key)[j]); 
    } 

    tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)key)[j]); 
    _mm_storeu_si128 (&((__m128i*)output)[0],tmp); 

	return 0;
}

#if defined(NEW_AES_DECRYPT_ALT)
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx, const unsigned char input[16], unsigned char output[16]) {
    if(ctx->aes_total <= AES_DEC_THRESHOLD) {
        return internal_aes_decrypt_og(ctx, input, output);
    } else {
    	return internal_aes_decrypt_alt_1(ctx, input, output);
    }
}
#endif
#endif /* MBEDTLS_AES_DECRYPT_ALT */