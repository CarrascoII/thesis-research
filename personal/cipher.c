#include <stdio.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"
#include "config_alt.h"

void sort(unsigned char arr[], int n) {
    int i,j;
    for (i = 0; i < n-1; i++) {
        for (j = 0; j < n-i-1; j++) {
            if (arr[j] > arr[j+1]) {
                int temp = arr[j];
                arr[j] = arr[j+1];
                arr[j+1] = temp;
            }
        }
    }
}

int arrays_equal(unsigned char arr1[], unsigned char arr2[], int n, int m) {
    int i;

    sort(arr1, n);
    sort(arr2, m);

    for(i = 0; i < n; i++) {
        if(arr1[i] != arr2[i]) {
            return 0;
        }
    }

    return 1;
}

void print_hex(unsigned char array[], int size) {
    int i;

    for(i = 0; i < size; i++) {
        printf("%.2x", array[i]);
    }
    printf("\n");
}

int main() {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_aes_context aes;

    unsigned char input[32] = {
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
        0x72, 0x6c, 0x64, 0x21, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    //  unsigned char key[32] =  {
    //      0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54,
    //      0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11,
    //      0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    //      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5};

    //  unsigned char iv1[16] = {
    //      0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    //      0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d};

    //  unsigned char iv2[16] = {
    //      0x6c, 0x70, 0xed, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    //      0x51, 0xa3, 0x40, 0xbd, 0x92, 0x9d, 0x38, 0x9d};

    // int i;
    int ret;
    unsigned char output[32], decipher[32];
    unsigned char key[32], iv1[16], iv2[16];
    char *pers = "aes generate key", *pers_iv = "aes generate iv";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_aes_init(&aes);

    memset(output, 0, 32);
    memset(decipher, 0, 32);

    // Generate the key
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers, strlen(pers))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, 32)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }

    // Generate the ivs
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_iv, strlen(pers_iv))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_init returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv1, 16)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }
    
    memcpy(iv2, iv1, 16);

    // Actual test
    printf("Input:\n"); print_hex(input, sizeof(input));
    // printf("Output:\n"); print_hex(output, sizeof(output));
    // printf("Decipher:\n"); print_hex(decipher, sizeof(decipher));
    // printf("Key: \n"); print_hex(key, sizeof(key));
    // printf("IV1: \n"); print_hex(iv1, sizeof(iv1));
    // printf("IV2: \n"); print_hex(iv2, sizeof(iv2));
    printf("\n");

    // Cipher the input into output
    if((ret = mbedtls_aes_setkey_enc(&aes, key, 256)) != 0) {
        printf(" failed\n ! mbedtls_aes_setkey_enc returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv1, input, output)) != 0) {
        printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
        goto exit;
    }

    // printf("Input:\n"); print_hex(input, sizeof(input));
    printf("Output:\n"); print_hex(output, sizeof(output));
    // printf("Decipher:\n"); print_hex(decipher, sizeof(decipher));
    // printf("Key: \n"); print_hex(key, sizeof(key));
    // printf("IV1: \n"); print_hex(iv1, sizeof(iv1));
    // printf("IV2: \n"); print_hex(iv2, sizeof(iv2));
    printf("\n");

    // printf("N(rk) -> %lu\n", sizeof((&aes)->rk));
    // for(i = 0; i < (int) sizeof((&aes)->rk); i++) {
    //     printf("rk[%d] -> %u\n", i, (&aes)->rk[i]);
    // }
    // printf("nr -> %d\n", (&aes)->nr);

    // Decipher output into decipher
    if((ret = mbedtls_aes_setkey_dec(&aes, key, 256)) != 0) {
        printf(" failed\n ! mbedtls_aes_setkey_dec returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv2, output, decipher)) != 0) {
        printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
        goto exit;
    }

    // printf("Input:\n"); print_hex(input, sizeof(input));
    // printf("Output:\n"); print_hex(output, sizeof(output));
    printf("Decipher:\n"); print_hex(decipher, sizeof(decipher));
    // printf("Key: \n"); print_hex(key, sizeof(key));
    // printf("IV1: \n"); print_hex(iv1, sizeof(iv1));
    // printf("IV2: \n"); print_hex(iv2, sizeof(iv2));
    printf("\n");

    // printf("N(rk) -> %lu\n", sizeof((&aes)->rk));
    // for(i = 0; i < (int) sizeof((&aes)->rk); i++) {
    //     printf("rk[%d] -> %u\n", i, (&aes)->rk[i]);
    // }
    // printf("nr -> %d\n", (&aes)->nr);

    printf("Arrays are......... ");

    if(arrays_equal(input, decipher, sizeof(input), sizeof(decipher)) == 0) {
        printf("Different\n");
    } else {
        printf("Equal\n");
    }

exit:
    mbedtls_aes_free(&aes);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret);
}