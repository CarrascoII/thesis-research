#include <stdio.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"
#include "config_alt.h"

#if defined(USE_PAPI)
#include "papi.h"
#endif 

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

#if defined(USE_PAPI)
    long long start_cycles_wall, end_cycles_wall, start_usec_wall, end_usec_wall,
              cycles_wall_enc, usec_wall_enc, cycles_wall_dec, usec_wall_dec,
              start_cycles_cpu, end_cycles_cpu, start_usec_cpu, end_usec_cpu,
              cycles_cpu_enc, usec_cpu_enc, cycles_cpu_dec, usec_cpu_dec;
#endif

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_aes_init(&aes);

    memset(output, 0, 32);
    memset(decipher, 0, 32);

#if defined(USE_PAPI)
    ret = PAPI_library_init(PAPI_VER_CURRENT);

    if(ret != PAPI_VER_CURRENT && ret > PAPI_OK) {
        printf("PAPI library version mismatch 0x%08x\n", ret);
        goto exit;
    }

    if(ret < PAPI_OK) {
        printf("PAPI_library_init returned -0x%04x\n", -ret);
        goto exit;
    }
#endif

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
    printf("Input:\n");
    print_hex(input, sizeof(input)); printf("\n");

    // Cipher the input into output
    if((ret = mbedtls_aes_setkey_enc(&aes, key, 256)) != 0) {
        printf(" failed\n ! mbedtls_aes_setkey_enc returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(USE_PAPI)
    /* Gets the starting time in clock cycles and microseconds */
    start_cycles_wall = PAPI_get_real_cyc();
    start_usec_wall = PAPI_get_real_usec();
    start_cycles_cpu = PAPI_get_virt_cyc();
    start_usec_cpu = PAPI_get_virt_usec();
#endif

    if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32, iv1, input, output)) != 0) {
        printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(USE_PAPI)
    /* Gets the ending time in clock cycles and microseconds */
    end_cycles_wall = PAPI_get_real_cyc();
    end_usec_wall = PAPI_get_real_usec();
    end_cycles_cpu = PAPI_get_virt_cyc();
    end_usec_cpu = PAPI_get_virt_usec();

    cycles_wall_enc = end_cycles_wall - start_cycles_wall;
    usec_wall_enc = end_usec_wall - start_usec_wall;
    cycles_cpu_enc = end_cycles_cpu - start_cycles_cpu;
    usec_cpu_enc = end_usec_cpu - start_usec_cpu;
#endif

    printf("Output:\n");
    print_hex(output, sizeof(output)); printf("\n");

    // Decipher output into decipher
    if((ret = mbedtls_aes_setkey_dec(&aes, key, 256)) != 0) {
        printf(" failed\n ! mbedtls_aes_setkey_dec returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(USE_PAPI)
    /* Gets the starting time in clock cycles and microseconds */
    start_cycles_wall = PAPI_get_real_cyc();
    start_usec_wall = PAPI_get_real_usec();
    start_cycles_cpu = PAPI_get_virt_cyc();
    start_usec_cpu = PAPI_get_virt_usec();
#endif

    if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32, iv2, output, decipher)) != 0) {
        printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(USE_PAPI)
    /* Gets the ending time in clock cycles and microseconds */
    end_cycles_wall = PAPI_get_real_cyc();
    end_usec_wall = PAPI_get_real_usec();
    end_cycles_cpu = PAPI_get_virt_cyc();
    end_usec_cpu = PAPI_get_virt_usec();

    cycles_wall_dec = end_cycles_wall - start_cycles_wall;
    usec_wall_dec = end_usec_wall - start_usec_wall;
    cycles_cpu_dec = end_cycles_cpu - start_cycles_cpu;
    usec_cpu_dec = end_usec_cpu - start_usec_cpu;
#endif

    printf("Decipher:\n");
    print_hex(decipher, sizeof(decipher)); printf("\n");

    printf("Arrays are......... ");
    if(arrays_equal(input, decipher, sizeof(input), sizeof(decipher)) == 0) {
        printf("Different\n");
    } else {
        printf("Equal\n");
    }

#if defined(USE_PAPI)
    printf("\n-----Encryption-----\n");
    printf("Wall cycles: %lld\n", cycles_wall_enc);
    printf("Wall time (usec): %lld\n", usec_wall_enc);
    printf("--------------------\n");
    printf("CPU cycles: %lld\n", cycles_cpu_enc);
    printf("CPU time (usec): %lld\n", usec_cpu_enc);

    printf("\n-----Decryption-----\n");
    printf("Wall cycles: %lld\n", cycles_wall_dec);
    printf("Wall time (usec): %lld\n", usec_wall_dec);
    printf("--------------------\n");
    printf("CPU cycles: %lld\n", cycles_cpu_dec);
    printf("CPU time (usec): %lld\n", usec_cpu_dec);
#endif

exit:
    mbedtls_aes_free(&aes);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret);
}