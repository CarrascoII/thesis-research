#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <time.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

#if defined(USE_PAPI)
#include "papi.h"
#endif 

#define INPUT_SIZE  16
#define KEY_SIZE	32
#define IV_SIZE		16
#define N_TESTS     1

void sort(unsigned char arr[], int n) {
    int i, j;
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

int arrays_equal(unsigned char arr1[], unsigned char arr2[], int n) {
    int i;

    sort(arr1, n);
    sort(arr2, n);
    
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

#if defined(USE_PAPI)
long long calc_avg(long long *avg, int n_tests) {
    int i;
    long long sum = 0;

    for(i = 0; i < n_tests; i++) {
        sum += avg[i];
    }

    return (sum / n_tests);
}
#endif

int main(int argc, char **argv) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
#if !defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_context aes;
#else
    mbedtls_aes_xts_context aes;
#endif

    int i, ret, n_tests = N_TESTS,
        input_size = INPUT_SIZE, key_size = KEY_SIZE;
    unsigned char *input, *output, *decipher, *key;
    char *pers_input = "drbg generate input",
		 *pers_key = "aes generate key",
		 *p, *q;
    // struct timespec start, end;
    // long cpu_time_enc, cpu_time_dec;

#if defined(MBEDTLS_CIPHER_MODE_CBC) || defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    unsigned char iv1[IV_SIZE], iv2[IV_SIZE];
	char *pers_iv = "aes generate iv";
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB) || defined(MBEDTLS_CIPHER_MODE_CTR) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    unsigned long offset = 0;
#endif

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    unsigned char nonce_counter1[IV_SIZE], nonce_counter2[IV_SIZE], stream_block[IV_SIZE];
    char *pers_nonce = "drbg generate nonce";
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    unsigned char data_unit1[IV_SIZE], data_unit2[IV_SIZE];
    char *pers_data = "drbg generate data_unit";
#endif

#if defined(USE_PAPI)
    // long long start_cycles_wall, end_cycles_wall, start_usec_wall, end_usec_wall, cycles_wall_enc, usec_wall_enc, cycles_wall_dec, usec_wall_dec;

    long long start_cycles_cpu, end_cycles_cpu, start_usec_cpu, end_usec_cpu,
              cycles_cpu_enc, usec_cpu_enc, cycles_cpu_dec, usec_cpu_dec;

    long long *avg_cycles_enc, *avg_usec_enc, *avg_cycles_dec, *avg_usec_dec;
#endif

	for(i = 1; i < argc; i++) {
        p = argv[i];
        if((q = strchr(p, '=')) == NULL) {
            printf("To assign own variables, run with <variable>=X\n");
            return 1;
        }

        *q++ = '\0';
        if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);
            if(input_size < 0 || input_size > MBEDTLS_CTR_DRBG_MAX_REQUEST || input_size % 16 != 0) {
                printf("Input size must be multiple of 16, between 16 and 1024 \n");
                return 1;
            }
        } else if(strcmp(p, "key_size") == 0) {
			key_size = atoi(q);
#if !defined(MBEDTLS_CIPHER_MODE_XTS)
            if(key_size != 16 && key_size != 24 && key_size != 32) {
                printf("Key size must be 16, 24 or 32\n");
#else
            if(key_size != 32 && key_size != 64) {
                printf("Key size must be 32 or 64\n");
#endif
                return 1;
            }
		} else if(strcmp(p, "n_tests") == 0) {
			n_tests = atoi(q);
            if(n_tests < 1 || n_tests > 1000) {
                printf("Number of tests must be between 1 and 1000\n");
                return 1;
            }
		} else {
			printf("Available options are input_size, key_size and n_tests\n");
			return 1;
		}
	}

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
#if !defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_init(&aes);
#else
    mbedtls_aes_xts_init(&aes);
#endif

	input = (unsigned char *) malloc(input_size*sizeof(unsigned char));
	output = (unsigned char *) malloc(input_size*sizeof(unsigned char));
	decipher = (unsigned char *) malloc(input_size*sizeof(unsigned char));
	key = (unsigned char *) malloc(key_size*sizeof(unsigned char));

    memset(output, 0, input_size);
    memset(decipher, 0, input_size);

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

    avg_cycles_enc = (long long *) malloc(n_tests*sizeof(long long));
    avg_usec_enc = (long long *) malloc(n_tests*sizeof(long long));
    avg_cycles_dec = (long long *) malloc(n_tests*sizeof(long long));
    avg_usec_dec = (long long *) malloc(n_tests*sizeof(long long));
#endif

    // Generate the input
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_input, strlen(pers_input))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, input, input_size)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }

    // Generate the key
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_key, strlen(pers_key))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC) || defined(MBEDTLS_CIPHER_MODE_CFB) || \
    defined(MBEDTLS_CIPHER_MODE_OFB)
    // Generate the ivs
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_iv, strlen(pers_iv))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv1, IV_SIZE)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }
    
    memcpy(iv2, iv1, IV_SIZE);
#endif
    
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    // Generate the nonce
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_nonce, strlen(pers_nonce))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, nonce_counter1, IV_SIZE)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }

    memcpy(nonce_counter2, nonce_counter1, IV_SIZE);
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    // Generate the data_unit
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_data, strlen(pers_data))) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }

    if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, data_unit1, IV_SIZE)) != 0) {
        printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
        goto exit;
    }

    memcpy(data_unit2, data_unit1, IV_SIZE);
#endif

    // Actual test
    for(i = 0; i < n_tests; i++) {
        printf("\n-------TEST %02d-------\n", i+1);

#if !defined(MBEDTLS_CIPHER_MODE_XTS)
        // Cipher the input into output
        if((ret = mbedtls_aes_setkey_enc(&aes, key, key_size*8)) != 0) {
            printf(" failed\n ! mbedtls_aes_setkey_enc returned -0x%04x\n", -ret);
            goto exit;
        }
#else
        // Cipher the input into output
        if((ret = mbedtls_aes_xts_setkey_enc(&aes, key, key_size*8)) != 0) {
            printf(" failed\n ! mbedtls_aes_xts_setkey_enc returned -0x%04x\n", -ret);
            goto exit;
        }
#endif

#if !defined(USE_PAPI)
        printf("Input:\n");
        print_hex(input, input_size); printf("\n");
#else
        /* Gets the starting time in clock cycles and microseconds */
        // start_cycles_wall = PAPI_get_real_cyc();
        // start_usec_wall = PAPI_get_real_usec();
        start_cycles_cpu = PAPI_get_virt_cyc();
        start_usec_cpu = PAPI_get_virt_usec();
#endif

        // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
        printf("Using CBC\n");
        if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_size, iv1, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
        printf("Using CFB\n");
        if((ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, input_size, &offset, iv1, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_cfb128 returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_CTR)
        printf("Using CTR\n");
        if((ret = mbedtls_aes_crypt_ctr(&aes, input_size, &offset, nonce_counter1, stream_block, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ctr returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_OFB)
        printf("Using OFB\n");
        if((ret = mbedtls_aes_crypt_ofb(&aes, input_size, &offset, iv1, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ofb returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_XTS)
        printf("Using XTS\n");
        if((ret = mbedtls_aes_crypt_xts(&aes, MBEDTLS_AES_ENCRYPT, input_size, data_unit1, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_xts returned -0x%04x\n", -ret);
            goto exit;
        }
#else 
        printf("Using ECB\n");
        if((ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ecb returned -0x%04x\n", -ret);
            goto exit;
        }
#endif

        // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
        // cpu_time_enc = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);

#if !defined(USE_PAPI)
        printf("Output:\n");
        print_hex(output, input_size); printf("\n");
#else
        /* Gets the ending time in clock cycles and microseconds */
        // end_cycles_wall = PAPI_get_real_cyc();
        // end_usec_wall = PAPI_get_real_usec();
        end_cycles_cpu = PAPI_get_virt_cyc();
        end_usec_cpu = PAPI_get_virt_usec();

        // cycles_wall_enc = end_cycles_wall - start_cycles_wall;
        // usec_wall_enc = end_usec_wall - start_usec_wall;
        cycles_cpu_enc = end_cycles_cpu - start_cycles_cpu;
        usec_cpu_enc = end_usec_cpu - start_usec_cpu;

        avg_cycles_enc[i] = cycles_cpu_enc;
        avg_usec_enc[i] = usec_cpu_enc;
#endif

#if !defined(MBEDTLS_CIPHER_MODE_CFB) && !defined(MBEDTLS_CIPHER_MODE_CTR) && \
    !defined(MBEDTLS_CIPHER_MODE_OFB) && !defined(MBEDTLS_CIPHER_MODE_XTS)
        // Decipher output into decipher
        if((ret = mbedtls_aes_setkey_dec(&aes, key, key_size*8)) != 0) {
            printf(" failed\n ! mbedtls_aes_setkey_dec returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_XTS)
        // Decipher output into decipher
        if((ret = mbedtls_aes_xts_setkey_dec(&aes, key, key_size*8)) != 0) {
            printf(" failed\n ! mbedtls_aes_xts_setkey_dec returned -0x%04x\n", -ret);
            goto exit;
        }
#endif

#if defined(USE_PAPI)
        /* Gets the starting time in clock cycles and microseconds */
        // start_cycles_wall = PAPI_get_real_cyc();
        // start_usec_wall = PAPI_get_real_usec();
        start_cycles_cpu = PAPI_get_virt_cyc();
        start_usec_cpu = PAPI_get_virt_usec();
#endif

        // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

#if defined(MBEDTLS_CIPHER_MODE_CBC)
        if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_size, iv2, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
        if((ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_DECRYPT, input_size, &offset, iv2, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_cfb128 returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_CTR)
        if((ret = mbedtls_aes_crypt_ctr(&aes, input_size, &offset, nonce_counter2, stream_block, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ctr returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_OFB)
        if((ret = mbedtls_aes_crypt_ofb(&aes, input_size, &offset, iv2, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ofb returned -0x%04x\n", -ret);
            goto exit;
        }
#elif defined(MBEDTLS_CIPHER_MODE_XTS)
        if((ret = mbedtls_aes_crypt_xts(&aes, MBEDTLS_AES_DECRYPT, input_size, data_unit2, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_xts returned -0x%04x\n", -ret);
            goto exit;
        }
#else
        if((ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, output, decipher)) != 0) {
            printf(" failed\n ! mbedtls_aes_crypt_ecb returned -0x%04x\n", -ret);
            goto exit;
        }
#endif

        // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);
        // cpu_time_dec = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);

#if !defined(USE_PAPI)
        printf("Decipher:\n");
        print_hex(decipher, input_size); printf("\n");

        printf("Arrays are......... ");
        if(arrays_equal(input, decipher, input_size) == 0) {
            printf("Different\n");
        } else {
            printf("Equal\n");
        }
#else
        /* Gets the ending time in clock cycles and microseconds */
        // end_cycles_wall = PAPI_get_real_cyc();
        // end_usec_wall = PAPI_get_real_usec();
        end_cycles_cpu = PAPI_get_virt_cyc();
        end_usec_cpu = PAPI_get_virt_usec();

        // cycles_wall_dec = end_cycles_wall - start_cycles_wall;
        // usec_wall_dec = end_usec_wall - start_usec_wall;
        cycles_cpu_dec = end_cycles_cpu - start_cycles_cpu;
        usec_cpu_dec = end_usec_cpu - start_usec_cpu;

        avg_cycles_dec[i] = cycles_cpu_dec;
        avg_usec_dec[i] = usec_cpu_dec;

        printf("\n-----Encryption-----\n");
        // printf("Wall cycles: %lld\n", cycles_wall_enc);
        // printf("Wall time (usec): %lld\n", usec_wall_enc);
        // printf("--------------------\n");
        printf("CPU cycles: %lld\n", cycles_cpu_enc);
        printf("CPU time (usec): %lld\n", usec_cpu_enc);

        printf("\n-----Decryption-----\n");
        // printf("Wall cycles: %lld\n", cycles_wall_dec);
        // printf("Wall time (usec): %lld\n", usec_wall_dec);
        // printf("--------------------\n");
        printf("CPU cycles: %lld\n", cycles_cpu_dec);
        printf("CPU time (usec): %lld\n", usec_cpu_dec);
#endif

        // printf("\ntime.h enc: %ld\ntime.h dec: %ld\n", cpu_time_enc, cpu_time_dec);
        printf("\n");
    }

#if defined(USE_PAPI)
        printf("\n--------FINAL--------\n");

        printf("\n-----Encryption-----\n");
        printf("CPU cycles: %lld\n", calc_avg(avg_cycles_enc, n_tests));
        printf("CPU time (usec): %lld\n", calc_avg(avg_usec_enc, n_tests));

        printf("\n-----Decryption-----\n");
        printf("CPU cycles: %lld\n", calc_avg(avg_cycles_dec, n_tests));
        printf("CPU time (usec): %lld\n", calc_avg(avg_usec_dec, n_tests));
#endif

exit:
#if defined(USE_PAPI)
    free(avg_cycles_enc);
    free(avg_usec_enc);
    free(avg_cycles_dec);
    free(avg_usec_dec);
#endif

	free(key);
	free(decipher);
	free(output);
	free(input);

#if !defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_free(&aes);
#else
    mbedtls_aes_xts_free(&aes);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret);
}