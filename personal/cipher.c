#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
// #include <time.h>

#include "mbedtls/platform_util.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

#if defined(USE_PAPI)
#include "papi.h"
#endif 

#define MIN_INPUT_SIZE  16
#define MAX_INPUT_SIZE  1024
#define N_TESTS         1000
#define IV_SIZE         16
#if !defined(MBEDTLS_CIPHER_MODE_XTS)
#define MIN_KEY_SIZE    16
#define MAX_KEY_SIZE    32
#define KEY_JUMP        8
#else
#define MIN_KEY_SIZE    32
#define MAX_KEY_SIZE    64
#define KEY_JUMP        32
#endif

#if !defined(USE_PAPI)
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
#else
long long calc_avg(long long *avg, int n_tests) {
    int i;
    long long sum = 0;

    for(i = 0; i < n_tests; i++) {
        sum += avg[i];
    }

    return (sum / n_tests);
}

void print_csv(FILE *csv, long long *array, char* name, int input_size, int n_inputs, int key_size, int n_keys) {
    int i, j;

    fprintf(csv, "\n%s", name);
    for(i = 0; i < n_inputs; i++) {
        fprintf(csv, ",%d", (int) pow(2, (log(input_size)/log(2)) - n_inputs + i));
    }

    for(j = 0; j < n_keys; j++) {
        fprintf(csv, "\n%d", (key_size/KEY_JUMP - n_keys + j)*KEY_JUMP);

        for(i = 0; i < n_inputs; i++) {
            fprintf(csv, ",%lld", array[j*n_inputs + i]);
        }
    }

    fprintf(csv, "\n");
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

    int x, y, z, ret, n_tests = N_TESTS,
        n_inputs, input_size = MIN_INPUT_SIZE, initial_input_size,
        n_keys, key_size = MIN_KEY_SIZE;
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
    unsigned int offset = 0;
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
    long long start_cycles_cpu, end_cycles_cpu, start_usec_cpu, end_usec_cpu;
    long long *test_cycles_enc, *test_usec_enc, *test_cycles_dec, *test_usec_dec,
              *avg_cycles_enc, *avg_usec_enc, *avg_cycles_dec, *avg_usec_dec;
    FILE *csv;
    char filename[20] = "";
    int pos, exp, mult;
#endif

	for(x = 1; x < argc; x++) {
        p = argv[x];
        if((q = strchr(p, '=')) == NULL) {
            printf("To assign own variables, run with <variable>=X\n");
            return 1;
        }

        *q++ = '\0';
        if(strcmp(p, "input_size") == 0) {
            input_size = atoi(q);
            if(input_size < MIN_INPUT_SIZE || input_size > MAX_INPUT_SIZE || input_size % IV_SIZE != 0) {
                printf("Input size must be multiple of %d, between %d and %d \n", IV_SIZE, MIN_INPUT_SIZE, MAX_INPUT_SIZE);
                return 1;
            }
        } else if(strcmp(p, "key_size") == 0) {
			key_size = atoi(q);
            if(key_size < MIN_KEY_SIZE || key_size > MAX_KEY_SIZE || key_size % KEY_JUMP != 0) {
                printf("Key size must be multiple of %d, between %d and %d\n", KEY_JUMP, MIN_KEY_SIZE, MAX_KEY_SIZE);
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

    n_inputs = (log(MAX_INPUT_SIZE) - log(input_size))/log(2) + 1;
    n_keys = (MAX_KEY_SIZE - key_size)/KEY_JUMP + 1;
    initial_input_size = input_size;

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

    avg_cycles_enc = (long long *) malloc(n_inputs*n_keys*sizeof(long long));
    avg_usec_enc = (long long *) malloc(n_inputs*n_keys*sizeof(long long));
    avg_cycles_dec = (long long *) malloc(n_inputs*n_keys*sizeof(long long));
    avg_usec_dec = (long long *) malloc(n_inputs*n_keys*sizeof(long long));

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    strcat(filename, "PAPI_CBC");
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
    strcat(filename, "PAPI_CFB");
#elif defined(MBEDTLS_CIPHER_MODE_CTR)
    strcat(filename, "PAPI_CTR");
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
    strcat(filename, "PAPI_OFB");
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
    strcat(filename, "PAPI_XTS");
#else
    strcat(filename, "PAPI_ECB");
#endif
#if defined(MBEDTLS_AES_ENCRYPT_ALT) && defined(MBEDTLS_AES_SETKEY_ENC_ALT) && \
    defined(MBEDTLS_AES_DECRYPT_ALT) && defined(MBEDTLS_AES_SETKEY_DEC_ALT)
    strcat(filename, "_alt.csv");
#else
    strcat(filename, ".csv");
#endif
#endif

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

    for(z = 0; z < n_keys; key_size += KEY_JUMP, z++) {

	    key = (unsigned char *) malloc(key_size*sizeof(unsigned char));

        // Generate the key
        if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_key, strlen(pers_key))) != 0) {
            printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
            goto exit;
        }

        if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size)) != 0) {
            printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
            goto exit;
        }

        for(y = 0, input_size = initial_input_size; y < n_inputs; input_size *= 2, y++) {
            printf("\n---------KEY_SIZE=%d---------\n", key_size);
            printf("\n--------INPUT_SIZE=%d--------\n", input_size);

#if defined(USE_PAPI)
            test_cycles_enc = (long long *) malloc(n_tests*sizeof(long long));
            test_usec_enc = (long long *) malloc(n_tests*sizeof(long long));
            test_cycles_dec = (long long *) malloc(n_tests*sizeof(long long));
            test_usec_dec = (long long *) malloc(n_tests*sizeof(long long));
#endif

            input = (unsigned char *) malloc(input_size*sizeof(unsigned char));
            output = (unsigned char *) malloc(input_size*sizeof(unsigned char));
            decipher = (unsigned char *) malloc(input_size*sizeof(unsigned char));
            
            memset(output, 0, input_size);
            memset(decipher, 0, input_size);

            // Generate the input
            if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) pers_input, strlen(pers_input))) != 0) {
                printf(" failed\n ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
                goto exit;
            }

            if((ret = mbedtls_ctr_drbg_random(&ctr_drbg, input, input_size)) != 0) {
                printf(" failed\n ! mbedtls_ctr_drbg_random returned -0x%04x\n", -ret);
                goto exit;
            }

            // Actual test
            for(x = 0; x < n_tests; x++) {
                printf("\n-----------TEST %02d-----------\n", x+1);

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

                // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
                if((ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_size, iv1, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_cbc returned -0x%04x\n", -ret);
                    goto exit;
                }
#elif defined(MBEDTLS_CIPHER_MODE_CFB)
                if((ret = mbedtls_aes_crypt_cfb128(&aes, MBEDTLS_AES_ENCRYPT, input_size, &offset, iv1, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_cfb128 returned -0x%04x\n", -ret);
                    goto exit;
                }
#elif defined(MBEDTLS_CIPHER_MODE_CTR)
                if((ret = mbedtls_aes_crypt_ctr(&aes, input_size, &offset, nonce_counter1, stream_block, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_ctr returned -0x%04x\n", -ret);
                    goto exit;
                }
#elif defined(MBEDTLS_CIPHER_MODE_OFB)
                if((ret = mbedtls_aes_crypt_ofb(&aes, input_size, &offset, iv1, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_ofb returned -0x%04x\n", -ret);
                    goto exit;
                }
#elif defined(MBEDTLS_CIPHER_MODE_XTS)
                if((ret = mbedtls_aes_crypt_xts(&aes, MBEDTLS_AES_ENCRYPT, input_size, data_unit1, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_xts returned -0x%04x\n", -ret);
                    goto exit;
                }
#else 
                if((ret = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, input, output)) != 0) {
                    printf(" failed\n ! mbedtls_aes_crypt_ecb returned -0x%04x\n", -ret);
                    goto exit;
                }
#endif

#if !defined(USE_PAPI)
                printf("Output:\n");
                print_hex(output, input_size); printf("\n");
#else
                /* Gets the ending time in clock cycles and microseconds */
                // end_cycles_wall = PAPI_get_real_cyc();
                // end_usec_wall = PAPI_get_real_usec();
                end_cycles_cpu = PAPI_get_virt_cyc();
                end_usec_cpu = PAPI_get_virt_usec();

                // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

                // cycles_wall_enc = end_cycles_wall - start_cycles_wall;
                // usec_wall_enc = end_usec_wall - start_usec_wall;

                // cpu_time_enc = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);

                test_cycles_enc[x] = end_cycles_cpu - start_cycles_cpu;
                test_usec_enc[x] = end_usec_cpu - start_usec_cpu;
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

                // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
#endif

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

                // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

                // cycles_wall_dec = end_cycles_wall - start_cycles_wall;
                // usec_wall_dec = end_usec_wall - start_usec_wall;

                // cpu_time_dec = (end.tv_sec - start.tv_sec)*1e9 + (end.tv_nsec - start.tv_nsec);

                test_cycles_dec[x] = end_cycles_cpu - start_cycles_cpu;
                test_usec_dec[x] = end_usec_cpu - start_usec_cpu;

                printf("\n-----Encryption-----\n");
                // printf("Wall cycles: %lld\n", cycles_wall_enc);
                // printf("Wall time (usec): %lld\n", usec_wall_enc);
                // printf("--------------------\n");
                printf("CPU cycles: %lld\n", test_cycles_enc[x]);
                printf("CPU time (usec): %lld\n", test_usec_enc[x]);

                printf("\n-----Decryption-----\n");
                // printf("Wall cycles: %lld\n", cycles_wall_dec);
                // printf("Wall time (usec): %lld\n", usec_wall_dec);
                // printf("--------------------\n");
                printf("CPU cycles: %lld\n", test_cycles_dec[x]);
                printf("CPU time (usec): %lld\n", test_usec_dec[x]);

                // printf("\n------time.h Measures------\n");^M
                // printf("Encryption time (nsec): %ld\n", cpu_time_enc);
                // printf("Decryption time (nsec): %ld\n", cpu_time_dec);
#endif

                printf("\n");
            }

#if defined(USE_PAPI)
            pos = z*n_inputs + y;

            avg_cycles_enc[pos] = calc_avg(test_cycles_enc, n_tests);
            avg_usec_enc[pos] = calc_avg(test_usec_enc, n_tests);
            avg_cycles_dec[pos] = calc_avg(test_cycles_dec, n_tests);
            avg_usec_dec[pos] = calc_avg(test_usec_dec, n_tests);

            printf("\n-----Avg Encryption-----\n");
            printf("CPU cycles: %lld\n", avg_cycles_enc[pos]);
            printf("CPU time (usec): %lld\n", avg_usec_enc[pos]);

            printf("\n-----Avg Decryption-----\n");
            printf("CPU cycles: %lld\n", avg_cycles_dec[pos]);
            printf("CPU time (usec): %lld\n", avg_usec_dec[pos]);

            free(test_usec_dec);
            free(test_cycles_dec);
            free(test_usec_enc);
            free(test_cycles_enc);
#endif

            free(decipher);
            free(output);
            free(input);
        }

        free(key);        
    }

#if defined(USE_PAPI)
    printf("\n--------FINAL (input_size:key_size)--------\n");

    for(z = 0; z < n_keys; z++) {
        mult = key_size/KEY_JUMP - n_keys + z;

        for(y = 0; y < n_inputs; y++) {
            pos = z*n_inputs + y;
            exp = (log(input_size)/log(2)) - n_inputs + y;

            printf("\n---Encryption (%d:%d bytes)---\n", (int) pow(2, exp), mult*KEY_JUMP);
            printf("CPU cycles: %lld\n", avg_cycles_enc[pos]);
            printf("CPU time (usec): %lld\n", avg_usec_enc[pos]);

            printf("\n---Decryption (%d:%d bytes)---\n", (int) pow(2, exp), mult*KEY_JUMP);
            printf("CPU cycles: %lld\n", avg_cycles_dec[pos]);
            printf("CPU time (usec): %lld\n", avg_usec_dec[pos]);
        }
    }
    
    csv = fopen(filename, "w+");
    print_csv(csv, avg_cycles_enc, "cycles_enc", input_size, n_inputs, key_size, n_keys);
    print_csv(csv, avg_cycles_dec, "cycles_dec", input_size, n_inputs, key_size, n_keys);
    print_csv(csv, avg_usec_enc, "usec_enc", input_size, n_inputs, key_size, n_keys);
    print_csv(csv, avg_usec_dec, "usec_dec", input_size, n_inputs, key_size, n_keys);
    fclose(csv);
#endif

exit:
#if defined(USE_PAPI)
    free(avg_usec_dec);
    free(avg_cycles_dec);
    free(avg_usec_enc);
    free(avg_cycles_enc);

    PAPI_shutdown();
#endif

    free(key);

#if !defined(MBEDTLS_CIPHER_MODE_XTS)
    mbedtls_aes_free(&aes);
#else
    mbedtls_aes_xts_free(&aes);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return(ret);
}