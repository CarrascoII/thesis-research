#ifndef MEASURE_PAPILIB_H
#define MEASURE_PAPILIB_H

#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#include "papi.h"

#define MEASURE_PAPI_START      0 /**< PAPI start. */
#define MEASURE_PAPI_END        1 /**< PAPI end. */

#define MEASURE_ERR_PAPI_WRONG_VERSION      -0xA100  /**< Wrong library version. */
#define MEARURE_ERR_PAPI_INIT_FAILED        -0xA101  /**< Papi init failed. */
#define MEASURE_ERR_PAPI_BAD_INPUT_DATA     -0xA102  /**< Invalid input data. */
#define MEASURE_ERR_PAPI_MISSING_VAL        -0xA103  /**< Missing start, end or both vals */ 

typedef struct measure_papi_context {
    long long start_cycles;
    long long end_cycles;
    long long start_time;
    long long end_time;
} measure_papi_context;

int measure_papi_init(measure_papi_context *ctx);

void measure_papi_free(measure_papi_context *ctx);

void measure_papi_reset(measure_papi_context *ctx);

int measure_papi_get_cycles(measure_papi_context *ctx, int mode);

int measure_papi_get_time(measure_papi_context *ctx, int mode);

int measure_papi_starts(measure_papi_context *ctx, const char *file_name, const char *file_output);

int measure_papi_finish(measure_papi_context *ctx, const char *file_name, const char *file_output);

#endif /* MEASURE_PAPILIB_H */