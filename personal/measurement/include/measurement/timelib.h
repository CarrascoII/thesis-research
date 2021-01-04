#ifndef MEASURE_TIMELIB_H
#define MEASURE_TIMELIB_H

#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#include <sys/time.h>

#define MEASURE_TIMELIB_START       0 /**< TIMELIB start measurement. */
#define MEASURE_TIMELIB_END         1 /**< TIMELIB end measurement. */

#define MEARURE_ERR_TIMELIB_INIT_FAILED         -0xA200  /**< Papi init failed. */
#define MEASURE_ERR_TIMELIB_BAD_INPUT_DATA      -0xA201  /**< Invalid input data. */
#define MEASURE_ERR_TIMELIB_MISSING_VAL         -0xA202  /**< Missing start, end or both vals */
#define MEASURE_ERR_TIMELIB_FILE_NOT_FOUND      -0xA203  /**< Could not open file */

typedef struct measure_timelib_context {
    struct timeval start_time;
    struct timeval end_time;
} measure_timelib_context;

void measure_timelib_init(measure_timelib_context *ctx);

void measure_timelib_free(measure_timelib_context *ctx);

void measure_timelib_reset(measure_timelib_context *ctx);

int measure_timelib_get_time(measure_timelib_context *ctx, int mode);

int measure_timelib_starts(measure_timelib_context *ctx, const char *file_name, const char *file_output);

int measure_timelib_finish(measure_timelib_context *ctx, const char *file_name, const char *file_output);

#endif /* MEASURE_TIMELIB_H */