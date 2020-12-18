#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MEASURE_TIMELIB_C)
#include "timelib.h"

void measure_timelib_init(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return(NULL);
    }

    memset(ctx, 0, sizeof(measure_timelib_context));
}

void measure_timelib_free(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return(NULL);
    }

    memset(ctx, 0, sizeof(measure_timelib_context));
}

void measure_timelib_reset(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return(NULL);
    }

    memset(ctx, 0, sizeof(measure_timelib_context));
}

int measure_timelib_get_time(measure_timelib_context *ctx, int mode) {
    if(ctx == NULL || (mode != MEASURE_TIMELIB_START && mode != MEASURE_TIMELIB_END)) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }

    if(mode == MEASURE_TIMELIB_START) {
        ctx->start_time = clock();
    } else {
        ctx->end_time = clock();
    }

    return(0);
}

int measure_timelib_finish(measure_timelib_context *ctx, const char *file_name, const char *file_output) {
    double final_cycles, final_time;
    FILE *csv;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }

    if(ctx->start_time == 0 || ctx->end_time == 0) {
        return(MEASURE_ERR_TIMELIB_MISSING_VAL);
    }

    final_cycles = (double) (ctx->end_cycles - ctx->start_cycles) / CLOCK_PER_SEC;
    final_time = (double) (ctx->end_time - ctx->start_time) / CLOCK_PER_SEC;

#if defined(PRINT_MEASUREMENTS)
    printf("%s", file_output);
    printf(", %d, %d", final_cycles, final_time);
#endif

    csv = fopen(file_name, "a+");
    fprintf(csv, file_output);
    fprintf(csv, ",%d,%d", final_cycles, final_time);
    fclose(csv);

    measure_timelib_reset(ctx);

    return(0);
}

#endif /* MEASURE_TIMELIB_C */