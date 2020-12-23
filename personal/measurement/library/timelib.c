#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#if defined(MEASUREMENT_TIMELIB_C)
#include "measurement/timelib.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void measure_timelib_init(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(measure_timelib_context));
}

void measure_timelib_free(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(measure_timelib_context));
}

void measure_timelib_reset(measure_timelib_context *ctx) {
    if(ctx == NULL) {
        return;
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
    double final_time;
    FILE *csv;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }

    if(ctx->start_time == 0 || ctx->end_time == 0) {
        return(MEASURE_ERR_TIMELIB_MISSING_VAL);
    }

    final_time = (double) (ctx->end_time - ctx->start_time) / CLOCKS_PER_SEC;

#if defined(PRINT_MEASUREMENTS)
    printf("%s", file_output);
    printf(", %d, %d", final_cycles, final_time);
#endif

    csv = fopen(file_name, "a+");
    fprintf(csv, "%s", file_output);
    fprintf(csv, ",%f", final_time);
    fclose(csv);

    measure_timelib_reset(ctx);

    return(0);
}

#endif /* MEASUREMENT_TIMELIB_C */