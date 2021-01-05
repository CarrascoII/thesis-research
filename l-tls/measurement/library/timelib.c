#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#if defined(MEASUREMENT_TIMELIB_C)
#include "measurement/timelib.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
        gettimeofday(&ctx->start_time, NULL);
#if defined(PRINT_MEASUREMENTS)
        printf("\nSTART_TIME =  %ld", (long) (ctx->start_time.tv_sec*1e6 + ctx->start_time.tv_usec));
#endif
    } else {
        gettimeofday(&ctx->end_time, NULL);
#if defined(PRINT_MEASUREMENTS)
        printf("\nEND_TIME =    %ld", (long) (ctx->end_time.tv_sec*1e6 + ctx->end_time.tv_usec));
#endif
    }

    return(0);
}

int measure_timelib_starts(measure_timelib_context *ctx, const char *file_name, const char *file_output) {
    FILE *csv;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }
    
    if((csv = fopen(file_name, "w")) == NULL) {
        return(MEASURE_ERR_TIMELIB_FILE_NOT_FOUND);
    }

    fprintf(csv, "%s,time", file_output);
    fclose(csv);

    return(0);
}

int measure_timelib_finish(measure_timelib_context *ctx, const char *file_name, const char *file_output) {
    FILE *csv;
    long final_time;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }

    if((ctx->start_time.tv_sec == 0 && ctx->start_time.tv_usec == 0) ||
        (ctx->end_time.tv_sec == 0 && ctx->end_time.tv_usec == 0)) {
        return(MEASURE_ERR_TIMELIB_MISSING_VAL);
    }

    final_time = (long) ((ctx->end_time.tv_sec - ctx->start_time.tv_sec)*1e6 +
                        (ctx->end_time.tv_usec - ctx->start_time.tv_usec));

#if defined(PRINT_MEASUREMENTS)
    printf("%s, %ld", file_output, final_time);
#endif

    if((csv = fopen(file_name, "a+")) == NULL) {
        return(MEASURE_ERR_TIMELIB_FILE_NOT_FOUND);
    }

    fprintf(csv, "%s,%ld", file_output, final_time);
    fclose(csv);

    measure_timelib_reset(ctx);

    return(0);
}

#endif /* MEASUREMENT_TIMELIB_C */