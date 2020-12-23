#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#if defined(MEASUREMENT_PAPI_C)
#include "measurement/papilib.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int measure_papi_init(measure_papi_context *ctx) {
    int ret;

    if(ctx == NULL) {
        return(MEASURE_ERR_PAPI_BAD_INPUT_DATA);
    }

    ret = PAPI_library_init(PAPI_VER_CURRENT);

    if(ret != PAPI_VER_CURRENT && ret > PAPI_OK) {
        return(MEASURE_ERR_PAPI_WRONG_VERSION);
    }

    if(ret < PAPI_OK) {
        return(MEARURE_ERR_PAPI_INIT_FAILED);
    }

    memset(ctx, 0, sizeof(measure_papi_context));

    return(0);
}

void measure_papi_free(measure_papi_context *ctx) {
    if(ctx == NULL) {
        return(NULL);
    }

    PAPI_shutdown();

    memset(ctx, 0, sizeof(measure_papi_context));
}

void measure_papi_reset(measure_papi_context *ctx) {
    if(ctx == NULL) {
        return(NULL);
    }

    memset(ctx, 0, sizeof(measure_papi_context));
}

int measure_papi_get_cycles(measure_papi_context *ctx, int mode) {
    if(ctx == NULL || (mode != MEASURE_PAPI_START && mode != MEASURE_PAPI_END)) {
        return(MEASURE_ERR_PAPI_BAD_INPUT_DATA);
    }

    if(mode == MEASURE_PAPI_START) {
        ctx->start_cycles = PAPI_get_virt_cyc();
    } else {
        ctx->end_cycles = PAPI_get_virt_cyc();
    }

    return(0);
}

int measure_papi_get_time(measure_papi_context *ctx, int mode) {
    if(ctx == NULL || (mode != MEASURE_PAPI_START && mode != MEASURE_PAPI_END)) {
        return(MEASURE_ERR_PAPI_BAD_INPUT_DATA);
    }

    if(mode == MEASURE_PAPI_START) {
        ctx->start_time = PAPI_get_virt_usec();
    } else {
        ctx->end_time = PAPI_get_virt_usec();
    }

    return(0);
}

int measure_papi_starts(measure_papi_context *ctx, const char *file_name, const char *file_output) {
    FILE *csv;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_TIMELIB_BAD_INPUT_DATA);
    }

    csv = fopen(file_name, "w");
    fprintf(csv, "%s", file_output);
    fprintf(csv, ",cycles,time");
    fclose(csv);

    return(0);
}

int measure_papi_finish(measure_papi_context *ctx, const char *file_name, const char *file_output) {
    long long final_cycles, final_time;
    FILE *csv;

    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_PAPI_BAD_INPUT_DATA);
    }

    if(ctx->start_cycles == 0 || ctx->end_cycles == 0 ||
       ctx->start_time == 0 || ctx->end_time == 0) {
        return(MEASURE_ERR_PAPI_MISSING_VAL);
    }

    final_cycles = ctx->end_cycles - ctx->start_cycles;
    final_time = ctx->end_time - ctx->start_time;

#if defined(PRINT_MEASUREMENTS)
    printf("%s", file_output);
    printf(", %lld, %lld", final_cycles, final_time);
#endif

    csv = fopen(file_name, "a+");
    fprintf(csv, file_output);
    fprintf(csv, ",%lld,%lld", final_cycles, final_time);
    fclose(csv);

    measure_papi_reset(ctx);

    return(0);
}

#endif /* MEASUREMENT_PAPI_C */