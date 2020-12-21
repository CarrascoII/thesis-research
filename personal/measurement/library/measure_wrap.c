#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#if defined(MEASURE_C)
#include "measurement/measure_internal.h"
#if defined(MEASURE_PAPI_C)
#include "measurement/papilib.h"
#endif
#if defined(MEASURE_TIMELIB_C)
#include "measurement/timelib.h"
#endif

#if defined(MEASURE_PAPI_C)
static void* papi_ctx_alloc(void) {
    int ret;

    measure_papi_context *papi = calloc(1, sizeof(measure_papi_context));

    if(papi == NULL)
        return(NULL);

    if((ret = measure_papi_init(papi)) != 0) {
        printf("measure_papi_init returned an error: -%.4x", -ret);
        return(NULL);
    }

    return(papi);
}

static void papi_ctx_free(void *ctx) {
    measure_papi_free((measure_papi_ctx *) ctx);
    free(ctx);
}

static int papi_get_cycles_wrap(void *ctx, int mode) {
    return measure_papi_get_cycles((measure_papi_ctx *) ctx, mode);
}

static int papi_get_time_wrap(void *ctx, int mode) {
    return measure_papi_get_time((measure_papi_ctx *) ctx, mode);
}

static int papi_finish_wrap(void *ctx, const char *file_name, const char *file_output) {
    return measure_papi_finish((measure_papi_ctx *) ctx, file_name, file_output);
}

static const measure_base_t measure_papi_base = {
    papi_ctx_alloc,
    papi_ctx_free,
    papi_get_cycles_wrap,
    papi_get_time_wrap,
    papi_finish_wrap
};

const measure_info_t measure_papi_info = {
    MEASURE_TOOL_PAPI,
    "PAPI",
    "MICROSECONDS",
    MEASURE_TYPE_CYCLES | MEASURE_TYPE_TIME,
    &measure_papi_base
};
#endif /* MEASURE_PAPI_C */

#if defined(MEASURE_TIMELIB_C)
static void* timelib_ctx_alloc(void) {
    measure_timelib_context *timelib = calloc(1, sizeof(measure_timelib_context));

    if(timelib == NULL)
        return(NULL);

    measure_timelib_init(timelib);

    return(timelib);
}

static void timelib_ctx_free(void *ctx) {
    measure_timelib_free((measure_timelib_context *) ctx);
    free(ctx);
}

static int timelib_get_time_wrap(void *ctx, int mode) {
    return measure_timelib_get_time((measure_timelib_context *) ctx, mode);
}

static int timelib_finish_wrap(void *ctx, const char *file_name, const char *file_output) {
    return measure_timelib_finish((measure_timelib_context *) ctx, file_name, file_output);
}

static const measure_base_t measure_timelib_base = {
    timelib_ctx_alloc,
    timelib_ctx_free,
    NULL,
    timelib_get_time_wrap,
    timelib_finish_wrap
};

const measure_info_t measure_timelib_info = {
    MEASURE_TOOL_TIMELIB,
    "TIMELIB",
    "SECONDS",
    MEASURE_TYPE_TIME,
    &measure_timelib_base
};
#endif /* MEASURE_TIMELIB_C */

#endif /* MEASURE_C */