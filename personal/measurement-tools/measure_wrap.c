#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MEASURE_C)
#include "measure_internal.h"
#if defined(MEASURE_PAPI_C)
#include "papilib.h"
#endif
#if defined(MEASURE_TIMELIB_C)
#include "timelib.h"
#endif

#include <stdlib.h>

#if defined(MEASURE_PAPI_C)
static void* papi_ctx_alloc(void) {
    int ret;

    measure_context *papi = calloc(1, sizeof(measure_context));

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

static int papi_get_cycles_wrap(void *ctx) {
    return measure_papi_get_cycles((measure_papi_ctx *) ctx);
}

static int papi_get_time_wrap(void *ctx) {
    return measure_papi_get_time((measure_papi_ctx *) ctx);
}

static int papi_finish_wrap(void *ctx, const char *file_name, const char *file_output) {
    return measure_papi_finish((measure_papi_ctx *) ctx, file_name, file_output);
}

static const measure_base_t measure_papi_base = {
    MEASURE_TOOL_PAPI,
    papi_ctx_alloc,
    papi_ctx_free,
    papi_get_cycles_wrap,
    papi_get_time_wrap,
    papi_finish_wrap
};

static const measure_info_t measure_papi_info = {
    "PAPI",
    "MICROSECONDS",
    MEASURE_TYPE_CYCLES | MEASURE_TYPE_TIME,
    &measure_papi_base
};
#endif /* MEASURE_PAPI_C */

#if defined(MEASURE_TIMELIB_C)
static void* timelib_ctx_alloc(void) {
    measure_context *timelib = calloc(1, sizeof(measure_context));

    if(timelib == NULL)
        return(NULL);

    measure_timelib_init(timelib);

    return(timelib);
}

static void timelib_ctx_free(void *ctx) {
    measure_timelib_free((measure_timelib_ctx *) ctx);
    free(ctx);
}

static int timelib_get_time_wrap(void *ctx) {
    return measure_timelib_get_time((measure_timelib_ctx *) ctx);
}

static int timelib_finish_wrap(void *ctx, const char *file_name, const char *file_output) {
    return measure_timelib_finish((measure_papi_ctx *) ctx, file_name, file_output);
}

static const measure_base_t measure_timelib_base = {
    MEASURE_TOOL_TIMELIB,
    timelib_ctx_alloc,
    timelib_ctx_free,
    NULL,
    timelib_get_time_wrap,
    timelib_finish_wrap
};

static const measure_info_t measure_timelib_info = {
    "TIMELIB",
    "SECONDS",
    MEASURE_TYPE_TIME,
    &measure_timelib_base
};
#endif /* MEASURE_TIMELIB_C */

#endif /* MEASURE_C */