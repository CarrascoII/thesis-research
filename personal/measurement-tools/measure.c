#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MEASURE_C)
#include "measure.h"
#include "measure_internal.h"

#include <stdlib.h>
#include <string.h>

static const int supported_tools[] = {
#if defined(MEASURE_PAPI_C)
    MEASURE_PAPI,
#endif
#if defined(MEASURE_TIMELIB_C)
    MEASURE_TIME_LIB,
#endif
    MBEDTLS_MD_NONE
};

const int *measure_tools_list(void) {
    return(supported_tools);
}

const measure_info_t *measure_info_from_string(const char *tool_name) {
    if(NULL == tool_name)
        return(NULL);

    /* Get the appropriate measurement tool information */
#if defined(MEASURE_PAPI_C)
    if(!strcmp("PAPI", tool_name))
        return measure_info_from_type(MEASURE_PAPI);
#endif
#if defined(MEASURE_TIMELIB_C)
    if(!strcmp("TIME_LIB", tool_name))
        return measure_info_from_type(MEASURE_TIME_LIB);
#endif
    return(NULL);
}

const measure_info_t *measure_info_from_type(measure_tool_t measure_tool) {
    switch(measure_tool) {
#if defined(MEASURE_PAPI_C)
        case MEASURE_TOOL_PAPI:
            return(&measure_papi_info);
#endif
#if defined(MEASURE_TIMELIB_C)
        case MEASURE_TOOL_TIMELIB:
            return(&measure_timelib_info);
#endif
        default:
            return(NULL);
    }
}

void measure_init(measure_context_t *ctx) {
    memset(ctx, 0, sizeof(measure_context_t));
}

void measure_free(measure_context_t *ctx) {
}

int measure_setup(measure_context_t *ctx, const measure_info_t *measure_info) {
}

int measure_clone(measure_context_t *dst, const measure_context_t *src) {
}

unsigned char measure_get_time_unit(const measure_info_t *measure_info) {
}

measure_tool_t measure_get_type(const measure_info_t *measure_info) {
}

const char *measure_get_name(const measure_info_t *measure_info) {
}

#endif /* MEASURE_C */