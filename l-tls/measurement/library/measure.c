#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#if defined(MEASUREMENT_MEASURE_C)
#include "measurement/measure.h"
#include "measurement/measure_internal.h"

#include <stdlib.h>
#include <string.h>

static const int supported_tools[] = {
#if defined(MEASUREMENT_PAPI_C)
    MEASURE_TOOL_PAPI,
#endif
#if defined(MEASUREMENT_TIMELIB_C)
    MEASURE_TOOL_TIMELIB,
#endif
    MEASURE_TOOL_NONE
};

const int* measure_tools_list(void) {
    return(supported_tools);
}

const measure_info_t* measure_info_from_string(const char *tool_name) {
    if(NULL == tool_name)
        return(NULL);

    /* Get the appropriate measurement tool information */
#if defined(MEASUREMENT_PAPI_C)
    if(!strcmp("PAPI", tool_name))
        return measure_info_from_type(MEASURE_TOOL_PAPI);
#endif
#if defined(MEASUREMENT_TIMELIB_C)
    if(!strcmp("TIME_LIB", tool_name))
        return measure_info_from_type(MEASURE_TOOL_TIMELIB);
#endif
    return(NULL);
}

const measure_info_t* measure_info_from_type(measure_tool_t measure_tool) {
    switch(measure_tool) {
#if defined(MEASUREMENT_PAPI_C)
        case MEASURE_TOOL_PAPI:
            return(&measure_papi_info);
#endif
#if defined(MEASUREMENT_TIMELIB_C)
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
    if(ctx == NULL || ctx->measure_info == NULL)
        return;

    if(ctx->measure_ctx != NULL) {
        ctx->measure_info->base->ctx_free_func(ctx->measure_ctx);
    }

    memset(ctx, 0, sizeof(measure_context_t));
}

int measure_setup(measure_context_t *ctx, const measure_info_t *measure_info) {
    if(ctx == NULL || measure_info == NULL) {
        return(MEASURE_ERR_BAD_INPUT_DATA);
    }

    if((ctx->measure_ctx = measure_info->base->ctx_alloc_func()) == NULL) {
        return(MEASURE_ERR_ALLOC_FAILED);
    }

    ctx->measure_info = measure_info;

    return(0);
}

int measurement_measure_config(measure_context_t *ctx) {
    const measure_info_t *tmp;
    const int *tool_list;

    if((tool_list = measure_tools_list()) == MEASURE_TOOL_NONE) {
        return(MEASURE_ERR_FEATURE_UNAVAILABLE);
    }

    for(; *tool_list != MEASURE_TOOL_NONE; tool_list++) {
        if((tmp = measure_info_from_type(*tool_list)) != NULL) {
            return measure_setup(ctx, tmp);
        }
    }

    return(MEASURE_ERR_FEATURE_UNAVAILABLE);
}

int measure_get_vals(measure_context_t *ctx, measure_val_t mode) {
    int ret;

    if(ctx == NULL || (mode != MEASURE_START && mode != MEASURE_END)) {
        return(MEASURE_ERR_BAD_INPUT_DATA);
    }

    if(can_measure_cycles(ctx)) {
        if((ret = ctx->measure_info->base->get_cycles_func(ctx->measure_ctx, mode)) != 0) {
            return(ret);
        }
    }

    if(can_measure_time(ctx)) {
        if((ret = ctx->measure_info->base->get_time_func(ctx->measure_ctx, mode)) != 0) {
            return(ret);
        }
    }

    return(0);
}

int measure_starts(measure_context_t *ctx, const char *file_name, const char *file_output) {
    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_BAD_INPUT_DATA);
    }

    return ctx->measure_info->base->starts_func(ctx->measure_ctx, file_name, file_output);
}

int measure_finish(measure_context_t *ctx, const char *file_name, const char *file_output) {
    if(ctx == NULL || file_name == NULL || file_output == NULL) {
        return(MEASURE_ERR_BAD_INPUT_DATA);
    }

    return ctx->measure_info->base->finish_func(ctx->measure_ctx, file_name, file_output);
}

#endif /* MEASUREMENT_MEASURE_C */