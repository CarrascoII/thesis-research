#ifndef MEASURE_INTERNAL_H
#define MEASURE_INTERNAL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "measure.h"

typedef measure_base_t {
    /** Base Measurement tool */
    measure_tool_t measure;

    /** Allocate a new context */
    void* (*ctx_alloc_func)(void);

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);

    /** Get virtual CPU cycles measurement */
    int (*get_cycles_func)(void *ctx);
    
    /** Get virtual time measurement */
    int (*get_time_func)(void *ctx);
};

#endif /* MEASURE_INTERNAL_H */