#ifndef MEASURE_INTERNAL_H
#define MEASURE_INTERNAL_H

#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#include "measurement/measure.h"

struct measure_base_t {    
    /** Allocate a new context */
    void* (*ctx_alloc_func)(void);

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);

    /** Get virtual CPU cycles measurement */
    int (*get_cycles_func)(void *ctx, int mode);
    
    /** Get virtual time measurement */
    int (*get_time_func)(void *ctx, int mode);

    /** Calculates and saves measured values */
    int (*finish_func)(void *ctx, const char *file_name, const char *file_output);
};

#if defined(MEASUREMENT_PAPI_C)
extern const measure_info_t measure_papi_info;
#endif
#if defined(MEASUREMENT_TIMELIB_C)
extern const measure_info_t measure_timelib_info;
#endif

#endif /* MEASURE_INTERNAL_H */