#ifndef MEASURE_H
#define MEASURE_H

#if !defined(MEASURE_CONFIG_FILE)
#include "measurement/config.h"
#else
#include MEASURE_CONFIG_FILE
#endif

#include <stdio.h>
#include <stdlib.h>

#define MEASURE_ERR_FEATURE_UNAVAILABLE     -0xA000  /**< The selected feature is not available. */
#define MEASURE_ERR_ALLOC_FAILED            -0xA001  /**< Failed to allocate memory. */
#define MEASURE_ERR_BAD_INPUT_DATA          -0xA002  /**< Bad input parameters to function. */
#define MEASURE_ERR_CYCLES_FAILED           -0xA003  /**< Failed to get virtual cycles */
#define MEASURE_ERR_TIME_FAILED             -0xA004  /**< Failed to get vitual time */
#define MEASURE_ERR_BAD_OPERATION           -0xA005  /**< Incorrect order of functions (ex: MEASURE_START within MEASURE_START) */

#define MEASURE_TYPE_CYCLES     0x01    /**< Measurement tool can measure clock cycles. */
#define MEASURE_TYPE_TIME       0x02    /**< Measurement tool can measure time. */

/**
 * \brief     Supported measurement tools.
 */
typedef enum {
    MEASURE_TOOL_NONE = 0,  /**< None. */
    MEASURE_TOOL_PAPI,      /**< The PAPI performance analysis library. */
    MEASURE_TOOL_TIMELIB    /**< The time library from C. */
} measure_tool_t;

/** Type of operation. */
typedef enum {
    MEASURE_VAL_NONE = -1,
    MEASURE_START = 0,
    MEASURE_END,
} measure_val_t;

/**
 * Base measurement tool information (opaque struct).
 */
typedef struct measure_base_t measure_base_t;

typedef struct measure_info_t {
    /** Base Measurement tool */
    measure_tool_t tool;

    /** Name of the measurement tool */
    const char *name;

    /** Time unit of the measurements  */
    const char *time_units;

    /** Bitflag comprised of MEASURE_TYPE_CYCLES and
     *  MEASURE_TYPE_TIME indicating which measurements the
     *  measurement tool supports.
     */
    int flags;

    /** Struct for base measurement functions. */
    const measure_base_t *base;
} measure_info_t;

/**
 * The generic measure context.
 */
typedef struct measure_context_t {
    /** Information about the associated measurement tool. */
    const measure_info_t *measure_info;

    /** The measure-specific context. */
    void *measure_ctx;
} measure_context_t;

/**
 * \brief   This function returns the list of measurement tools supported
 *          by the generic measure module.
 *
 * \return  A statically allocated array of measurements. Each element
 *          in the returned list is an integer belonging to the
 *          measurement tools enumeration #measure_tool_t.
 *          The last entry is 0.
 */
const int *measure_tools_list(void);

/**
 * \brief           This function returns the measurement tool information
 *                  associated with the given tool name.
 *
 * \param tool_name The name of the tool to search for.
 *
 * \return          The measurement tool information associated with \p tool_name.
 * \return          NULL if the associated measurement tool information is not found.
 */
const measure_info_t* measure_info_from_string(const char *tool_name);

/**
 * \brief               This function returns the measurement tool information
 *                      associated with the given measurement tool.
 *
 * \param measure_tool  The measurement tool to search for.
 *
 * \return              The measurement tool information associated with \p measure_tool.
 * \return              NULL if the associated measurement tool information is not found.
 */
const measure_info_t* measure_info_from_type(measure_tool_t measure_tool);

/**
 * \brief   This function initializes a measure context without
 *          binding it to a particular measurement tool.
 *
 *          This function should always be called first. It prepares the
 *          context for measure_setup() for binding it to a
 *          measurement tool.
 */
void measure_init(measure_context_t *ctx);

/**
 * \brief   This function clears the internal structure of \p ctx and
 *          frees any embedded internal structure, but does not free
 *          \p ctx itself.
 *
 *          If you have called measure_setup() on \p ctx, you must
 *          call measure_free() when you are no longer using the
 *          context.
 *          Calling this function if you have previously
 *          called measure_init() and nothing else is optional.
 *          You must not call this function if you have not called
 *          measure_init().
 */
void measure_free(measure_context_t *ctx);

/**
 * \brief               This function selects the measurent tool to use,
 *                      and allocates internal structures.
 *
 *                      It should be called after measure_init() or
 *                      measure_free(). Makes it necessary to call
 *                      measure_free() later.
 *
 * \param ctx           The context to set up.
 * \param measure_info  The information structure of the measurement tool to use.
 *
 * \return              \c 0 on success.
 * \return              #MEASURE_ERR_BAD_INPUT_DATA on parameter-verification
 *                      failure.
 * \return              #MEASURE_ERR_ALLOC_FAILED on memory-allocation failure.
 */
int measure_setup(measure_context_t *ctx, const measure_info_t *measure_info);

int measurement_measure_config(measure_context_t *ctx);

/**
 * \brief       This function extracts the measurement tool name from the
 *              measurement tool information structure.
 *
 * \param ctx   The context of the measurement tool. This must be initialized.
 *
 * \return      The name of the measurent tool.
 */
static inline const char* measure_get_name(const measure_context_t *ctx) {
    if(ctx == NULL || ctx->measure_info == NULL) {
        return 0;
    }

    return ctx->measure_info->name;
}

/**
 * \brief       This function extracts the time unit from the
 *              measure information structure.
 *
 * \param ctx   The context of the measurement tool. This must be initialized.
 * 
 * \return      The time unit of the measurement tool.
 */
static inline const char* measure_get_time_unit(const measure_context_t *ctx) {
    if(ctx == NULL || ctx->measure_info == NULL) {
        return 0;
    }

    return ctx->measure_info->time_units;
}

/**
 * \brief       This function extracts the measurement tool from the
 *              measurement tool information structure.
 *
 * \param ctx   The context of the measurement tool. This must be initialized.
 *
 * \return      The measurement tool.
 */
static inline measure_tool_t measure_get_type(const measure_context_t *ctx) {
    if(ctx == NULL || ctx->measure_info == NULL) {
        return(MEASURE_TOOL_NONE);
    }

    return(ctx->measure_info->tool);
}

/**
 * \brief       This function verifies if context can measure cycles.
 *
 * \param ctx   The context of the measurement tool. This must be initialized.
 * 
 * \return      1 if the context can measure cycles. 0 otherwise.
 */
static inline int can_measure_cycles(const measure_context_t *ctx) {
    if(ctx == NULL || ctx->measure_info == NULL) {
        return 0;
    }

    return((ctx->measure_info->flags & MEASURE_TYPE_CYCLES) == MEASURE_TYPE_CYCLES);
}

/**
 * \brief       This function verifies if context can measure time.
 *
 * \param ctx   The context of the measurement tool. This must be initialized.
 * 
 * \return      1 if the context can measure time. 0 otherwise.
 */
static inline int can_measure_time(const measure_context_t *ctx) {
    if(ctx == NULL || ctx->measure_info == NULL) {
        return 0;
    }

    return((ctx->measure_info->flags & MEASURE_TYPE_TIME) == MEASURE_TYPE_TIME);
}

int measure_get_vals(measure_context_t *ctx, measure_val_t mode);

int measure_starts(measure_context_t *ctx, const char *file_name, const char *file_output);

int measure_finish(measure_context_t *ctx, const char *file_name, const char *file_output);

#endif /* MEASURE_H */