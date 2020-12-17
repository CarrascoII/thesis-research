#ifndef MEASURE_H
#define MEASURE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MEASURE_ERR_FEATURE_UNAVAILABLE     -0xA000  /**< The selected feature is not available. */
#define MEASURE_ERR_ALLOC_FAILED            -0xA001  /**< Failed to allocate memory. */
#define MEASURE_ERR_BAD_INPUT_DATA          -0xA002  /**< Bad input parameters to function. */
#define MEASURE_ERR_CYCLES_FAILED           -0xA003  /**< Failed to get virtual cycles */
#define MEASURE_ERR_TIME_FAILED             -0xA004  /**< Failed to get vitual time */

#define MEASURE_TYPE_CYCLES     0x01    /**< Measurement tool can measure clock cycles. */
#define MEASURE_TYPE_TIME       0x02    /**< Measurement tool can measure time. */

/**
 * \brief     Supported measurement tools.
 */
typedef enum {
    MEASURE_TOOL_NONE = 0,  /**< None. */
    MEASURE_TOOL_PAPI,      /**< The PAPI performance analysis library. */
    MEASURE_TOOL_TIMELIB   /**< The time library from C. */
} measure_tool_t;

/**
 * Base measurement tool information (opaque struct).
 */
typedef struct measure_base_t measure_base_t;

typedef measure_info_t {
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
};

/**
 * The generic measure context.
 */
typedef struct measure_context_t {
    /** Information about the associated measurement tool. */
    const measure_info_t *measure_info;

    /** The measure-specific context. */
    void *measure_ctx;

    /** The starting and ending values
     *  for the clock cycle measurements.
     */
    // void *cycle_measurements;

    /** The starting and ending values
     *  for the time measurements.
     */
    // void *time_measurements;
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
const measure_info_t *measure_info_from_string(const char *tool_name);

/**
 * \brief               This function returns the measurement tool information
 *                      associated with the given measurement tool.
 *
 * \param measure_tool  The measurement tool to search for.
 *
 * \return              The measurement tool information associated with \p measure_tool.
 * \return              NULL if the associated measurement tool information is not found.
 */
const measure_info_t *measure_info_from_type(measure_tool_t measure_tool);

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

/**
 * \brief       This function clones the state of an measure context.
 *
 * \note        You must call measure_setup() on \c dst before calling
 *              this function.
 *
 * \note        The two contexts must use the same tool,
 *              for example, both use PAPI.
 *
 * \param dst   The destination context.
 * \param src   The context to be cloned.
 *
 * \return      \c 0 on success.
 * \return      #MEASURE_ERR_BAD_INPUT_DATA on parameter-verification failure.
 */
int measure_clone(measure_context_t *dst, const measure_context_t *src);

/**
 * \brief               This function extracts the time unit from the
 *                      measure information structure.
 *
 * \param measure_info  The information structure of the measurement tool to use.
 *
 * \return              The time unit of the measurement tool.
 */
unsigned char measure_get_time_unit(const measure_info_t *measure_info);

/**
 * \brief               This function extracts the measurement tool from the
 *                      measurement tool information structure.
 *
 * \param measure_info  The information structure of the measurement tool to use.
 *
 * \return              The measurement tool.
 */
measure_tool_t measure_get_type(const measure_info_t *measure_info);

/**
 * \brief               This function extracts the measurement tool name from the
 *                      measurement tool information structure.
 *
 * \param measure_info  The information structure of the measurement tool to use.
 *
 * \return              The name of the measurent tool.
 */
const char *measure_get_name(const measure_info_t *measure_info);

#endif /* MEASURE_H */