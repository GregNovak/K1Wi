#include <stdio.h>
#include <stdarg.h>
#include "logging.h"

#if defined(__clang__)
#define OPUS_DIAG_PUSH _Pragma("clang diagnostic push")
#define OPUS_DIAG_POP  _Pragma("clang diagnostic pop")
#define OPUS_DIAG_IGNORE_FORMAT_NONLITERAL \
    _Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"")
#else
#define OPUS_DIAG_PUSH
#define OPUS_DIAG_POP
#define OPUS_DIAG_IGNORE_FORMAT_NONLITERAL
#endif

void opus_log_warn(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, "[WARN] ");

    OPUS_DIAG_PUSH;
    OPUS_DIAG_IGNORE_FORMAT_NONLITERAL;
    vfprintf(stderr, fmt, ap);
    OPUS_DIAG_POP;

    fprintf(stderr, "\n");
    va_end(ap);
}

void log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, "[ERROR] ");

    OPUS_DIAG_PUSH;
    OPUS_DIAG_IGNORE_FORMAT_NONLITERAL;
    vfprintf(stderr, fmt, args);
    OPUS_DIAG_POP;

    fprintf(stderr, "\n");
    va_end(args);
}

void log_info(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    fprintf(stdout, "[INFO] ");

    OPUS_DIAG_PUSH;
    OPUS_DIAG_IGNORE_FORMAT_NONLITERAL;
    vfprintf(stdout, fmt, args);
    OPUS_DIAG_POP;

    fprintf(stdout, "\n");
    va_end(args);
}

void log_state(const solver_state_t *current,
               const solver_state_t *best,
               const solve_params_t *params)
{
    (void)current;
    (void)best;
    (void)params;
}
