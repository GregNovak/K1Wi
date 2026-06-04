#ifndef OPUS_LOGGING_H
#define OPUS_LOGGING_H

#include "state.h"
#include "params.h"

void opus_log_warn(const char *fmt, ...);

void log_error(const char *fmt, ...);
void log_info(const char *fmt, ...);

void log_state(const solver_state_t *current,
               const solver_state_t *best,
               const solve_params_t *params);

#endif

