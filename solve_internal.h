// solve_internal.h (optional, or inline in solve.c)
#ifndef OPUS_SOLVE_INTERNAL_H
#define OPUS_SOLVE_INTERNAL_H

#include <stdbool.h>

static inline double lerp(double a, double b, double t) {
    return a + (b - a) * t;
}

// Simple SA acceptance
static inline bool accept(double old_score, double new_score, double temp, uint64_t rand64) {
    if (new_score >= old_score) return true;
    if (temp <= 0.0) return false;

    // rand64 in [0, 2^64-1] -> u in (0,1)
    double u = (rand64 + 1.0) / (18446744073709551616.0); // 2^64
    double delta = new_score - old_score;
    double prob  = exp(delta / temp);
    return u < prob;
}

#endif

