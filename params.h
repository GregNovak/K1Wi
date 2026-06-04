#ifndef OPUS_PARAMS_H
#define OPUS_PARAMS_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint64_t max_iters;
    double   start_temp;
    double   end_temp;
    uint64_t plateau_limit;
    int      verbose;
    uint64_t log_interval;
    uint64_t random_seed;

    // NEW FIELDS
    int  use_initial_key;     // 0 = random start, 1 = use initial_key
    char initial_key[26];     // cipher->plain mapping
} solve_params_t;


#endif

