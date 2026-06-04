#include <string.h>
#include "params.h"

solve_params_t default_solve_params(void)
{
    solve_params_t p;

    p.max_iters      = 2000000;   // or whatever defaults you prefer
    p.start_temp     = 1.0;
    p.end_temp       = 0.001;
    p.plateau_limit  = 50000;
    p.verbose        = 0;
    p.log_interval   = 10000;
    p.random_seed    = 0;         // 0 = auto-seed

    p.use_initial_key = 0;
    memset(p.initial_key, 0, sizeof(p.initial_key));

    return p;
}

