#ifndef SOLVER_TASK_H
#define SOLVER_TASK_H

#include "state.h"
#include "params.h"
#include "opus_solve.h"




// Context passed to the worker thread
typedef struct {
    cipher_t cipher;
    quadgram_model_t *model;
    solve_params_t params;
    char *forced_spec;
    char *plaintext;
    double final_score;
} SolverTaskCtx;

// Worker thread entry point
void solver_task_worker(void *vctx);

// Called whenever the solver posts progress
void solver_task_progress(void *vctx, const char *msg);

// Called when the solver finishes
void solver_task_done(void *vctx, int result);

#endif

