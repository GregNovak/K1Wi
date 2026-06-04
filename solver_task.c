#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "solve.h"
#include "solver_task.h"
#include "task_pool.h"


// Globals from Opus.c
extern pthread_mutex_t status_lock;
extern int active_solver_tasks;
extern char last_solver_progress[256];
extern double last_score;

extern void post_progress_msg_internal(const char *msg);

void solver_task_worker(void *vctx) {
    SolverTaskCtx *ctx = (SolverTaskCtx *)vctx;

    solution_t sol = solve_monoalphabetic(&ctx->cipher,
                                          ctx->model,
                                          &ctx->params);

    pthread_mutex_lock(&status_lock);
    last_score = sol.score;
    pthread_mutex_unlock(&status_lock);

    ctx->plaintext   = sol.plaintext;
    ctx->final_score = sol.score;
}



void solver_task_progress(void *vctx, const char *msg) {
    (void)vctx;

    pthread_mutex_lock(&status_lock);
    strncpy(last_solver_progress, msg, sizeof(last_solver_progress) - 1);
    pthread_mutex_unlock(&status_lock);

    post_progress_msg_internal(msg);
}

void solver_task_done(void *vctx, int result) {

	(void)result;
	
    SolverTaskCtx *ctx = (SolverTaskCtx *)vctx;

    printf("\n=== SOLVER COMPLETE ===\n");
    printf("Best score: %.4f\n", ctx->final_score);
    printf("Plaintext:\n%s\n", ctx->plaintext);

    free(ctx->cipher.text);
    free(ctx->plaintext);
    free(ctx);
    
    pthread_mutex_lock(&status_lock);
    active_solver_tasks--;
    pthread_mutex_unlock(&status_lock);
}

