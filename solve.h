#ifndef OPUS_SOLVE_H
#define OPUS_SOLVE_H

#include "state.h"
#include "params.h"
#include "score.h"

// Solver result
typedef struct {
    opus_key_t key;
    double     score;
    char      *plaintext;
} solution_t;

// Provided by params.c
solve_params_t default_solve_params(void);

// Provided by solve.c
solution_t solve_monoalphabetic(const cipher_t *cipher,
                                const quadgram_model_t *model,
                                const solve_params_t *params);

#endif

