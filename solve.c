#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>

#include "solve.h"
#include "mutation.h"
#include "score.h"
#include "logging.h"
#include "rng.h"

static inline double lerp(double a, double b, double t) {
    return a + (b - a) * t;
}

static inline int accept_move(double old_score, double new_score, double temp, uint64_t r) {
    if (new_score >= old_score) return 1;
    if (temp <= 0.0) return 0;

    double u = ((double)r + 1.0) / 18446744073709551616.0;
    double delta = new_score - old_score;
    double prob  = exp(delta / temp);
    return u < prob;
}

static uint64_t solver_rand64(void) {
    return opus_rng64();   // Opus’s RNG (you already have this)
}

static void init_random_key(opus_key_t *key) {
    for (int i = 0; i < 26; i++) key->map[i] = (char)('A' + i);

    for (int i = 25; i > 0; i--) {
        uint32_t j = (uint32_t)(solver_rand64() % (uint64_t)(i + 1));
        char tmp = key->map[i];
        key->map[i] = key->map[j];
        key->map[j] = tmp;
    }
}

static void copy_state(const solver_state_t *src, solver_state_t *dst) {
    dst->cipher   = src->cipher;
    dst->key      = src->key;
    dst->score    = src->score;
    dst->model    = src->model;
    dst->iter     = src->iter;
    memcpy(dst->plaintext, src->plaintext, src->cipher.length + 1);
}

solution_t solve_monoalphabetic(const cipher_t *cipher,
                                const quadgram_model_t *model,
                                const solve_params_t *params)
{
    char *cur_plain  = malloc(cipher->length + 1);
    char *best_plain = malloc(cipher->length + 1);

    mutation_init_rng(params->random_seed);

    solver_state_t current = {
        .cipher    = *cipher,
        .model     = model,
        .plaintext = cur_plain,
        .iter      = 0
    };

// NEW: allow seeded key
if (params->use_initial_key) {
    for (int i = 0; i < 26; i++) {
        current.key.map[i] = params->initial_key[i];
    }
} else {
    init_random_key(&current.key);
}

apply_key_to_ciphertext(cipher, &current.key, current.plaintext);
current.score = score_plaintext(current.plaintext, (uint32_t)cipher->length, model);

    solver_state_t best = {
        .cipher    = *cipher,
        .model     = model,
        .plaintext = best_plain,
        .iter      = 0
    };
    copy_state(&current, &best);

    uint64_t plateau = 0;

    for (uint64_t iter = 0; iter < params->max_iters; iter++) {
        current.iter = iter;

        double t_frac = (params->max_iters > 1)
            ? (double)iter / (double)(params->max_iters - 1)
            : 1.0;

        double temp = lerp(params->start_temp, params->end_temp, t_frac);

        mutation_t m = propose_mutation(&current);
        apply_mutation(&current.key, m);
        apply_key_to_ciphertext(cipher, &current.key, current.plaintext);

        double new_score = score_plaintext(current.plaintext, (uint32_t)cipher->length, model);

        uint64_t r = solver_rand64();
        if (accept_move(current.score, new_score, temp, r)) {
            current.score = new_score;

            if (new_score > best.score) {
                copy_state(&current, &best);
                plateau = 0;
            } else {
                plateau++;
            }
        } else {
            revert_mutation(&current.key, m);
            apply_key_to_ciphertext(cipher, &current.key, current.plaintext);
            plateau++;
        }

        if (params->verbose && (iter % params->log_interval == 0)) {
            log_state(&current, &best, params);
        }

        if (plateau >= params->plateau_limit) break;
    }

    solution_t sol = {
        .key       = best.key,
        .score     = best.score,
        .plaintext = best_plain
    };

    free(cur_plain);
    return sol;
}

