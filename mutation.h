#ifndef OPUS_MUTATION_H
#define OPUS_MUTATION_H

#include "state.h"
#include <stdint.h>

// A simple mutation: swap positions i and j in key.map
typedef struct {
    uint8_t i;
    uint8_t j;
} mutation_t;

void mutation_init_rng(uint64_t seed);

// Propose a new mutation based on current state
mutation_t propose_mutation(const solver_state_t *state);

// Apply mutation to a key
void apply_mutation(opus_key_t *key, mutation_t m);

// Revert mutation
void revert_mutation(opus_key_t *key, mutation_t m);

#endif

