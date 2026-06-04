#include "mutation.h"
#include "rng.h"

void mutation_init_rng(uint64_t seed) {
    opus_srand(seed);
}

mutation_t propose_mutation(const solver_state_t *state) {
    (void)state;
    mutation_t m;
    m.i = opus_rng32() % 26;
    do {
        m.j = opus_rng32() % 26;
    } while (m.j == m.i);
    return m;
}

void apply_mutation(opus_key_t *key, mutation_t m) {
    char tmp = key->map[m.i];
    key->map[m.i] = key->map[m.j];
    key->map[m.j] = tmp;
}

void revert_mutation(opus_key_t *key, mutation_t m) {
    apply_mutation(key, m);
}

