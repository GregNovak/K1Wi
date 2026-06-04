#include "rng.h"

static uint64_t rng_state = 88172645463393265ULL;

void opus_srand(uint64_t seed) {
    if (seed == 0) seed = 88172645463393265ULL;
    rng_state = seed;
}

static uint64_t xorshift64(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

uint64_t opus_rng64(void) {
    return xorshift64();
}

uint32_t opus_rng32(void) {
    return (uint32_t)(xorshift64() >> 32);
}

