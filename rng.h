#ifndef OPUS_RNG_H
#define OPUS_RNG_H

#include <stdint.h>

void     opus_srand(uint64_t seed);
uint64_t opus_rng64(void);
uint32_t opus_rng32(void);

#endif

