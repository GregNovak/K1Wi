#ifndef OPUS_SCORE_H
#define OPUS_SCORE_H

#include <stdint.h>
#include "state.h"

double score_plaintext(const char *pt, uint32_t len, const quadgram_model_t *model);
void apply_key_to_ciphertext(const cipher_t *c, const opus_key_t *k, char *out_plain);

#endif

