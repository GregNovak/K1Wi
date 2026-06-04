#include <stdint.h>
#include "score.h"
#include "state.h"

// Example hash: base-26 index for quadgram
static inline uint32_t quad_index(char a, char b, char c, char d) {
    return (uint32_t)((a - 'A') * 26 * 26 * 26 +
                      (b - 'A') * 26 * 26 +
                      (c - 'A') * 26 +
                      (d - 'A'));
}

double score_plaintext(const char *pt, uint32_t len, const quadgram_model_t *model) {
    if (len < 4) return model->floor_log_prob * 4;

    double score = 0.0;
    for (uint32_t i = 0; i + 3 < len; i++) {
        char a = pt[i];
        char b = pt[i+1];
        char c = pt[i+2];
        char d = pt[i+3];

        if (a < 'A' || a > 'Z' ||
            b < 'A' || b > 'Z' ||
            c < 'A' || c > 'Z' ||
            d < 'A' || d > 'Z') {
            score += model->floor_log_prob;
            continue;
        }

        uint32_t idx = quad_index(a, b, c, d);
        if (idx < model->table_size) {
            score += model->log_probs[idx];
        } else {
            score += model->floor_log_prob;
        }
    }
    return score;
}

void apply_key_to_ciphertext(const cipher_t *c, const opus_key_t *k, char *out_plain) {

    for (size_t i = 0; i < c->length; i++) {
        char ch = c->text[i];
        if (ch >= 'A' && ch <= 'Z') {
            out_plain[i] = k->map[ch - 'A'];
        } else {
            out_plain[i] = ch;
        }
    }
    out_plain[c->length] = '\0';
}

