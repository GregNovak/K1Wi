#ifndef OPUS_STATE_H
#define OPUS_STATE_H

#include <stdint.h>
#include <stddef.h>

/* Ciphertext container */
typedef struct {
    char   *text;     // remove const
    size_t  length;   // change uint32_t → size_t
} cipher_t;

/* Monoalphabetic key: map[i] = plaintext letter for ciphertext 'A'+i */
typedef struct {
    char map[26];
} opus_key_t;

/* Quadgram model */
typedef struct {
    double   *log_probs;      // array of size table_size
    double    floor_log_prob; // fallback score
    uint32_t  table_size;     // usually 26^4
} quadgram_model_t;

/* Solver state used internally by SOLVE */
typedef struct {
    cipher_t                cipher;
    opus_key_t                   key;
    double                  score;
    char                   *plaintext; // buffer length = cipher.length + 1
    const quadgram_model_t *model;
    uint64_t                iter;
} solver_state_t;

#endif

