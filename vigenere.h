#ifndef VIGENERE_H
#define VIGENERE_H

#include <stddef.h>
#include <stdint.h>

/* Mode enum for clarity */
typedef enum {
    VIGENERE_MODE_ENCRYPT = 0,
    VIGENERE_MODE_DECRYPT = 1
} vigenere_mode_t;

/*
 * Normalize a key string:
 * - Converts to uppercase A–Z
 * - Removes non-letters
 * - Writes into out_key (NUL-terminated), up to max_out_len-1 chars
 * Returns length of normalized key, or 0 on error (no valid letters).
 */
size_t vigenere_normalize_key(const char *key_in,
                              char *out_key,
                              size_t max_out_len);

/*
 * Apply Vigenère to input buffer.
 *
 * - in:       input buffer (raw bytes, typically text)
 * - out:      output buffer (must have at least len bytes)
 * - len:      number of bytes in input/output
 * - key:      normalized key: uppercase A–Z, at least 1 char, NUL-terminated
 * - mode:     encrypt or decrypt
 *
 * Behavior:
 * - ASCII letters A–Z and a–z are shifted, preserving original case.
 * - Non-letters are copied as-is and DO NOT advance key position.
 * - Returns 0 on success, -1 on invalid key or arguments.
 */
int vigenere_apply_buffer(const uint8_t *in,
                          uint8_t *out,
                          size_t len,
                          const char *key,
                          vigenere_mode_t mode);

#endif /* VIGENERE_H */

