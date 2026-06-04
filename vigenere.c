#include "vigenere.h"
#include <ctype.h>
#include <string.h>

size_t vigenere_normalize_key(const char *key_in,
                              char *out_key,
                              size_t max_out_len)
{
    if (!key_in || !out_key || max_out_len == 0) {
        return 0;
    }

    size_t out_len = 0;

    for (const char *p = key_in; *p != '\0'; ++p) {
        if (isalpha((unsigned char)*p)) {
            if (out_len + 1 >= max_out_len) {
                /* Not enough space for more + NUL */
                break;
            }
            out_key[out_len++] = (char)toupper((unsigned char)*p);
        }
    }

    if (out_len == 0) {
        /* No usable letters in key */
        out_key[0] = '\0';
        return 0;
    }

    out_key[out_len] = '\0';
    return out_len;
}

/* Convert an uppercase A–Z letter to 0–25 */
static int letter_to_index(char c)
{
    return c - 'A';
}

/* Convert 0–25 back to uppercase A–Z */
static char index_to_letter(int idx)
{
    return (char)('A' + (idx % 26));
}

int vigenere_apply_buffer(const uint8_t *in,
                          uint8_t *out,
                          size_t len,
                          const char *key,
                          vigenere_mode_t mode)
{
    if (!in || !out || !key || key[0] == '\0') {
        return -1;
    }

    size_t key_len = strlen(key);
    if (key_len == 0) {
        return -1;
    }

    size_t key_pos = 0;

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = in[i];

        if (isalpha(c)) {
            int is_lower = islower(c);
            char upper_c = (char)toupper(c);

            /* Key char is assumed uppercase A–Z */
            char key_c = key[key_pos];
            int key_shift = letter_to_index(key_c);

            int plain_idx;
            int cipher_idx;

            if (mode == VIGENERE_MODE_ENCRYPT) {
                /* plaintext -> ciphertext */
                plain_idx  = letter_to_index(upper_c);
                cipher_idx = (plain_idx + key_shift) % 26;
                upper_c = index_to_letter(cipher_idx);
            } else {
                /* ciphertext -> plaintext */
                cipher_idx = letter_to_index(upper_c);
                plain_idx  = (cipher_idx - key_shift + 26) % 26;
                upper_c = index_to_letter(plain_idx);
            }

            /* Restore original case */
            if (is_lower) {
                out[i] = (uint8_t)tolower((unsigned char)upper_c);
            } else {
                out[i] = (uint8_t)upper_c;
            }

            /* Advance key position, wrapping */
            key_pos = (key_pos + 1) % key_len;
        } else {
            /* Non-letter: copy as-is, don't advance key */
            out[i] = c;
        }
    }

    return 0;
}

