// opus_vig_crack.c
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "opus_vig_crack.h"

// English letter frequencies (A-Z)
static const double eng_freq[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
    0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
    0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974,
    0.00074
};

static double index_of_coincidence(const int counts[26], int N) {
    if (N <= 1) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < 26; i++) {
        sum += counts[i] * (counts[i] - 1);
    }
    return sum / (N * (N - 1));
}

static double chi_square(const int counts[26], int N) {
    if (N == 0) return 1e9;
    double chi = 0.0;
    for (int i = 0; i < 26; i++) {
        double expected = eng_freq[i] * N;
        double diff = counts[i] - expected;
        chi += (diff * diff) / (expected + 1e-9);
    }
    return chi;
}

// Build a compact uppercase-only buffer and a map to original positions.
static char *normalize_cipher(const char *input, int *out_len, int **map_out) {

	size_t input_len = strlen(input);

	if (input_len > INT_MAX) {
	    return NULL;
	}

	int n = (int)input_len;
	size_t n_size = (size_t)n;

	char *buf = malloc(n_size + 1);
	int *map = malloc(n_size * sizeof(int));
    if (!buf || !map) {
        free(buf);
        free(map);
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)input[i];
        if (isalpha(ch)) {
            buf[j] = (char)toupper(ch);
            map[j] = i;   // compact index j corresponds to original index i
            j++;
        }
    }
    buf[j] = '\0';
    *out_len = j;
    *map_out = map;
    return buf;
}

int vig_crack(const char *cipher_raw,
              char *key_out,
              char *plain_out,
              int max_keylen,
              int forced_keylen)

{
    if (!cipher_raw || !key_out || !plain_out) return -1;

    int clen_compact = 0;
    int *idx_map = NULL;

    char *cipher = normalize_cipher(cipher_raw, &clen_compact, &idx_map);
    if (!cipher || clen_compact == 0) {
        free(cipher);
        free(idx_map);
        return -1;
    }

    if (max_keylen <= 0 || max_keylen > MAX_VIG_KEYLEN) {
        max_keylen = MAX_VIG_KEYLEN;
    }

    // 1) Estimate key length via IC
    int best_klen = 1;
    double best_ic_score = 0.0;

    for (int klen = 1; klen <= max_keylen; klen++) {
        double ic_sum = 0.0;
        int cols_used = 0;

        for (int offset = 0; offset < klen; offset++) {
            int counts[26] = {0};
            int N = 0;

            for (int i = offset; i < clen_compact; i += klen) {
                int c = cipher[i] - 'A';
                if (c >= 0 && c < 26) {
                    counts[c]++;
                    N++;
                }
            }
            if (N > 0) {
                ic_sum += index_of_coincidence(counts, N);
                cols_used++;
            }
        }

        if (cols_used > 0) {
            double avg_ic = ic_sum / cols_used;
            if (avg_ic > best_ic_score) {
                best_ic_score = avg_ic;
                best_klen = klen;
            }
        }
    }

    int klen = best_klen;

	if (forced_keylen > 0 && forced_keylen <= max_keylen) {
	    klen = forced_keylen;
	}


    // 2) Solve each column as a Caesar shift via chi-square
    for (int pos = 0; pos < klen; pos++) {
        double best_chi = 1e9;
        int best_shift = 0;

        for (int shift = 0; shift < 26; shift++) {
            int counts[26] = {0};
            int N = 0;

            for (int i = pos; i < clen_compact; i += klen) {
                int c = cipher[i] - 'A';
                if (c >= 0 && c < 26) {
                    int p = (c - shift + 26) % 26;
                    counts[p]++;
                    N++;
                }
            }

            double chi = chi_square(counts, N);
            if (chi < best_chi) {
                best_chi = chi;
                best_shift = shift;
            }
        }

        key_out[pos] = (char)('A' + best_shift);
    }
    key_out[klen] = '\0';

    // 3) Decrypt into a buffer matching the original text layout
    size_t raw_len = strlen(cipher_raw);
    for (size_t i = 0; i < raw_len; i++) {
        plain_out[i] = cipher_raw[i];  // default: copy as-is
    }
    plain_out[raw_len] = '\0';

    // Only decrypt letters; preserve original case and punctuation
    for (int j = 0; j < clen_compact; j++) {
        int orig_i = idx_map[j];
        char ch = cipher_raw[orig_i];
        int k = key_out[j % klen] - 'A';

        if (isupper((unsigned char)ch)) {
            int c = ch - 'A';
            int p = (c - k + 26) % 26;
            plain_out[orig_i] = (char)('A' + p);
        } else if (islower((unsigned char)ch)) {
            int c = ch - 'a';
            int p = (c - k + 26) % 26;
            plain_out[orig_i] = (char)('a' + p);
        }
    }

    free(cipher);
    free(idx_map);
    return klen;
}

