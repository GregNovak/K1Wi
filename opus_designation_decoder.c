#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "opus_designation_decoder.h"

/* For sorting by frequency descending */
static int cmp_freq_desc(const void *a, const void *b) {
    const designation_freq_t *x = (const designation_freq_t *)a;
    const designation_freq_t *y = (const designation_freq_t *)b;
    return (y->count - x->count);
}

/* Simple linear lookup; fine for small sets */
static int find_suffix(designation_freq_t *arr, size_t n, int number) {
    for (size_t i = 0; i < n; i++) {
        if (arr[i].number == number) return (int)i;
    }
    return -1;
}

void opus_decode_designations(const char *filename) {
    if (!filename || filename[0] == '\0') {
        printf("[!] No filename loaded. Use O to open a file first.\n");
        return;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("[!] Error opening file");
        return;
    }

    printf("\n--- Designation Decoder ---\n");
    printf("Scanning: %s\n\n", filename);

    /* Load entire file */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }
    long size = ftell(fp);
    if (size < 0) {
        perror("[!] ftell failed");
        fclose(fp);
        return;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }

 
  
    size_t file_size = (size_t)size;
    char *buf = malloc(file_size + 1);

    if (!buf) {
        printf("[!] Memory allocation failed.\n");
        fclose(fp);
        return;
    }
    size_t read_bytes = fread(buf, 1, file_size, fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    /* First pass: collect all suffixes with counts */
    designation_freq_t *freqs = NULL;
    size_t freq_count = 0;

    /* Also store the raw sequence of suffixes in order for later decoding */
    int *sequence = NULL;
    size_t seq_len = 0;

    for (long i = 0; i + 5 < (long)read_bytes; i++) {
        unsigned char c0 = (unsigned char)buf[i];
        unsigned char c1 = (unsigned char)buf[i+1];
        unsigned char c2 = (unsigned char)buf[i+2];
        unsigned char c3 = (unsigned char)buf[i+3];
        unsigned char c4 = (unsigned char)buf[i+4];
        unsigned char c5 = (unsigned char)buf[i+5];

        if (isdigit(c0) &&
            c1 == '-' &&
            isdigit(c2) &&
            isdigit(c3) &&
            isdigit(c4) &&
            isdigit(c5)) {

            int prefix = c0 - '0';
            int number =
                (c2 - '0') * 1000 +
                (c3 - '0') * 100 +
                (c4 - '0') * 10 +
                (c5 - '0');

            /* Grow sequence */
            int *tmp_seq = realloc(sequence, (seq_len + 1) * sizeof(int));
            if (!tmp_seq) {
                printf("[!] Memory allocation failed.\n");
                free(buf);
                free(sequence);
                free(freqs);
                return;
            }
            sequence = tmp_seq;
            sequence[seq_len++] = number;

            /* Update frequency table (group by suffix only) */
            int idx = find_suffix(freqs, freq_count, number);
            if (idx == -1) {
                designation_freq_t *tmp = realloc(freqs, (freq_count + 1) * sizeof(designation_freq_t));
                if (!tmp) {
                    printf("[!] Memory allocation failed.\n");
                    free(buf);
                    free(sequence);
                    free(freqs);
                    return;
                }
                freqs = tmp;
                freqs[freq_count].prefix = prefix;
                freqs[freq_count].number = number;
                freqs[freq_count].count = 1;
                freq_count++;
            } else {
                freqs[idx].count++;
            }

            i += 5; /* skip this pattern */
        }
    }

    free(buf);

    if (freq_count == 0) {
        printf("[!] No designations found to decode.\n");
        free(sequence);
        free(freqs);
        return;
    }

    /* Sort by frequency descending */
    qsort(freqs, freq_count, sizeof(designation_freq_t), cmp_freq_desc);

    printf("Unique suffixes by frequency:\n");
    printf("Rank | Number | Count | Prefix(sample)\n");
    printf("-----+--------+-------+--------------\n");
    for (size_t i = 0; i < freq_count; i++) {
        printf("%4zu | %4d  | %5d | %d\n",
               i + 1,
               freqs[i].number,
               freqs[i].count,
               freqs[i].prefix);
    }
    printf("\n");

    /* Build a naive mapping: most frequent -> E, then T, A, O, I, N, S, H, R, D, L, U... */
    const char *freq_letters = "ETAOINSHRDLUCMFYWGPBVKXQJZ";
    char *number_to_letter = malloc(sizeof(char) * freq_count);
    if (!number_to_letter) {
        printf("[!] Memory allocation failed.\n");
        free(sequence);
        free(freqs);
        return;
    }

    for (size_t i = 0; i < freq_count; i++) {
        if (i < strlen(freq_letters)) {
            number_to_letter[i] = freq_letters[i];
        } else {
            number_to_letter[i] = '?';
        }
    }

    printf("Proposed mapping (by frequency):\n");
    printf("Number -> Letter\n");
    printf("-------+--------\n");
    for (size_t i = 0; i < freq_count; i++) {
        printf("%5d -> %c\n", freqs[i].number, number_to_letter[i]);
    }
    printf("\n");

    /* Decode the sequence using this mapping */
    printf("Decoded sequence (by frequency-based guess):\n");
    for (size_t i = 0; i < seq_len; i++) {
        int num = sequence[i];
        int idx = find_suffix(freqs, freq_count, num);
        if (idx >= 0) {
            char ch = number_to_letter[idx];
            putchar(ch);
        } else {
            putchar('?');
        }
    }
    printf("\n\n--- End of designation decode ---\n");

    free(sequence);
    free(freqs);
    free(number_to_letter);
}

