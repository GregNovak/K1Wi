#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "opus_designation_solve.h"

/* Find suffix in table */
static int find_suffix(int *suffixes, size_t count, int number) {
    for (size_t i = 0; i < count; i++) {
        if (suffixes[i] == number) return (int)i;
    }
    return -1;
}

void opus_designation_solve(const char *filename) {
    if (!filename || filename[0] == '\0') {
        printf("[!] No filename loaded. Use O to open a file first.\n");
        return;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("[!] Error opening file");
        return;
    }

    printf("\n--- Designation Ciphertext Generator (for SOLVE) ---\n");
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

    /* Sequence of suffixes in order */
    int *sequence = NULL;
    size_t seq_len = 0;

    /* Unique suffix list */
    int *suffixes = NULL;
    size_t suffix_count = 0;

    /* Extract patterns */
    for (long i = 0; i + 5 < (long)read_bytes; i++) {
	unsigned char c0 = (unsigned char)buf[i];
	unsigned char c1 = (unsigned char)buf[i + 1];
	unsigned char c2 = (unsigned char)buf[i + 2];
	unsigned char c3 = (unsigned char)buf[i + 3];
	unsigned char c4 = (unsigned char)buf[i + 4];
	unsigned char c5 = (unsigned char)buf[i + 5];

        if (isdigit(c0) &&
            c1 == '-' &&
            isdigit(c2) &&
            isdigit(c3) &&
            isdigit(c4) &&
            isdigit(c5)) {

            int number =
                (c2 - '0') * 1000 +
                (c3 - '0') * 100 +
                (c4 - '0') * 10 +
                (c5 - '0');

            /* Append to sequence */
            int *tmp_seq = realloc(sequence, (seq_len + 1) * sizeof(int));
            if (!tmp_seq) {
                printf("[!] Memory allocation failed.\n");
                free(buf);
                free(sequence);
                free(suffixes);
                return;
            }
            sequence = tmp_seq;
            sequence[seq_len++] = number;

            /* Add to unique suffix list if new */
            int idx = find_suffix(suffixes, suffix_count, number);
            if (idx == -1) {
                int *tmp_suf = realloc(suffixes, (suffix_count + 1) * sizeof(int));
                if (!tmp_suf) {
                    printf("[!] Memory allocation failed.\n");
                    free(buf);
                    free(sequence);
                    free(suffixes);
                    return;
                }
                suffixes = tmp_suf;
                suffixes[suffix_count++] = number;
            }

            i += 5;
        }
    }

    free(buf);

    if (seq_len == 0) {
        printf("[!] No designations found.\n");
        free(sequence);
        free(suffixes);
        return;
    }

    /* Print symbol table */
    printf("Unique suffixes mapped to ciphertext symbols:\n");
    printf("Symbol | Suffix\n");
    printf("-------+--------\n");
    for (size_t i = 0; i < suffix_count; i++) {
        printf("   %c   | %d\n", 'A' + (int)i, suffixes[i]);
    }
    printf("\n");

    /* Generate ciphertext */
    printf("Ciphertext (copy/paste into SOLVE):\n");

    for (size_t i = 0; i < seq_len; i++) {
        int idx = find_suffix(suffixes, suffix_count, sequence[i]);
        if (idx >= 0)
            putchar('A' + idx);
        else
            putchar('?');
    }

    printf("\n\n--- End of ciphertext generation ---\n");

    free(sequence);
    free(suffixes);
}

