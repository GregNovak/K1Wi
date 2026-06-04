#ifndef JPEG_HUFF_FINGERPRINT_H
#define JPEG_HUFF_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

/* Summary of a single Huffman table */
typedef struct jpeg_huff_table_summary {
    int  is_dc;
    int  table_index;
    int  is_present;

    uint16_t code_counts[16];
    int num_symbols_preview;
    uint8_t symbols_preview[16];

    /* New fields: comparison to standard tables */
    int matches_standard;   /* 1 = exact match to known standard table */
} jpeg_huff_table_summary_t;

typedef struct jpeg_huff_fingerprint {
    int num_tables;
    jpeg_huff_table_summary_t tables[8];

    /* New global flags */
    int num_exact_standard;   /* how many tables exactly match known standards */
    int num_custom;           /* tables that are present but non-standard */
} jpeg_huff_fingerprint_t;

/* Analyze Huffman tables in a JPEG file. Returns 0 on success, -1 on error. */
int opus_jpeg_huffman_fingerprint(const char *path, jpeg_huff_fingerprint_t *out);

/* Print a human-readable fingerprint and a coarse assessment. */
void opus_jpeg_huffman_print(const jpeg_huff_fingerprint_t *fp);

#endif /* JPEG_HUFF_FINGERPRINT_H */

