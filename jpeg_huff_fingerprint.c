#include <stdio.h>
#include <string.h>
#include <jpeglib.h>
#include "jpeg_huff_fingerprint.h"



/* Canonical JPEG Huffman tables (from Annex K of the JPEG standard). */

/* DC Luminance (table 0) */
static const uint8_t STD_DC_LUMA_BITS[17] = {
    0x00,
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t STD_DC_LUMA_VALS[12] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B
};

/* DC Chrominance (table 1) */
static const uint8_t STD_DC_CHROMA_BITS[17] = {
    0x00,
    0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t STD_DC_CHROMA_VALS[12] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B
};

/* AC Luminance (table 0) */
static const uint8_t STD_AC_LUMA_BITS[17] = {
    0x00,
    0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03,
    0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D
};
static const uint8_t STD_AC_LUMA_VALS_16[16] = {
    0x01, 0x02, 0x03, 0x00,
    0x04, 0x11, 0x05, 0x12,
    0x21, 0x31, 0x41, 0x06,
    0x13, 0x51, 0x61, 0x07
};

/* AC Chrominance (table 1) */
static const uint8_t STD_AC_CHROMA_BITS[17] = {
    0x00,
    0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x03, 0x04,
    0x07, 0x05, 0x04, 0x04, 0x00, 0x01, 0x02, 0x77
};
static const uint8_t STD_AC_CHROMA_VALS_16[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x11, 0x04, 0x05, 0x21,
    0x31, 0x06, 0x12, 0x41,
    0x51, 0x07, 0x61, 0x71
};



/* Helper to extract one Huffman table into our summary */
static void fill_huff_summary(jpeg_huff_table_summary_t *dst,
                              int is_dc,
                              int idx,
                              JHUFF_TBL *ht)
{
    memset(dst, 0, sizeof(*dst));
    dst->is_dc = is_dc;
    dst->table_index = idx;
    dst->is_present = (ht != NULL);

    if (!ht) return;

    /* ht->bits[1..16] are counts of codes of each length */
    for (int i = 1; i <= 16; i++) {
        dst->code_counts[i - 1] = ht->bits[i];
    }

    /* Copy a preview of the first N symbol values */
    unsigned int total_symbols = 0;
    for (int i = 1; i <= 16; i++) {
        total_symbols += ht->bits[i];
    }

    int preview = (total_symbols < 16) ? (int)total_symbols : 16;
    dst->num_symbols_preview = preview;

    for (int i = 0; i < preview; i++) {
        dst->symbols_preview[i] = ht->huffval[i];
    }
}
/* Compare a parsed Huffman table to standard JFIF tables. */
static int matches_standard_table(const jpeg_huff_table_summary_t *ht)
{
    if (!ht->is_present) return 0;

    /* Reconstruct bits[1..16] from our code_counts. */
    uint8_t bits[17];
    bits[0] = 0;
    for (int i = 0; i < 16; i++) {
        bits[i + 1] = (uint8_t)ht->code_counts[i];
    }

    /* We only have a preview of the first 16 symbols. That's enough
       to distinguish the canonical tables reliably. */

    if (ht->is_dc && ht->table_index == 0) {
        /* DC Luma */
        if (memcmp(bits, STD_DC_LUMA_BITS, 17) != 0) return 0;
        if (ht->num_symbols_preview < 12) return 0;
        if (memcmp(ht->symbols_preview, STD_DC_LUMA_VALS, 12) != 0) return 0;
        return 1;
    }

    if (ht->is_dc && ht->table_index == 1) {
        /* DC Chroma */
        if (memcmp(bits, STD_DC_CHROMA_BITS, 17) != 0) return 0;
        if (ht->num_symbols_preview < 12) return 0;
        if (memcmp(ht->symbols_preview, STD_DC_CHROMA_VALS, 12) != 0) return 0;
        return 1;
    }

    if (!ht->is_dc && ht->table_index == 0) {
        /* AC Luma */
        if (memcmp(bits, STD_AC_LUMA_BITS, 17) != 0) return 0;
        if (ht->num_symbols_preview < 16) return 0;
        if (memcmp(ht->symbols_preview, STD_AC_LUMA_VALS_16, 16) != 0) return 0;
        return 1;
    }

    if (!ht->is_dc && ht->table_index == 1) {
        /* AC Chroma */
        if (memcmp(bits, STD_AC_CHROMA_BITS, 17) != 0) return 0;
        if (ht->num_symbols_preview < 16) return 0;
        if (memcmp(ht->symbols_preview, STD_AC_CHROMA_VALS_16, 16) != 0) return 0;
        return 1;
    }

    /* Other table indices (2,3) are treated as non-standard here. */
    return 0;
}
int opus_jpeg_huffman_fingerprint(const char *path, jpeg_huff_fingerprint_t *out)
{
    if (!path || !out) return -1;
    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("opus_jpeg_huffman_fingerprint fopen");
        return -1;
    }

    struct jpeg_decompress_struct cinfo;
    struct jpeg_error_mgr jerr;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_stdio_src(&cinfo, fp);

    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        fclose(fp);
        return -1;
    }

    /* Tables are available immediately after read_header. */
    int t = 0;
    out->num_tables = 0;
    out->num_exact_standard = 0;
    out->num_custom = 0;

    /* ---- DC tables ---- */
    for (int i = 0; i < NUM_HUFF_TBLS && t < 8; i++) {
        fill_huff_summary(&out->tables[t], 1, i, cinfo.dc_huff_tbl_ptrs[i]);

        if (out->tables[t].is_present) {
            out->num_tables++;
            out->tables[t].matches_standard =
                matches_standard_table(&out->tables[t]);

            if (out->tables[t].matches_standard)
                out->num_exact_standard++;
            else
                out->num_custom++;
        }
        t++;
    }

    /* ---- AC tables ---- */
    for (int i = 0; i < NUM_HUFF_TBLS && t < 8; i++) {
        fill_huff_summary(&out->tables[t], 0, i, cinfo.ac_huff_tbl_ptrs[i]);

        if (out->tables[t].is_present) {
            out->num_tables++;
            out->tables[t].matches_standard =
                matches_standard_table(&out->tables[t]);

            if (out->tables[t].matches_standard)
                out->num_exact_standard++;
            else
                out->num_custom++;
        }
        t++;
    }

    jpeg_destroy_decompress(&cinfo);
    fclose(fp);
    return 0;
}

/* Very coarse heuristic for "standard-ish" vs "custom" tables */
static __attribute__((unused)) int looks_standard_like(const jpeg_huff_table_summary_t *ht)
{
    if (!ht->is_present) return 1;

    /* Standard tables tend to use codes of many lengths. Very simple check:
       require: at least 4 non-zero code length buckets and some short and long codes. */
    int nonzero_lengths = 0;
    int has_short = 0; /* length <= 4 */
    int has_long  = 0; /* length >= 10 */

    for (int i = 0; i < 16; i++) {
        if (ht->code_counts[i] > 0) {
            nonzero_lengths++;
            int length = i + 1;
            if (length <= 4) has_short = 1;
            if (length >= 10) has_long = 1;
        }
    }

    if (nonzero_lengths >= 4 && has_short && has_long)
        return 1;

    return 0;
}

void opus_jpeg_huffman_print(const jpeg_huff_fingerprint_t *fp)
{
    if (!fp) return;

    printf("\n--- JPEG Huffman Fingerprint ---\n");
    printf("Tables present: %d (exact-standard: %d, custom: %d)\n",
           fp->num_tables, fp->num_exact_standard, fp->num_custom);

    for (int i = 0; i < 8; i++) {
        const jpeg_huff_table_summary_t *ht = &fp->tables[i];
        if (!ht->is_present) continue;

        printf("\nTable: %s %d%s\n",
               ht->is_dc ? "DC" : "AC",
               ht->table_index,
               ht->matches_standard ? " [STANDARD]" : " [NON-STANDARD]");

        printf("  Code length counts (bits 1..16):\n");
        printf("   ");
        for (int k = 0; k < 16; k++) {
            printf("%2u ", ht->code_counts[k]);
        }
        printf("\n");

        printf("  First %d symbols (hex):\n", ht->num_symbols_preview);
        printf("   ");
        for (int k = 0; k < ht->num_symbols_preview; k++) {
            printf("%02X ", ht->symbols_preview[k]);
        }
        printf("\n");
    }

    if (fp->num_tables == 0) {
        printf("\nAssessment: No Huffman tables found (not a baseline JPEG?).\n");
    } else if (fp->num_custom == 0 && fp->num_exact_standard > 0) {
        printf("\nAssessment: All present Huffman tables exactly match baseline JFIF standards.\n");
    } else if (fp->num_exact_standard > 0 && fp->num_custom > 0) {
        printf("\nAssessment: Mix of standard and custom Huffman tables (possible recompression or specialized encoder).\n");
    } else {
        printf("\nAssessment: All Huffman tables are non-standard (likely recompression or custom encoder/stego).\n");
    }
}


