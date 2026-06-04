#ifndef DCT_ANALYSIS_H
#define DCT_ANALYSIS_H

#include <stddef.h>
#include <stdint.h>

/* Simple summary of JPEG DCT coefficient statistics. */
typedef struct dct_summary {
    size_t blocks;          /* number of 8x8 blocks seen */
    size_t coeffs;          /* total coefficients (blocks * 64 * components used) */
    double zero_frac;       /* fraction of coefficients that are exactly 0 */
    double odd_frac;        /* fraction of non-zero coeffs that are odd */
    double lsb1_frac;       /* fraction of coeffs with LSB == 1 (abs value) */
} dct_summary_t;

/*
 * Analyze JPEG DCT coefficients using libjpeg.
 * Returns 0 on success, -1 on error or if file is not a JPEG.
 */
int opus_dct_analyze_file(const char *path, dct_summary_t *out);

/* Pretty-print the summary. */
void opus_dct_print_summary(const dct_summary_t *s);

#endif /* DCT_ANALYSIS_H */

