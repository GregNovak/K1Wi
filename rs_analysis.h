#ifndef RS_ANALYSIS_H
#define RS_ANALYSIS_H

#include <stddef.h>

/* Results of RS analysis for LSB embedding. */
typedef struct rs_result {
    size_t n_groups;      /* number of groups analyzed */
    double R;             /* regular groups (original) */
    double S;             /* singular groups (original) */
    double R_flipped;     /* regular groups after flipping LSBs */
    double S_flipped;     /* singular groups after flipping LSBs */
    double suspect_score; /* 0.0–1.0, higher = more likely LSB stego */
} rs_result_t;

/* Run RS analysis on file at path. Returns 0 on success, -1 on error. */
int opus_rs_analyze_file(const char *path, rs_result_t *out);

/* Pretty-print RS result. */
void opus_rs_print_result(const rs_result_t *res);

#endif

