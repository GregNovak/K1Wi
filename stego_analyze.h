#ifndef STEGO_ANALYZE_H
#define STEGO_ANALYZE_H

#include <stddef.h>

struct stego_report {
    double entropy;
    double lsb_bias;      /* fraction of LSB=1, expected ~0.5 */
    double chi_square;    /* chi-square for LSB distribution */
    double suspicion;     /* 0.0–1.0 heuristic score */
    size_t bytes_analyzed;
};

int opus_stego_analyze_file(const char *path, struct stego_report *out);
void opus_print_stego_report(const struct stego_report *rep);

#endif

