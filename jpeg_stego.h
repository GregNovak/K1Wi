#ifndef JPEG_STEGO_H
#define JPEG_STEGO_H

#include <stddef.h>

struct jpeg_stego_report {
    size_t entropy_bytes;   /* number of bytes in entropy-coded segment */
    double entropy;         /* entropy of entropy segment */
    double lsb_fraction;    /* fraction of LSB=1 in entropy segment */
    double chi_square;      /* chi-square for LSB vs 0.5/0.5 */
    double suspicion;       /* 0.0–1.0 heuristic score */
    int    has_sos;         /* found Start Of Scan */
    int    has_eoi;         /* found End Of Image */
};

int opus_jpeg_stego_analyze(const char *path, struct jpeg_stego_report *out);
void opus_jpeg_stego_print_report(const struct jpeg_stego_report *rep);

#endif

