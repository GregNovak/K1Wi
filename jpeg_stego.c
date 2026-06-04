#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "jpeg_stego.h"

static double compute_entropy(const size_t hist[256], size_t total)
{
    if (total == 0) return 0.0;
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (hist[i] == 0) continue;
        double p = (double)hist[i] / (double)total;
        H -= p * log2(p);
    }
    return H;
}

/* Read big-endian 16-bit from file (for segment lengths) */
static int read_be16(FILE *fp, uint16_t *out)
{
    int hi = fgetc(fp);
    int lo = fgetc(fp);
    if (hi == EOF || lo == EOF) return -1;
    *out = (uint16_t)((hi << 8) | lo);
    return 0;
}

int opus_jpeg_stego_analyze(const char *path, struct jpeg_stego_report *out)
{
    if (!path || !out) return -1;

    memset(out, 0, sizeof(*out));

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    /* Check SOI marker */
    int b0 = fgetc(fp);
    int b1 = fgetc(fp);
    if (b0 != 0xFF || b1 != 0xD8) {
        fclose(fp);
        return -1; /* not a JPEG */
    }

    int in_entropy = 0;
    size_t hist[256] = {0};
    size_t total = 0;
    size_t lsb0 = 0, lsb1 = 0;

    for (;;) {
        int marker_prefix = fgetc(fp);
        if (marker_prefix == EOF) break;

        if (marker_prefix != 0xFF) {
            /* If we're in entropy mode, any non-0xFF byte is entropy data */
            if (in_entropy) {
                uint8_t bb = (uint8_t)marker_prefix;
                hist[bb]++;
                total++;
                if (bb & 1) lsb1++; else lsb0++;
                continue;
            } else {
                /* outside entropy: malformed or unexpected, bail */
                break;
            }
        }

        /* Skip fill bytes 0xFF FF ... */
        int marker = fgetc(fp);
        if (marker == EOF) break;

        while (marker == 0xFF) {
            marker = fgetc(fp);
            if (marker == EOF) break;
        }
        if (marker == EOF) break;

        /* Stuffed 0xFF inside entropy data: FF 00 means literal 0xFF */
        if (in_entropy && marker == 0x00) {
            hist[0xFF]++;
            total++;
            if (0xFF & 1) lsb1++; else lsb0++;
            continue;
        }

        /* EOI (End Of Image) */
        if (marker == 0xD9) {
            out->has_eoi = 1;
            break;
        }

        /* SOS (Start Of Scan) – after this marker, entropy-coded data begins */
        if (marker == 0xDA) {
            out->has_sos = 1;

            /* Read SOS segment length and skip its parameters */
            uint16_t seglen;
            if (read_be16(fp, &seglen) != 0) {
                break;
            }

            if (fseek(fp, seglen - 2, SEEK_CUR) != 0) {
                break;
            }

            /* From here on, until we hit 0xFF D9 (EOI) or another marker, we are in entropy */
            in_entropy = 1;
            continue;
        }

        /* For all other markers with parameters, skip their segments. 
           Marker range with length: 0xE0-0xEF (APPn), 0xC0-0xFE (most others),
           except stand-alone ones like 0xD0-0xD7 (RSTn). 
        */

        if (marker >= 0xD0 && marker <= 0xD7) {
            /* RST markers: no additional data */
            continue;
        }

        uint16_t seglen;
        if (read_be16(fp, &seglen) != 0) {
            break;
        }
        /* length includes the two length bytes we just read, so skip seglen - 2 */
        if (fseek(fp, seglen - 2, SEEK_CUR) != 0) {
            break;
        }
    }

    fclose(fp);

    out->entropy_bytes = total;
    if (total == 0) {
        out->entropy      = 0.0;
        out->lsb_fraction = 0.0;
        out->chi_square   = 0.0;
        out->suspicion    = 0.0;
        return 0;
    }

    double entropy = compute_entropy(hist, total);
    double p1 = (double)lsb1 / (double)total;
//    double p0 = 1.0 - p1;
    double exp_each = (double)total / 2.0;
    double chi = 0.0;
    if (exp_each > 0.0) {
        double d0 = (double)lsb0 - exp_each;
        double d1 = (double)lsb1 - exp_each;
        chi = (d0 * d0) / exp_each + (d1 * d1) / exp_each;
    }

    /* Heuristic suspicion: high entropy + very balanced LSBs */
    double bias = fabs(p1 - 0.5);                /* 0 = perfect balance */
    double lsb_score = 1.0 - fmin(bias * 4.0, 1.0);
    double entropy_score = fmin(entropy / 8.0, 1.0); /* JPEG entropy ~7-8 */

    double suspicion = 0.5 * lsb_score + 0.5 * entropy_score;

    out->entropy      = entropy;
    out->lsb_fraction = p1;
    out->chi_square   = chi;
    out->suspicion    = suspicion;

    return 0;
}

void opus_jpeg_stego_print_report(const struct jpeg_stego_report *rep)
{
    if (!rep) return;

    printf("\n--- JPEG Entropy Segment Stego Analysis ---\n");
    if (!rep->has_sos) {
        printf("No Start Of Scan (SOS) found. Not a standard JPEG scan.\n");
        return;
    }
    if (!rep->has_eoi) {
        printf("Warning: End Of Image (EOI) not found. Truncated JPEG?\n");
    }

    printf("Entropy-coded bytes: %zu\n", rep->entropy_bytes);
    printf("Entropy (entropy segment): %.4f bits/byte\n", rep->entropy);
    printf("LSB(1) fraction: %.4f (expected ~0.5)\n", rep->lsb_fraction);
    printf("Chi-square (LSB): %.4f\n", rep->chi_square);
    printf("Suspicion score: %.3f (0=low, 1=high)\n", rep->suspicion);

    if (rep->suspicion >= 0.75) {
        printf("Assessment: HIGH suspicion of JPEG stego in entropy-coded data.\n");
    } else if (rep->suspicion >= 0.5) {
        printf("Assessment: MODERATE suspicion of JPEG stego.\n");
    } else {
        printf("Assessment: LOW suspicion; entropy segment appears normal.\n");
    }
}

