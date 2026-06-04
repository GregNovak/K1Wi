#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "stego_analyze.h"
#include "format_utils.h"

#define CLR_RESET  "\033[0m"
#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"

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

int opus_stego_analyze_file(const char *path, struct stego_report *out)
{
    if (!path || !out) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    size_t hist[256] = {0};
    size_t total = 0;
    size_t lsb0 = 0, lsb1 = 0;

    int c;
    while ((c = fgetc(fp)) != EOF) {
        uint8_t b = (uint8_t)c;
        hist[b]++;
        total++;
        if (b & 1) lsb1++; else lsb0++;
    }

    fclose(fp);

    if (total == 0) return -1;

    double entropy = compute_entropy(hist, total);

    double p1 = (double)lsb1 / (double)total;
 //   double p0 = 1.0 - p1;

    /* Chi-square for LSB distribution vs expected 0.5 / 0.5 */
    double exp_each = (double)total / 2.0;
    double chi = 0.0;
    if (exp_each > 0.0) {
        double d0 = (double)lsb0 - exp_each;
        double d1 = (double)lsb1 - exp_each;
        chi = (d0 * d0) / exp_each + (d1 * d1) / exp_each;
    }

    /* Heuristic suspicion score 0..1
       - high when LSB is extremely balanced (~0.5) AND entropy is high
       - low when LSB is skewed or entropy is low
    */
    double bias = fabs(p1 - 0.5);          /* 0 = perfect, 0.5 = all ones or zeros */
    double lsb_score = 1.0 - fmin(bias * 4.0, 1.0);  /* compress: bias <= 0.25 -> score >= 0 */
    double entropy_score = fmin(entropy / 8.0, 1.0); /* 0..1, JPEG often ~7-8 */

    double suspicion = 0.5 * lsb_score + 0.5 * entropy_score;

    out->entropy      = entropy;
    out->lsb_bias     = p1;       /* fraction of ones */
    out->chi_square   = chi;
    out->suspicion    = suspicion;
    out->bytes_analyzed = total;

    return 0;
}



void opus_print_stego_report(const struct stego_report *rep)
{
    if (!rep) return;

    print_block_header("Stego Heuristics");

    char buf[64];

    snprintf(buf, sizeof(buf), "%zu", rep->bytes_analyzed);
    print_kv("Bytes analyzed:", buf);

    snprintf(buf, sizeof(buf), "%.4f bits/byte", rep->entropy);
    print_kv("Entropy (global):", buf);

    snprintf(buf, sizeof(buf), "%.4f", rep->lsb_bias);
    print_kv("LSB(1) fraction:", buf);

    snprintf(buf, sizeof(buf), "%.4f", rep->chi_square);
    print_kv("Chi-square (LSB):", buf);

    snprintf(buf, sizeof(buf), "%.3f", rep->suspicion);
    print_kv("Suspicion score:", buf);

    if (rep->suspicion >= 0.75) {
              printf("%-22s %sHIGH%s suspicion of stego. Try steghide/stegseek.\n",
       "Assessment:", CLR_RED, CLR_RESET);
        
    } 
    else if (rep->suspicion >= 0.5) {
        printf("%-22s %sMODERATE%s suspicion. Worth deeper stego tests.\n",
       "Assessment:", CLR_YELLOW, CLR_RESET);
    } 
    else {

        printf("%-22s %sLOW%s suspicion.\n",
       "Assessment:", CLR_GREEN, CLR_RESET);
    }
}

