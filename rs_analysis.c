#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "rs_analysis.h"

#define CLR_RESET  "\033[0m"
#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"

/*
 * We use a 4-byte group and a simple discrimination function:
 *   f(G) = sum |g[i+1] - g[i]|
 * A group is:
 *   - regular   if f(G_flipped) >  f(G)
 *   - singular  if f(G_flipped) <  f(G)
 *   - unchanged if f(G_flipped) == f(G)
 */

static int read_all_bytes(const char *path, uint8_t **out_buf, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(fp); return -1; }

    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if (n != (size_t)sz) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = n;
    return 0;
}

static int discrimination_function(const uint8_t *g, size_t k)
{
    int sum = 0;
    for (size_t i = 0; i + 1 < k; i++) {
        int a = g[i];
        int b = g[i+1];
        int d = a - b;
        if (d < 0) d = -d;
        sum += d;
    }
    return sum;
}

static void flip_lsb_group(uint8_t *dst, const uint8_t *src, size_t k)
{
    for (size_t i = 0; i < k; i++) {
        dst[i] = src[i] ^ 1u;  /* flip LSB */
    }
}

int opus_rs_analyze_file(const char *path, rs_result_t *out)
{
    if (!path || !out) return -1;

    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_all_bytes(path, &buf, &len) != 0) {
        return -1;
    }

    const size_t k = 4; /* group size */
    if (len < k) {
        free(buf);
        return -1;
    }

    size_t n_groups = 0;
    double R = 0.0, S = 0.0;
    double Rf = 0.0, Sf = 0.0;

    uint8_t g[4];
    uint8_t gf[4];

    /* We walk the whole file in non-overlapping groups of size k. */
    size_t i = 0;
    while (i + k <= len) {
        for (size_t j = 0; j < k; j++) {
            g[j] = buf[i + j];
        }

        int f_orig = discrimination_function(g, k);
        flip_lsb_group(gf, g, k);
        int f_flip = discrimination_function(gf, k);

        if (f_flip > f_orig)      R += 1.0;
        else if (f_flip < f_orig) S += 1.0;

        /* Now treat the *already flipped* group as "flipped cover"
           and flip it again to simulate embedding. */
        int f2_orig = f_flip;
        flip_lsb_group(g, gf, k);
        int f2_flip = discrimination_function(g, k);

        if (f2_flip > f2_orig)      Rf += 1.0;
        else if (f2_flip < f2_orig) Sf += 1.0;

        n_groups++;
        i += k;
    }

    free(buf);

    out->n_groups     = n_groups;
    out->R            = (n_groups > 0) ? R / (double)n_groups : 0.0;
    out->S            = (n_groups > 0) ? S / (double)n_groups : 0.0;
    out->R_flipped    = (n_groups > 0) ? Rf / (double)n_groups : 0.0;
    out->S_flipped    = (n_groups > 0) ? Sf / (double)n_groups : 0.0;

    /* Simple suspicion heuristic:
     * If (R - Rf) and (Sf - S) are both significantly positive,
     * we consider it suspicious. Normalize to 0..1.
     */
    double d1 = out->R - out->R_flipped;
    double d2 = out->S_flipped - out->S;

    double raw = 0.0;
    if (d1 > 0.0) raw += d1;
    if (d2 > 0.0) raw += d2;

    /* Clamp and squash: typical values are small, so scale. */
    double score = raw * 5.0; /* tweak factor */
    if (score > 1.0) score = 1.0;
    if (score < 0.0) score = 0.0;

    out->suspect_score = score;

    return 0;
}

void opus_rs_print_result(const rs_result_t *res)
{
    if (!res) return;

    printf("\n--- RS Analysis (LSB stego detection) ---\n");
    printf("Groups analyzed:   %zu\n", res->n_groups);
    printf("R (orig):          %.6f\n", res->R);
    printf("S (orig):          %.6f\n", res->S);
    printf("R (flipped):       %.6f\n", res->R_flipped);
    printf("S (flipped):       %.6f\n", res->S_flipped);
    printf("Suspicion score:   %.3f (0=clean, 1=strong stego)\n",
           res->suspect_score);

    if (res->suspect_score >= 0.8) {
       printf("Assessment:        %sHIGH%s suspicion of LSB stego.\n",
       CLR_RED, CLR_RESET);
    } else if (res->suspect_score >= 0.4) {
       printf("Assessment:        %sMODERATE%s suspicion of LSB stego.\n",
       CLR_YELLOW, CLR_RESET);
        
    } else {
       printf("Assessment:        %sLOW%s suspicion of LSB stego.\n",
       CLR_GREEN, CLR_RESET);
    }
}

