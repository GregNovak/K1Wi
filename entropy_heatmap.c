#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "entropy_heatmap.h"

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

int opus_entropy_heatmap_analyze(const char *path,
                                 size_t block_size,
                                 struct entropy_heatmap *out)
{
    if (!path || !out || block_size == 0) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    if (fsize < 0) {
	fclose(fp);
	return -1;
    }

    size_t file_size = (size_t)fsize;
    size_t total_blocks = (file_size + block_size - 1) / block_size;
    
    struct entropy_block *blocks =
        calloc(total_blocks, sizeof(struct entropy_block));
    if (!blocks) { fclose(fp); return -1; }

    size_t offset = 0;
    size_t block_index = 0;

    while (offset < (size_t)fsize) {
        size_t hist[256] = {0};
        size_t total = 0;
        size_t lsb1 = 0;

        size_t remaining = (size_t)fsize - offset;
        size_t this_len = remaining < block_size ? remaining : block_size;

        for (size_t i = 0; i < this_len; i++) {
            int c = fgetc(fp);
            if (c == EOF) break;
            uint8_t b = (uint8_t)c;
            hist[b]++;
            total++;
            if (b & 1) lsb1++;
        }

        double H = compute_entropy(hist, total);
        double p1 = (total > 0) ? (double)lsb1 / (double)total : 0.0;

        blocks[block_index].index        = block_index;
        blocks[block_index].offset       = offset;
        blocks[block_index].length       = this_len;
        blocks[block_index].entropy      = H;
        blocks[block_index].lsb_fraction = p1;

        offset += this_len;
        block_index++;
    }

    fclose(fp);

    out->blocks = blocks;
    out->count  = block_index;
    return 0;
}

void opus_entropy_heatmap_free(struct entropy_heatmap *map)
{
    if (!map) return;
    free(map->blocks);
    map->blocks = NULL;
    map->count  = 0;
}

void opus_entropy_heatmap_print(const struct entropy_heatmap *map)
{
    if (!map || !map->blocks) return;

    printf("\n--- Entropy Heatmap (block-level) ---\n");
    printf("Idx   Offset      Len      Entropy   LSB(1)\n");
    printf("----  ----------  -------  --------  -------\n");

    for (size_t i = 0; i < map->count; i++) {
        const struct entropy_block *b = &map->blocks[i];

        const char *label = "LOW";
        if (b->entropy >= 7.5) label = "HIGH";
        else if (b->entropy >= 6.5) label = "MED";

        printf("%3zu   %8zu   %7zu  %8.4f  %7.4f  %s\n",
               b->index,
               b->offset,
               b->length,
               b->entropy,
               b->lsb_fraction,
               label);
    }
}

/* Map entropy to ANSI color */
static const char *entropy_color_bar(double H)
{
    if (H < 2.0) return "\x1b[34m";   /* Blue: very low entropy */
    if (H < 4.0) return "\x1b[32m";   /* Green: low/medium */
    if (H < 6.0) return "\x1b[33m";   /* Yellow: medium */
    if (H < 7.5) return "\x1b[31m";   /* Red: high */
    return "\x1b[35m";                /* Magenta: very high (encrypted/compressed) */
}

/* Render a horizontal ANSI color heatmap bar */
void opus_entropy_heatmap_render_color(const struct entropy_heatmap *map)
{
    if (!map || !map->blocks || map->count == 0) {
        printf("No entropy data available for color heatmap.\n");
        return;
    }

    printf("\nEntropy Color Heatmap:\n");
    printf("(Blue=low, Green=med-low, Yellow=med, Red=high, Magenta=very high)\n\n");

    for (size_t i = 0; i < map->count; i++) {
        double H = map->blocks[i].entropy;
        const char *color = entropy_color_bar(H);
        printf("%s█\x1b[0m", color);
    }

    printf("\n\n");
}
/* Classify entropy delta */
static const char *classify_delta(double delta)
{
    if (delta >= 1.5) return "ANOMALY";
    if (delta >= 0.5) return "TRANSITION";
    return "NORMAL";
}

/* Analyze entropy transitions between blocks */
void opus_entropy_heatmap_detect_anomalies(const struct entropy_heatmap *map)
{
    if (!map || !map->blocks || map->count < 2) {
        printf("Not enough data for anomaly detection.\n");
        return;
    }

    printf("\n--- Entropy Anomaly Detection ---\n");
    printf("Idx   ΔEntropy   Classification\n");
    printf("----  ---------  --------------\n");

    for (size_t i = 1; i < map->count; i++) {
        double prev = map->blocks[i - 1].entropy;
        double curr = map->blocks[i].entropy;
        double delta = fabs(curr - prev);

        const char *label = classify_delta(delta);

        printf("%3zu   %8.4f   %s\n", i, delta, label);
    }

    printf("\n");
}


