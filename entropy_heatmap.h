#ifndef ENTROPY_HEATMAP_H
#define ENTROPY_HEATMAP_H

#include <stddef.h>
#include <stdint.h>

/* Block-level entropy info */
struct entropy_block {
    size_t index;
    size_t offset;
    size_t length;
    double entropy;
    double lsb_fraction;
};

/* Heatmap container */
struct entropy_heatmap {
    struct entropy_block *blocks;
    size_t count;
};

/* API */
int  opus_entropy_heatmap_analyze(const char *path,
                                  size_t block_size,
                                  struct entropy_heatmap *out);

void opus_entropy_heatmap_print(const struct entropy_heatmap *map);

void opus_entropy_heatmap_render_color(const struct entropy_heatmap *map);

void opus_entropy_heatmap_free(struct entropy_heatmap *map);
void opus_entropy_heatmap_detect_anomalies(const struct entropy_heatmap *map);

#endif

