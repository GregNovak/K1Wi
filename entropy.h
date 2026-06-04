#ifndef ENTROPY_H
#define ENTROPY_H

struct entropy_heatmap;


double opus_entropy_file(const char *path);
double opus_entropy_block(const unsigned char *buf, size_t len);
double *opus_entropy_windowed(const char *path, size_t block_size, size_t *out_count);


#endif

