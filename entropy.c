
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <stdlib.h>

double opus_entropy_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1.0;

    uint64_t counts[256] = {0};
    uint64_t total = 0;
    int c;

    while ((c = fgetc(f)) != EOF) {
        counts[(unsigned char)c]++;
        total++;
    }

    fclose(f);

    if (total == 0)
        return 0.0;

    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)total;
        H -= p * (log(p) / log(2.0));
    }

    return H;
}

double opus_entropy_block(const unsigned char *buf, size_t len)
{
    if (!buf || len == 0) return 0.0;

    size_t freq[256] = {0};

    for (size_t i = 0; i < len; i++)
        freq[buf[i]]++;

    double H = 0.0;
    double inv = 1.0 / (double)len;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] * inv;
        H -= p * log2(p);
    }

    return H;
}
double *opus_entropy_windowed(const char *path, size_t block_size, size_t *out_count)
{
    if (!path || block_size == 0 || !out_count)
        return NULL;

    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    unsigned char *buf = malloc(block_size);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t capacity = 128;
    size_t count = 0;
    double *results = malloc(capacity * sizeof(double));
    if (!results) {
        free(buf);
        fclose(fp);
        return NULL;
    }

    size_t n;
    while ((n = fread(buf, 1, block_size, fp)) > 0) {

        if (count == capacity) {
            capacity *= 2;
            double *tmp = realloc(results, capacity * sizeof(double));
            if (!tmp) {
                free(results);
                free(buf);
                fclose(fp);
                return NULL;
            }
            results = tmp;
        }

        results[count++] = opus_entropy_block(buf, n);
    }

    free(buf);
    fclose(fp);

    *out_count = count;
    return results;
}

