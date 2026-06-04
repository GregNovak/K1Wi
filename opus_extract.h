#ifndef OPUS_EXTRACT_H
#define OPUS_EXTRACT_H

#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <limits.h>

typedef enum {
    OPUS_OUTMODE_HUMAN = 0,
    OPUS_OUTMODE_JSONL,
    OPUS_OUTMODE_BRIEF
} opus_outmode_t;

typedef struct {
    opus_outmode_t outmode;
    int pager;
    int verbose;
    char logfile[PATH_MAX];
} opus_run_context_t;

void opus_extract_set_run_context(const opus_run_context_t *ctx);

char *extract_layers(const char *start_path, int depth, char **visited, int *visited_count);
int opus_extract_recursive(const char *path);

#endif /* OPUS_EXTRACT_H */

