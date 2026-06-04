#ifndef OPUS_EXTRACT_DESIGNATIONS_H
#define OPUS_EXTRACT_DESIGNATIONS_H

typedef struct {
    char name[64];
    int prefix;
    int number;
} designation_t;

void opus_extract_designations(const char *filename);

#endif

