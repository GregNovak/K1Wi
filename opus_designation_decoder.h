#ifndef OPUS_DESIGNATION_DECODER_H
#define OPUS_DESIGNATION_DECODER_H

/* Reuse same struct style for consistency */
typedef struct {
    int prefix;     /* X */
    int number;     /* YYYY */
    int count;      /* frequency */
} designation_freq_t;

void opus_decode_designations(const char *filename);

#endif

