#ifndef OPUS_STRING_INTEL_H
#define OPUS_STRING_INTEL_H

#include <stddef.h>
#include <stdbool.h>



typedef struct {
    size_t length;
    int is_printable;
    double entropy;
    const char *detected_type;
    char *decoded_output;
    int secret_score;
} OpusStringIntelResult;
/*
 * UNIVERSAL STRING ANALYZER
 *
 * Takes a raw string and returns a fully populated
 * OpusStringIntelResult struct.
 */
OpusStringIntelResult opus_string_intel(const char *input);

/*
 * RESULT PRINTER
 *
 * Pretty‑prints the analysis result.
 * Must be declared here so cmd_string.c can call it.
 */
void opus_string_intel_print(const OpusStringIntelResult *r);

#endif /* OPUS_STRING_INTEL_H */

