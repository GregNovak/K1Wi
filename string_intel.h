#ifndef STRING_INTEL_H
#define STRING_INTEL_H
#define OPUS_MAX_STRING_HITS 16
#include <stddef.h>
#include <stdint.h>


typedef enum opus_secret_confidence {
    OPUS_SECRET_LOW = 0,
    OPUS_SECRET_MEDIUM = 1,
    OPUS_SECRET_HIGH = 2
} opus_secret_confidence_t;

typedef struct opus_string_hit {
    size_t offset;
    char type[64];
    char text[256];
    opus_secret_confidence_t confidence;
    int score;
} opus_string_hit_t;

/* Summary statistics for string intelligence analysis. */
typedef struct opus_string_report {
    int ascii_count;        /* number of ASCII strings found */
    int utf8_count;         /* number of strings that look UTF-8 */
    int base64_count;       /* number of base64-like strings */
    int url_count;          /* number of URL-like strings */
    int email_count;        /* number of email-like strings */
    int suspicious_count;   /* private keys, secrets, tokens, etc. */
    
    opus_string_hit_t suspicious_hits[OPUS_MAX_STRING_HITS];
    int suspicious_hit_count;
} opus_string_report_t;

/* Analyze a file for ASCII/UTF8/base64/URL/email strings.
   Returns 0 on success, -1 on error. */
int opus_string_file(const char *path, opus_string_report_t *report);

#endif /* STRING_INTEL_H */

