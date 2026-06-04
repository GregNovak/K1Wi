#ifndef EMBEDDED_SIG_H
#define EMBEDDED_SIG_H

#include <stddef.h>

typedef struct embedded_sig_result {
    size_t offset;
    const char *type;
} embedded_sig_result_t;

typedef struct embedded_sig_report {
    int count;
    embedded_sig_result_t hits[32];
} embedded_sig_report_t;

int embedded_sig_scan_file(const char *path, embedded_sig_report_t *report);

#endif
