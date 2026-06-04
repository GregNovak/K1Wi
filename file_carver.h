#ifndef FILE_CARVER_H
#define FILE_CARVER_H

#include <stddef.h>
#include <stdint.h>

typedef struct opus_carve_result {
    int files_carved;    /* number of carved files */
    int errors;          /* non-fatal errors during carving */
} opus_carve_result_t;

/* Carve known file types out of a container file.
   Returns 0 on success (even if nothing carved), -1 on fatal error. */
int opus_file_carve(const char *path, const char *outdir, opus_carve_result_t *res);

#endif /* FILE_CARVER_H */

