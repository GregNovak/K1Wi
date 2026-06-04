#ifndef OPUS_FILE_COPY_H
#define OPUS_FILE_COPY_H

/* 
 * opus_file_copy
 * Copies a file from src_path to dst_path with:
 *  - chunked copying
 *  - MD5 hashing of source and destination
 *  - MD5 verification
 *  - progress reporting
 *  - logging for all stages
 *
 * Returns:
 *   0  on success
 *  -1  on any failure
 */
int opus_file_copy(const char *src_path, const char *dst_path);

#endif /* OPUS_FILE_COPY_H */

