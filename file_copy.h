#ifndef OPUS_FILE_COPY_H
#define OPUS_FILE_COPY_H

/*
 * opus_file_copy
 *
 * Performs a forensic-style verified file copy:
 *  - refuses overwrite by default
 *  - copies regular files in chunks
 *  - verifies source and destination sizes
 *  - verifies source and destination SHA-256 hashes
 *  - reports source and destination MD5 hashes for legacy workflows
 *  - reports PASS/FAIL verification status
 *
 * Returns:
 *   0  on verified success
 *  -1  on failure
 */
int opus_file_copy(const char *src_path, const char *dst_path);

/*
 * Extended copy interface.
 *
 * force:
 *   0 = refuse overwrite
 *   1 = allow destination overwrite
 */
int opus_file_copy_ex(const char *src_path, const char *dst_path, int force);

#endif /* OPUS_FILE_COPY_H */
