#ifndef OPUS_SHA256_H
#define OPUS_SHA256_H

#include <stddef.h>
#include <stdint.h>

/*
 * Output: 64 lowercase hex chars + NUL
 * buffer must be at least 65 bytes.
 */
void sha256_string(const char *input, char output[65]);

/*
 * Returns:
 *   0  on success
 *  -1  on error (e.g. cannot open file)
 */
int sha256_file(const char *filename, char output[65]);

#endif /* OPUS_SHA256_H */

