#ifndef OPUS_MD5_H
#define OPUS_MD5_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>   /* <-- REQUIRED for bool */

/* MD5 context */
typedef struct {
    uint32_t state[4];   /* A, B, C, D */
    uint32_t count[2];   /* number of bits, modulo 2^64 */
    uint8_t  buffer[64]; /* input buffer */
} OPUS_MD5_CTX;

/* Core MD5 engine */
void opus_md5_init(OPUS_MD5_CTX *ctx);
void opus_md5_update(OPUS_MD5_CTX *ctx, const void *data, size_t len);
void opus_md5_final(uint8_t digest[16], OPUS_MD5_CTX *ctx);

/* Optional helper to compute MD5 in one call */
void opus_md5(const void *data, size_t len, uint8_t digest[16]);

/* NEW WRAPPERS — used by TUI and CLI */
bool opus_md5_file(const char *path, char out_hex[33]);
bool opus_md5_buffer(const void *data, size_t len, char out_hex[33]);
bool opus_md5_string(const char *s, char out_hex[33]);

#endif /* OPUS_MD5_H */

