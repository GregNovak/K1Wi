#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "logging.h"
#include "file_copy.h"
#include "md5.h"

#define COPY_BUFFER_SIZE 8192

/* Convert 16‑byte MD5 digest to lowercase hex string */
static void md5_to_hex(const uint8_t digest[16], char *out_hex) {
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i * 2]     = hex_digits[(digest[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = hex_digits[digest[i] & 0xF];
    }
    out_hex[32] = '\0';
}

/* Copy a file and verify integrity using MD5, with progress reporting */
int opus_file_copy(const char *src_path, const char *dst_path) {
    FILE *src = fopen(src_path, "rb");
    if (!src) {
        log_error("FILE_COPY: failed to open source: %s", src_path);
        return -1;
    }

    FILE *dst = fopen(dst_path, "wb");
    if (!dst) {
        log_error("FILE_COPY: failed to open destination: %s", dst_path);
        fclose(src);
        return -1;
    }

    /* Determine total size for progress reporting */
    if (fseek(src, 0, SEEK_END) != 0) {
        log_error("FILE_COPY: failed to determine file size for %s", src_path);
        fclose(src);
        fclose(dst);
        return -1;
    }

    long total_size = ftell(src);
    if (total_size < 0) total_size = 0;
    rewind(src);

    long copied = 0;
    int last_percent = -1;

    uint8_t buffer[COPY_BUFFER_SIZE];
    size_t bytes;

    OPUS_MD5_CTX md_src;
    OPUS_MD5_CTX md_dst;
    uint8_t digest_src[16];
    uint8_t digest_dst[16];

    opus_md5_init(&md_src);
    opus_md5_init(&md_dst);

    log_info("FILE_COPY: starting copy %s -> %s (%ld bytes)",
             src_path, dst_path, total_size);

    /* Copy source → destination while hashing source */
    while ((bytes = fread(buffer, 1, COPY_BUFFER_SIZE, src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            log_error("FILE_COPY: write error to %s", dst_path);
            fclose(src);
            fclose(dst);
            return -1;
        }

        opus_md5_update(&md_src, buffer, bytes);

        /* Progress tracking */
        copied += bytes;
        if (total_size > 0) {
            int percent = (int)((copied * 100L) / total_size);
            if (percent >= last_percent + 5 || percent == 100) {
                log_info("FILE_COPY: progress %d%% (%ld/%ld bytes)",
                         percent, copied, total_size);
                last_percent = percent;
            }
        }
    }

    if (ferror(src)) {
        log_error("FILE_COPY: read error from %s", src_path);
        fclose(src);
        fclose(dst);
        return -1;
    }

    fclose(src);
    fflush(dst);
    fclose(dst);

    /* Re-open destination to compute its MD5 */
    dst = fopen(dst_path, "rb");
    if (!dst) {
        log_error("FILE_COPY: failed to re-open destination for verification: %s", dst_path);
        return -1;
    }

    while ((bytes = fread(buffer, 1, COPY_BUFFER_SIZE, dst)) > 0) {
        opus_md5_update(&md_dst, buffer, bytes);
    }

    if (ferror(dst)) {
        log_error("FILE_COPY: read error during verification from %s", dst_path);
        fclose(dst);
        return -1;
    }

    fclose(dst);

    opus_md5_final(digest_src, &md_src);
    opus_md5_final(digest_dst, &md_dst);

    char hex_src[33];
    char hex_dst[33];
    md5_to_hex(digest_src, hex_src);
    md5_to_hex(digest_dst, hex_dst);

    log_info("FILE_COPY: MD5(source)      = %s", hex_src);
    log_info("FILE_COPY: MD5(destination) = %s", hex_dst);

    if (memcmp(digest_src, digest_dst, 16) != 0) {
        log_error("FILE_COPY: MD5 mismatch! Copy verification FAILED.");
        return -1;
    }

    log_info("FILE_COPY: copy verified successfully (MD5 match).");
    return 0;
}

