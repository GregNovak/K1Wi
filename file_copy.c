#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file_copy.h"
#include "logging.h"
#include "md5.h"
#include "sha256.h"

#define COPY_BUFFER_SIZE 65536

static int copy_stat_regular_file(const char *path, struct stat *st)
{
    if (!path || !st) {
        return -1;
    }

    if (stat(path, st) != 0) {
        return -1;
    }

    return S_ISREG(st->st_mode) ? 0 : -1;
}

static int copy_write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            return -1;
        }

        total += (size_t)n;
    }

    return 0;
}

int opus_file_copy(const char *src_path, const char *dst_path)
{
    return opus_file_copy_ex(src_path, dst_path, 0);
}

int opus_file_copy_ex(const char *src_path, const char *dst_path, int force)
{
    if (!src_path || !dst_path || src_path[0] == '\0' || dst_path[0] == '\0') {
        log_error("FILE_COPY: invalid source or destination path");
        return -1;
    }

    struct stat src_st;
    if (copy_stat_regular_file(src_path, &src_st) != 0) {
        log_error("FILE_COPY: source is missing, unreadable, or not a regular file: %s", src_path);
        return -1;
    }

    struct stat dst_existing_st;
    if (stat(dst_path, &dst_existing_st) == 0) {
        if (src_st.st_dev == dst_existing_st.st_dev && src_st.st_ino == dst_existing_st.st_ino) {
            log_error("FILE_COPY: source and destination refer to the same file; refusing copy");
            return -1;
        }

        if (!force) {
            log_error("FILE_COPY: destination already exists; refusing overwrite: %s", dst_path);
            log_error("FILE_COPY: use --force to overwrite intentionally");
            return -1;
        }
    }

    char src_sha256[65];
    char dst_sha256[65];
    char src_md5[33];
    char dst_md5[33];

    if (sha256_file(src_path, src_sha256) != 0) {
        log_error("FILE_COPY: failed to hash source with SHA-256: %s", src_path);
        return -1;
    }

    if (!opus_md5_file(src_path, src_md5)) {
        log_error("FILE_COPY: failed to hash source with MD5: %s", src_path);
        return -1;
    }

    FILE *src = fopen(src_path, "rb");
    if (!src) {
        log_error("FILE_COPY: failed to open source: %s", src_path);
        return -1;
    }

    int flags = O_WRONLY | O_CREAT;
    flags |= force ? O_TRUNC : O_EXCL;

    int dst_fd = open(dst_path, flags, (mode_t)(src_st.st_mode & 0777));
    if (dst_fd < 0) {
        log_error("FILE_COPY: failed to open destination: %s", dst_path);
        fclose(src);
        return -1;
    }

    log_info("FILE_COPY: starting verified copy %s -> %s (%" PRIdMAX " bytes)",
             src_path, dst_path, (intmax_t)src_st.st_size);

    uint8_t buffer[COPY_BUFFER_SIZE];
    size_t bytes = 0;
    uintmax_t copied = 0;
    int last_percent = -1;

    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (copy_write_all(dst_fd, buffer, bytes) != 0) {
            log_error("FILE_COPY: write error to %s", dst_path);
            fclose(src);
            close(dst_fd);
            return -1;
        }

        copied += (uintmax_t)bytes;

        if (src_st.st_size > 0) {
            int percent = (int)((copied * 100U) / (uintmax_t)src_st.st_size);
            if (percent >= last_percent + 5 || percent == 100) {
                log_info("FILE_COPY: progress %d%% (%" PRIuMAX "/%" PRIdMAX " bytes)",
                         percent, copied, (intmax_t)src_st.st_size);
                last_percent = percent;
            }
        }
    }

    if (ferror(src)) {
        log_error("FILE_COPY: read error from %s", src_path);
        fclose(src);
        close(dst_fd);
        return -1;
    }

    if (fsync(dst_fd) != 0) {
        log_error("FILE_COPY: failed to sync destination to storage: %s", dst_path);
        fclose(src);
        close(dst_fd);
        return -1;
    }

    if (close(dst_fd) != 0) {
        log_error("FILE_COPY: failed to close destination cleanly: %s", dst_path);
        fclose(src);
        return -1;
    }

    if (fclose(src) != 0) {
        log_error("FILE_COPY: failed to close source cleanly: %s", src_path);
        return -1;
    }

    struct stat dst_st;
    if (copy_stat_regular_file(dst_path, &dst_st) != 0) {
        log_error("FILE_COPY: destination missing or not a regular file after copy: %s", dst_path);
        return -1;
    }

    if (sha256_file(dst_path, dst_sha256) != 0) {
        log_error("FILE_COPY: failed to hash destination with SHA-256: %s", dst_path);
        return -1;
    }

    if (!opus_md5_file(dst_path, dst_md5)) {
        log_error("FILE_COPY: failed to hash destination with MD5: %s", dst_path);
        return -1;
    }

    int size_match = (src_st.st_size == dst_st.st_size);
    int sha256_match = (strcmp(src_sha256, dst_sha256) == 0);
    int md5_match = (strcmp(src_md5, dst_md5) == 0);

    printf("\nCOPY Verification Report\n");
    printf("------------------------\n");
    printf("Source       : %s\n", src_path);
    printf("Destination  : %s\n", dst_path);
    printf("Bytes copied : %" PRIuMAX "\n", copied);
    printf("Source size  : %" PRIdMAX "\n", (intmax_t)src_st.st_size);
    printf("Dest size    : %" PRIdMAX "\n", (intmax_t)dst_st.st_size);
    printf("Source SHA256: %s\n", src_sha256);
    printf("Dest SHA256  : %s\n", dst_sha256);
    printf("Source MD5   : %s\n", src_md5);
    printf("Dest MD5     : %s\n", dst_md5);
    printf("Size match   : %s\n", size_match ? "yes" : "no");
    printf("SHA256 match : %s\n", sha256_match ? "yes" : "no");
    printf("MD5 match    : %s\n", md5_match ? "yes" : "no");
    printf("Verification : %s\n\n", (size_match && sha256_match && md5_match) ? "PASS" : "FAIL");

    log_info("FILE_COPY: SHA256(source)      = %s", src_sha256);
    log_info("FILE_COPY: SHA256(destination) = %s", dst_sha256);
    log_info("FILE_COPY: MD5(source)         = %s", src_md5);
    log_info("FILE_COPY: MD5(destination)    = %s", dst_md5);

    if (!size_match || !sha256_match || !md5_match) {
        log_error("FILE_COPY: verification failed");
        return -1;
    }

    log_info("FILE_COPY: copy verified successfully using SHA-256, MD5, and size comparison");
    return 0;
}
