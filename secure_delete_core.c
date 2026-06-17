#define _POSIX_C_SOURCE 200809L

#include "secure_delete_core.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static void fill_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        for (size_t i = 0; i < len; i++) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
        return;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r <= 0) break;
        off += (size_t)r;
    }
    close(fd);
}

void opus_sd_policy_preset(opus_sd_mode_t mode, opus_sd_policy_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->mode = mode;

    static const uint8_t nist_pattern = 0x00;
    static const uint8_t dod_patterns[2] = { 0xFF, 0x00 };

    switch (mode) {
        case OPUS_SD_MODE_NIST:
            out->passes   = 1;
            out->patterns = &nist_pattern;
            out->verify   = 0;
            break;
        case OPUS_SD_MODE_DOD3:
            out->passes   = 3;
            out->patterns = dod_patterns;
            out->verify   = 0;
            break;
        default:
            out->passes   = 1;
            out->patterns = &nist_pattern;
            out->verify   = 0;
            break;
    }
}

int opus_secure_delete_file(const char *path, const opus_sd_policy_t *policy) {
    if (!path || !policy) {
        errno = EINVAL;
        return -1;
    }

    struct stat lst;
    if (lstat(path, &lst) < 0) {
        return -1;
    }

    if (S_ISLNK(lst.st_mode)) {
        errno = ELOOP;
        return -1;
    }

    if (!S_ISREG(lst.st_mode)) {
        errno = EINVAL;
        return -1;
    }

    int flags = O_RDWR;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    int fd = open(path, flags);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int se = errno;
        close(fd);
        errno = se;
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    if (st.st_dev != lst.st_dev || st.st_ino != lst.st_ino) {
        close(fd);
        errno = EAGAIN;
        return -1;
    }

    off_t size = st.st_size;
    if (size <= 0) {
        close(fd);
        return (unlink(path) == 0) ? 0 : -1;
    }

    const size_t buf_size = 64 * 1024;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        int se = errno;
        close(fd);
        errno = se;
        return -1;
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int passes = policy->passes > 0 ? policy->passes : 1;

    for (int pass = 0; pass < passes; pass++) {
        int use_random = 0;
        uint8_t pattern = 0x00;

        if (policy->mode == OPUS_SD_MODE_DOD3 && pass == passes - 1) {
            use_random = 1;
        } else if (policy->patterns && pass < policy->passes) {
            pattern = policy->patterns[pass];
        } else {
            pattern = 0x00;
        }

        if (lseek(fd, 0, SEEK_SET) < 0) {
            int se = errno;
            free(buf);
            close(fd);
            errno = se;
            return -1;
        }

        off_t remaining = size;
        while (remaining > 0) {
            size_t chunk = (remaining > (off_t)buf_size) ? buf_size : (size_t)remaining;

            if (use_random) {
                fill_random(buf, chunk);
            } else {
                memset(buf, pattern, chunk);
            }

            size_t written = 0;
            while (written < chunk) {
                ssize_t w = write(fd, buf + written, chunk - written);
                if (w < 0) {
                    int se = errno;
                    free(buf);
                    close(fd);
                    errno = se;
                    return -1;
                }
                written += (size_t)w;
            }

            remaining -= (off_t)chunk;
        }

        if (fsync(fd) < 0) {
            int se = errno;
            free(buf);
            close(fd);
            errno = se;
            return -1;
        }
    }

    if (ftruncate(fd, 0) != 0) {
        int se = errno;
        free(buf);
        close(fd);
        errno = se;
        return -1;
    }

    if (fsync(fd) < 0) {
        int se = errno;
        free(buf);
        close(fd);
        errno = se;
        return -1;
    }

    free(buf);
    close(fd);

    struct stat final_st;
    if (lstat(path, &final_st) < 0) {
        return -1;
    }

    if (!S_ISREG(final_st.st_mode) ||
        final_st.st_dev != lst.st_dev ||
        final_st.st_ino != lst.st_ino) {
        errno = EAGAIN;
        return -1;
    }

    return (unlink(path) == 0) ? 0 : -1;
}

