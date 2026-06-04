#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <limits.h>

#include "secure_delete_core.h"

static int make_wipe_dir(const char *base, char *out, size_t out_sz) {
    if (snprintf(out, out_sz, "%s/.opus_wipe", base) >= (int)out_sz) {
        fprintf(stderr, "Path too long\n");
        return -1;
    }
    if (mkdir(out, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed to create wipe dir '%s': %s\n", out, strerror(errno));
        return -1;
    }
    return 0;
}

void wipeFsCmd(const char *args) {
    char target[PATH_MAX];
    const char *path = (args && *args) ? args : ".";

    /* strip trailing newline/spaces if coming from line buffer */
    snprintf(target, sizeof(target), "%s", path);
    size_t len = strlen(target);
    while (len > 0 && (target[len-1] == '\n' || target[len-1] == ' ' || target[len-1] == '\t'))
        target[--len] = '\0';

    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "WIPEFS: cannot stat '%s': %s\n", target, strerror(errno));
        return;
    }

    /* If it's a file, use its directory; if dir, use it directly */
    char base[PATH_MAX];
    if (S_ISDIR(st.st_mode)) {
        snprintf(base, sizeof(base), "%s", target);
    } else {
        char *slash = strrchr(target, '/');
        if (slash) {
            size_t dlen = (size_t)(slash - target);
            if (dlen >= sizeof(base)) dlen = sizeof(base) - 1;
            memcpy(base, target, dlen);
            base[dlen] = '\0';
        } else {
            snprintf(base, sizeof(base), ".");
        }
    }

    /* Get filesystem stats for info (optional) */
    struct statvfs vfs;
    if (statvfs(base, &vfs) != 0) {
        fprintf(stderr, "WIPEFS: statvfs failed on '%s': %s\n", base, strerror(errno));
        return;
    }

    unsigned long long free_bytes = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
    fprintf(stderr, "WIPEFS: starting free-space wipe on '%s' (~%llu bytes free)\n",
            base, free_bytes);

    char wipe_dir[PATH_MAX];
    if (make_wipe_dir(base, wipe_dir, sizeof(wipe_dir)) != 0) {
        return;
    }

    opus_sd_policy_t policy;
    opus_sd_policy_preset(OPUS_SD_MODE_NIST, &policy); /* free-space wipe: NIST zeros */

    int file_index = 0;
    int rc = 0;

    while (1) {
        char fname[PATH_MAX];
        if (snprintf(fname, sizeof(fname), "%s/wipe_%06d.bin", wipe_dir, file_index++) >= (int)sizeof(fname)) {
            fprintf(stderr, "WIPEFS: filename too long, stopping.\n");
            break;
        }

        FILE *fp = fopen(fname, "wb");
        if (!fp) {
            if (errno == ENOSPC) {
                fprintf(stderr, "WIPEFS: no space left while creating files.\n");
            } else {
                fprintf(stderr, "WIPEFS: fopen('%s') failed: %s\n", fname, strerror(errno));
            }
            break;
        }

        /* Write in chunks until ENOSPC */
        const size_t chunk_size = 64 * 1024;
        unsigned char *buf = malloc(chunk_size);
        if (!buf) {
            fprintf(stderr, "WIPEFS: memory allocation failed.\n");
            fclose(fp);
            rc = -1;
            break;
        }
        memset(buf, 0x00, chunk_size);

        while (1) {
            size_t w = fwrite(buf, 1, chunk_size, fp);
            if (w < chunk_size) {
                if (ferror(fp)) {
                    if (errno == ENOSPC) {
                        fprintf(stderr, "WIPEFS: filesystem full.\n");
                    } else {
                        fprintf(stderr, "WIPEFS: write error on '%s': %s\n", fname, strerror(errno));
                    }
                }
                break;
            }
        }

        free(buf);
        fflush(fp);
        fclose(fp);

        /* Now securely delete this wipe file using the core engine */
        if (opus_secure_delete_file(fname, &policy) != 0) {
            fprintf(stderr, "WIPEFS: secure delete failed for '%s': %s\n", fname, strerror(errno));
            rc = -1;
            break;
        }

        /* Check remaining free space; if very low, stop */
        if (statvfs(base, &vfs) == 0) {
            free_bytes = (unsigned long long)vfs.f_bavail * vfs.f_frsize;
            if (free_bytes < (unsigned long long)chunk_size) {
                fprintf(stderr, "WIPEFS: nearly out of space, stopping.\n");
                break;
            }
        }
    }

    /* Try to remove the wipe directory (should be empty if all deletes succeeded) */
    if (rmdir(wipe_dir) != 0) {
        fprintf(stderr, "WIPEFS: warning: could not remove '%s': %s\n", wipe_dir, strerror(errno));
    }

    if (rc == 0) {
        fprintf(stderr, "WIPEFS: free-space wipe complete on '%s'.\n", base);
    } else {
        fprintf(stderr, "WIPEFS: completed with errors on '%s'.\n", base);
    }
}

