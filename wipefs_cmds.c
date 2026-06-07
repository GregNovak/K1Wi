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
    char target[PATH_MAX] = ".";
    unsigned long long max_bytes = 0;
    int dry_run = 0;
    int yes = 0;

    if (!args || !*args) {
        fprintf(stderr,
                "WIPEFS: refused. Usage: WIPEFS <path> --dry-run OR WIPEFS <path> --max-bytes <N> --yes\n");
        return;
    }

    char *copy = strdup(args);
    if (!copy) {
        fprintf(stderr, "WIPEFS: memory allocation failed.\n");
        return;
    }

    char *saveptr = NULL;
    char *tok = strtok_r(copy, " \t\r\n", &saveptr);
    int have_target = 0;

    while (tok) {
        if (strcmp(tok, "--dry-run") == 0) {
            dry_run = 1;
        } else if (strcmp(tok, "--yes") == 0 || strcmp(tok, "-y") == 0) {
            yes = 1;
        } else if (strcmp(tok, "--max-bytes") == 0) {
            char *v = strtok_r(NULL, " \t\r\n", &saveptr);
            if (!v) {
                fprintf(stderr, "WIPEFS: --max-bytes requires a value.\n");
                free(copy);
                return;
            }
            max_bytes = strtoull(v, NULL, 10);
        } else if (!have_target) {
            snprintf(target, sizeof(target), "%s", tok);
            have_target = 1;
        } else {
            fprintf(stderr, "WIPEFS: unknown extra argument '%s'\n", tok);
            free(copy);
            return;
        }

        tok = strtok_r(NULL, " \t\r\n", &saveptr);
    }

    free(copy);

    if (!dry_run && (!yes || max_bytes == 0)) {
        fprintf(stderr,
                "WIPEFS: refused. Destructive mode requires --max-bytes <N> and --yes.\n");
        return;
    }
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
            
    if (dry_run) {
    fprintf(stderr,
            "WIPEFS: dry-run only. Would create temporary wipe files in '%s'.\n",
            base);

    fprintf(stderr,
            "WIPEFS: available free space: %llu bytes.\n",
            free_bytes);

    return;
    }

    char wipe_dir[PATH_MAX];
    if (make_wipe_dir(base, wipe_dir, sizeof(wipe_dir)) != 0) {
        return;
    }

    opus_sd_policy_t policy;
    opus_sd_policy_preset(OPUS_SD_MODE_NIST, &policy); /* free-space wipe: NIST zeros */

    int file_index = 0;
    int rc = 0;
    unsigned long long written_total = 0;
    
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
    size_t to_write = chunk_size;

    if (max_bytes > 0) {
        unsigned long long remaining = max_bytes - written_total;

        if (remaining == 0) {
            break;
        }

        if (remaining < (unsigned long long)chunk_size) {
            to_write = (size_t)remaining;
        }
    }

    size_t w = fwrite(buf, 1, to_write, fp);
    written_total += (unsigned long long)w;

    if (w < to_write) {
        if (ferror(fp)) {
            if (errno == ENOSPC) {
                fprintf(stderr, "WIPEFS: filesystem full.\n");
            } else {
                fprintf(stderr, "WIPEFS: write error on '%s': %s\n", fname, strerror(errno));
            }
        }
        break;
    }

    if (max_bytes > 0 && written_total >= max_bytes) {
        fprintf(stderr,
                "WIPEFS: reached max-bytes limit (%llu bytes).\n",
                max_bytes);
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

	if (max_bytes > 0 && written_total >= max_bytes) {
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

