#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "file_copy.h"
#include "logging.h"
#include "md5.h"
#include "sha256.h"

#define COPY_BUFFER_SIZE 65536

typedef struct {
    uintmax_t files_copied;
    uintmax_t dirs_created;
    uintmax_t entries_skipped;
    uintmax_t bytes_copied;
    uintmax_t failures;
} CopyTreeStats;

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

static char *copy_join_path(const char *left, const char *right)
{
    if (!left || !right) {
        return NULL;
    }

    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    int need_slash = (left_len > 0 && left[left_len - 1] != '/');

    size_t total = left_len + (need_slash ? 1U : 0U) + right_len + 1U;
    char *out = malloc(total);
    if (!out) {
        return NULL;
    }

    snprintf(out, total, "%s%s%s", left, need_slash ? "/" : "", right);
    return out;
}

static char *copy_parent_dir(const char *path)
{
    if (!path) {
        return NULL;
    }

    char *tmp = strdup(path);
    if (!tmp) {
        return NULL;
    }

    char *slash = strrchr(tmp, '/');
    if (!slash) {
        strcpy(tmp, ".");
        return tmp;
    }

    if (slash == tmp) {
        slash[1] = '\0';
        return tmp;
    }

    *slash = '\0';
    return tmp;
}

static const char *copy_basename_ptr(const char *path)
{
    if (!path) {
        return "";
    }

    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static const char *copy_relative_path(const char *root, const char *path)
{
    if (!root || !path) {
        return path ? path : "";
    }

    size_t root_len = strlen(root);

    if (strncmp(root, path, root_len) == 0 && path[root_len] == '/') {
        return path + root_len + 1;
    }

    return path;
}

static int copy_make_dir_if_needed(const char *path, mode_t mode, int force, int *created)
{
    struct stat st;

    if (created) {
        *created = 0;
    }

    if (stat(path, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            log_error("FILE_COPY: destination exists but is not a directory: %s", path);
            return -1;
        }

        if (!force) {
            log_error("FILE_COPY: destination directory already exists; refusing overwrite/merge: %s", path);
            log_error("FILE_COPY: use --force to merge into an existing directory intentionally");
            return -1;
        }

        return 0;
    }

    if (errno != ENOENT) {
        log_error("FILE_COPY: failed to stat destination directory: %s", path);
        return -1;
    }

    if (mkdir(path, mode & 0777) != 0) {
        log_error("FILE_COPY: failed to create destination directory: %s", path);
        return -1;
    }

    if (created) {
        *created = 1;
    }

    return 0;
}

static int copy_destination_inside_source(const char *src_path, const char *dst_path)
{
    char src_real[4096];
    char dst_real[4096];

    if (!realpath(src_path, src_real)) {
        return 0;
    }

    if (realpath(dst_path, dst_real)) {
        size_t src_len = strlen(src_real);
        return strncmp(src_real, dst_real, src_len) == 0 &&
               (dst_real[src_len] == '\0' || dst_real[src_len] == '/');
    }

    char *parent = copy_parent_dir(dst_path);
    if (!parent) {
        return 0;
    }

    char parent_real[4096];
    int result = 0;

    if (realpath(parent, parent_real)) {
        const char *base = copy_basename_ptr(dst_path);
        size_t needed = strlen(parent_real) + 1U + strlen(base) + 1U;
        char *combined = malloc(needed);
        if (combined) {
            snprintf(combined, needed, "%s/%s", parent_real, base);

            size_t src_len = strlen(src_real);
            result = strncmp(src_real, combined, src_len) == 0 &&
                     (combined[src_len] == '\0' || combined[src_len] == '/');

            free(combined);
        }
    }

    free(parent);
    return result;
}

static int copy_verified_regular_file(const char *src_path,
                                      const char *dst_path,
                                      int force,
                                      uintmax_t *bytes_out,
                                      int quiet_report,
                                      FILE *manifest,
                                      const char *manifest_rel_path)
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

        if (!S_ISREG(dst_existing_st.st_mode)) {
            log_error("FILE_COPY: destination exists but is not a regular file: %s", dst_path);
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

    if (!quiet_report) {
        log_info("FILE_COPY: starting verified copy %s -> %s (%" PRIdMAX " bytes)",
                 src_path, dst_path, (intmax_t)src_st.st_size);
    }

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

        if (!quiet_report && src_st.st_size > 0) {
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
    int verified = (size_match && sha256_match && md5_match);

    if (manifest && manifest_rel_path) {
        fprintf(manifest,
                "%s | %" PRIdMAX " | %s | %s | %s\n",
                verified ? "PASS" : "FAIL",
                (intmax_t)src_st.st_size,
                src_sha256,
                src_md5,
                manifest_rel_path);
    }

    if (!quiet_report) {
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
        printf("Verification : %s\n\n", verified ? "PASS" : "FAIL");

        log_info("FILE_COPY: SHA256(source)      = %s", src_sha256);
        log_info("FILE_COPY: SHA256(destination) = %s", dst_sha256);
        log_info("FILE_COPY: MD5(source)         = %s", src_md5);
        log_info("FILE_COPY: MD5(destination)    = %s", dst_md5);
    }

    if (!size_match || !sha256_match || !md5_match) {
        log_error("FILE_COPY: verification failed");
        return -1;
    }

    if (bytes_out) {
        *bytes_out = copied;
    }

    if (!quiet_report) {
        log_info("FILE_COPY: copy verified successfully using SHA-256, MD5, and size comparison");
    }
    return 0;
}

static int copy_tree_recursive(const char *src_root,
                               const char *src_dir,
                               const char *dst_dir,
                               int force,
                               CopyTreeStats *stats,
                               FILE *manifest)
{
    DIR *dir = opendir(src_dir);
    if (!dir) {
        log_error("FILE_COPY: failed to open source directory: %s", src_dir);
        if (stats) {
            stats->failures++;
        }
        return -1;
    }

    struct dirent *entry;
    int rc = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char *src_child = copy_join_path(src_dir, entry->d_name);
        char *dst_child = copy_join_path(dst_dir, entry->d_name);

        if (!src_child || !dst_child) {
            log_error("FILE_COPY: failed to allocate path for recursive copy");
            free(src_child);
            free(dst_child);
            rc = -1;
            if (stats) {
                stats->failures++;
            }
            continue;
        }

        struct stat st;
        if (lstat(src_child, &st) != 0) {
            log_error("FILE_COPY: failed to stat source entry: %s", src_child);
            rc = -1;
            if (stats) {
                stats->failures++;
            }
            free(src_child);
            free(dst_child);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            log_error("FILE_COPY: refusing symbolic link during recursive copy: %s", src_child);
            rc = -1;
            if (stats) {
                stats->entries_skipped++;
                stats->failures++;
            }
            free(src_child);
            free(dst_child);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int created = 0;
            if (copy_make_dir_if_needed(dst_child, st.st_mode, force, &created) != 0) {
                rc = -1;
                if (stats) {
                    stats->failures++;
                }
                free(src_child);
                free(dst_child);
                continue;
            }

            if (created && stats) {
                stats->dirs_created++;
            }

            if (copy_tree_recursive(src_root, src_child, dst_child, force, stats, manifest) != 0) {
                rc = -1;
            }

            free(src_child);
            free(dst_child);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            uintmax_t copied = 0;
            const char *rel_path = copy_relative_path(src_root, src_child);
            if (copy_verified_regular_file(src_child, dst_child, force, &copied, 1, manifest, rel_path) != 0) {
                rc = -1;
                if (stats) {
                    stats->failures++;
                }
            } else if (stats) {
                stats->files_copied++;
                stats->bytes_copied += copied;
            }

            free(src_child);
            free(dst_child);
            continue;
        }

        log_error("FILE_COPY: refusing unsupported file type during recursive copy: %s", src_child);
        rc = -1;
        if (stats) {
            stats->entries_skipped++;
            stats->failures++;
        }

        free(src_child);
        free(dst_child);
    }

    if (closedir(dir) != 0) {
        log_error("FILE_COPY: failed to close source directory: %s", src_dir);
        rc = -1;
        if (stats) {
            stats->failures++;
        }
    }

    return rc;
}

static int copy_verified_directory_tree(const char *src_path,
                                        const char *dst_path,
                                        int force)
{
    struct stat src_st;
    if (lstat(src_path, &src_st) != 0 || !S_ISDIR(src_st.st_mode)) {
        log_error("FILE_COPY: source is not a readable directory: %s", src_path);
        return -1;
    }

    if (S_ISLNK(src_st.st_mode)) {
        log_error("FILE_COPY: refusing symbolic link directory source: %s", src_path);
        return -1;
    }

    struct stat dst_st;
    if (stat(dst_path, &dst_st) == 0) {
        if (src_st.st_dev == dst_st.st_dev && src_st.st_ino == dst_st.st_ino) {
            log_error("FILE_COPY: source and destination refer to the same directory; refusing copy");
            return -1;
        }
    }

    if (copy_destination_inside_source(src_path, dst_path)) {
        log_error("FILE_COPY: destination is inside the source tree; refusing recursive copy");
        return -1;
    }

    int created = 0;
    if (copy_make_dir_if_needed(dst_path, src_st.st_mode, force, &created) != 0) {
        return -1;
    }

    CopyTreeStats stats;
    memset(&stats, 0, sizeof(stats));
    if (created) {
        stats.dirs_created = 1;
    }

    char *manifest_path = copy_join_path(dst_path, ".k1wi_copy_manifest.txt");
    if (!manifest_path) {
        log_error("FILE_COPY: failed to allocate manifest path");
        return -1;
    }

    FILE *manifest = fopen(manifest_path, "w");
    if (!manifest) {
        log_error("FILE_COPY: failed to create recursive copy manifest: %s", manifest_path);
        free(manifest_path);
        return -1;
    }

    fprintf(manifest, "# K1Wi Recursive COPY Manifest\n");
    fprintf(manifest, "# Source: %s\n", src_path);
    fprintf(manifest, "# Destination: %s\n", dst_path);
    fprintf(manifest, "# Format: status | size_bytes | sha256 | md5 | relative_path\n");

    int rc = copy_tree_recursive(src_path, src_path, dst_path, force, &stats, manifest);

    if (fflush(manifest) != 0) {
        log_error("FILE_COPY: failed to flush recursive copy manifest: %s", manifest_path);
        rc = -1;
        stats.failures++;
    }

    if (fsync(fileno(manifest)) != 0) {
        log_error("FILE_COPY: failed to sync recursive copy manifest: %s", manifest_path);
        rc = -1;
        stats.failures++;
    }

    if (fclose(manifest) != 0) {
        log_error("FILE_COPY: failed to close recursive copy manifest: %s", manifest_path);
        rc = -1;
        stats.failures++;
    }

    printf("\nCOPY Recursive Verification Report\n");
    printf("==================================\n");
    printf("Mode            : recursive directory copy\n");
    printf("Source          : %s\n", src_path);
    printf("Destination     : %s\n", dst_path);
    printf("Files copied    : %" PRIuMAX "\n", stats.files_copied);
    printf("Directories     : %" PRIuMAX "\n", stats.dirs_created);
    char manifest_sha256[65] = {0};
    char manifest_md5[33] = {0};

    int manifest_sha_ok = (sha256_file(manifest_path, manifest_sha256) == 0);
    int manifest_md5_ok = opus_md5_file(manifest_path, manifest_md5);

    printf("Bytes copied    : %" PRIuMAX "\n", stats.bytes_copied);
    printf("Hash algorithm  : SHA-256, MD5\n");
    printf("File hash records: %" PRIuMAX "\n", stats.files_copied);
    printf("Manifest SHA256 : %s\n", manifest_sha_ok ? manifest_sha256 : "unavailable");
    printf("Manifest MD5    : %s\n", manifest_md5_ok ? manifest_md5 : "unavailable");
    printf("Manifest        : %s\n", manifest_path);
    printf("Skipped entries : %" PRIuMAX "\n", stats.entries_skipped);
    printf("Failures        : %" PRIuMAX "\n", stats.failures);
    printf("Result          : %s\n", (rc == 0 && stats.failures == 0) ? "PASS" : "FAIL");
    printf("==================================\n\n");

    if (rc != 0 || stats.failures != 0) {
        log_error("FILE_COPY: recursive copy verification failed");
        free(manifest_path);
        return -1;
    }

    free(manifest_path);
    return 0;
}

int opus_file_copy(const char *src_path, const char *dst_path)
{
    return opus_file_copy_ex(src_path, dst_path, 0);
}

int opus_file_copy_ex(const char *src_path, const char *dst_path, int force)
{
    return opus_file_copy_ex2(src_path, dst_path, force, 0);
}

int opus_file_copy_ex2(const char *src_path, const char *dst_path, int force, int recursive)
{
    if (!src_path || !dst_path || src_path[0] == '\0' || dst_path[0] == '\0') {
        log_error("FILE_COPY: invalid source or destination path");
        return -1;
    }

    struct stat src_st;
    if (lstat(src_path, &src_st) != 0) {
        log_error("FILE_COPY: source is missing or unreadable: %s", src_path);
        return -1;
    }

    if (S_ISLNK(src_st.st_mode)) {
        log_error("FILE_COPY: refusing symbolic link source: %s", src_path);
        return -1;
    }

    if (S_ISREG(src_st.st_mode)) {
        return copy_verified_regular_file(src_path, dst_path, force, NULL, 0, NULL, NULL);
    }

    if (S_ISDIR(src_st.st_mode)) {
        if (!recursive) {
            log_error("FILE_COPY: source is a directory; recursive copy requires --recursive");
            return -1;
        }

        return copy_verified_directory_tree(src_path, dst_path, force);
    }

    log_error("FILE_COPY: unsupported source file type: %s", src_path);
    return -1;
}
