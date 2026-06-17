/* secure_delete_cmds.c */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>   /* ftruncate, getpid, access */
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Forward to interactive fallback in Opus.c */
void fileDelete(void);

/* Prototype exported to Opus.c via secure_delete_cmds.h */
int secure_delete_file(const char *filename, int standard);
void fileDeleteCmd(const char *args);

/* Validate filename: non-empty, no absolute paths, no directory traversal */
static int is_safe_filename(const char *fn) {
    if (!fn || !fn[0]) return 0;
    if (fn[0] == '/') return 0;
    if (strstr(fn, "..")) return 0;
    return 1;
}

/* Prompt helper used by both interactive and non-interactive flows */
static int prompt_for_confirmation(const char *prompt) {
    char buf[32];
    fprintf(stderr, "%s", prompt);
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    return (buf[0] == 'Y' || buf[0] == 'y');
}

/* secure_delete_file: overwrite, truncate, and unlink file
 * standard: 1 = DoD 5220.22-M (3-pass), 2 = NIST 800-88 (single zero pass)
 * returns 0 on success, -1 on error (errno set)
 */
int secure_delete_file(const char *filename, int standard) {
    if (!filename) { errno = EINVAL; return -1; }

    struct stat st;
    if (lstat(filename, &st) != 0) {
        fprintf(stderr, "[secure_delete_file] file not found: %s\n", filename);
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        errno = ELOOP;
        fprintf(stderr, "[secure_delete_file] refusing symlink target: %s\n", filename);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        errno = EINVAL;
        fprintf(stderr, "[secure_delete_file] refusing non-regular file: %s\n", filename);
        return -1;
    }

    int flags = O_RDWR;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    int fd = open(filename, flags);
    if (fd < 0) {
        fprintf(stderr, "[secure_delete_file] open('%s') failed: %s\n", filename, strerror(errno));
        return -1;
    }

    FILE *fp = fdopen(fd, "r+b");
    if (!fp) {
        int se = errno;
        close(fd);
        errno = se;
        fprintf(stderr, "[secure_delete_file] fdopen('%s') failed: %s\n", filename, strerror(errno));
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) { int se = errno; fclose(fp); errno = se; return -1; }
    long fsize = ftell(fp);
    if (fsize < 0) { int se = errno; fclose(fp); errno = se; return -1; }
    rewind(fp);

    unsigned char buffer[4096];

    if (standard == 2) {
        /* NIST: single pass zeros */
        size_t remaining = (size_t)fsize;
        while (remaining > 0) {
            size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
            memset(buffer, 0x00, chunk);
            if (fwrite(buffer, 1, chunk, fp) != chunk) { int se = errno; fclose(fp); errno = se; return -1; }
            remaining -= chunk;
        }
        fflush(fp);
    } else {
        /* DoD 3-pass: 0xFF, 0x00, random */
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        for (int pass = 0; pass < 3; ++pass) {
            size_t remaining = (size_t)fsize;
            rewind(fp);
            while (remaining > 0) {
                size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
                if (pass == 0) memset(buffer, 0xFF, chunk);
                else if (pass == 1) memset(buffer, 0x00, chunk);
                else for (size_t i = 0; i < chunk; ++i) buffer[i] = (unsigned char)(rand() & 0xFF);

                if (fwrite(buffer, 1, chunk, fp) != chunk) { int se = errno; fclose(fp); errno = se; return -1; }
                remaining -= chunk;
            }
            fflush(fp);
        }
    }

#if defined(_WIN32)
    if (_chsize(_fileno(fp), 0) != 0) { int se = errno; fclose(fp); errno = se; return -1; }
#else
    if (ftruncate(fileno(fp), 0) != 0) { int se = errno; fclose(fp); errno = se; return -1; }
#endif

    fclose(fp);

    if (remove(filename) != 0) {
        fprintf(stderr, "[secure_delete_file] remove('%s') failed: %s\n", filename, strerror(errno));
        return -1;
    }

    return 0;
}

/* fileDeleteCmd: parse one-line args and call secure_delete_file.
 * Ownership: args is non-owning (caller frees any heap buffer it passed).
 * Supported forms:
 *   NULL or ""        -> fallback to interactive fileDelete()
 *   "<filename>"      -> prompts for confirmation, then deletes
 *   "<filename> -s 2 -y" -> standard=2 (NIST), auto-yes
 */
void fileDeleteCmd(const char *args) {
    

    if (!args || !*args) {
        /* fallback to interactive behavior */
        fileDelete();
        return;
    }

    /* copy for safe tokenization */
    char *copy = strdup(args);
    if (!copy) { fprintf(stderr, "Memory error\n"); return; }

    char *saveptr = NULL;
    char *tok = strtok_r(copy, " \t", &saveptr);
    char *filename = NULL;
    int standard = 1; /* 1 = DoD, 2 = NIST */
    int auto_yes = 0;

    while (tok) {
        if (strcmp(tok, "-s") == 0 || strcmp(tok, "--standard") == 0) {
            char *v = strtok_r(NULL, " \t", &saveptr);
            if (v) standard = (atoi(v) == 2) ? 2 : 1;
        } else if (strcmp(tok, "-y") == 0 || strcmp(tok, "--yes") == 0) {
            auto_yes = 1;
        } else if (!filename) {
            filename = strdup(tok);
        } else {
            /* ignore extras */
        }
        tok = strtok_r(NULL, " \t", &saveptr);
    }

    free(copy);

    if (!filename) {
        /* nothing provided: fallback */
        fileDelete();
        return;
    }

    /* sanitize filename (strip surrounding quotes if present) */
    if ((filename[0] == '"' && filename[strlen(filename)-1] == '"') ||
        (filename[0] == '\'' && filename[strlen(filename)-1] == '\'')) {
        memmove(filename, filename+1, strlen(filename)); /* shift left */
        filename[strlen(filename)-1] = '\0';
    }

    if (!is_safe_filename(filename)) {
        fprintf(stderr, "Unsafe filename. Deletion aborted.\n");
        free(filename);
        return;
    }

    if (!auto_yes) {
        char q[512];
        snprintf(q, sizeof(q), "Are you sure you want to SECURELY DELETE '%s'? [Y/N]: ", filename);
        if (!prompt_for_confirmation(q)) {
            fprintf(stderr, "File deletion canceled.\n");
            free(filename);
            return;
        }
    }

    if (secure_delete_file(filename, standard) == 0) {
        fprintf(stderr, "Secure deletion complete for %s\n", filename);
    } else {
        fprintf(stderr, "Secure delete failed for %s\n", filename);
    }

    free(filename);
}

