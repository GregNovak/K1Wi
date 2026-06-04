#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include "opus_extract.h"
#include "file_carver.h" 
#include "string_intel.h"
#include "format_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/*Define color options */
#define OPUS_COLOR 1

#if OPUS_COLOR
#define C_RESET  "\033[0m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_BLUE   "\033[34m"
#define C_RED    "\033[31m"
#define C_CYAN   "\033[36m"
#else
#define C_RESET  ""
#define C_GREEN  ""
#define C_YELLOW ""
#define C_BLUE   ""
#define C_RED    ""
#define C_CYAN   ""
#endif
#define LOG_STRING(fmt, ...)  fprintf(stderr, C_GREEN  "[STRING]"  C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_EXTRACT(fmt, ...) fprintf(stderr, C_CYAN   "[EXTRACT]" C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_CARVER(fmt, ...)  fprintf(stderr, C_BLUE   "[CARVER]"  C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_RECURSE(fmt, ...) fprintf(stderr, C_YELLOW "[RECURSE]" C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_DONE(fmt, ...)    fprintf(stderr, C_GREEN  "[DONE]"    C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARN(fmt, ...)    fprintf(stderr, C_YELLOW "[WARN]"    C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERROR(fmt, ...)   fprintf(stderr, C_RED    "[ERROR]"   C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LOG_STEP(fmt, ...)    fprintf(stderr, C_CYAN   "[STEP]"    C_RESET " " fmt "\n" __VA_OPT__(,) __VA_ARGS__)


/* recursion safety */
#define OPUS_EXTRACT_MAX_DEPTH 16
#define OPUS_EXTRACT_MAX_VISITED 256
static double elapsed_seconds(const struct timeval *start,
                              const struct timeval *end)
{
    double s = (double)(end->tv_sec - start->tv_sec);
    double us = (double)(end->tv_usec - start->tv_usec) / 1000000.0;
    return s + us;
}
static void extract_indent(int depth)
{
    for (int i = 0; i < depth; i++) {
        fprintf(stderr, "  ");
    }
}


/* ---------------- Provenance / output helpers ---------------- */
static unsigned int g_extract_session_id = 0;
static unsigned int g_extract_branch_id = 0;
typedef struct {
    int step_id;
    int depth;
    char handler[64];
    char parent[PATH_MAX];
    char child[PATH_MAX];
    unsigned long size;
    char sha1[64]; /* optional; empty if not computed */
    char cmd[256];  /* external command used, if any */
    char ts[64];    /* ISO8601-ish timestamp */
} provenance_entry_t;

/* global run context (defaults) */
static opus_run_context_t g_run_ctx = {
    .outmode = OPUS_OUTMODE_HUMAN,
    .pager = 1,
    .verbose = 1,
    .logfile = ""
};

void opus_extract_set_run_context(const opus_run_context_t *ctx) {
    if (!ctx) return;
    g_run_ctx = *ctx;
}

/* sanitize a string for terminal/JSON output: replace control chars with spaces */
static void sanitize_str(const char *in, char *out, size_t out_sz) {
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < out_sz; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 0x20 || c == '\n' || c == '\t') {
            out[j++] = (char)c;
        } else {
            out[j++] = ' ';
        }
    }
    out[j] = '\0';
}

/* get ISO-like timestamp */
static void now_iso8601(char *buf, size_t sz) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm;
    gmtime_r(&tv.tv_sec, &tm);
    snprintf(buf, sz, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* append one provenance_entry as JSON to logfile */
static int write_provenance_jsonl(const char *logpath, const provenance_entry_t *e) {
    if (!logpath || !*logpath) return -1;
    FILE *f = fopen(logpath, "a");
    if (!f) return -1;
    char parent_s[PATH_MAX*2], child_s[PATH_MAX*2], cmd_s[sizeof(e->cmd)*2];
    sanitize_str(e->parent, parent_s, sizeof(parent_s));
    sanitize_str(e->child, child_s, sizeof(child_s));
    sanitize_str(e->cmd, cmd_s, sizeof(cmd_s));
    fprintf(f,
        "{\"step\":%d,\"depth\":%d,\"handler\":\"%s\",\"parent\":\"%s\",\"child\":\"%s\",\"size\":%lu,\"sha1\":\"%s\",\"cmd\":\"%s\",\"ts\":\"%s\"}\n",
        e->step_id, e->depth, e->handler, parent_s, child_s, e->size,
        e->sha1[0] ? e->sha1 : "", cmd_s, e->ts);
    fclose(f);
    return 0;
}

/* print a compact table row */
static void print_provenance_row(const provenance_entry_t *e) {
    char parent_s[64], child_s[64];
    sanitize_str(e->parent, parent_s, sizeof(parent_s));
    sanitize_str(e->child, child_s, sizeof(child_s));
    printf("%3d  %-10s  %-20.20s -> %-20.20s  %8lu  %s\n",
           e->step_id, e->handler, parent_s, child_s, e->size, e->sha1);
}

/* send long text to pager; returns 0 on success */
static int page_text_with_less(const char *text) {
    FILE *p = popen("less -R", "w");
    if (!p) return -1;
    fputs(text, p);
    pclose(p);
    return 0;
}

/* convenience: record one provenance entry according to current run context */
static void record_provenance(int step_id, int depth,
                              const char *handler,
                              const char *parent,
                              const char *child,
                              unsigned long size,
                              const char *sha1,
                              const char *cmd)
{
    provenance_entry_t e;
    memset(&e, 0, sizeof(e));
    e.step_id = step_id;
    e.depth = depth;
    strncpy(e.handler, handler ? handler : "", sizeof(e.handler)-1);
    strncpy(e.parent, parent ? parent : "", sizeof(e.parent)-1);
    strncpy(e.child, child ? child : "", sizeof(e.child)-1);
    e.size = size;
    if (sha1) strncpy(e.sha1, sha1, sizeof(e.sha1)-1);
    if (cmd) strncpy(e.cmd, cmd, sizeof(e.cmd)-1);
    now_iso8601(e.ts, sizeof(e.ts));

    if (g_run_ctx.outmode == OPUS_OUTMODE_JSONL && g_run_ctx.logfile[0]) {
        write_provenance_jsonl(g_run_ctx.logfile, &e);
    } else if (g_run_ctx.outmode == OPUS_OUTMODE_HUMAN) {
        if (g_run_ctx.verbose >= 2 && step_id == 0) {
            printf(" ID  Handler     Parent -> Child               Size     SHA1\n");
            printf("---- ----------  -------------------- -> --------------------  --------  -----------------\n");
        }
        if (g_run_ctx.verbose >= 1) print_provenance_row(&e);
    } else if (g_run_ctx.outmode == OPUS_OUTMODE_BRIEF) {
        if (g_run_ctx.verbose >= 1 && step_id >= 0) {
            printf("[EXTRACT] %s -> %s\n", parent ? parent : "", child ? child : "");
        }
    }
        /* optional: page long output when pager is enabled (prevents unused-function warning) */
    if (g_run_ctx.pager && g_run_ctx.verbose >= 2) {
        /* placeholder until real paging is wired; replace with actual long text when available */
        page_text_with_less("");
    }

}

static int visited_contains(char **visited, int visited_count, const char *path) {
    for (int i = 0; i < visited_count; i++) {
        if (visited[i] && strcmp(visited[i], path) == 0) return 1;
    }
    return 0;
}

static int visited_push(char **visited, int *visited_count, const char *path) {
    if (*visited_count >= OPUS_EXTRACT_MAX_VISITED) return -1;
    visited[*visited_count] = strdup(path);
    if (!visited[*visited_count]) return -1;
    (*visited_count)++;
    return 0;
}

static void visited_pop(char **visited, int *visited_count) {
    if (*visited_count <= 0) return;
    free(visited[*visited_count - 1]);
    visited[*visited_count - 1] = NULL;
    (*visited_count)--;
}

typedef struct format_handler {
    const char *name;
    int  (*detect)(const unsigned char *buf, size_t len);
    const char *preferred_ext;  // for suffix normalization
    int  (*extract)(const char *path, char *out_path, size_t out_sz);
} format_handler_t;

typedef struct log_entry {
    int depth;
    const char *format;
    char before[PATH_MAX];
    char after[PATH_MAX];
} log_entry_t;

#define MAX_LOG_ENTRIES 128

/* ---------- Utility helpers ---------- */

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}
static int ensure_extract_carve_dirs(char *session_dir,
                                     size_t session_sz,
                                     unsigned int session_id)
{
    if (snprintf(session_dir, session_sz,
                 "carved/extract_%04u", session_id) >= (int)session_sz) {
        return -1;
    }

    if (mkdir("carved", 0700) != 0 && errno != EEXIST) {
        perror("mkdir carved");
        return -1;
    }

    if (mkdir(session_dir, 0700) != 0 && errno != EEXIST) {
        perror("mkdir extract session");
        return -1;
    }

    return 0;
}
static int has_suffix(const char *path, const char *ext) {
    size_t lp = strlen(path);
    size_t le = strlen(ext);
    if (lp < le) return 0;
    return strcmp(path + lp - le, ext) == 0;
}

/*
 * ensure_suffix:
 *   - If path already ends with ext, copy it to newpath.
 *   - Otherwise, rename the file to add ext, and return the new path.
 */
static int ensure_suffix(const char *path, const char *ext,
                         char *newpath, size_t sz)
{
    if (!ext || !*ext) {
        // no suffix enforcement
        if (snprintf(newpath, sz, "%s", path) >= (int)sz) return -1;
        return 0;
    }

    if (has_suffix(path, ext)) {
        if (snprintf(newpath, sz, "%s", path) >= (int)sz) return -1;
        return 0;
    }

    // rename path -> path + ext
    if (snprintf(newpath, sz, "%s%s", path, ext) >= (int)sz) return -1;
    if (rename(path, newpath) != 0) {
        perror("rename");
        return -1;
    }
    return 0;
}

/*
 * run_cmd:
 *   - Simple wrapper around system()
 *   - Returns 0 on success, -1 on failure
 */
static int run_cmd(const char *cmd) {
    fprintf(stderr, "[CMD] %s\n", cmd);
    int rc = system(cmd);
    if (rc == -1) {
        perror("system");
        return -1;
    }
    if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
        return 0;
    }
    fprintf(stderr, "[!] Command failed with status %d\n", rc);
    return -1;
}

/* ---------- Detection helpers (magic/heuristics) ---------- */

static int is_gzip(const unsigned char *buf, size_t len) {
    return len >= 2 && buf[0] == 0x1f && buf[1] == 0x8b;
}

static int is_bzip2(const unsigned char *buf, size_t len) {
    return len >= 3 && buf[0] == 'B' && buf[1] == 'Z' && buf[2] == 'h';
}

static int is_xz(const unsigned char *buf, size_t len) {
    static const unsigned char sig[] = {0xFD,'7','z','X','Z',0x00};
    return len >= sizeof(sig) && memcmp(buf, sig, sizeof(sig)) == 0;
}

static int is_lzip(const unsigned char *buf, size_t len) {
    return len >= 4 && memcmp(buf, "LZIP", 4) == 0;
}

static int is_lz4(const unsigned char *buf, size_t len) {
    // very rough: check for frame magic 0x04224D18
    return len >= 4 &&
           buf[0] == 0x04 && buf[1] == 0x22 &&
           buf[2] == 0x4D && buf[3] == 0x18;
}

static int is_lzop(const unsigned char *buf, size_t len) {
    // LZOP magic: 89 4C 5A 4F 00 0D 0A 1A 0A
    static const unsigned char sig[] =
        {0x89, 'L', 'Z', 'O', 0x00, 0x0d, 0x0a, 0x1a, 0x0a};
    return len >= sizeof(sig) && memcmp(buf, sig, sizeof(sig)) == 0;
}

/*
 * Heuristic for raw LZMA stream: props + dict size.
 * Not perfect, but good enough for CTF workflows.
 */
static int is_lzma_raw(const unsigned char *buf, size_t len) {
    if (len < 13) return 0;
    unsigned char props = buf[0];
    unsigned int dict_size =
        (unsigned int)buf[1] |
        ((unsigned int)buf[2] << 8) |
        ((unsigned int)buf[3] << 16) |
        ((unsigned int)buf[4] << 24);
    if (props > 224) return 0;
    if (dict_size < (1u << 12) || dict_size > (1u << 27)) return 0;
    return 1;
}

static int is_shar(const unsigned char *buf, size_t len) {
    if (len < 10) return 0;
    // crude: looks like a shell script with "shar" string
    if (!(buf[0] == '#' && buf[1] == '!' && memmem(buf, len, "shar", 4)))
        return 0;
    return 1;
}

static int is_uuencode(const unsigned char *buf, size_t len) {
    // look for "begin " at the start (possibly after whitespace)
    size_t i = 0;
    while (i < len && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r'))
        i++;
    if (i + 6 <= len && memcmp(buf + i, "begin ", 6) == 0)
        return 1;
    return 0;
}

static int is_ar(const unsigned char *buf, size_t len) {
    // "!<arch>\n"
    return len >= 8 && memcmp(buf, "!<arch>\n", 8) == 0;
}

static int is_cpio_newc(const unsigned char *buf, size_t len) {
    // "070701"
    return len >= 6 && memcmp(buf, "070701", 6) == 0;
}
int opus_extract_single(const char *path) {
    printf("[EXTRACT] (stub) single extract: %s\n", path);
    return 0;
}

/* ---------- Extractor implementations ---------- */

static int extract_gzip(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".gz", fixed, sizeof(fixed)) != 0)
        return -1;

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "gunzip -f \"%s\"", fixed);
    if (run_cmd(cmd) != 0) return -1;

    // strip ".gz"
    size_t lf = strlen(fixed);
    if (lf < 3) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 3), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

static int extract_bzip2(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".bz2", fixed, sizeof(fixed)) != 0)
        return -1;
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "bunzip2 -f \"%s\"", fixed);
    if (run_cmd(cmd) != 0) return -1;
    size_t lf = strlen(fixed);
    if (lf < 4) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 4), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

static int extract_xz(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".xz", fixed, sizeof(fixed)) != 0)
        return -1;
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "xz -f -d \"%s\"", fixed);
    if (run_cmd(cmd) != 0) return -1;
    size_t lf = strlen(fixed);
    if (lf < 3) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 3), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

static int extract_lzip(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".lz", fixed, sizeof(fixed)) != 0)
        return -1;
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "lzip -f -d \"%s\"", fixed);
    if (run_cmd(cmd) != 0) return -1;
    size_t lf = strlen(fixed);
    if (lf < 3) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 3), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

static int extract_lz4(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".lz4", fixed, sizeof(fixed)) != 0)
        return -1;
    // we'll output to "<name>.out"
    char outtmp[PATH_MAX];
    snprintf(outtmp, sizeof(outtmp), "%s", fixed);
    strncat(outtmp, ".out", sizeof(outtmp) - strlen(outtmp) - 1);

    char cmd[PATH_MAX * 2];
    cmd[0] = '\0';

    snprintf(cmd, sizeof(cmd), "lz4 -f -d \"");
    strncat(cmd, fixed, sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, "\" \"", sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, outtmp, sizeof(cmd) - strlen(cmd) - 1);
    strncat(cmd, "\"", sizeof(cmd) - strlen(cmd) - 1);

    if (run_cmd(cmd) != 0) return -1;
    if (snprintf(out, out_sz, "%s", outtmp) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

static int extract_lzop(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".lzo", fixed, sizeof(fixed)) != 0)
        return -1;
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "lzop -f -d \"%s\"", fixed);
    if (run_cmd(cmd) != 0) return -1;
    size_t lf = strlen(fixed);
    if (lf < 4) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 4), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

/* raw LZMA via unlzma (from lzma package), fallback to xz --format=lzma */
static int extract_lzma_raw(const char *path, char *out, size_t out_sz) {
    char fixed[PATH_MAX];
    if (ensure_suffix(path, ".lzma", fixed, sizeof(fixed)) != 0)
        return -1;

    char cmd[PATH_MAX * 2];
    // try unlzma first
    snprintf(cmd, sizeof(cmd), "unlzma -f \"%s\"", fixed);
    if (run_cmd(cmd) != 0) {
        // fallback to xz raw mode
        snprintf(cmd, sizeof(cmd), "xz --format=lzma -f -d \"%s\"", fixed);
        if (run_cmd(cmd) != 0)
            return -1;
    }
    size_t lf = strlen(fixed);
    if (lf < 5) return -1;
    if (snprintf(out, out_sz, "%.*s", (int)(lf - 5), fixed) >= (int)out_sz)
        return -1;
    return file_exists(out) ? 0 : -1;
}

/* ar archive: extract to dir and pick first file (CTF-style heuristic) */
static int extract_ar(const char *path, char *out, size_t out_sz) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s.ar.extracted", path);
    mkdir(dir, 0700);

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "cd \"%s\" && ar x \"%s\"", dir, path);
    if (run_cmd(cmd) != 0) return -1;

    // naive: pick first regular file
    // TODO: improve by scanning directory properly
    snprintf(out, out_sz, "%s/%s", dir, "TODO_pick_first_file");
    // for now, user will adjust this; integrating dir scan is trivial
    return 0;
}

/* cpio: extract to dir and pick first file */
static int extract_cpio_newc(const char *path, char *out, size_t out_sz) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s.cpio.extracted", path);
    mkdir(dir, 0700);

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "cd \"%s\" && cpio -id < \"%s\"", dir, path);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(out, out_sz, "%s/%s", dir, "TODO_pick_first_file");
    return 0;
}

/* shar: execute as shell script in dir, pick first file */
static int extract_shar(const char *path, char *out, size_t out_sz) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s.shar.extracted", path);
    mkdir(dir, 0700);

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "cd \"%s\" && sh \"%s\"", dir, path);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(out, out_sz, "%s/%s", dir, "TODO_pick_first_file");
    return 0;
}

/* uuencode: uudecode in dir, pick first file */
static int extract_uuencode(const char *path, char *out, size_t out_sz) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s.uu.extracted", path);
    mkdir(dir, 0700);

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "cd \"%s\" && uudecode \"%s\"", dir, path);
    if (run_cmd(cmd) != 0) return -1;

    snprintf(out, out_sz, "%s/%s", dir, "TODO_pick_first_file");
    return 0;
}

/* ---------- Handler table ---------- */

static format_handler_t handlers[] = {
    { "gzip",      is_gzip,       ".gz",    extract_gzip      },
    { "bzip2",     is_bzip2,      ".bz2",   extract_bzip2     },
    { "xz",        is_xz,         ".xz",    extract_xz        },
    { "lzip",      is_lzip,       ".lz",    extract_lzip      },
    { "lz4",       is_lz4,        ".lz4",   extract_lz4       },
    { "lzma_raw",  is_lzma_raw,   ".lzma",  extract_lzma_raw  },
    { "lzop",      is_lzop,       ".lzo",   extract_lzop      },
    { "shar",      is_shar,       ".sh",    extract_shar      },
    { "uuencode",  is_uuencode,   ".uu",    extract_uuencode  },
    { "ar",        is_ar,         ".a",     extract_ar        },
    { "cpio_newc", is_cpio_newc,  ".cpio",  extract_cpio_newc },
};

static const size_t NUM_HANDLERS = sizeof(handlers) / sizeof(handlers[0]);

/* ---------- Format detection + recursive engine ---------- */

static format_handler_t *detect_format(const char *path) {
    unsigned char buf[4096];
    size_t n;
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    for (size_t i = 0; i < NUM_HANDLERS; i++) {
        if (handlers[i].detect(buf, n)) {
            fprintf(stderr, "[+] Detected %s in %s\n", handlers[i].name, path);
            return &handlers[i];
        }
    }
    return NULL;
}

/* ---------- Updated recurse_on_directory_files (passes visited + depth) ---------- */

static void recurse_on_directory_files(const char *dirpath,
                                       const char *parent_path,
                                       int base_depth,
                                       char **visited,
                                       int *visited_count)
{
    DIR *dir = opendir(dirpath);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *ent;
    char path[PATH_MAX];

    struct stat st_parent;
    int have_parent = 0;

    if (parent_path && stat(parent_path, &st_parent) == 0) {
        have_parent = 1;
    }

    while ((ent = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        if (snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name)
            >= (int)sizeof(path)) {
            fprintf(stderr, "[R] Path too long, skipping %s/%s\n",
                    dirpath, ent->d_name);
            continue;
        }

        struct stat st_child;
        if (stat(path, &st_child) != 0) {
            perror("stat");
            continue;
        }

        if (!S_ISREG(st_child.st_mode))
            continue;

        /* Prevent infinite recursion: if carved file is identical (size-wise) to the parent, skip it. */
	if (have_parent && st_child.st_size == st_parent.st_size) {
	    extract_indent(base_depth - 1);
	    LOG_WARN("skip same-size child=%s parent=%s",
		     path,
		     parent_path);
	    continue;
	}
        /* Prevent cycles: if we've already visited this path in this extraction chain, skip it */
        if (visited_contains(visited, *visited_count, path)) {
            fprintf(stderr, "[R] Skipping recursion into %s (already visited)\n", path);
            continue;
        }

        const char *node_name = strrchr(path, '/');
	node_name = node_name ? node_name + 1 : path;

	extract_indent(base_depth - 1);
	fprintf(stderr, "├── %s\n", node_name);

        /* Recurse into the carved file, passing depth and visited set */
        char *final = extract_layers(path, base_depth, visited, visited_count);
        if (final) free(final);
    }

    closedir(dir);
}

/* ---------- Reentrant, depth-aware extract_layers ---------- */

/*
 * New extract_layers signature:
 *   - start_path: input file
 *   - depth: current recursion depth
 *   - visited: array of strdup'd paths used to detect cycles
 *   - visited_count: pointer to visited count
 *
 * Returns: malloc'd final path string (caller must free) or NULL on error.
 */
char *extract_layers(const char *start_path, int depth, char **visited, int *visited_count) {
    if (depth > OPUS_EXTRACT_MAX_DEPTH) {
        fprintf(stderr, "[EXTRACT] Max depth %d reached at %s\n", OPUS_EXTRACT_MAX_DEPTH, start_path);
        return strdup(start_path);
    }

    if (visited_contains(visited, *visited_count, start_path)) {
        fprintf(stderr, "[EXTRACT] Already visited %s, skipping recursion\n", start_path);
        return strdup(start_path);
    }

    if (visited_push(visited, visited_count, start_path) != 0) {
        fprintf(stderr, "[EXTRACT] Warning: visited set full, aborting recursion at %s\n", start_path);
        return strdup(start_path);
    }

    char current[PATH_MAX];
    if (snprintf(current, sizeof(current), "%s", start_path) >= (int)sizeof(current)) {
        visited_pop(visited, visited_count);
        return NULL;
    }

	if (depth == 0) {
    fprintf(stderr,
            "\n============================================================\n"
            "EXTRACT SESSION %04u\n"
            "============================================================\n\n"
            "Target\n"
            "------------------------------------------------------------\n"
            "%s\n\n",
            g_extract_session_id,
            current);
            
} else {
    extract_indent(depth);
    fprintf(stderr,
            C_CYAN "[SCAN]" C_RESET " file=%s\n",
            current);
}

    log_entry_t log[MAX_LOG_ENTRIES];
    int log_count = 0;

    for (int d = depth; d < OPUS_EXTRACT_MAX_DEPTH; d++) {
        format_handler_t *h = detect_format(current);
        if (!h) {
            	extract_indent(depth);


            /* Optional: run string intelligence on the final layer */
            opus_string_report_t rep;
            if (opus_string_file(current, &rep) == 0) {
            
            if (depth == 0) {
	    fprintf(stderr,
		    "Analysis\n"
		    "------------------------------------------------------------\n");
		}
    		LOG_STRING("file=%s ASCII=%d UTF8=%d Base64=%d URL=%d Email=%d",
               current,
               rep.ascii_count,
               rep.utf8_count,
               rep.base64_count,
               rep.url_count,
               rep.email_count);
		}

            unsigned int branch_id = g_extract_branch_id++;

		opus_carve_result_t cres;
		char session_dir[PATH_MAX];
		char carve_dir[PATH_MAX];

		if (ensure_extract_carve_dirs(session_dir, sizeof(session_dir),
				              g_extract_session_id) != 0) {
		    fprintf(stderr, "[Carver] Failed to create carve session directory\n");
		} 
		else {
		    snprintf(carve_dir, sizeof(carve_dir), "%s/depth_%02d_branch_%03u_final", session_dir, d, branch_id);

		    if (opus_file_carve(current, carve_dir, &cres) == 0 &&
			cres.files_carved > 0) {
			extract_indent(depth);
			
			if (depth == 0) {
			    fprintf(stderr,
				    "Output : %s\n"
				    "Files  : %d\n\n",
				    carve_dir,
				    cres.files_carved);
			} else {
			    extract_indent(depth);
			    fprintf(stderr,
				    "[CARVER] files=%d out=%s\n",
				    cres.files_carved,
				    carve_dir);
			}
		}
	
	}
            break;
        }

        fprintf(stderr, "[>] Depth %d: %s on %s\n", d, h->name, current);

        char next[PATH_MAX];

        if (h->extract(current, next, sizeof(next)) != 0) {
            fprintf(stderr,
                    "[!] Extraction failed for %s on %s\n", h->name, current);
            break;
        }

        /* record log entry (in-memory) */
        if (log_count < MAX_LOG_ENTRIES) {
            log[log_count].depth = d;
            log[log_count].format = h->name;
            snprintf(log[log_count].before, sizeof(log[log_count].before), "%s", current);
            snprintf(log[log_count].after,  sizeof(log[log_count].after),  "%s", next);
            log_count++;
        }

        /* --- provenance recording (step info) --- */
        unsigned long next_size = 0;
        struct stat stn;
        if (stat(next, &stn) == 0) next_size = (unsigned long)stn.st_size;

        /* step id uses current log_count-1 if we just incremented it, otherwise use log_count */
        int step_id = (log_count > 0) ? (log_count - 1) : log_count;

        /* record_provenance(step_id, depth, handler, parent, child, size, sha1, cmd) */
        record_provenance(step_id, d, h->name, current, next, next_size, "", h->name);

        /* move to next layer */
        snprintf(current, sizeof(current), "%s", next);
	
	        /* After each successful extraction step, try carving this new layer. */
        {
            unsigned int branch_id = g_extract_branch_id++;

            opus_carve_result_t cres;
            char session_dir[PATH_MAX];
            char carve_dir[PATH_MAX];

            if (ensure_extract_carve_dirs(session_dir, sizeof(session_dir),
                                          g_extract_session_id) != 0) {
               fprintf(stderr, "[ERROR] failed to create carve session directory\n");
            } else {
                snprintf(carve_dir, sizeof(carve_dir),
                         "%s/depth_%02d_branch_%03u_layer",
                         session_dir,
                         d,
                         branch_id);

                if (opus_file_carve(current, carve_dir, &cres) == 0) {
                    if (cres.files_carved > 0) {
                        extract_indent(depth);
                        fprintf(stderr,
                                "[CARVER] files=%d out=%s\n",
                                cres.files_carved,
                                carve_dir);

                        recurse_on_directory_files(carve_dir, current, d + 1,
                                                   visited, visited_count);
                    } else if (depth == 0) {
                        fprintf(stderr,
                                "\nCarved Files\n"
                                "------------------------------------------------------------\n"
                                "None\n");
                    }
                }
            }
        }
}
	if (log_count > 0) {
	    fprintf(stderr, "\n[LOG] Extraction steps:\n");
	    for (int i = 0; i < log_count; i++) {
		fprintf(stderr, "  %02d: %-12s %s -> %s\n",
		        log[i].depth, log[i].format,
		        log[i].before, log[i].after);
	    }
	}

    /* pop visited for this start_path before returning final path */
    visited_pop(visited, visited_count);

    return strdup(current);
}

/* ---------- Public wrapper: allocate visited set and call new extract_layers ---------- */

int opus_extract_recursive(const char *path)
{
    char **visited = calloc(OPUS_EXTRACT_MAX_VISITED, sizeof(char *));
    if (!visited) {
        fprintf(stderr, "[EXTRACT] Memory allocation failed\n");
        return -1;
    }
    int visited_count = 0;
        g_extract_session_id++;
        g_extract_branch_id = 0;
        
        struct timeval t_start;
	struct timeval t_end;
	char started[64];
	char completed[64];

	gettimeofday(&t_start, NULL);
	now_iso8601(started, sizeof(started));
        
    char *final = extract_layers(path, 0, visited, &visited_count);
    if (!final) {
        fprintf(stderr, "[EXTRACT] Extraction failed for %s\n", path);
        /* cleanup visited */
        while (visited_count > 0) visited_pop(visited, &visited_count);
        free(visited);
        return -1;
    }

    gettimeofday(&t_end, NULL);
now_iso8601(completed, sizeof(completed));

fprintf(stderr,
        "\nFinal\n"
        "------------------------------------------------------------\n"
        "File      : %s\n"
        "Started   : %s\n"
        "Completed : %s\n"
        "Duration  : %.3f sec\n"
        "============================================================\n"
        "EXTRACT COMPLETE\n"
        "============================================================\n",
        final,
        started,
        completed,
        elapsed_seconds(&t_start, &t_end));
    free(final);

    /* cleanup visited */
    while (visited_count > 0) visited_pop(visited, &visited_count);
    free(visited);

    return 0;
}

/* sanitize a string for terminal/JSON output: remove control chars except newline */
