/*
 * tui_md5.c
 *
 * MD5 tools TUI module for Opus.
 *
 * Designed to compile cleanly with:
 *   -Wall -Wextra -Werror -std=c11
 *
 * Depends on:
 *   opus_tui.h  (struct opus_app, opus_tui_* API)
 *   md5.h       (bool opus_md5_file(const char *path, char out_hex[33]);)
 */

#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "opus_tui.h"
#include "md5.h"

/* ----------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------- */

enum {
    TUI_MD5_PATH_MAX   = 4096,
    TUI_MD5_HASH_HEX   = 33,    /* 32 hex chars + NUL */
    TUI_MD5_BUF_LARGE  = 8192
};

/* ----------------------------------------------------------------------
 * Helper functions
 * ---------------------------------------------------------------------- */

static bool
tui_prompt_path(struct opus_app *app,
                const char *title,
                char *out_path,
                size_t out_size)
{
    if (!out_path || out_size == 0) {
        return false;
    }
    out_path[0] = '\0';
    /* opus_tui_prompt_string returns non-zero on success, 0 on cancel */
    return opus_tui_prompt_string(app, title, out_path, out_size) != 0;
}

static void
tui_show_info(struct opus_app *app,
              const char *title,
              const char *message)
{
    opus_tui_show_message(app, title, message, 0);
}

/* Compute MD5 of a file into out_hex (size >= 33). */
static bool
tui_md5_file(const char *path,
             char out_hex[TUI_MD5_HASH_HEX])
{
    return opus_md5_file(path, out_hex);
}

/* ----------------------------------------------------------------------
 * MD5 operations
 * ---------------------------------------------------------------------- */

static int
opus_tui_md5_compute_file(struct opus_app *app)
{
    char path[TUI_MD5_PATH_MAX];
    char hash[TUI_MD5_HASH_HEX];
    char buf[TUI_MD5_BUF_LARGE];

    if (!tui_prompt_path(app, "MD5: Compute file hash", path, sizeof(path))) {
        return 0; /* user cancelled */
    }

    if (!tui_md5_file(path, hash)) {
        (void)snprintf(buf, sizeof(buf),
                       "Failed to compute MD5 for:\n%.*s",
                       4000, path);
        tui_show_info(app, "MD5 ERROR", buf);
        return -1;
    }

    (void)snprintf(buf, sizeof(buf),
                   "File: %.*s\nMD5:  %s",
                   4000, path,
                   hash);
    tui_show_info(app, "MD5 RESULT", buf);
    return 0;
}

static int
opus_tui_md5_verify_file(struct opus_app *app)
{
    char path[TUI_MD5_PATH_MAX];
    char expected[TUI_MD5_HASH_HEX];
    char computed[TUI_MD5_HASH_HEX];
    char buf[TUI_MD5_BUF_LARGE];
    bool match = false;

    if (!tui_prompt_path(app, "MD5: File to verify", path, sizeof(path))) {
        return 0;
    }

    if (!opus_tui_prompt_string(app,
                                "MD5: Expected hash (32 hex chars)",
                                expected,
                                sizeof(expected))) {
        return 0;
    }

    if (!tui_md5_file(path, computed)) {
        (void)snprintf(buf, sizeof(buf),
                       "Failed to compute MD5 for:\n%.*s",
                       4000, path);
        tui_show_info(app, "MD5 ERROR", buf);
        return -1;
    }

    match = (strncmp(expected, computed, 32) == 0);

    if (match) {
        (void)snprintf(buf, sizeof(buf),
                       "MD5 VERIFIED\n\n"
                       "File:     %.*s\n"
                       "Expected: %s\n"
                       "Computed: %s",
                       4000, path,
                       expected,
                       computed);
        tui_show_info(app, "MD5 VERIFIED", buf);
    } else {
        (void)snprintf(buf, sizeof(buf),
                       "MD5 MISMATCH\n\n"
                       "File:     %.*s\n"
                       "Expected: %s\n"
                       "Computed: %s",
                       4000, path,
                       expected,
                       computed);
        tui_show_info(app, "MD5 MISMATCH", buf);
    }

    return match ? 0 : 1;
}

static int
opus_tui_md5_compare_two_files(struct opus_app *app)
{
    char path1[TUI_MD5_PATH_MAX];
    char path2[TUI_MD5_PATH_MAX];
    char hash1[TUI_MD5_HASH_HEX];
    char hash2[TUI_MD5_HASH_HEX];
    char buf[TUI_MD5_BUF_LARGE];
    bool ok1, ok2, match;

    if (!tui_prompt_path(app, "MD5: First file", path1, sizeof(path1))) {
        return 0;
    }
    if (!tui_prompt_path(app, "MD5: Second file", path2, sizeof(path2))) {
        return 0;
    }

    ok1 = tui_md5_file(path1, hash1);
    ok2 = tui_md5_file(path2, hash2);

    if (!ok1 || !ok2) {
        (void)snprintf(buf, sizeof(buf),
                       "Failed to compute MD5 for one or both files:\n"
                       "File A: %.*s\n"
                       "File B: %.*s",
                       2000, path1,
                       2000, path2);
        tui_show_info(app, "MD5 ERROR", buf);
        return -1;
    }

    match = (strncmp(hash1, hash2, 32) == 0);

    (void)snprintf(buf, sizeof(buf),
                   "File A: %.*s\n"
                   "MD5 A : %s\n\n"
                   "File B: %.*s\n"
                   "MD5 B : %s\n\n"
                   "Result: %s",
                   2000, path1, hash1,
                   2000, path2, hash2,
                   match ? "MATCH" : "DIFFERENT");
    tui_show_info(app, "MD5 COMPARE", buf);

    return match ? 0 : 1;
}

/* Compute MD5 of an input string by writing to a temporary file.
 * This avoids depending on extra MD5 APIs beyond opus_md5_file().
 */
int opus_tui_md5_from_string(struct opus_app *app)
{
    char input[TUI_MD5_PATH_MAX];
    char hash[TUI_MD5_HASH_HEX];
    char buf[TUI_MD5_BUF_LARGE];
    char tmp_path[] = "/tmp/opus_md5_XXXXXX";

    if (!opus_tui_prompt_string(app,
                                "MD5: Input string",
                                input,
                                sizeof(input))) {
        return 0;
    }

    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1) {
        tui_show_info(app, "MD5 ERROR", "Failed to create temporary file.");
        return -1;
    }

    FILE *fp = fdopen(tmp_fd, "wb");
    if (!fp) {
        close(tmp_fd);
        remove(tmp_path);
        tui_show_info(app, "MD5 ERROR", "Failed to open temporary file.");
        return -1;
    }

    size_t len = strlen(input);
    if (fwrite(input, 1, len, fp) != len) {
        fclose(fp);
        remove(tmp_path);
        tui_show_info(app, "MD5 ERROR", "Failed to write temporary file.");
        return -1;
    }

    fclose(fp);

    if (!tui_md5_file(tmp_path, hash)) {
        remove(tmp_path);
        tui_show_info(app, "MD5 ERROR", "Failed to compute MD5 from string.");
        return -1;
    }

    remove(tmp_path);

    (void)snprintf(buf, sizeof(buf),
                   "Input: %.*s\n\nMD5:   %s",
                   2000, input,
                   hash);
    tui_show_info(app, "MD5 STRING", buf);
    return 0;
}

/* Verify using .md5 sidecar:
 * - Read first line of sidecar as expected hash
 * - Compute MD5 of main file
 * - Compare
 */
static int
opus_tui_md5_sidecar_verify(struct opus_app *app)
{
    char path[TUI_MD5_PATH_MAX];
    char sidecar[TUI_MD5_PATH_MAX];
    char expected[TUI_MD5_HASH_HEX];
    char computed[TUI_MD5_HASH_HEX];
    char buf[TUI_MD5_BUF_LARGE];
    bool match = false;

    if (!tui_prompt_path(app, "MD5: File (with .md5 sidecar)", path, sizeof(path))) {
        return 0;
    }

    /* Build sidecar path safely: base + ".md5" */
    (void)snprintf(sidecar, sizeof(sidecar),
                   "%.*s.md5",
                   (int)(sizeof(sidecar) - 6), /* leave room for ".md5" + NUL */
                   path);

    FILE *fp = fopen(sidecar, "r");
    if (!fp) {
        (void)snprintf(buf, sizeof(buf),
                       "Could not open sidecar MD5 file:\n%.*s",
                       4000, sidecar);
        tui_show_info(app, "MD5 ERROR", buf);
        return -1;
    }

    if (!fgets(expected, sizeof(expected), fp)) {
        fclose(fp);
        tui_show_info(app, "MD5 ERROR", "Failed to read sidecar MD5 file.");
        return -1;
    }
    fclose(fp);

    /* Strip trailing newline, if any */
    expected[strcspn(expected, "\r\n")] = '\0';

    if (!tui_md5_file(path, computed)) {
        (void)snprintf(buf, sizeof(buf),
                       "Failed to compute MD5 for:\n%.*s",
                       4000, path);
        tui_show_info(app, "MD5 ERROR", buf);
        return -1;
    }

    match = (strncmp(expected, computed, 32) == 0);

    if (match) {
        (void)snprintf(buf, sizeof(buf),
                       "MD5 VERIFIED (SIDECAR)\n\n"
                       "File:     %.*s\n"
                       "Sidecar:  %.*s\n"
                       "Expected: %s\n"
                       "Computed: %s",
                       2000, path,
                       2000, sidecar,
                       expected,
                       computed);
        tui_show_info(app, "MD5 VERIFIED", buf);
    } else {
        (void)snprintf(buf, sizeof(buf),
                       "MD5 MISMATCH (SIDECAR)\n\n"
                       "File:     %.*s\n"
                       "Sidecar:  %.*s\n"
                       "Expected: %s\n"
                       "Computed: %s",
                       2000, path,
                       2000, sidecar,
                       expected,
                       computed);
        tui_show_info(app, "MD5 MISMATCH", buf);
    }

    return match ? 0 : 1;
}

/* ----------------------------------------------------------------------
 * MD5 menu
 * ---------------------------------------------------------------------- */

int
opus_tui_md5_menu(struct opus_app *app)
{
    int choice = 0;
    bool running = true;

    while (running) {
        opus_tui_clear_screen(app);
        opus_tui_draw_centered_box(app, 60, 11, "MD5 TOOLS");

        opus_tui_draw_text_line(app, 0, 3,  "  1. Compute MD5 of a File");
        opus_tui_draw_text_line(app, 0, 4,  "  2. Verify File Against MD5");
        opus_tui_draw_text_line(app, 0, 5,  "  3. Compare Two Files by MD5");
        opus_tui_draw_text_line(app, 0, 6,  "  4. Compute MD5 from String");
        opus_tui_draw_text_line(app, 0, 7,  "  5. Verify File Using .md5 Sidecar");
        opus_tui_draw_text_line(app, 0, 8,  "  6. Return to Previous Menu");

        opus_tui_refresh(app);

        choice = opus_tui_get_menu_choice(app, 1, 6);
        if (choice <= 0) {
            break; /* user cancelled */
        }

        switch (choice) {
        case 1:
            (void)opus_tui_md5_compute_file(app);
            break;
        case 2:
            (void)opus_tui_md5_verify_file(app);
            break;
        case 3:
            (void)opus_tui_md5_compare_two_files(app);
            break;
        case 4:
            (void)opus_tui_md5_from_string(app);
            break;
        case 5:
            (void)opus_tui_md5_sidecar_verify(app);
            break;
        case 6:
        default:
            running = false;
            break;
        }
    }

    return 0;
}

