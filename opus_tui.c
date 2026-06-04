#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <ncurses.h>
#include <panel.h>

#include "opus_tui.h"
#include "tui_md5.h"
#include "solve.h"
#include "state.h"

/* ============================================================
 *  VIEW MODES
 * ============================================================ */

typedef enum {
    VIEW_MODE_AUTO = 0,  /* decide from is_text */
    VIEW_MODE_TEXT,
    VIEW_MODE_HEX
} view_mode_t;

typedef enum {
    PANEL_MENU = 0,
    PANEL_FILE,
    PANEL_VIGAN,
    PANEL_VIGSOLVE,
    PANEL_VIGREFINE,
    PANEL_VIGAUTO,
    PANEL_VIEW_PLAINTEXT,
    PANEL_SETTINGS,
    PANEL_COUNT
} panel_t;

/* --------- File Browser State --------- */
#define MAX_FILES 1024

typedef struct {
    char  *file_list[MAX_FILES];
    int    file_count;
    int    selected;
    int    scroll;
} file_browser_t;

/* --------- Text / Hex Preview State --------- */
typedef struct {
    char   *buf;
    size_t  len;
    int     scroll;
    bool    is_text;
    view_mode_t mode;
} preview_t;

/* --------- VIGAN Results State --------- */
typedef struct {
    char   *output;
    size_t  len;
    int     scroll;
} vigan_view_t;

/* --------- Main App State --------- */
typedef struct {
    panel_t        current_panel;
    int            menu_selected;

    char           status_text[128];
    char           last_action[4096];

    file_browser_t fb;
    preview_t      preview;
    vigan_view_t   vigan;

    char           cwd[1024];
} app_state_t;

static app_state_t g_app;

/* ============================================================
 *  COLOR DEFINITIONS
 * ============================================================ */

enum {
    CP_DEFAULT = 1,
    CP_BANNER,
    CP_MENUBAR,
    CP_MENU_ACTIVE,
    CP_STATUS,
    CP_BORDER,
    CP_ERROR,
    CP_SUCCESS
};

/* ============================================================
 *  FORWARD DECLARATIONS
 * ============================================================ */

static void init_app(app_state_t *app);
static void cleanup_app(app_state_t *app);

static void init_ui(void);
static void shutdown_ui(void);
static void init_colors(void);

static void draw_banner(const app_state_t *app);
static void draw_menu_bar(const app_state_t *app);
static void draw_status_bar(const app_state_t *app);
static void draw_panel(const app_state_t *app);

static void draw_panel_menu(const app_state_t *app, int top, int bottom);
static void draw_panel_file(const app_state_t *app, int top, int bottom);
static void draw_panel_vigan(const app_state_t *app, int top, int bottom);
static void draw_panel_vigsolve(const app_state_t *app, int top, int bottom);
static void draw_panel_vigrefine(const app_state_t *app, int top, int bottom);
static void draw_panel_vigauto(const app_state_t *app, int top, int bottom);
static void draw_panel_view_plaintext(const app_state_t *app, int top, int bottom);
static void draw_panel_settings(const app_state_t *app, int top, int bottom);

static void handle_global_key(app_state_t *app, int ch, bool *running);
static void handle_file_panel_key(app_state_t *app, int ch);
static void handle_vigan_panel_key(app_state_t *app, int ch);
static void handle_view_plaintext_key(app_state_t *app, int ch);

static void set_panel(app_state_t *app, panel_t p, const char *action);
static panel_t menu_selected_to_panel(int idx);

/* VIGAN mock hook */
static bool run_vigan_analysis(app_state_t *app, const char *filename);

/* ============================================================
 *  UI UTILITIES
 * ============================================================ */

static void draw_centered(WINDOW *win, int y, const char *s, int attr) {
    int maxy, maxx;
    getmaxyx(win, maxy, maxx);
    (void)maxy;

    int len = (int)strlen(s);
    int x = (maxx - len) / 2;
    if (x < 0) x = 0;

    wattron(win, attr);
    mvwprintw(win, y, x, "%s", s);
    wattroff(win, attr);
}

/* --- File preview loader --- */
static bool load_file_preview(preview_t *pv, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return false;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return false;
    }

    long size = ftell(fp);
    if (size <= 0) {
        fclose(fp);
        return false;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }

    pv->buf = malloc((size_t)size);
    if (!pv->buf) {
        fclose(fp);
        return false;
    }

    size_t nread = fread(pv->buf, 1, (size_t)size, fp);
    (void)nread; /* we trust the OS here, but we could check */
    fclose(fp);

    pv->len = (size_t)size;
    pv->scroll = 0;

    /* Text detection: >90% printable or whitespace = text mode */
    int printable = 0;
    for (long i = 0; i < size; i++) {
        unsigned char c = (unsigned char)pv->buf[i];
        if ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t')
            printable++;
    }

    pv->is_text = ((float)printable / (float)size) > 0.90f;
    pv->mode = VIEW_MODE_AUTO;

    return true;
}

/* --- Directory sorting helper --- */
static int file_sorter(const void *a, const void *b) {
    const char *fa = *(const char * const *)a;
    const char *fb = *(const char * const *)b;

    /* ".." always first */
    if (strcmp(fa, "..") == 0 && strcmp(fb, "..") != 0) return -1;
    if (strcmp(fb, "..") == 0 && strcmp(fa, "..") != 0) return 1;

    bool a_dir = (fa[strlen(fa) - 1] == '/');
    bool b_dir = (fb[strlen(fb) - 1] == '/');

    if (a_dir && !b_dir) return -1;
    if (!a_dir && b_dir) return 1;

    return strcasecmp(fa, fb);
}

/* --- Directory loader with dirs + files + ".." --- */
static void load_directory_files(file_browser_t *fb, const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        fb->file_count = 0;
        return;
    }

    struct dirent *ent;
    fb->file_count = 0;

    /* Always include parent directory */
    fb->file_list[fb->file_count++] = strdup("..");

    while ((ent = readdir(dir)) != NULL) {
        if (fb->file_count >= MAX_FILES)
            break;

        /* Skip "." */
        if (strcmp(ent->d_name, ".") == 0)
            continue;

        /* Directories */
        if (ent->d_type == DT_DIR) {
            char *name = malloc(strlen(ent->d_name) + 2);
            if (!name)
                continue;
            sprintf(name, "%s/", ent->d_name);
            fb->file_list[fb->file_count++] = name;
            continue;
        }

        /* Regular files */
        if (ent->d_type == DT_REG) {
            fb->file_list[fb->file_count++] = strdup(ent->d_name);
        }
    }

    closedir(dir);

    if (fb->file_count > 1) {
        qsort(fb->file_list, (size_t)fb->file_count, sizeof(char *), file_sorter);
    }

    fb->selected = 0;
    fb->scroll = 0;
}

/* ============================================================
 *  APP INIT / CLEANUP
 * ============================================================ */

static void init_app(app_state_t *app) {
    memset(app, 0, sizeof(*app));

    if (!getcwd(app->cwd, sizeof(app->cwd))) {
        strncpy(app->cwd, ".", sizeof(app->cwd) - 1);
        app->cwd[sizeof(app->cwd) - 1] = '\0';
    }

    app->current_panel = PANEL_MENU;
    app->menu_selected = 0;

    strncpy(app->status_text, "Idle", sizeof(app->status_text) - 1);
    app->status_text[sizeof(app->status_text) - 1] = '\0';
    strncpy(app->last_action, "Startup", sizeof(app->last_action) - 1);
    app->last_action[sizeof(app->last_action) - 1] = '\0';

    load_directory_files(&app->fb, app->cwd);

    app->preview.buf     = NULL;
    app->preview.len     = 0;
    app->preview.scroll  = 0;
    app->preview.is_text = true;
    app->preview.mode    = VIEW_MODE_AUTO;

    app->vigan.output = NULL;
    app->vigan.len = 0;
    app->vigan.scroll = 0;
}

static void cleanup_app(app_state_t *app) {
    for (int i = 0; i < app->fb.file_count; i++) {
        free(app->fb.file_list[i]);
        app->fb.file_list[i] = NULL;
    }

    free(app->preview.buf);
    app->preview.buf = NULL;
    app->preview.len = 0;

    free(app->vigan.output);
    app->vigan.output = NULL;
    app->vigan.len = 0;
}

/* ============================================================
 *  PANEL + MENU MANAGEMENT
 * ============================================================ */

static const char *menu_items[] = {
    "Menu",
    "File",
    "Analyze",
    "Crypto",
    "Tools",
    "Settings"
};
static const int menu_count = sizeof(menu_items) / sizeof(menu_items[0]);

static panel_t menu_selected_to_panel(int idx) {
    switch (idx) {
        case 0: return PANEL_MENU;
        case 1: return PANEL_FILE;
        case 2: return PANEL_VIGAN;
        case 3: return PANEL_VIGSOLVE;
        case 4: return PANEL_VIGAUTO;
        case 5: return PANEL_SETTINGS;
        default: return PANEL_MENU;
    }
}

static void set_panel(app_state_t *app, panel_t p, const char *action) {
    app->current_panel = p;

    switch (p) {
        case PANEL_MENU:           app->menu_selected = 0; break;
        case PANEL_FILE:           app->menu_selected = 1; break;
        case PANEL_VIGAN:          app->menu_selected = 2; break;
        case PANEL_VIGSOLVE:       app->menu_selected = 3; break;
        case PANEL_VIGREFINE:      app->menu_selected = 3; break;
        case PANEL_VIGAUTO:        app->menu_selected = 4; break;
        case PANEL_VIEW_PLAINTEXT: app->menu_selected = 2; break;
        case PANEL_SETTINGS:       app->menu_selected = 5; break;
        case PANEL_COUNT:          break;
    }

    if (action) {
        strncpy(app->last_action, action, sizeof(app->last_action) - 1);
        app->last_action[sizeof(app->last_action) - 1] = '\0';
    }

    strncpy(app->status_text, "OK", sizeof(app->status_text) - 1);
    app->status_text[sizeof(app->status_text) - 1] = '\0';
}

/* ============================================================
 *  DRAWING: BANNER, MENU, STATUS, PANELS
 * ============================================================ */

static void init_colors(void) {
    start_color();
    use_default_colors();

    init_pair(CP_DEFAULT,      COLOR_WHITE,  -1);
    init_pair(CP_BANNER,       COLOR_CYAN,   -1);
    init_pair(CP_MENUBAR,      COLOR_WHITE,  COLOR_BLUE);
    init_pair(CP_MENU_ACTIVE,  COLOR_BLACK,  COLOR_YELLOW);
    init_pair(CP_STATUS,       COLOR_BLACK,  COLOR_GREEN);
    init_pair(CP_BORDER,       COLOR_WHITE,  -1);
    init_pair(CP_ERROR,        COLOR_RED,    -1);
    init_pair(CP_SUCCESS,      COLOR_GREEN,  -1);
}

static void init_ui(void) {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        init_colors();
    }
}

static void shutdown_ui(void) {
    endwin();
}

static void draw_banner(const app_state_t *app) {
    (void)app;
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);
    (void)maxy;

    attron(COLOR_PAIR(CP_BANNER) | A_BOLD);
    mvhline(0, 0, ' ', maxx);
    draw_centered(stdscr, 0, "OPUS Forensic & Cryptanalysis Suite",
                  COLOR_PAIR(CP_BANNER) | A_BOLD);
    attroff(COLOR_PAIR(CP_BANNER) | A_BOLD);
}

static void draw_menu_bar(const app_state_t *app) {
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);
    (void)maxy;

    attron(COLOR_PAIR(CP_MENUBAR));
    mvhline(1, 0, ' ', maxx);

    int x = 1;
    for (int i = 0; i < menu_count; i++) {
        const char *label = menu_items[i];

        if (i == app->menu_selected) {
            attron(COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD);
            mvprintw(1, x, "[%s]", label);
            attroff(COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD);
        } else {
            mvprintw(1, x, " %s ", label);
        }

        x += (int)strlen(label) + 3;
    }

    attroff(COLOR_PAIR(CP_MENUBAR));
}

static void draw_status_bar(const app_state_t *app) {
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    attron(COLOR_PAIR(CP_STATUS));
    mvhline(maxy - 1, 0, ' ', maxx);
    mvprintw(maxy - 1, 1, "Status: %s | Last Action: %s",
             app->status_text, app->last_action);
    attroff(COLOR_PAIR(CP_STATUS));
}

static void draw_panel(const app_state_t *app) {
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    int top = 2;
    int bottom = maxy - 1;

    for (int y = top; y < bottom; y++) {
        move(y, 0);
        clrtoeol();
    }

    attron(COLOR_PAIR(CP_BORDER));
    mvhline(top, 0, '-', maxx);
    mvhline(bottom - 1, 0, '-', maxx);
    attroff(COLOR_PAIR(CP_BORDER));

    switch (app->current_panel) {
        case PANEL_MENU:
            draw_panel_menu(app, top, bottom);
            break;
        case PANEL_FILE:
            draw_panel_file(app, top, bottom);
            break;
        case PANEL_VIGAN:
            draw_panel_vigan(app, top, bottom);
            break;
        case PANEL_VIGSOLVE:
            draw_panel_vigsolve(app, top, bottom);
            break;
        case PANEL_VIGREFINE:
            draw_panel_vigrefine(app, top, bottom);
            break;
        case PANEL_VIGAUTO:
            draw_panel_vigauto(app, top, bottom);
            break;
        case PANEL_VIEW_PLAINTEXT:
            draw_panel_view_plaintext(app, top, bottom);
            break;
        case PANEL_SETTINGS:
            draw_panel_settings(app, top, bottom);
            break;
        case PANEL_COUNT:
            break;
    }
}

/* ============================================================
 *  PANEL IMPLEMENTATIONS
 * ============================================================ */

static void draw_panel_menu(const app_state_t *app, int top, int bottom) {
    (void)app;
    int height = bottom - top;
    int center_y = top + height / 2;

    draw_centered(stdscr, center_y - 1,
                  "Main Menu",
                  A_BOLD | COLOR_PAIR(CP_DEFAULT));
    draw_centered(stdscr, center_y + 1,
                  "Use F1–F6 or arrow keys to switch panels. Q to quit.",
                  COLOR_PAIR(CP_DEFAULT));
}

static void draw_panel_file(const app_state_t *app, int top, int bottom) {
    const file_browser_t *fb = &app->fb;

    int y = top + 1;
    int available = (bottom - 1) - y;

    int dirs = 0, files = 0;
    for (int i = 0; i < fb->file_count; i++) {
        const char *n = fb->file_list[i];
        if (strcmp(n, "..") == 0) continue;
        if (n[strlen(n) - 1] == '/') dirs++;
        else files++;
    }

    mvprintw(top, 2, "[File Browser] %s  (%d dirs, %d files)",
             g_app.cwd, dirs, files);

    if (fb->file_count == 0) {
        draw_centered(stdscr, (top + bottom) / 2,
                      "No entries.",
                      COLOR_PAIR(CP_DEFAULT) | A_BOLD);
        return;
    }

    for (int i = 0; i < available; i++) {
        int idx = fb->scroll + i;
        if (idx >= fb->file_count)
            break;

        const char *name = fb->file_list[idx];
        bool is_dir = (name[strlen(name) - 1] == '/');

        if (idx == fb->selected)
            attron(A_REVERSE);
        if (is_dir)
            attron(A_BOLD);

        mvprintw(y + i, 4, "%s", name);

        if (is_dir)
            attroff(A_BOLD);
        if (idx == fb->selected)
            attroff(A_REVERSE);
    }

    mvprintw(bottom - 1, 2,
             "[UP/DOWN] Move  [ENTER] Open/Preview  [A] Analyze (VIGAN)  [Q] Back");
}

static void draw_panel_vigan(const app_state_t *app, int top, int bottom) {
    const vigan_view_t *vv = &app->vigan;
    mvprintw(top, 2, "[VIGAN Analysis Results]");

    int y = top + 1;
    int visible = (bottom - 1) - y;

    if (!vv->output || vv->len == 0) {
        draw_centered(stdscr, (top + bottom) / 2,
                      "No VIGAN output. Run from File panel with 'A'.",
                      COLOR_PAIR(CP_DEFAULT) | A_BOLD);
        return;
    }

    int line = 0;
    int printed = 0;

    for (size_t i = 0; i < vv->len && printed < visible; i++) {
        if (line >= vv->scroll) {
            mvprintw(y + printed, 2, "%c", vv->output[i]);
            if (vv->output[i] == '\n')
                printed++;
        } else {
            if (vv->output[i] == '\n')
                line++;
        }
    }

    mvprintw(bottom - 1, 2, "[UP/DOWN] Scroll  [Q] Back to File");
}

static void draw_panel_vigsolve(const app_state_t *app, int top, int bottom) {
    (void)app;
    int height = bottom - top;
    int center_y = top + height / 2;

    draw_centered(stdscr, center_y - 1,
                  "Vigenere Solver (VIGSOLVE)",
                  A_BOLD | COLOR_PAIR(CP_DEFAULT));
    draw_centered(stdscr, center_y + 1,
                  "Placeholder: integrate solver results here.",
                  COLOR_PAIR(CP_DEFAULT));
}

static void draw_panel_vigrefine(const app_state_t *app, int top, int bottom) {
    (void)app;
    int height = bottom - top;
    int center_y = top + height / 2;

    draw_centered(stdscr, center_y - 1,
                  "Vigenere Refinement (VIGREFINE)",
                  A_BOLD | COLOR_PAIR(CP_DEFAULT));
    draw_centered(stdscr, center_y + 1,
                  "Placeholder: iterative refinement UI goes here.",
                  COLOR_PAIR(CP_DEFAULT));
}

static void draw_panel_vigauto(const app_state_t *app, int top, int bottom) {
    (void)app;
    int height = bottom - top;
    int center_y = top + height / 2;

    draw_centered(stdscr, center_y - 1,
                  "Vigenere Auto-Crack (VIGAUTO / VIGCRACK)",
                  A_BOLD | COLOR_PAIR(CP_DEFAULT));
    draw_centered(stdscr, center_y + 1,
                  "Placeholder: auto-crack status & results.",
                  COLOR_PAIR(CP_DEFAULT));
}

static void draw_panel_view_plaintext(const app_state_t *app, int top, int bottom) {
    const preview_t *pv = &app->preview;

    mvprintw(top, 2, "[Plaintext / Preview]");

    int y = top + 1;
    int visible = (bottom - 1) - y;

    if (!pv->buf || pv->len == 0) {
        draw_centered(stdscr, (top + bottom) / 2,
                      "No preview loaded.",
                      COLOR_PAIR(CP_DEFAULT) | A_BOLD);
        return;
    }

    bool show_text;
    if (pv->mode == VIEW_MODE_TEXT)
        show_text = true;
    else if (pv->mode == VIEW_MODE_HEX)
        show_text = false;
    else
        show_text = pv->is_text;

    if (show_text) {
        int line = 0;
        int printed = 0;
        size_t start = 0;

        for (size_t i = 0; i <= pv->len; i++) {
            bool end_of_line = (i == pv->len || pv->buf[i] == '\n');

            if (end_of_line) {
                if (line >= pv->scroll && printed < visible) {
                    mvprintw(y + printed, 2, "%04d  %.*s",
                             line + 1,
                             (int)(i - start),
                             pv->buf + start);
                    printed++;
                }
                line++;
                start = i + 1;
            }
        }
    } else {
        size_t bytes_per_line = 16;
	size_t total_lines = (pv->len + bytes_per_line - 1) / bytes_per_line;

        for (int i = 0; i < visible; i++) {
            int line = pv->scroll + i;
	    if (line < 0 || (size_t)line >= total_lines)
                break;

            size_t offset = (size_t)line * (size_t)bytes_per_line;
            size_t remaining = pv->len - offset;
            int line_bytes = (remaining < (size_t)bytes_per_line)
                           ? (int)remaining
                           : (int)bytes_per_line;

            mvprintw(y + i, 2, "%08zx  ", offset);

            int col = 2 + 10;
            move(y + i, col);

           for (int b = 0; b < line_bytes; b++) {
                if (b < line_bytes) {
                    unsigned char c = (unsigned char)pv->buf[offset + (size_t)b];
                    printw("%02x ", c);
                } else {
                    printw("   ");
                }
            }

            col += 3 * bytes_per_line + 2;
            mvprintw(y + i, col, "|");

            for (int b = 0; b < line_bytes; b++) {
                unsigned char c = (unsigned char)pv->buf[offset + (size_t)b];
                char out = (c >= 32 && c <= 126) ? (char)c : '.';

                if (c >= 32 && c <= 126) {
                    attron(A_BOLD);
                    mvaddch(y + i, col + 1 + b, out);
                    attroff(A_BOLD);
                } else {
                    attron(A_DIM);
                    mvaddch(y + i, col + 1 + b, out);
                    attroff(A_DIM);
                }
            }

            mvaddch(y + i, col + 1 + line_bytes, '|');
        }
    }

    mvprintw(bottom - 1, 2,
             "[UP/DOWN] Scroll  [PgUp/PgDn] Page  [T]ext  [H]ex  [A]uto  [Q] Back");
}

static void draw_panel_settings(const app_state_t *app, int top, int bottom) {
    (void)app;
    int height = bottom - top;
    int center_y = top + height / 2;

    draw_centered(stdscr, center_y - 1,
                  "Settings",
                  A_BOLD | COLOR_PAIR(CP_DEFAULT));
    draw_centered(stdscr, center_y + 1,
                  "Future: color themes, iterations, paths, etc.",
                  COLOR_PAIR(CP_DEFAULT));
}

/* ============================================================
 *  INPUT HANDLING
 * ============================================================ */

static void handle_file_panel_key(app_state_t *app, int ch) {
    file_browser_t *fb = &app->fb;
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);
    (void)maxx;

    int top = 2;
    int bottom = maxy - 1;
    int y = top + 1;
    int available = (bottom - 1) - y;

    switch (ch) {
        case KEY_UP:
            if (fb->selected > 0) {
                fb->selected--;
                if (fb->selected < fb->scroll)
                    fb->scroll--;
            }
            break;

        case KEY_DOWN:
            if (fb->selected < fb->file_count - 1) {
                fb->selected++;
                if (fb->selected >= fb->scroll + available)
                    fb->scroll++;
            }
            break;
	case 'm':
	case 'M': {
	    if (fb->file_count == 0)
		break;

	    const char *name = fb->file_list[fb->selected];
	    if (name[strlen(name) - 1] == '/')
		break;

	    char fullpath[4096];
	    snprintf(fullpath, sizeof(fullpath), "%s/%s", app->cwd, name);

	    opus_tui_md5_menu((struct opus_app *)app, fullpath);
	    break;
	}

	case 'v':
	case 'V': {
	    if (fb->file_count == 0)
		break;

	    const char *name = fb->file_list[fb->selected];
	    if (name[strlen(name) - 1] == '/')
		break;

	    char fullpath[4096];
	    snprintf(fullpath, sizeof(fullpath), "%s/%s", app->cwd, name);

	   // opus_tui_md5_quick_verify((struct opus_app *)app, fullpath);
	    break;
	}

        case 10: { /* Enter */
            if (fb->file_count == 0)
                return;

            const char *name = fb->file_list[fb->selected];

            if (strcmp(name, "..") == 0) {
                if (chdir("..") == 0) {
                    if (!getcwd(app->cwd, sizeof(app->cwd))) {
                        strncpy(app->cwd, ".", sizeof(app->cwd) - 1);
                        app->cwd[sizeof(app->cwd) - 1] = '\0';
                    }
                    for (int i = 0; i < fb->file_count; i++)
                        free(fb->file_list[i]);
                    load_directory_files(fb, app->cwd);
                    snprintf(app->last_action, sizeof(app->last_action),
                             "Up to: %s", app->cwd);
                }
                return;
            }

            if (name[strlen(name) - 1] == '/') {
                char newpath[4096];
                snprintf(newpath, sizeof(newpath), "%s/%s", app->cwd, name);
                newpath[strlen(newpath) - 1] = '\0';

                if (chdir(newpath) == 0) {
                    if (!getcwd(app->cwd, sizeof(app->cwd))) {
                        strncpy(app->cwd, ".", sizeof(app->cwd) - 1);
                        app->cwd[sizeof(app->cwd) - 1] = '\0';
                    }
                    for (int i = 0; i < fb->file_count; i++)
                        free(fb->file_list[i]);
                    load_directory_files(fb, app->cwd);
                    snprintf(app->last_action, sizeof(app->last_action),
                             "Entered: %s", app->cwd);
                }
                return;
            }

            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", app->cwd, name);

            free(app->preview.buf);
            app->preview.buf     = NULL;
            app->preview.len     = 0;
            app->preview.scroll  = 0;
            app->preview.is_text = true;
            app->preview.mode    = VIEW_MODE_AUTO;

            if (load_file_preview(&app->preview, fullpath)) {
                snprintf(app->last_action, sizeof(app->last_action),
                         "Preview: %s", name);
                strncpy(app->status_text, "Loaded preview", sizeof(app->status_text) - 1);
                app->status_text[sizeof(app->status_text) - 1] = '\0';
                set_panel(app, PANEL_VIEW_PLAINTEXT, "Preview file");
            } else {
                snprintf(app->last_action, sizeof(app->last_action),
                         "Failed preview: %s", name);
                strncpy(app->status_text, "Preview failed", sizeof(app->status_text) - 1);
                app->status_text[sizeof(app->status_text) - 1] = '\0';
            }
            return;
        }

        case 'a':
        case 'A': {
            if (fb->file_count == 0)
                break;

            const char *name = fb->file_list[fb->selected];
            if (name[strlen(name) - 1] == '/')
                break;

            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", app->cwd, name);

            snprintf(app->last_action, sizeof(app->last_action),
                     "Run VIGAN on: %s", name);
            strncpy(app->status_text, "Running VIGAN...", sizeof(app->status_text) - 1);
            app->status_text[sizeof(app->status_text) - 1] = '\0';

            if (run_vigan_analysis(app, fullpath)) {
                set_panel(app, PANEL_VIGAN, "VIGAN results");
                strncpy(app->status_text, "VIGAN completed", sizeof(app->status_text) - 1);
                app->status_text[sizeof(app->status_text) - 1] = '\0';
            } else {
                strncpy(app->status_text, "VIGAN failed", sizeof(app->status_text) - 1);
                app->status_text[sizeof(app->status_text) - 1] = '\0';
            }
            break;
        }

        case 'q':
        case 'Q':
            set_panel(app, PANEL_MENU, "Back to menu");
            break;

        default:
            break;
    }
}

static void handle_vigan_panel_key(app_state_t *app, int ch) {
    vigan_view_t *vv = &app->vigan;

    switch (ch) {
        case KEY_UP:
            if (vv->scroll > 0)
                vv->scroll--;
            break;
        case KEY_DOWN:
            vv->scroll++;
            break;
        case 'q':
        case 'Q':
            set_panel(app, PANEL_FILE, "Back to file browser");
            break;
        default:
            break;
    }
}

static void handle_view_plaintext_key(app_state_t *app, int ch) {
    preview_t *pv = &app->preview;

    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);
    (void)maxx;
    int top = 2;
    int bottom = maxy - 1;
    int y = top + 1;
    int visible = (bottom - 1) - y;

    switch (ch) {
        case KEY_UP:
            if (pv->scroll > 0)
                pv->scroll--;
            break;

        case KEY_DOWN:
            pv->scroll++;
            break;

        case KEY_PPAGE:
            if (pv->scroll > visible)
                pv->scroll -= visible;
            else
                pv->scroll = 0;
            break;

        case KEY_NPAGE:
            pv->scroll += visible;
            break;

        case 't':
        case 'T':
            pv->mode = VIEW_MODE_TEXT;
            strncpy(app->status_text, "Text mode", sizeof(app->status_text) - 1);
            app->status_text[sizeof(app->status_text) - 1] = '\0';
            break;

        case 'h':
        case 'H':
            pv->mode = VIEW_MODE_HEX;
            strncpy(app->status_text, "Hex mode", sizeof(app->status_text) - 1);
            app->status_text[sizeof(app->status_text) - 1] = '\0';
            break;

        case 'a':
        case 'A':
            pv->mode = VIEW_MODE_AUTO;
            strncpy(app->status_text, "Auto mode", sizeof(app->status_text) - 1);
            app->status_text[sizeof(app->status_text) - 1] = '\0';
            break;

        case 'q':
        case 'Q':
            set_panel(app, PANEL_FILE, "Back to file browser");
            break;

        default:
            break;
    }
}

static void handle_global_key(app_state_t *app, int ch, bool *running) {
    switch (app->current_panel) {
        case PANEL_FILE:
            handle_file_panel_key(app, ch);
            break;
        case PANEL_VIGAN:
            handle_vigan_panel_key(app, ch);
            break;
        case PANEL_VIEW_PLAINTEXT:
            handle_view_plaintext_key(app, ch);
            break;
        default:
            break;
    }

    switch (ch) {
        case KEY_F(1):
            set_panel(app, PANEL_MENU, "F1: Menu");
            return;
        case KEY_F(2):
            set_panel(app, PANEL_FILE, "F2: File");
            return;
        case KEY_F(3):
            set_panel(app, PANEL_VIGAN, "F3: Analyze");
            return;
        case KEY_F(4):
            set_panel(app, PANEL_VIGSOLVE, "F4: Crypto");
            return;
        case KEY_F(5):
            set_panel(app, PANEL_VIGAUTO, "F5: Tools/Auto");
            return;
        case KEY_F(6):
            set_panel(app, PANEL_SETTINGS, "F6: Settings");
            return;

        case KEY_LEFT:
            if (app->menu_selected > 0)
                app->menu_selected--;
            else
                app->menu_selected = menu_count - 1;
            set_panel(app, menu_selected_to_panel(app->menu_selected), "Menu switch");
            return;

        case KEY_RIGHT:
            app->menu_selected = (app->menu_selected + 1) % menu_count;
            set_panel(app, menu_selected_to_panel(app->menu_selected), "Menu switch");
            return;

        case 'q':
        case 'Q':
            *running = false;
            return;

        default:
            break;
    }
}

/* ============================================================
 *  MOCK VIGAN ENGINE
 * ============================================================ */

static bool run_vigan_analysis(app_state_t *app, const char *filename) {
    vigan_view_t *vv = &app->vigan;

    free(vv->output);
    vv->output = NULL;
    vv->len = 0;
    vv->scroll = 0;

    char header[1024];
    snprintf(header, sizeof(header),
             "VIGAN Analysis Results (Mock)\n"
             "-----------------------------\n"
             "File: %s\n"
             "\n"
             "Index of Coincidence Table (mock):\n"
             "  k=1:  0.041\n"
             "  k=2:  0.052\n"
             "  k=3:  0.067\n"
             "  k=4:  0.041\n"
             "  k=5:  0.072\n"
             "\n"
             "Likely Key Lengths (mock):\n"
             "  3, 5\n"
             "\n"
             "Harmonic Peaks (mock):\n"
             "  3 → strong\n"
             "  5 → moderate\n"
             "\n"
             "Press Q to return.\n",
             filename);

    vv->len = strlen(header);
    vv->output = malloc(vv->len + 1);
    if (!vv->output) {
        strncpy(app->status_text, "VIGAN: memory error", sizeof(app->status_text) - 1);
        app->status_text[sizeof(app->status_text) - 1] = '\0';
        vv->len = 0;
        return false;
    }

    strcpy(vv->output, header);
    vv->scroll = 0;

    return true;
}

/* ============================================================
 *  MAIN ENTRY POINT
 * ============================================================ */

int opus_tui_main(void) {
    init_app(&g_app);
    init_ui();

    bool running = true;
    set_panel(&g_app, PANEL_MENU, "Startup");

    while (running) {
        erase();
        draw_banner(&g_app);
        draw_menu_bar(&g_app);
        draw_panel(&g_app);
        draw_status_bar(&g_app);
        refresh();

        int ch = getch();
        handle_global_key(&g_app, ch, &running);
    }

    shutdown_ui();
    cleanup_app(&g_app);
    return 0;
}


int opus_tui_prompt_string(struct opus_app *app,
                           const char *title,
                           char *out,
                           size_t out_size)
{
 	(void)app;
	(void)title;
	(void)out;
	(void)out_size;
	
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    int w = 50;
    int h = 5;
    int y = (maxy - h) / 2;
    int x = (maxx - w) / 2;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);

    mvwprintw(win, 1, 2, "%s:", title);
    wmove(win, 2, 2);
    wrefresh(win);

    echo();
    wgetnstr(win, out, (int)(out_size - 1));
    noecho();

    delwin(win);
    return 1;
}
void opus_tui_show_message(struct opus_app *app,
                           const char *title,
                           const char *msg,
                           int type)
{ 

	(void)app;
	(void)title;
	(void)msg;
	(void)type;
	
	
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    int w = 60;
    int h = 7;
    int y = (maxy - h) / 2;
    int x = (maxx - w) / 2;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);

    mvwprintw(win, 1, 2, "%s", title);
    mvwprintw(win, 3, 2, "%s", msg);
    mvwprintw(win, 5, 2, "Press any key...");
    wrefresh(win);

    wgetch(win);
    delwin(win);
}
void opus_tui_clear_screen(struct opus_app *app)
{
	(void)app;
    clear();
}
void opus_tui_draw_centered_box(struct opus_app *app,
                                int w, int h,
                                const char *title)
{

	(void)app;
	(void)w;
	(void)h;
	(void)title;
	
    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    int y = (maxy - h) / 2;
    int x = (maxx - w) / 2;

    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);

	if (title) {
	    int title_x = (w - (int)strlen(title)) / 2;
	    mvwprintw(win, 0, title_x, "%s", title);
	}

    wrefresh(win);
    delwin(win);
}
void opus_tui_draw_text_line(struct opus_app *app,
                             int relx, int rely,
                             const char *text)
{
	(void)app;
	(void)relx;
	(void)rely;
	(void)text;
	

    mvprintw(rely, relx, "%s", text);
}
void opus_tui_refresh(struct opus_app *app)
{

	(void)app;
	
    refresh();
}
int opus_tui_get_menu_choice(struct opus_app *app,
                             int min, int max)
{
	(void)app;
	(void)min;
	(void)max;
	
    int ch = getch();
    if (ch >= '0' + min && ch <= '0' + max)
        return ch - '0';
    return 0;
}

