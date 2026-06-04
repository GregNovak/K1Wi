#ifndef OPUS_TUI_MD5_H
#define OPUS_TUI_MD5_H
#include "tui_md5.h"

struct opus_app;  /* Forward declare your main app/context type */

/*
 * Open the MD5 tools submenu.
 * Optionally, a preselected file path may be passed (e.g., from file browser).
 * If selected_path is NULL, the menu will prompt for paths as needed.
 */
void opus_tui_md5_menu(struct opus_app *app, const char *selected_path);
void opus_tui_md5_quick_verify(struct opus_app *app, const char *path);

#endif /* OPUS_TUI_MD5_H */

