#ifndef OPUS_TUI_H
#define OPUS_TUI_H

#include <stddef.h>

// Forward declaration of the TUI app struct.
// If you later define a real struct in opus_tui.c, update this.
struct opus_app;

// Core TUI functions used by other modules (like tui_md5.c)
int  opus_tui_prompt_string(struct opus_app *app,
                            const char *title,
                            char *out,
                            size_t out_size);

void opus_tui_show_message(struct opus_app *app,
                           const char *title,
                           const char *message,
                           int type);

void opus_tui_clear_screen(struct opus_app *app);

void opus_tui_draw_centered_box(struct opus_app *app,
                                int width,
                                int height,
                                const char *title);

void opus_tui_draw_text_line(struct opus_app *app,
                             int x,
                             int y,
                             const char *text);

void opus_tui_refresh(struct opus_app *app);

int  opus_tui_get_menu_choice(struct opus_app *app,
                              int min_choice,
                              int max_choice);

#endif

