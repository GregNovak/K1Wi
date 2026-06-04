#ifndef OPUS_CMD_H
#define OPUS_CMD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opus_context opus_context;

/* Command function signature.
 * ctx   – global Opus context (current file, config, etc.)
 * argc  – argument count (at least 1; argv[0] is the command name)
 * argv  – argument vector
 * Return 0 on success, non-zero on error.
 */
typedef int (*opus_cmd_fn)(opus_context *ctx, int argc, char **argv);

typedef struct {
    const char   *name;      /* Canonical name, e.g. "EXTRACT"       */
    const char   *alias;     /* Optional short alias, e.g. "X"       */
    const char   *category;  /* e.g. "Extraction", "Forensics"       */
    const char   *help;      /* One-line description                  */
    opus_cmd_fn   fn;        /* Implementation                        */
} opus_command;

/* Look up a command entry by token (name or alias). */
const opus_command *opus_cmd_find(const char *token);

/* Dispatch a line of input, already tokenized into argv. */
int opus_cmd_dispatch(opus_context *ctx, int argc, char **argv);

/* Access the full static command table and length. */
const opus_command *opus_cmd_table(size_t *out_count);

/* Convenience helpers for HELP / MENU. */
void opus_cmd_print_help(void);
void opus_cmd_print_menu(void);

#ifdef __cplusplus
}
#endif

#endif /* OPUS_CMD_H */

