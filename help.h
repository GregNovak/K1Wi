#ifndef OPUS_HELP_H
#define OPUS_HELP_H

typedef struct {
    const char *cmd;
    const char * const *lines;
    size_t line_count;
} help_entry_t;

void opus_help_general(void);
void opus_help_specific(const char *cmd);

#endif

