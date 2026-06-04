#ifndef OPUS_COMMANDS_H
#define OPUS_COMMANDS_H

int cmd_string(int argc, char **argv);

struct OpusCLI;  // forward declaration
int cmd_string_wrapper(const struct OpusCLI *cli, int argc, char **argv);

typedef struct {
    const char *name;
    const char *category;
    const char *description;
    
} opus_cmd_t;


extern const opus_cmd_t opus_commands[];
extern const size_t opus_commands_count;


#endif

