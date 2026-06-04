#ifndef OPUS_CLI_H
#define OPUS_CLI_H

#include <stdbool.h>

/* -----------------------------------------
   TYPE DEFINITIONS
   ----------------------------------------- */

typedef struct {
    bool recursive;
    bool json;
    int  min_length;
} OpusFlags;

typedef struct {
    const char *command;
    const char *subcommand;
    OpusFlags   flags;
    int         arg_start;   // index where positional args begin
} OpusCLI;

/* -----------------------------------------
   COMMAND MODULE PROTOTYPES
   ----------------------------------------- */
int cmd_string_extractor(const OpusCLI *cli, int argc, char **argv);

int cmd_extract(const OpusCLI *cli, int argc, char **argv);
int cmd_string(int argc, char **argv);

int cmd_entropy(const OpusCLI *cli, int argc, char **argv);
int cmd_crypto(const OpusCLI *cli, int argc, char **argv);
int cmd_binary(const OpusCLI *cli, int argc, char **argv);
int cmd_desig(const OpusCLI *cli, int argc, char **argv);
int cmd_wipefs(const OpusCLI *cli, int argc, char **argv);
int cmd_help(const OpusCLI *cli, int argc, char **argv);
int cmd_version(const OpusCLI *cli, int argc, char **argv);

/* -----------------------------------------
   CLI ENTRYPOINTS
   ----------------------------------------- */

int opus_cli_main(int argc, char **argv);

/* REPL entrypoint (implemented in Opus.c) */
int opus_repl(void);

#endif /* OPUS_CLI_H */

