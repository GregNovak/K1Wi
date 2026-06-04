#include <stdio.h>
#include "cli.h"

int opus_elfinfo_print(const char *path);

int cmd_binary(const OpusCLI *cli, int argc, char **argv)
{
    int argi = cli->arg_start;

    if (argi >= argc) {
        fprintf(stderr, "Usage: opus elf <file>\n");
        return 1;
    }

    const char *path = argv[argi];

    if (opus_elfinfo_print(path) != 0) {
        fprintf(stderr, "ELF: failed to analyze '%s'\n", path);
        return 1;
    }

    return 0;
}

