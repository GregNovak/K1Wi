#include <stdio.h>
#include "cli.h"

int cmd_wipefs(const OpusCLI *cli, int argc, char **argv) {
    (void)cli;
    (void)argc;
    (void)argv;

    printf("[WIPEFS] legacy CLI stub; use WIPEFS from the main Opus shell if enabled.\n");
    return 0;
}

