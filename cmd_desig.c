#include <stdio.h>
#include "cli.h"

int cmd_desig(const OpusCLI *cli, int argc, char **argv) {
    (void)cli;
    (void)argc;
    (void)argv;

    printf("[DESIG] legacy CLI group stub; use DESIG, DESIGDEC, DESIGSOLVE, or DESIGANALYZE.\n");
    return 0;
}

