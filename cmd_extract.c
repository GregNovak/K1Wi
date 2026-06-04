#include <stdio.h>
#include <string.h>
#include "cmd_extract.h"

// Forward declaration of your real extraction engine.
// You will replace this with your actual function.
int opus_extract_recursive(const char *path);
int opus_extract_single(const char *path);

int cmd_extract(const OpusCLI *cli, int argc, char **argv) {
    int argi = cli->arg_start;

    if (argi >= argc) {
        fprintf(stderr, "ERROR: extract requires a file path\n");
        fprintf(stderr, "Usage: opus extract [--recursive] <file>\n");
        return 1;
    }

    const char *file = argv[argi];

    // Show what the CLI interpreted
    printf("[EXTRACT] file=%s\n", file);
    printf("[EXTRACT] recursive=%s\n", cli->flags.recursive ? "yes" : "no");

    // Dispatch to the correct engine
    if (cli->flags.recursive) {
        return opus_extract_recursive(file);
    } else {
        return opus_extract_single(file);
    }
}

