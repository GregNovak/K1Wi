#include <stdio.h>
#include "cli.h"
#include "opus_cmd.h"
#include "rsa_factor.h"


int opus_lyzer_file(const char *path, const char *mode);

int cmd_lyzer(opus_context *ctx, int argc, char **argv)
{
    (void)ctx;

    if (argc < 2) {
        fprintf(stderr, "Usage: LYZER <file> [H|R|E|C|S|J|D|ALL]\n");
        return 1;
    }

    const char *path = argv[1];
    const char *mode = "ALL";

    if (argc >= 3) {
        mode = argv[2];
    }

    return opus_lyzer_file(path, mode);
}

double opus_entropy_file(const char *path);

int cmd_entropy(const OpusCLI *cli, int argc, char **argv)
{
    int argi = cli->arg_start;

    if (argi >= argc) {
        fprintf(stderr, "Usage: k1wi entropy <file>\n");
        return 1;
    }

    const char *path = argv[argi];

    double H = opus_entropy_file(path);

    if (H < 0.0) {
        fprintf(stderr, "Failed to open: %s\n", path);
        return 1;
    }

    printf("File: %s\n", path);
    printf("Global entropy: %.6f bits/byte\n", H);

    return 0;
}


int cmd_magic(int argc, char **argv) {
  (void)argc;
  (void)argv;

    fprintf(stderr, "[cmd_magic] legacy CLI stub; use READ/STRING/ENTROPY/LYZER in the main k1wi shell.\n");
    return -1; // legacy compatibility stub
}

int cmd_vig(int argc, char **argv) {
  (void)argc;
  (void)argv;

    fprintf(stderr, "[cmd_vig] legacy CLI stub; use VIGAN/VIGCRACK/VIGSOLVE/VIGAUTO in the main k1wi shell.\n");
    return -1; // legacy compatibility stub
}

int cmd_sub(int argc, char **argv) {
  (void)argc;
  (void)argv;

    fprintf(stderr, "[cmd_sub] legacy CLI stub; use SOLVE/MONO in the main k1wi shell.\n");
    return -1; // legacy compatibility stub
}

int cmd_rsa(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: k1wi rsa <rsa_file>\n");
        return 1;
    }

    return opus_rsa_factor(argv[1]);
}


int cmd_elf(int argc, char **argv) {
  (void)argc;
  (void)argv;

    fprintf(stderr, "[cmd_elf] legacy CLI stub; use ELFINFO/PIECALC/PIETIME in the main k1wi shell.\n");
    return -1; // legacy compatibility stub
}

int cmd_exit(int argc, char **argv) {
  (void)argc;
  (void)argv;	

    fprintf(stderr, "[cmd_exit] legacy CLI stub; use EXIT in the main k1wi shell.\n");
    return 0;  // legacy compatibility stub
}


