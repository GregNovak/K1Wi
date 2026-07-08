#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "opus_cmd.h"
#include "rsa_factor.h"
#include "entropy.h"
#include "entropy_heatmap.h"


int opus_lyzer_file(const char *path, const char *mode);

int cmd_lyzer(opus_context *ctx, int argc, char **argv)
{
    (void)ctx;

    if (argc < 2) {
        fprintf(stderr, "Usage: LYZER <file> [H|R|E|C|S|J|D|ALL|--summary|--full|--verbose]\n");
        return 1;
    }

    const char *path = argv[1];
    const char *mode = "SUMMARY";

    if (argc >= 3) {
        mode = argv[2];
    }

    return opus_lyzer_file(path, mode);
}



int cmd_entropy(const OpusCLI *cli, int argc, char **argv)
{
    int argi = cli->arg_start;
    const size_t block_size = 4096;

    const char *path = NULL;
    const char *mode = "--global";

    if (argi >= argc) {
        fprintf(stderr, "Usage: k1wi ENTROPY <file> [--global|--window|--heatmap]\n");
        fprintf(stderr, "       k1wi ENTROPY --global <file>\n");
        fprintf(stderr, "       k1wi ENTROPY --window <file>\n");
        fprintf(stderr, "       k1wi ENTROPY --heatmap <file>\n");
        return 1;
    }

    /*
     * Support both documented flag-first form:
     *   ENTROPY --window file.bin
     *
     * and GUI/user-friendly file-first form:
     *   ENTROPY file.bin --window
     */
    if (strcmp(argv[argi], "--global") == 0 ||
        strcmp(argv[argi], "--window") == 0 ||
        strcmp(argv[argi], "--heatmap") == 0) {
        mode = argv[argi];

        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: k1wi ENTROPY %s <file>\n", mode);
            return 1;
        }

        path = argv[argi + 1];
    } else {
        path = argv[argi];

        if (argi + 1 < argc) {
            if (strcmp(argv[argi + 1], "--global") == 0 ||
                strcmp(argv[argi + 1], "--window") == 0 ||
                strcmp(argv[argi + 1], "--heatmap") == 0) {
                mode = argv[argi + 1];
            } else {
                fprintf(stderr, "Unknown ENTROPY option: %s\n", argv[argi + 1]);
                return 1;
            }
        }
    }

    if (strcmp(mode, "--global") == 0) {
        double H = opus_entropy_file(path);

        if (H < 0.0) {
            fprintf(stderr, "Failed to open: %s\n", path);
            return 1;
        }

        printf("File: %s\n", path);
        printf("Global entropy: %.6f bits/byte\n", H);
        return 0;
    }

    if (strcmp(mode, "--window") == 0) {
        size_t count = 0;
        double *blocks = opus_entropy_windowed(path, block_size, &count);

        if (blocks == NULL || count == 0) {
            fprintf(stderr, "Failed to compute windowed entropy: %s\n", path);
            free(blocks);
            return 1;
        }

        printf("File: %s\n", path);
        printf("Sliding-window entropy (block size %zu bytes):\n", block_size);

        for (size_t i = 0; i < count; i++) {
            printf("  block %04zu: %.6f bits/byte\n", i, blocks[i]);
        }

        free(blocks);
        return 0;
    }

    if (strcmp(mode, "--heatmap") == 0) {
        struct entropy_heatmap map = {0};

        if (opus_entropy_heatmap_analyze(path, block_size, &map) != 0) {
            fprintf(stderr, "Failed to analyze entropy heatmap: %s\n", path);
            return 1;
        }

        printf("File: %s\n", path);
        printf("Entropy heatmap (block size %zu bytes):\n", block_size);

        opus_entropy_heatmap_render_color(&map);
        opus_entropy_heatmap_print(&map);
        opus_entropy_heatmap_detect_anomalies(&map);
        opus_entropy_heatmap_free(&map);

        return 0;
    }

    fprintf(stderr, "Unknown ENTROPY mode: %s\n", mode);
    return 1;
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


