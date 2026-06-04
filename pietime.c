// pietime.c - PIE return-address time estimator for Opus
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <elf.h>

#include "elfinfo.h"

// Minimal color: only for confidence percentage
#define C_RESET   "\x1b[0m"
#define C_GREEN   "\x1b[92m"
#define C_YELLOW  "\x1b[93m"
#define C_RED     "\x1b[91m"

// Confidence based on how safely "inside" the function we are.
// Since we don't have function sizes from elf_symbol_t, we treat
// all size as unknown and use a neutral confidence.
static int pietime_confidence_unknown_size(uint64_t dist_into)
{
    (void)dist_into;
    // With no size information, we can't say much; use neutral.
    return 50;
}

static const char *pietime_conf_color(int conf)
{
    if (conf >= 90) return C_GREEN;
    if (conf >= 60) return C_YELLOW;
    return C_RED;
}

// Core logic: given binary path, leak, and optional base, compute progress inside a function.
int opus_pie_time(const char *path,
                  uint64_t leak_addr,
                  uint64_t base_opt,
                  int have_base_opt)
{
    elf_symbol_t funcs[1024];
    int count = 0;

    if (opus_elf_load_functions(path, funcs, &count, 1024) != 0) {
        // Error already printed by loader.
        return 1;
    }

    if (count == 0) {
        fprintf(stderr, "[PIETIME] ERROR: no functions found in '%s'\n", path);
        return 1;
    }

    // If no base given, assume offsets are already relative to link-time base (0).
    uint64_t base = have_base_opt ? base_opt : 0;

    if (leak_addr < base) {
        fprintf(stderr, "[PIETIME] WARNING: leak address (0x%llx) is below base (0x%llx)\n",
                (unsigned long long)leak_addr,
                (unsigned long long)base);
    }

    uint64_t offset = leak_addr - base;

    // Find containing function. Since we have no size info, we treat any
    // function whose start is <= offset as a candidate and pick the one
    // with the largest start address (closest from below).
    ssize_t matched_idx = -1;
    for (int i = 0; i < count; i++) {
        uint64_t start = funcs[i].offset;
        if (offset >= start) {
            if (matched_idx == -1 || start > funcs[matched_idx].offset) {
                matched_idx = i;
            }
        }
    }

    printf("[PIETIME] ANALYSIS\n");
    printf("  binary:        %s\n", path);
    printf("  base:          0x%llx\n", (unsigned long long)base);
    printf("  leaked addr:   0x%llx\n", (unsigned long long)leak_addr);
    printf("  offset:        0x%llx (from base)\n", (unsigned long long)offset);

    if (matched_idx == -1) {
        printf("\n[PIETIME] RESULT\n");
        printf("  The leaked address does not fall inside or after any known function start.\n");
        printf("  (symbol table may be stripped or incomplete.)\n");
        return 0;
    }

    elf_symbol_t *f = &funcs[matched_idx];
    uint64_t start = f->offset;
    uint64_t dist_into = offset - start;


    int conf = pietime_confidence_unknown_size(dist_into);
    const char *color = pietime_conf_color(conf);

    printf("\n[PIETIME] FUNCTION\n");
    printf("  name:          %s\n", f->name[0] ? f->name : "(anonymous)");
    printf("  start offset:  0x%llx\n", (unsigned long long)start);
    printf("  size:          unknown (no size info)\n");
    printf("  distance:      0x%llx bytes into function\n",
           (unsigned long long)dist_into);

    printf("\n[PIETIME] PROGRESS\n");
    printf("  progress:      unknown (function size not available)\n");
    printf("  confidence:    %s%d%%%s\n", color, conf, C_RESET);

    printf("\n[PIETIME] NOTE: function size is not available from symbol table; "
           "analysis is based only on start offset.\n");

    return 0;
}

// CLI wrapper: PIETIME -IN <file> -LEAK <addr> [-BASE <addr>]
int opus_pie_time_cli(int argc, char **argv)
{
    const char *path = NULL;
    uint64_t leak = 0;
    uint64_t base = 0;
    int have_leak = 0;
    int have_base = 0;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-IN") && i + 1 < argc) {
            path = argv[++i];
        } else if (!strcmp(argv[i], "-LEAK") && i + 1 < argc) {
            leak = strtoull(argv[++i], NULL, 0);
            have_leak = 1;
        } else if (!strcmp(argv[i], "-BASE") && i + 1 < argc) {
            base = strtoull(argv[++i], NULL, 0);
            have_base = 1;
        } else {
            fprintf(stderr, "[PIETIME] ERROR: unknown or incomplete argument '%s'\n", argv[i]);
            fprintf(stderr, "Usage: PIETIME -IN <file> -LEAK <addr> [-BASE <addr>]\n");
            return 1;
        }
    }

    if (!path || !have_leak) {
        fprintf(stderr, "Usage: PIETIME -IN <file> -LEAK <addr> [-BASE <addr>]\n");
        return 1;
    }

    return opus_pie_time(path, leak, base, have_base);
}

