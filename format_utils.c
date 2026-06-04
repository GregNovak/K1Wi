#include <stdio.h>
#include <stdlib.h>
#include "format_utils.h"

void print_block_header(const char *title) {
    printf("\n=== %s ===\n", title);
}

void print_grouped_strings(char **items, size_t count, size_t per_row) {
    for (size_t i = 0; i < count; i++) {
        printf("%-24s", items[i]);
        if ((i + 1) % per_row == 0 || i + 1 == count)
            printf("\n");
        else
            printf("  ");
    }
}

void print_offsets_grouped(long *offsets, size_t count, size_t per_row) {
    for (size_t i = 0; i < count; i++) {
        printf("%-12ld", offsets[i]);
        if ((i + 1) % per_row == 0 || i + 1 == count)
            printf("\n");
        else
            printf("  ");
    }
}

void print_kv(const char *key, const char *value) {
    printf("%-22s %s\n", key, value);
}

