#ifndef FORMAT_UTILS_H
#define FORMAT_UTILS_H

#include <stddef.h>

void print_block_header(const char *title);
void print_grouped_strings(char **items, size_t count, size_t per_row);
void print_offsets_grouped(long *offsets, size_t count, size_t per_row);
void print_kv(const char *key, const char *value);

#endif

