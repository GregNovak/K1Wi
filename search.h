#ifndef SEARCH_H
#define SEARCH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* search mode */
typedef enum {
    SEARCH_MODE_AUTO = 0,
    SEARCH_MODE_ASCII,
    SEARCH_MODE_HEX
} search_mode_t;

/* multi‑pattern compiled entry */
typedef struct {
    uint8_t *needle;
    uint8_t *mask;
    size_t   len;
    char     raw[256];
} search_pattern_t;

/* single‑pattern search */
int opus_search(const char *filename,
                const char *pattern,
                search_mode_t mode,
                size_t before,
                size_t after,
                size_t before_hex,
                size_t after_hex,
                bool flag_mode);

/* multi‑pattern search */
int opus_search_multi(const char *filename,
                      const char *single_pattern,
                      const char *patterns_file,
                      search_mode_t mode,
                      size_t before,
                      size_t after,
                      size_t before_hex,
                      size_t after_hex,
                      bool flag_mode);

#endif

