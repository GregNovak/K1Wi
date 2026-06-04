#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include "search.h"



static int is_hex_or_wild_string(const char *s);
static uint8_t *hex_to_bytes_with_mask(const char *hex,
                                       size_t *out_len,
                                       uint8_t **out_mask);




static int is_hex_or_wild_string(const char *s) {
    size_t n = strlen(s);
    if (n % 2 != 0) return 0;

    for (size_t i = 0; i < n; i += 2) {
        if (s[i] == '?' && s[i+1] == '?')
            continue;

        if (!isxdigit((unsigned char)s[i]) ||
            !isxdigit((unsigned char)s[i+1]))
            return 0;
    }
    return 1;
}



static void print_hit(size_t offset, const uint8_t *data, size_t len) {
    printf("\033[1;32m[+] Hit at offset 0x%zx (%zu)\033[0m\n", offset, offset);

    printf("    Hex:   ");
    for (size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
    printf("\n");

    printf("    ASCII: ");
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }
    printf("\n\n");
}

int opus_search(const char *filename,
                const char *pattern,
                search_mode_t mode,
                size_t before,
                size_t after,
                size_t before_hex,
                size_t after_hex,
                bool flag_mode)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[-] Could not open %s\n", filename);
        return -1;
    }

       if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
	}

	long pos = ftell(f);
	if (pos < 0) {
	    fclose(f);
	    return -1;
	}

	size_t fsize = (size_t)pos;

	if (fseek(f, 0, SEEK_SET) != 0) {
	    fclose(f);
	    return -1;
	}

    uint8_t *buf = malloc(fsize);
    if (!buf) {
        fclose(f);
        return -1;
    }

    fread(buf, 1, fsize, f);
    fclose(f);

    uint8_t *needle = NULL;
    uint8_t *mask   = NULL;
    size_t needle_len = 0;

if (mode == SEARCH_MODE_AUTO) {
    mode = SEARCH_MODE_ASCII;   // default to ASCII unless user explicitly requests HEX
}


    if (mode == SEARCH_MODE_ASCII) {
        needle = (uint8_t *)pattern;
        needle_len = strlen(pattern);
    } else {
        needle = hex_to_bytes_with_mask(pattern, &needle_len, &mask);
        if (!needle) {
            free(buf);
            return -1;
        }
    }

    size_t hits = 0;

    for (size_t i = 0; i + needle_len <= fsize; i++) {

        int match = 1;

        if (mode == SEARCH_MODE_ASCII) {
            if (memcmp(buf + i, needle, needle_len) != 0)
                match = 0;
        } else {
            for (size_t k = 0; k < needle_len; k++) {
                if (mask[k] == 0x00)
                    continue;
                if (buf[i + k] != needle[k]) {
                    match = 0;
                    break;
                }
            }
        }

        if (!match)
            continue;

        print_hit(i, buf + i, needle_len);

        if (before > 0) {
            size_t start = (i > before) ? i - before : 0;
            printf("    Before (%zu bytes):\n    ", before);
            for (size_t j = start; j < i; j++) {
                uint8_t c = buf[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n\n");
        }

        if (after > 0) {
            size_t start = i + needle_len;
            size_t end = start + after;
            if (end > fsize) end = fsize;

            printf("    After (%zu bytes):\n    ", after);
            for (size_t j = start; j < end; j++) {
                uint8_t c = buf[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n\n");
        }

        if (before_hex > 0) {
            size_t start = (i > before_hex) ? i - before_hex : 0;
            printf("    Before-Hex (%zu bytes):\n    ", before_hex);
            for (size_t j = start; j < i; j++)
                printf("%02X ", buf[j]);
            printf("\n\n");
        }

        if (after_hex > 0) {
            size_t start = i + needle_len;
            size_t end = start + after_hex;
            if (end > fsize) end = fsize;

            printf("    After-Hex (%zu bytes):\n    ", after_hex);
            for (size_t j = start; j < end; j++)
                printf("%02X ", buf[j]);
            printf("\n\n");
        }

        if (flag_mode) {
            size_t start = i;
            size_t end = i;

            while (end < fsize && buf[end] != '}')
                end++;

            if (end < fsize) end++;

            printf("    FLAG MODE:\n    ");
            for (size_t j = start; j < end; j++) {
                uint8_t c = buf[j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            printf("\n\n");
        }

        hits++;
    }

    if (mode == SEARCH_MODE_HEX) {
        free(needle);
        free(mask);
    }

    free(buf);

    if (!hits)
        printf("[-] No matches found.\n");

    return 0;
}



static uint8_t *hex_to_bytes_with_mask(const char *hex,
                                       size_t *out_len,
                                       uint8_t **out_mask)
{
    size_t n = strlen(hex);
    *out_len = n / 2;

    uint8_t *buf  = malloc(*out_len);
    uint8_t *mask = malloc(*out_len);
    if (!buf || !mask) {
        free(buf);
        free(mask);
        return NULL;
    }

    for (size_t i = 0; i < *out_len; i++) {
        char hi = hex[2*i];
        char lo = hex[2*i + 1];

        if (hi == '?' && lo == '?') {
            buf[i]  = 0x00;
            mask[i] = 0x00;   // wildcard
        } else {
            unsigned int v;
            sscanf(&hex[2*i], "%2x", &v);
            buf[i]  = (uint8_t)v;
            mask[i] = 0xFF;   // must match
        }
    }

    *out_mask = mask;
    return buf;
}



static size_t load_patterns(const char *filename, search_pattern_t **out) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[256];
    size_t count = 0;
    size_t cap = 16;

    search_pattern_t *list = malloc(sizeof(search_pattern_t) * cap);

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 0) continue;

        if (count == cap) {
            cap *= 2;
            list = realloc(list, sizeof(search_pattern_t) * cap);
        }

        search_pattern_t *p = &list[count];
        memset(p, 0, sizeof(*p));
        strncpy(p->raw, line, sizeof(p->raw)-1);

        if (is_hex_or_wild_string(line)) {
            p->needle = hex_to_bytes_with_mask(line, &p->len, &p->mask);
        } else {
            p->len = strlen(line);
            p->needle = malloc(p->len);
            p->mask   = malloc(p->len);
            for (size_t i = 0; i < p->len; i++) {
                p->needle[i] = (uint8_t)line[i];
                p->mask[i]   = 0xFF;
            }
        }

        count++;
    }

    fclose(f);
    *out = list;
    return count;
}



int opus_search_multi(const char *filename,
                      const char *single_pattern,
                      const char *patterns_file,
                      search_mode_t mode,
                      size_t before,
                      size_t after,
                      size_t before_hex,
                      size_t after_hex,
                      bool flag_mode)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "[-] Could not open %s\n", filename);
        return -1;
    }

	if (fseek(f, 0, SEEK_END) != 0) {
	    fclose(f);
	    return -1;
	}

	long pos = ftell(f);
	if (pos < 0) {
	    fclose(f);
	    return -1;
	}

	size_t fsize = (size_t)pos;

	if (fseek(f, 0, SEEK_SET) != 0) {
	    fclose(f);
	    return -1;
	}

	uint8_t *buf = malloc(fsize);
	if (!buf) {
	    fclose(f);
	    return -1;
	}

	if (fread(buf, 1, fsize, f) != fsize) {
	    free(buf);
	    fclose(f);
	    return -1;
	}

	fclose(f);

    search_pattern_t *patterns = NULL;
    size_t pcount = 0;

    if (patterns_file) {
        pcount = load_patterns(patterns_file, &patterns);
    } else {
        patterns = malloc(sizeof(search_pattern_t));
        memset(patterns, 0, sizeof(search_pattern_t));
        strncpy(patterns[0].raw, single_pattern, sizeof(patterns[0].raw)-1);

        if (mode == SEARCH_MODE_AUTO) {
            if (is_hex_or_wild_string(single_pattern))
                mode = SEARCH_MODE_HEX;
            else
                mode = SEARCH_MODE_ASCII;
        }

        if (mode == SEARCH_MODE_ASCII) {
            patterns[0].len = strlen(single_pattern);
            patterns[0].needle = malloc(patterns[0].len);
            patterns[0].mask   = malloc(patterns[0].len);
            for (size_t i = 0; i < patterns[0].len; i++) {
                patterns[0].needle[i] = (uint8_t)single_pattern[i];
                patterns[0].mask[i]   = 0xFF;
            }
        } else {
            patterns[0].needle = hex_to_bytes_with_mask(single_pattern,
                                                        &patterns[0].len,
                                                        &patterns[0].mask);
        }

        pcount = 1;
    }

    size_t hits = 0;

    for (size_t i = 0; i < fsize; i++) {
        for (size_t p = 0; p < pcount; p++) {
            search_pattern_t *pat = &patterns[p];

            if (i + pat->len > fsize)
                continue;

            int match = 1;
            for (size_t k = 0; k < pat->len; k++) {
                if (pat->mask[k] == 0x00)
                    continue;
                if (buf[i + k] != pat->needle[k]) {
                    match = 0;
                    break;
                }
            }

            if (!match)
                continue;

            printf("\033[1;32m[+] Pattern \"%s\" hit at 0x%zx\033[0m\n",
                   pat->raw, i);

            print_hit(i, buf + i, pat->len);

            /* reuse your existing before/after/flag logic */
            if (before > 0) {
                size_t start = (i > before) ? i - before : 0;
                printf("    Before (%zu bytes):\n    ", before);
                for (size_t j = start; j < i; j++) {
                    uint8_t c = buf[j];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n\n");
            }

            if (after > 0) {
                size_t start = i + pat->len;
                size_t end = start + after;
                if (end > fsize) end = fsize;

                printf("    After (%zu bytes):\n    ", after);
                for (size_t j = start; j < end; j++) {
                    uint8_t c = buf[j];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n\n");
            }

            if (before_hex > 0) {
                size_t start = (i > before_hex) ? i - before_hex : 0;
                printf("    Before-Hex (%zu bytes):\n    ", before_hex);
                for (size_t j = start; j < i; j++)
                    printf("%02X ", buf[j]);
                printf("\n\n");
            }

            if (after_hex > 0) {
                size_t start = i + pat->len;
                size_t end = start + after_hex;
                if (end > fsize) end = fsize;

                printf("    After-Hex (%zu bytes):\n    ", after_hex);
                for (size_t j = start; j < end; j++)
                    printf("%02X ", buf[j]);
                printf("\n\n");
            }

            if (flag_mode) {
                size_t start = i;
                size_t end = i;

                while (end < fsize && buf[end] != '}')
                    end++;

                if (end < fsize) end++;

                printf("    FLAG MODE:\n    ");
                for (size_t j = start; j < end; j++) {
                    uint8_t c = buf[j];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
                printf("\n\n");
            }

            hits++;
        }
    }

    for (size_t p = 0; p < pcount; p++) {
        free(patterns[p].needle);
        free(patterns[p].mask);
    }
    free(patterns);
    free(buf);

    if (!hits)
        printf("[-] No matches found.\n");

    return 0;
}

