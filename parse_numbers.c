/* parse_numbers.c */
#define _POSIX_C_SOURCE 200809L
#include "parse_numbers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>



/* Helper: is token all digits? */
static int is_all_digits_local(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

/* Helper: normalize separators to spaces and return a heap copy */
static char *normalize_separators_local(const char *in) {
    if (!in) return NULL;
    char *copy = strdup(in);
    if (!copy) return NULL;
    for (char *p = copy; *p; ++p) {
        if (*p == ',' || *p == ';' || *p == '|' || *p == '\t') *p = ' ';
    }
    return copy;
}

/* Parse a single token into a 32-bit unsigned integer with base heuristics.
 * Returns 0 on success and sets *out; returns -1 on parse error.
 */
static int parse_token_uint32_local(const char *tok, uint32_t *out) {
    if (!tok || !*tok) return -1;

    const char *p = tok;
    if (*p == '+' || *p == '-') ++p;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        char *end = NULL;
        unsigned long v = strtoul(p + 2, &end, 16);
        if (end == p + 2) return -1;
        *out = (uint32_t)v;
        return 0;
    }
    if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) {
        char *end = NULL;
        unsigned long v = strtoul(p + 2, &end, 2);
        if (end == p + 2) return -1;
        *out = (uint32_t)v;
        return 0;
    }
    if ((p[0] == 'o' || p[0] == 'O') && isdigit((unsigned char)p[1])) {
        char *end = NULL;
        unsigned long v = strtoul(p + 1, &end, 8);
        if (end == p + 1) return -1;
        *out = (uint32_t)v;
        return 0;
    }
    int has_hex_letter = 0;
    for (const char *q = p; *q; ++q) {
        if (isalpha((unsigned char)*q) && (toupper((unsigned char)*q) >= 'A' && toupper((unsigned char)*q) <= 'F')) {
            has_hex_letter = 1;
            break;
        }
    }
    if (has_hex_letter) {
        char *end = NULL;
        unsigned long v = strtoul(p, &end, 16);
        if (end == p) return -1;
        *out = (uint32_t)v;
        return 0;
    }
    if (is_all_digits_local(p)) {
        char *end = NULL;
        unsigned long v = strtoul(p, &end, 10);
        if (end == p) return -1;
        *out = (uint32_t)v;
        return 0;
    }
    {
        char *end = NULL;
        unsigned long v = strtoul(p, &end, 0);
        if (end == p) return -1;
        *out = (uint32_t)v;
        return 0;
    }
}

/* Print bytes (as characters) for a numeric token. Values >255 are expanded big-endian. */
static void print_value_as_bytes_local(uint32_t v) {
    if (v <= 0xFFu) {
        putchar((char)(v & 0xFFu));
    } else {
        int bytes = 0;
        uint32_t tmp = v;
        while (tmp) { bytes++; tmp >>= 8; }
        for (int i = bytes - 1; i >= 0; --i) {
            unsigned char b = (unsigned char)((v >> (8 * i)) & 0xFFu);
            putchar((char)b);
        }
    }
}

/* Public function used by Opus.c */
int parse_and_print_numeric_tokens(const char *input) {
    if (!input) return -1;

    char *copy = normalize_separators_local(input);
    if (!copy) return -1;

    char *saveptr = NULL;
    char *tok = strtok_r(copy, " ", &saveptr);
    int any = 0;

    while (tok) {
        uint32_t v;

        /* First: try numeric parse */
        if (parse_token_uint32_local(tok, &v) == 0) {

            /* Reject absurd values */
            if (v > 255) {
                free(copy);
                return -1;
            }

            print_value_as_bytes_local(v);
            any = 1;
        }
        else {
            /* If numeric parse failed, only accept literal ASCII tokens
               that contain NO digits and are printable. */
            int printable = 1;
            int has_digit = 0;

            for (char *p = tok; *p; ++p) {
                if (!isprint((unsigned char)*p)) {
                    printable = 0;
                    break;
                }
                if (isdigit((unsigned char)*p)) {
                    has_digit = 1;
                }
            }

            if (printable && !has_digit) {
                fputs(tok, stdout);
                any = 1;
            } else {
                free(copy);
                return -1;
            }
        }

        tok = strtok_r(NULL, " ", &saveptr);
    }

    free(copy);
    return any ? 0 : -1;
}

int isStrictAsciiCode(const char *s) {
    if (!s || !*s) return 0;

    char *copy = normalize_separators_local(s);
    if (!copy) return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, " ", &save);
    if (!tok) {
        free(copy);
        return 0;
    }

    while (tok) {
        /* must be digits only */
        for (const char *p = tok; *p; ++p) {
            if (!isdigit((unsigned char)*p)) {
                free(copy);
                return 0;
            }
        }

        /* reject leading zeros unless exactly "0" */
        if (tok[0] == '0' && tok[1] != '\0') {
            free(copy);
            return 0;
        }

        /* enforce ASCII range */
        long v = strtol(tok, NULL, 10);
        if (v < 0 || v > 255) {
            free(copy);
            return 0;
        }

        tok = strtok_r(NULL, " ", &save);
    }

    free(copy);
    return 1;
}

/* Strict decimal ASCII-code validator:
 * - digits only
 * - no leading zeros unless token == "0"
 * - range 0–255
 * - space-separated tokens
 */
int isStrictDecimalList(const char *s) {
    if (!s || !*s) return 0;

    char *copy = normalize_separators_local(s);
    if (!copy) return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, " ", &save);
    if (!tok) {
        free(copy);
        return 0;
    }

    while (tok) {
        /* must be digits only */
        for (const char *p = tok; *p; ++p) {
            if (!isdigit((unsigned char)*p)) {
                free(copy);
                return 0;
            }
        }

        /* reject leading zeros unless exactly "0" */
        if (tok[0] == '0' && tok[1] != '\0') {
            free(copy);
            return 0;
        }

        /* range check */
        long v = strtol(tok, NULL, 10);
        if (v < 0 || v > 255) {
            free(copy);
            return 0;
        }

        tok = strtok_r(NULL, " ", &save);
    }

    free(copy);
    return 1;
}
int isStrictHex(const char *s) {
    if (!s || !*s) return 0;

    /* normalize separators (comma, semicolon, tab → space) */
    char *copy = normalize_separators_local(s);
    if (!copy) return 0;

    /* detect if this is a single contiguous token */
    int space_present = (strchr(copy, ' ') != NULL);

    if (!space_present) {
        /* contiguous hex mode */
        size_t len = strlen(copy);

        /* must be even length */
        if (len == 0 || (len % 2) != 0) {
            free(copy);
            return 0;
        }

        /* must be all hex chars */
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit((unsigned char)copy[i])) {
                free(copy);
                return 0;
            }
        }

        free(copy);
        return 1;
    }

    /* space-separated hex tokens */
    char *save = NULL;
    char *tok = strtok_r(copy, " ", &save);
    if (!tok) {
        free(copy);
        return 0;
    }

    while (tok) {
        size_t len = strlen(tok);

        /* each token must be 1–2 hex chars */
        if (len == 0 || len > 2) {
            free(copy);
            return 0;
        }

        /* must be hex digits only */
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit((unsigned char)tok[i])) {
                free(copy);
                return 0;
            }
        }

        tok = strtok_r(NULL, " ", &save);
    }

    free(copy);
    return 1;
}
