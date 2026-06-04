#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "string_helpers.h"

/* ---------------------------------------------------------
 * Trim leading/trailing whitespace
 * --------------------------------------------------------- */
void str_trim(char *s)
{
    if (!s) return;

    // Trim leading
    char *start = s;
    while (*start && isspace((unsigned char)*start))
        start++;

    // Trim trailing
    char *end = s + strlen(s);
    while (end > start && isspace((unsigned char)*(end - 1)))
        end--;

    size_t new_len = (size_t)(end - start);
    memmove(s, start, new_len);
    s[new_len] = '\0';
}

/* ---------------------------------------------------------
 * Convert string to lowercase in-place
 * --------------------------------------------------------- */
void str_tolower(char *s)
{
    if (!s) return;
    for (size_t i = 0; s[i]; i++)
        s[i] = (char)tolower((unsigned char)s[i]);
}

/* ---------------------------------------------------------
 * Case-insensitive strcmp
 * --------------------------------------------------------- */
int str_icmp(const char *a, const char *b)
{
    if (!a || !b) return (a == b ? 0 : (a ? 1 : -1));

    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* ---------------------------------------------------------
 * Case-sensitive contains
 * --------------------------------------------------------- */
bool str_contains(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;
    return strstr(haystack, needle) != NULL;
}

/* ---------------------------------------------------------
 * Case-insensitive contains
 * --------------------------------------------------------- */
bool str_icontains(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return false;

    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hlen) return false;

    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j = 0;
        while (j < nlen &&
               tolower((unsigned char)haystack[i + j]) ==
               tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == nlen) return true;
    }
    return false;
}

/* ---------------------------------------------------------
 * Safe substring search
 * --------------------------------------------------------- */
const char *str_find(const char *haystack, const char *needle)
{
    if (!haystack || !needle) return NULL;
    return strstr(haystack, needle);
}

/* ---------------------------------------------------------
 * strdup wrapper
 * --------------------------------------------------------- */
char *str_dup(const char *s)
{
    if (!s) return NULL;
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len + 1);
    return out;
}

/* ---------------------------------------------------------
 * Remove newline characters
 * --------------------------------------------------------- */
void str_chomp(char *s)
{
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

/* ---------------------------------------------------------
 * Split string by delimiter
 * --------------------------------------------------------- */
size_t str_split(char *s, char delim, char **out, size_t max_tokens)
{
    if (!s || !out || max_tokens == 0) return 0;

    size_t count = 0;
    char *p = s;

    while (count < max_tokens) {
        out[count++] = p;

        char *d = strchr(p, delim);
        if (!d) break;

        *d = '\0';
        p = d + 1;
    }

    return count;
}

