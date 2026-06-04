#ifndef STRING_HELPERS_H
#define STRING_HELPERS_H

#include <stddef.h>
#include <stdbool.h>

/*
 * STRING HELPERS — OPUS INTERNAL UTILS
 *
 * These functions provide safe, reusable string utilities
 * used by cmd_string.c and the universal analyzer.
 */

/* Trim leading/trailing whitespace in-place */
void str_trim(char *s);

/* Convert string to lowercase in-place */
void str_tolower(char *s);

/* Case-insensitive comparison */
int str_icmp(const char *a, const char *b);

/* Check if 'haystack' contains 'needle' (case-sensitive) */
bool str_contains(const char *haystack, const char *needle);

/* Case-insensitive contains */
bool str_icontains(const char *haystack, const char *needle);

/* Safe substring search (returns pointer or NULL) */
const char *str_find(const char *haystack, const char *needle);

/* Duplicate a string (malloc) */
char *str_dup(const char *s);

/* Remove newline characters in-place */
void str_chomp(char *s);

/* Split string by delimiter; returns number of tokens */
size_t str_split(char *s, char delim, char **out, size_t max_tokens);

#endif /* STRING_HELPERS_H */

