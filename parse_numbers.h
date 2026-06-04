/* parse_numbers.h */
#ifndef PARSE_NUMBERS_H
#define PARSE_NUMBERS_H

#include <stdint.h>
#include <stddef.h>


int parse_and_print_numeric_tokens(const char *input);
int isStrictDecimalList(const char *s);
int isStrictHex(const char *s);   // <--- add this
int isStrictAsciiCode(const char *s);

#endif /* PARSE_NUMBERS_H */

