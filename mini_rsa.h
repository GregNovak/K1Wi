// mini_rsa.h
#ifndef MINI_RSA_H
#define MINI_RSA_H
#include <gmp.h>

// Return 0 on success, non-zero on failure.
int opus_mini_rsa(const char *path);
int parse_rsa_file(const char *path, mpz_t N, mpz_t e, mpz_t c);
void opus_print_plaintext_from_bigint(const mpz_t m);

#endif // MINI_RSA_H

