#ifndef RSA_COMMON_H
#define RSA_COMMON_H

#include <gmp.h>

char *mpz_to_hex_string(const mpz_t m);

int parse_rsa_file(const char *path, mpz_t N, mpz_t e, mpz_t c);
int rsa_validate_pq(const mpz_t p, const mpz_t q);
#endif

