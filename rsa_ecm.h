#ifndef RSA_ECM_H
#define RSA_ECM_H

#include <gmp.h>

/*
 * Try to find a nontrivial factor of n using ECM.
 * Returns 1 on success, 0 on failure.
 * On success, factor will contain a nontrivial divisor of n (2 <= factor < n).
 */
int opus_rsa_ecm_factor(const mpz_t n, mpz_t factor);

#endif

