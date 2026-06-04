#ifndef RSA_SMALL_E_H
#define RSA_SMALL_E_H

#include <gmp.h>

/*
 * Try small-exponent RSA attack:
 * Given c and e, attempt to recover m such that m^e = c (over the integers).
 *
 * Returns:
 *   1 on success (m is set),
 *   0 if the attack does not apply (no exact e-th root).
 */
int rsa_small_e_attack(mpz_t m, const mpz_t c, unsigned long e);

#endif /* RSA_SMALL_E_H */

