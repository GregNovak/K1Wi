#ifndef RSA_WIENER_H
#define RSA_WIENER_H

#include "mini_rsa.h"   // this now brings in <gmp.h>

int opus_rsa_wiener_attack(const mpz_t n,
                           const mpz_t e,
                           mpz_t d_out);

#endif

