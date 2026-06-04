
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "rsa_small_e.h"
#include "rsa_common.h"   // ← ADD THIS

int rsa_small_e_attack(mpz_t m, const mpz_t c, unsigned long e)
{
    if (e == 0) {
        return 0;
    }

    /* Compute floor(c^(1/e)) into m */
    int exact = mpz_root(m, c, e);
    if (!exact) {
        /* m^e != c, so no exact integer root */
        return 0;
    }

    /* Double-check: m^e must equal c exactly */
    mpz_t tmp;
    mpz_init(tmp);

    mpz_pow_ui(tmp, m, e);
    int ok = (mpz_cmp(tmp, c) == 0);

    mpz_clear(tmp);
    return ok ? 1 : 0;
}

