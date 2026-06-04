#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include "rsa_dfrompq.h"

bool opus_rsa_dfrompq(const char *p_str, const char *q_str, const char *e_str)
{
    mpz_t p, q, e, phi, d, tmp;
    mpz_inits(p, q, e, phi, d, tmp, NULL);

    /* Parse inputs */
    if (mpz_set_str(p, p_str, 10) != 0 ||
        mpz_set_str(q, q_str, 10) != 0 ||
        mpz_set_str(e, e_str, 10) != 0) {
        printf("[-] RSA-DFROMPQ: invalid integer input.\n");
        mpz_clears(p, q, e, phi, d, tmp, NULL);
        return false;
    }

    /* phi = (p - 1) * (q - 1) */
    mpz_sub_ui(tmp, p, 1);     /* tmp = p - 1 */
    mpz_sub_ui(phi, q, 1);     /* phi = q - 1 */
    mpz_mul(phi, phi, tmp);    /* phi = (p - 1) * (q - 1) */

    gmp_printf("[+] phi = %Zd\n", phi);

    /* d = e^{-1} mod phi */
    if (mpz_invert(d, e, phi) == 0) {
        printf("[-] RSA-DFROMPQ: modular inverse does not exist (gcd(e, phi) != 1)\n");
        mpz_clears(p, q, e, phi, d, tmp, NULL);
        return false;
    }

    gmp_printf("[+] d = %Zd\n", d);

    mpz_clears(p, q, e, phi, d, tmp, NULL);
    return true;
}

