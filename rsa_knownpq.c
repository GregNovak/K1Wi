/* rsa_knownpq.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <stdbool.h>

#include "rsa_knownpq.h"
#include "rsa_common.h"
#include "rsa_factor.h"   /* for parse_rsa_file, opus_print_plaintext_from_bigint */
#include "mini_rsa.h"

/* Helper: trim leading spaces */
static const char *skip_spaces(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* Main entry: decrypt using known p, q */
bool opus_rsa_knownpq(const char *path, const char *p_str, const char *q_str)
{
    mpz_t N, e, c, p, q, phi, d, m, tmp;
    mpz_inits(N, e, c, p, q, phi, d, m, tmp, NULL);

    /* Parse RSA file: N, e, c */
    if (parse_rsa_file(path, N, e, c) != 0) {
        printf("rsa-knownpq: failed to parse RSA file '%s'\n", path);
        mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
        return false;
    }

    printf("[*] RSA-KNOWNPQ: loaded RSA parameters from '%s'\n", path);
    gmp_printf("[DEBUG] N = %Zd\n", N);
    gmp_printf("[DEBUG] e = %Zd\n", e);
    gmp_printf("[DEBUG] c = %Zd\n", c);

    /* Load p, q from strings */
    p_str = skip_spaces(p_str);
    q_str = skip_spaces(q_str);

    if (mpz_set_str(p, p_str, 10) != 0) {
        printf("[-] RSA-KNOWNPQ: invalid p argument: '%s'\n", p_str);
        mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
        return false;
    }
    if (mpz_set_str(q, q_str, 10) != 0) {
        printf("[-] RSA-KNOWNPQ: invalid q argument: '%s'\n", q_str);
        mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
        return false;
    }

    printf("[*] RSA-KNOWNPQ: using provided primes p and q\n");
    gmp_printf("[DEBUG] p = %Zd\n", p);
    gmp_printf("[DEBUG] q = %Zd\n", q);

	/* Validate p and q using shared primality + factor logic */
	if (!rsa_validate_pq(p, q)) {
    	 printf("[-] RSA-KNOWNPQ: p or q is not prime. Aborting.\n");
    	 mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
    	 return false;
	}




    /* Sanity check: p * q == N */
    mpz_mul(tmp, p, q);
    if (mpz_cmp(tmp, N) != 0) {
        printf("[-] RSA-KNOWNPQ: sanity check failed: p*q != N\n");
        gmp_printf("[DEBUG] p*q = %Zd\n", tmp);
        mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
        return false;
    }

	printf("[*] RSA-KNOWNPQ: computing phi = (p - 1)*(q - 1)\n");

	/* phi = (p - 1)*(q - 1) */
	mpz_sub_ui(tmp, p, 1);   // tmp = p - 1
	mpz_sub_ui(phi, q, 1);   // phi = q - 1
	mpz_mul(phi, tmp, phi);  // phi = (p - 1) * (q - 1)

	gmp_printf("[DEBUG] phi = %Zd\n", phi);


    printf("[*] RSA-KNOWNPQ: computing d = e^{-1} mod phi\n");

    /* d = e^{-1} mod phi */
    if (mpz_invert(d, e, phi) == 0) {
        printf("[-] RSA-KNOWNPQ: modular inverse does not exist (gcd(e, phi) != 1)\n");
        mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
        return false;
    }

    gmp_printf("[DEBUG] d = %Zd\n", d);

    printf("[*] RSA-KNOWNPQ: decrypting m = c^d mod N\n");

    /* m = c^d mod N */
    mpz_powm(m, c, d, N);

    gmp_printf("[+] m (int) = %Zd\n", m);

    /* Reuse existing plaintext printer (int → bytes → text/hex) */
    opus_print_plaintext_from_bigint(m);

    mpz_clears(N, e, c, p, q, phi, d, m, tmp, NULL);
    return true;
}

