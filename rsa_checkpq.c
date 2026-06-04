#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include "rsa_checkpq.h"

/* Pollard Rho factorization */
static void pollard_rho(const mpz_t n, mpz_t factor) {
    mpz_t x, y, c, d, tmp;
    mpz_inits(x, y, c, d, tmp, NULL);

    if (mpz_cmp_ui(n, 2) <= 0) {
        mpz_set_ui(factor, 0);
        goto cleanup;
    }

    if (mpz_even_p(n)) {
        mpz_set_ui(factor, 2);
        goto cleanup;
    }

    mpz_set_ui(c, 1);
    mpz_set_ui(x, 2);
    mpz_set_ui(y, 2);
    mpz_set_ui(d, 1);

    while (mpz_cmp_ui(d, 1) == 0) {
        mpz_mul(tmp, x, x);
        mpz_add(tmp, tmp, c);
        mpz_mod(x, tmp, n);

        mpz_mul(tmp, y, y);
        mpz_add(tmp, tmp, c);
        mpz_mod(y, tmp, n);

        mpz_mul(tmp, y, y);
        mpz_add(tmp, tmp, c);
        mpz_mod(y, tmp, n);

        mpz_sub(tmp, x, y);
        mpz_abs(tmp, tmp);
        mpz_gcd(d, tmp, n);
    }

    if (mpz_cmp(d, n) == 0)
        mpz_set_ui(factor, 0);
    else
        mpz_set(factor, d);

cleanup:
    mpz_clears(x, y, c, d, tmp, NULL);
}

static void check_and_print(const char *label, const mpz_t n) {
    gmp_printf("[*] %s = %Zd\n", label, n);

    int r = mpz_probab_prime_p(n, 25);
    if (r > 0) {
        printf("[+] %s is prime.\n\n", label);
        fflush(stdout);
        return;
    }

    printf("[-] %s is composite. Factoring...\n", label);
    fflush(stdout);

    mpz_t f, other;
    mpz_inits(f, other, NULL);

    pollard_rho(n, f);

    if (mpz_cmp_ui(f, 0) == 0) {
        printf("[-] Pollard Rho failed to find a factor for %s.\n\n", label);
        fflush(stdout);
    } else {
        gmp_printf("[+] Factor 1 of %s: %Zd\n", label, f);
        mpz_divexact(other, n, f);
        gmp_printf("[+] Factor 2 of %s: %Zd\n\n", label, other);
        fflush(stdout);
    }

    mpz_clears(f, other, NULL);
}

bool opus_rsa_checkpq(const char *p_str, const char *q_str) {
    mpz_t p, q;
    mpz_inits(p, q, NULL);

    if (mpz_set_str(p, p_str, 10) != 0 ||
        mpz_set_str(q, q_str, 10) != 0) {
        printf("[-] Invalid integer input.\n");
        fflush(stdout);
        mpz_clears(p, q, NULL);
        return false;
    }

    printf("[*] Starting RSA-CHECKPQ...\n");
    fflush(stdout);

    check_and_print("p", p);
    check_and_print("q", q);

    printf("[*] RSA-CHECKPQ complete.\n");
    fflush(stdout);

    mpz_clears(p, q, NULL);
    return true;
}

