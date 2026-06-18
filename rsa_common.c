#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <gmp.h>
#include "rsa_common.h"

/*
 * Convert an mpz_t to a newly allocated hex string.
 * Caller must free().
 */
char *mpz_to_hex_string(const mpz_t m) {
    return mpz_get_str(NULL, 16, m);
}

/*
 * Parse RSA file with lines:
 * N=<decimal>
 * e=<decimal>
 * c=<decimal>
 */
int parse_rsa_file(const char *path, mpz_t N, mpz_t e, mpz_t c) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("[-] Could not open RSA file: %s\n", path);
        return 1;
    }

    char line[4096];
    int have_N = 0;
    int have_e = 0;
    int have_c = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;

        while (isspace((unsigned char)*p)) {
            p++;
        }

        if (*p == '\0' || *p == '#') {
            continue;
        }

        char key = (char)tolower((unsigned char)*p);
        p++;

        while (isspace((unsigned char)*p)) {
            p++;
        }

        if (*p != '=') {
            continue;
        }

        p++;

        while (isspace((unsigned char)*p)) {
            p++;
        }

        char *value = p;
        char *comment = strchr(value, '#');
        if (comment) {
            *comment = '\0';
        }

        char *end = value + strlen(value);
        while (end > value && isspace((unsigned char)end[-1])) {
            end--;
        }
        *end = '\0';

        if (*value == '\0') {
            continue;
        }

        if (key == 'n') {
            if (mpz_set_str(N, value, 10) != 0) {
                printf("[-] Failed to parse N.\n");
                fclose(fp);
                return 1;
            }
            have_N = 1;
        } else if (key == 'e') {
            if (mpz_set_str(e, value, 10) != 0) {
                printf("[-] Failed to parse e.\n");
                fclose(fp);
                return 1;
            }
            have_e = 1;
        } else if (key == 'c') {
            if (mpz_set_str(c, value, 10) != 0) {
                printf("[-] Failed to parse c.\n");
                fclose(fp);
                return 1;
            }
            have_c = 1;
        }
    }

    fclose(fp);

    if (!have_N || !have_e || !have_c) {
        printf("[-] RSA file missing N, e, or c.\n");
        return 1;
    }

    return 0;
}

/*
 * Internal Pollard Rho used by rsa_validate_pq().
 */
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

/*
 * Shared validator for RSA-KNOWNPQ and RSA-CHECKPQ.
 * Returns 1 if both p and q are prime.
 * Returns 0 and prints factors if either is composite.
 */
int rsa_validate_pq(const mpz_t p, const mpz_t q) {
    mpz_t f, other;
    mpz_inits(f, other, NULL);

    /* Check p */
    if (mpz_probab_prime_p(p, 25) == 0) {
        printf("[-] p is composite. Factoring...\n");
        pollard_rho(p, f);

        if (mpz_cmp_ui(f, 0) == 0) {
            printf("[-] Pollard Rho failed to factor p.\n");
        } else {
            gmp_printf("[+] p factor 1: %Zd\n", f);
            mpz_divexact(other, p, f);
            gmp_printf("[+] p factor 2: %Zd\n", other);
        }

        mpz_clears(f, other, NULL);
        return 0;
    }

    /* Check q */
    if (mpz_probab_prime_p(q, 25) == 0) {
        printf("[-] q is composite. Factoring...\n");
        pollard_rho(q, f);

        if (mpz_cmp_ui(f, 0) == 0) {
            printf("[-] Pollard Rho failed to factor q.\n");
        } else {
            gmp_printf("[+] q factor 1: %Zd\n", f);
            mpz_divexact(other, q, f);
            gmp_printf("[+] q factor 2: %Zd\n", other);
        }

        mpz_clears(f, other, NULL);
        return 0;
    }

    mpz_clears(f, other, NULL);
    return 1;
}

