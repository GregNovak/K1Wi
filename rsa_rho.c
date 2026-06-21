#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <string.h>
#include <ctype.h>
#include "rsa_rho.h"
#include "rsa_common.h"


// Provided elsewhere in Opus
extern void stringAnalyzerFromBuffer(const char *buf);

/*
 * Pollard Rho (Floyd cycle detection) to find a nontrivial factor of n.
 * Returns 1 on success, 0 on failure.
 */
static int pollard_rho(mpz_t factor, const mpz_t n) {
    if (mpz_even_p(n)) {
        mpz_set_ui(factor, 2);
        return 1;
    }

    mpz_t x, y, c, d, tmp;
    mpz_inits(x, y, c, d, tmp, NULL);

    // We'll try several different constants c if needed
    unsigned long c_val = 1;
    int found = 0;

    while (!found && c_val < 50) {
        mpz_set_ui(x, 2);
        mpz_set_ui(y, 2);
        mpz_set_ui(c, c_val);
        mpz_set_ui(d, 1);

        long iter = 0;
        const long max_iter = 1000000;

        while (mpz_cmp_ui(d, 1) == 0 && iter < max_iter) {
            // x = (x^2 + c) mod n
            mpz_mul(x, x, x);
            mpz_add(x, x, c);
            mpz_mod(x, x, n);

            // y = (y^2 + c) mod n; twice (Floyd)
            mpz_mul(y, y, y);
            mpz_add(y, y, c);
            mpz_mod(y, y, n);

            mpz_mul(y, y, y);
            mpz_add(y, y, c);
            mpz_mod(y, y, n);

            // d = gcd(|x - y|, n)
            if (mpz_cmp(x, y) > 0)
                mpz_sub(tmp, x, y);
            else
                mpz_sub(tmp, y, x);

            mpz_gcd(d, tmp, n);

            iter++;
        }

        if (mpz_cmp_ui(d, 1) > 0 && mpz_cmp(d, n) < 0) {
            mpz_set(factor, d);
            found = 1;
            break;
        }

        c_val++;
    }

    mpz_clears(x, y, c, d, tmp, NULL);
    return found;
}

/*
 * opus_rsa_rho:
 *   - Reads n, e, c from filename (e.g., "rsa_values.txt")
 *   - Factors n using Pollard Rho
 *   - Computes phi, d
 *   - Decrypts c -> m
 *   - Prints plaintext in hex, then runs stringAnalyzerFromBuffer on hex
 *
 * File format:
 *   n: <decimal>
 *   e: <decimal>
 *   c: <decimal>
 */
int opus_rsa_rho(const char *filename) {
    mpz_t n, c, p, q, phi, d, m, e_mpz, tmp;


    // ------------------------------------------------------------
    // 1. INITIALIZE VARIABLES
    // ------------------------------------------------------------
    mpz_inits(n, c, p, q, phi, d, m, e_mpz, tmp, NULL);

    // ------------------------------------------------------------
    // 2. INSERT THE NEW PARSER *RIGHT HERE*
    // ------------------------------------------------------------
    if (parse_rsa_file(filename, n, e_mpz, c) != 0) {
        fprintf(stderr, "rsa-rho: failed to parse RSA file '%s'\n", filename);
        return 0;
    }

    printf("\nRSA Input\n");
    printf("---------\n");
    gmp_printf("N = %Zd\n", n);
    gmp_printf("e = %Zd\n", e_mpz);
    gmp_printf("c = %Zd\n", c);

    // ------------------------------------------------------------
    // 3. DELETE THE OLD FSCANF BLOCK (everything below)
    // ------------------------------------------------------------
    // FILE *fp = fopen(filename, "r");
    // if (!fp) { ... }
    // if (gmp_fscanf(fp, "n: %Zd", n) != 1) { ... }
    // if (fscanf(fp, "\ne: %lu", &e_ul) != 1) { ... }
    // if (gmp_fscanf(fp, "\nc: %Zd", c) != 1) { ... }
    // fclose(fp);
    // printf("[DEBUG] e = %lu\n", e_ul);

    // ------------------------------------------------------------
    // 4. CONTINUE WITH THE REST OF YOUR FUNCTION
    // ------------------------------------------------------------

    if (mpz_cmp_ui(n, 0) == 0) {
        fprintf(stderr, "RSA-RHO: n is zero, aborting\n");
        return 0;
    }

    printf("[*] RSA-RHO: starting Pollard Rho factorization\n");

    if (!pollard_rho(p, n)) {
        printf("[-] RSA-RHO: Pollard Rho failed to find a factor\n");
        printf("[*] RSA-RHO: this can happen with larger or harder semiprimes\n");
        printf("[*] RSA-RHO: try RSA-ECM with higher bounds, RSA-FACTOR for close primes, or RSA-KNOWNPQ if p/q are known\n");
        return 0;
    }

    mpz_fdiv_q(q, n, p);

    mpz_mul(tmp, p, q);
    if (mpz_cmp(tmp, n) != 0) {
        printf("[-] RSA-RHO: factorization sanity check failed\n");
        return 0;
    }

    gmp_printf("[+] p = %Zd\n", p);
    gmp_printf("[+] q = %Zd\n", q);

    mpz_t p1, q1;
    mpz_inits(p1, q1, NULL);

    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    mpz_clears(p1, q1, NULL);



    if (mpz_invert(d, e_mpz, phi) == 0) {
        printf("[-] RSA-RHO: modular inverse failed (bad phi or e)\n");
        return 0;
    }

    printf("\nKey Recovery\n");
    printf("------------\n");
    gmp_printf("d = %Zd\n", d);

    mpz_powm(m, c, d, n);

    printf("\nPlaintext Recovery\n");
    printf("------------------\n");
    gmp_printf("m = %Zd\n", m);

    char *hex = mpz_get_str(NULL, 16, m);
    printf("Hex plaintext:\n%s\n", hex);

	printf("\nDecoded ASCII:\n");

	size_t hex_len = strlen(hex);

	/* Pad odd-length hex values with a leading zero */
	size_t start = 0;
	if (hex_len % 2 != 0) {
	    char byte_hex[3] = { '0', hex[0], '\0' };
	    unsigned int byte = 0;

	    if (sscanf(byte_hex, "%02x", &byte) == 1) {
		if (byte >= 32 && byte <= 126)
		    putchar((char)byte);
		else
		    putchar('.');
	    }

	    start = 1;
	}

	for (size_t i = start; i + 1 < hex_len; i += 2) {
	    char byte_hex[3] = { hex[i], hex[i + 1], '\0' };
	    unsigned int byte = 0;

	    if (sscanf(byte_hex, "%02x", &byte) == 1) {
		if (byte >= 32 && byte <= 126)
		    putchar((char)byte);
		else
		    putchar('.');
	    }
	}

	putchar('\n');

    free(hex);
    return 1;
}


