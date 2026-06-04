#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
#include <gmp.h>
#include <ctype.h>
#include "rsa_factor.h"
#include "rsa_common.h"


// Provided elsewhere in Opus
extern void stringAnalyzerFromBuffer(const char *buf);

/*
 * Fermat factorization:
 *   n = p * q, with p ≈ q
 *   n = a^2 - b^2 = (a - b)(a + b)
 *   Start at a = ceil(sqrt(n)), increment until a^2 - n is a perfect square.
 *
 * Returns 1 on success, 0 on failure.
 */
static int fermat_factor(mpz_t p, mpz_t q, const mpz_t n) {
    mpz_t a, b2, b;
    mpz_inits(a, b2, b, NULL);

    // a = ceil(sqrt(n))
    mpz_sqrt(a, n);
    if (mpz_cmp_ui(a, 0) == 0 || mpz_cmp(a, n) < 0)
        mpz_add_ui(a, a, 1);

    long iter = 0;
    const long max_iter = 5000000;  // safety cap; adjust as needed

    while (1) {
        // b2 = a^2 - n
        mpz_mul(b2, a, a);
        mpz_sub(b2, b2, n);

        // If b2 is a perfect square, we found p and q
        if (mpz_perfect_square_p(b2)) {
            mpz_sqrt(b, b2);

            mpz_sub(p, a, b);
            mpz_add(q, a, b);

            mpz_clears(a, b2, b, NULL);
            return 1;
        }

        mpz_add_ui(a, a, 1);
        iter++;

        if (iter % 100000 == 0) {
            gmp_printf("[DEBUG] Fermat: a=%Zd (steps=%ld)\n", a, iter);
        }

        if (iter > max_iter) {
            printf("[-] RSA-Factor: Fermat exceeded %ld iterations, giving up\n", max_iter);
            mpz_clears(a, b2, b, NULL);
            return 0;
        }
    }
}

/*
 * opus_rsa_factor:
 *   - Reads n, e, c from filename (e.g., "rsa_values.txt")
 *   - Factors n using Fermat
 *   - Computes phi, d
 *   - Decrypts c -> m
 *   - Prints plaintext in hex, then runs stringAnalyzerFromBuffer on hex
 *
 * Expected file format:
 *   n: <decimal>
 *   e: <decimal>
 *   c: <decimal>
 */
int opus_rsa_factor(const char *filename) {
    mpz_t n, c, p, q, phi, d, m, e_mpz;
    unsigned long e_ul;
    
    mpz_inits(n, c, p, q, phi, d, m, e_mpz, NULL);

	if (parse_rsa_file(filename, n, e_mpz, c) != 0) {
	    fprintf(stderr, "rsa-factor: failed to parse RSA file '%s'\n", filename);
	    return 0;
	}

	e_ul = mpz_get_ui(e_mpz);


	printf("\nRSA Input\n");
	printf("---------\n");
	gmp_printf("N = %Zd\n", n);
	gmp_printf("e = %Zd\n", e_mpz);
	gmp_printf("c = %Zd\n", c);




    // Basic sanity
    if (mpz_cmp_ui(n, 0) == 0) {
        fprintf(stderr, "RSA-Factor: n is zero, aborting\n");
        return 0;
    }

    printf("[*] RSA-Factor: starting Fermat factorization\n");

    if (!fermat_factor(p, q, n)) {
        printf("[-] RSA-Factor: Fermat failed (no factors found within limit)\n");
        return 0;
    }

    gmp_printf("[+] p = %Zd\n", p);
    gmp_printf("[+] q = %Zd\n", q);

    // phi = (p - 1) * (q - 1)
    mpz_t p1, q1;
    mpz_inits(p1, q1, NULL);

    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    mpz_clears(p1, q1, NULL);

    // d = e^{-1} mod phi
    
    if (mpz_invert(d, e_mpz, phi) == 0) {
        printf("[-] RSA-Factor: modular inverse failed (bad phi or e)\n");
        return 0;
    }

    printf("\nKey Recovery\n");
    printf("------------\n");
    gmp_printf("d = %Zd\n", d);

    // m = c^d mod n
    mpz_powm(m, c, d, n);

    printf("\nPlaintext Recovery\n");
    printf("------------------\n");
    gmp_printf("m = %Zd\n", m);

	// Convert to hex string
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

