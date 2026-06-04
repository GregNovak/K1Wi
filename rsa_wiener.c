#include <stdio.h>
#include <gmp.h>
#include "rsa_wiener.h"

/*
 * Wiener attack implementation using GMP mpz_t.
 * Returns 0 on success (d_out set), -1 on failure.
 */

int opus_rsa_wiener_attack(const mpz_t n,
                           const mpz_t e,
                           mpz_t d_out)
{
    // Convergents: k_i / d_i
    mpz_t k_prev2, k_prev1, k_curr;
    mpz_t d_prev2, d_prev1, d_curr;

    // Temporary bigints
    mpz_t a, q, r;
    mpz_t ed_minus_1, phi, sum_pq, disc, tmp, sqrt_disc;

    // Working copies for continued fraction
    mpz_t N, E, n_work, e_work;

    mpz_inits(k_prev2, k_prev1, k_curr,
              d_prev2, d_prev1, d_curr,
              a, q, r,
              ed_minus_1, phi, sum_pq, disc, tmp, sqrt_disc,
              N, E, n_work, e_work, NULL);

    // N <- n, E <- e
    mpz_set(N, n);
    mpz_set(E, e);

    // Seeds:
    // k(-2)=0, k(-1)=1
    // d(-2)=1, d(-1)=0
    mpz_set_ui(k_prev2, 0);
    mpz_set_ui(k_prev1, 1);
    mpz_set_ui(d_prev2, 1);
    mpz_set_ui(d_prev1, 0);

    // Setup working copies
    mpz_set(n_work, n);
    mpz_set(e_work, e);

    // Continued fraction loop
    while (mpz_cmp_ui(n_work, 0) != 0) {

        // q = e_work / n_work, r = e_work % n_work
        mpz_fdiv_qr(q, r, e_work, n_work);

        // a = q
        mpz_set(a, q);

        // k_curr = a*k_prev1 + k_prev2
        mpz_mul(k_curr, a, k_prev1);
        mpz_add(k_curr, k_curr, k_prev2);

        // d_curr = a*d_prev1 + d_prev2
        mpz_mul(d_curr, a, d_prev1);
        mpz_add(d_curr, d_curr, d_prev2);

        // Shift convergents
        mpz_set(k_prev2, k_prev1);
        mpz_set(k_prev1, k_curr);
        mpz_set(d_prev2, d_prev1);
        mpz_set(d_prev1, d_curr);

        // Next CF step
        mpz_set(e_work, n_work);
        mpz_set(n_work, r);

        // Skip if k_curr == 0
        if (mpz_cmp_ui(k_curr, 0) == 0)
            continue;

        // ed_minus_1 = e*d - 1
        mpz_mul(ed_minus_1, e, d_curr);
        mpz_sub_ui(ed_minus_1, ed_minus_1, 1);

        // phi = (e*d - 1) / k, check exact division
        mpz_fdiv_qr(phi, r, ed_minus_1, k_curr);
        if (mpz_cmp_ui(r, 0) != 0)
            continue; // not exact

        // sum_pq = N - phi + 1
        mpz_sub(sum_pq, N, phi);
        mpz_add_ui(sum_pq, sum_pq, 1);

        // disc = (p+q)^2 - 4N
        mpz_mul(disc, sum_pq, sum_pq);
        mpz_mul_ui(tmp, N, 4);
        mpz_sub(disc, disc, tmp);

        if (mpz_sgn(disc) < 0)
            continue;

        // sqrt_disc = sqrt(disc)
        mpz_sqrt(sqrt_disc, disc);

        // Check perfect square
        mpz_mul(tmp, sqrt_disc, sqrt_disc);
        if (mpz_cmp(tmp, disc) != 0)
            continue;

        // SUCCESS: d_curr is the private exponent
        mpz_set(d_out, d_curr);

        mpz_clears(k_prev2, k_prev1, k_curr,
                   d_prev2, d_prev1, d_curr,
                   a, q, r,
                   ed_minus_1, phi, sum_pq, disc, tmp, sqrt_disc,
                   N, E, n_work, e_work, NULL);
        return 0;
    }

    // Failure
    mpz_clears(k_prev2, k_prev1, k_curr,
               d_prev2, d_prev1, d_curr,
               a, q, r,
               ed_minus_1, phi, sum_pq, disc, tmp, sqrt_disc,
               N, E, n_work, e_work, NULL);
    return -1;
}

