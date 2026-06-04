#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa_ecm.h"





/*
 * Uses the external `ecm` binary (GMP-ECM) to factor n.
 * Requires: `ecm` installed and in PATH.
 *
 * Returns 1 on success (factor found), 0 on failure.
 */


int opus_rsa_ecm_factor(const mpz_t n, mpz_t factor)
{
    char n_str[4096];
    gmp_snprintf(n_str, sizeof(n_str), "%Zd", n);

    // temp file for ecm output
    const char *tmp_path = "/tmp/opus_ecm_out.txt";

    // B1 = 1e6, 2000 curves; tune as desired
    char cmd[8192];
    snprintf(cmd, sizeof(cmd),
             "ecm -c 2000 1000000 %s > %s 2>/dev/null",
             n_str, tmp_path);

    int status = system(cmd);
    (void)status; // we’ll just inspect the file

    FILE *fp = fopen(tmp_path, "r");
    if (!fp) {
        fprintf(stderr, "RSA-ECM: failed to open temp file %s\n", tmp_path);
        mpz_set_ui(factor, 0);
        return 0;
    }

    char line[8192];
    char fac_str[8192] = {0};

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Found") != NULL) {
            char *tok = strtok(line, " \t\n");
            char *last = NULL;
            while (tok) {
                last = tok;
                tok = strtok(NULL, " \t\n");
            }
            if (last) {
                strncpy(fac_str, last, sizeof(fac_str) - 1);
                fac_str[sizeof(fac_str) - 1] = '\0';
                break;
            }
        }
    }

    fclose(fp);

    if (fac_str[0] == '\0') {
        mpz_set_ui(factor, 0);
        return 0;
    }

    if (mpz_set_str(factor, fac_str, 10) != 0) {
        fprintf(stderr, "RSA-ECM: failed to parse factor '%s'\n", fac_str);
        mpz_set_ui(factor, 0);
        return 0;
    }

    if (mpz_cmp_ui(factor, 1) <= 0 || mpz_cmp(factor, n) >= 0) {
        mpz_set_ui(factor, 0);
        return 0;
    }

    return 1;
}


