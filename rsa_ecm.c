#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "rsa_ecm.h"





/*
 * Uses the external `ecm` binary (GMP-ECM) to factor n.
 * Requires: `ecm` installed and in PATH.
 *
 * Returns 1 on success (factor found), 0 on failure.
 */

static int is_decimal_token(const char *s)
{
    if (!s || *s == '\0')
        return 0;

    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (!isdigit(*p))
            return 0;
    }

    return 1;
}

int opus_rsa_ecm_factor(const mpz_t n, mpz_t factor)
{
    char n_str[4096];
    gmp_snprintf(n_str, sizeof(n_str), "%Zd", n);

    const char *tmp_path = "/tmp/opus_ecm_out.txt";

    for (int attempt = 1; attempt <= 20; attempt++) {
        char cmd[8192];

        snprintf(cmd, sizeof(cmd),
                 "echo %s | ecm -c 1 5000 > %s 2>/dev/null",
                 n_str, tmp_path);

        int status = system(cmd);
        (void)status;

        FILE *fp = fopen(tmp_path, "r");
        if (!fp) {
            fprintf(stderr, "RSA-ECM: failed to open temp file %s\n", tmp_path);
            mpz_set_ui(factor, 0);
            return 0;
        }

        char line[8192];

        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Found") == NULL &&
                strstr(line, "factor") == NULL) {
                continue;
            }

            char *tok = strtok(line, " \t\r\n:=,");
            while (tok) {
                if (is_decimal_token(tok)) {
                    mpz_t candidate;
                    mpz_init(candidate);

                    if (mpz_set_str(candidate, tok, 10) == 0 &&
                        mpz_cmp_ui(candidate, 1) > 0 &&
                        mpz_cmp(candidate, n) < 0) {

                        mpz_set(factor, candidate);
                        mpz_clear(candidate);
                        fclose(fp);
                        return 1;
                    }

                    mpz_clear(candidate);
                }

                tok = strtok(NULL, " \t\r\n:=,");
            }
        }

        fclose(fp);
    }

    mpz_set_ui(factor, 0);
    return 0;
}



