// mini_rsa.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <gmp.h>
#include "mini_rsa.h"
#include "rsa_common.h"


void stringAnalyzerFromBuffer(const char *buf);



static int parse_line_prefix(const char *line, const char *prefix, char **out_value) {
    size_t plen = strlen(prefix);
    if (strncmp(line, prefix, plen) != 0)
        return 0;

    const char *p = line + plen;

    while (*p == ' ' || *p == '\t')
        p++;

    size_t len = strlen(p);
    while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r'))
        len--;

    char *val = malloc(len + 1);
    if (!val) return -1;

    memcpy(val, p, len);
    val[len] = '\0';
    *out_value = val;
    return 1;
}

static __attribute__((unused)) int read_rsa_values(const char *filename, mpz_t N, unsigned long *e, mpz_t c){
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    char buf[4096];
    char *n_str = NULL;
    char *e_str = NULL;
    char *c_str = NULL;

    while (fgets(buf, sizeof(buf), fp)) {
        char *val = NULL;

        int r = parse_line_prefix(buf, "N:", &val);
        if (r == 1) {
            n_str = val;
            continue;
        } else if (r < 0) {
            goto fail;
        }

        r = parse_line_prefix(buf, "e:", &val);
        if (r == 1) {
            e_str = val;
            continue;
        } else if (r < 0) {
            goto fail;
        }

        r = parse_line_prefix(buf, "ciphertext (c):", &val);
        if (r == 1) {
            c_str = val;
            continue;
        } else if (r < 0) {
            goto fail;
        }
    }

    fclose(fp);

    if (!n_str || !e_str || !c_str) {
        fprintf(stderr, "mini_rsa: missing N, e, or ciphertext (c) in %s\n", filename);
        goto fail_no_fp;
    }

    if (mpz_set_str(N, n_str, 10) != 0) {
        fprintf(stderr, "mini_rsa: failed to parse N\n");
        goto fail_no_fp;
    }

    char *endptr = NULL;
    unsigned long e_val = strtoul(e_str, &endptr, 10);
    if (endptr == e_str || *endptr != '\0') {
        fprintf(stderr, "mini_rsa: failed to parse e\n");
        goto fail_no_fp;
    }
    *e = e_val;

    if (mpz_set_str(c, c_str, 10) != 0) {
        fprintf(stderr, "mini_rsa: failed to parse ciphertext c\n");
        goto fail_no_fp;
    }

    free(n_str);
    free(e_str);
    free(c_str);
    return 0;

fail:
    fclose(fp);
fail_no_fp:
    free(n_str);
    free(e_str);
    free(c_str);
    return -1;
}

static __attribute__((unused)) void dump_plaintext(const mpz_t M) {
    size_t count = 0;
    unsigned char *buf = mpz_export(NULL, &count, 1, 1, 1, 0, M);
    if (!buf) {
        fprintf(stderr, "mini_rsa: mpz_export failed\n");
        return;
    }

    printf("[+] Plaintext bytes (%zu bytes):\n", count);
    for (size_t i = 0; i < count; i++)
        printf("%02x", buf[i]);
    printf("\n");

    int fully_printable = 1;
    for (size_t i = 0; i < count; i++) {
        if (buf[i] != 0x09 && buf[i] != 0x0a && buf[i] != 0x0d &&
            (buf[i] < 0x20 || buf[i] > 0x7e)) {
            fully_printable = 0;
            break;
        }
    }

    if (fully_printable) {
        printf("[+] ASCII:\n");
        fwrite(buf, 1, count, stdout);
        printf("\n");
    } else {
        printf("[+] ASCII (best-effort printable slice):\n");
        size_t start = 0;
        while (start < count && !isprint(buf[start]) && buf[start] != '{')
            start++;
        size_t end = count;
        while (end > start && !isprint(buf[end - 1]) && buf[end - 1] != '}')
            end--;

        if (end > start) {
            fwrite(buf + start, 1, end - start, stdout);
            printf("\n");
        } else {
            printf("   (no obvious printable region)\n");
        }
    }

    free(buf);
}

int opus_mini_rsa(const char *path) {
    mpz_t N, e, c, x, m, test;
    mpz_inits(N, e, c, x, m, test, NULL);

    // ------------------------------------------------------------
    // Use the shared RSA parser (no FILE*, no fgets, no brittle logic)
    // ------------------------------------------------------------
    if (parse_rsa_file(path, N, e, c) != 0) {
        printf("mini_rsa: failed to parse %s\n", path);
        mpz_clears(N, e, c, x, m, test, NULL);
        return 0;
    }


    // ------------------------------------------------------------
    // Only support e = 3 for this attack
    // ------------------------------------------------------------
    if (mpz_cmp_ui(e, 3) != 0) {
        printf("mini_rsa: only e=3 supported for this attack\n");
        mpz_clears(N, e, c, x, m, test, NULL);
        return 0;
    }

    printf("[*] mini_rsa: starting search for small k\n");

    long start_k = 0;
    long end_k   = 5000000;   // tune as needed

    for (long k = start_k; k <= end_k; k++) {

        // x = c + k*N
        mpz_mul_ui(x, N, k);
        mpz_add(x, x, c);

        // m = floor(cuberoot(x))
        mpz_root(m, x, 3);

        // test = m^3
        mpz_pow_ui(test, m, 3);

        // Check exact cube
        if (mpz_cmp(test, x) == 0) {
            gmp_printf("[+] Found exact cube at k=%ld\nm = %Zd\n", k, m);

            char *hex = mpz_to_hex_string(m);
            printf("Hex plaintext:\n%s\n", hex);

            printf("\n--- Running stringAnalyzer() on plaintext ---\n");
            stringAnalyzerFromBuffer(hex);

            free(hex);
            mpz_clears(N, e, c, x, m, test, NULL);
            return 1;
        }

        if (k % 100000 == 0)
            printf("  checked k=%ld...\n", k);
    }

    printf("[-] mini_rsa: no exact cube found in range\n");
    mpz_clears(N, e, c, x, m, test, NULL);
    return 0;
}


void opus_print_plaintext_from_bigint(const mpz_t m)
{
    // Convert mpz_t → hex → bytes
    char *hex = mpz_get_str(NULL, 16, m);

    // Ensure even length
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        char *fixed = malloc(len + 2);
        fixed[0] = '0';
        strcpy(fixed + 1, hex);
        free(hex);
        hex = fixed;
        len++;
    }

    printf("Plaintext (hex): %s\n", hex);

    printf("Plaintext (ASCII): ");
    for (size_t i = 0; i < len; i += 2) {
        char byte_str[3] = { hex[i], hex[i+1], 0 };
        unsigned int byte;
        sscanf(byte_str, "%x", &byte);
        printf("%c", (char)byte);
    }
    printf("\n");

    free(hex);
}

