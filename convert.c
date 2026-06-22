#include <ctype.h>
#include <errno.h>
#include <gmp.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void convert_usage(void) {
    printf("CONVERT - Numeric / Encoding Conversion Helper\n\n");
    printf("Usage:\n");
    printf("  CONVERT --hex-to-int <hex>\n");
    printf("  CONVERT --int-to-hex <integer>\n");
    printf("  CONVERT --bytes-to-long <file>\n");
    printf("  CONVERT --long-to-bytes <integer> [--out file]\n");
    printf("  CONVERT --ascii-to-hex <text>\n");
    printf("  CONVERT --hex-to-ascii <hex>\n");
    printf("  CONVERT --base64-to-hex <base64>\n");
    printf("  CONVERT --hex-to-base64 <hex>\n");
    printf("  CONVERT --sha256-to-int <file>\n");
    printf("  CONVERT --sha256-text-to-int <text>\n");
    printf("\nAliases:\n");
    printf("  NUMCONV may be used as an alias for CONVERT.\n");
}

static int is_command_name(const char *s) {
    return s != NULL &&
           (strcasecmp(s, "CONVERT") == 0 || strcasecmp(s, "NUMCONV") == 0);
}

static int hex_value(int ch) {
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static char *dup_range_without_outer_quotes(const char *input) {
    size_t len = strlen(input);

    if (len >= 2U &&
        ((input[0] == '"' && input[len - 1U] == '"') ||
         (input[0] == '\'' && input[len - 1U] == '\''))) {
        char *out = malloc(len - 1U);
        if (out == NULL)
            return NULL;

        memcpy(out, input + 1U, len - 2U);
        out[len - 2U] = '\0';
        return out;
    }

    char *out = malloc(len + 1U);
    if (out == NULL)
        return NULL;

    memcpy(out, input, len + 1U);
    return out;
}

static char *join_args_with_spaces(int argc, char **argv, int start) {
    size_t total = 0U;

    for (int i = start; i < argc; i++)
        total += strlen(argv[i]) + 1U;

    char *joined = malloc(total + 1U);
    if (joined == NULL)
        return NULL;

    joined[0] = '\0';

    for (int i = start; i < argc; i++) {
        if (i > start)
            strcat(joined, " ");
        strcat(joined, argv[i]);
    }

    char *clean = dup_range_without_outer_quotes(joined);
    free(joined);

    return clean;
}

static char *normalize_hex(const char *input) {
    size_t in_len = strlen(input);
    char *tmp = malloc(in_len + 2U);
    if (tmp == NULL)
        return NULL;

    size_t j = 0;
    size_t i = 0;

    while (isspace((unsigned char)input[i]))
        i++;

    if (input[i] == '0' && (input[i + 1U] == 'x' || input[i + 1U] == 'X'))
        i += 2U;

    for (; input[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)input[i];

        if (isspace(ch) || ch == ':' || ch == '_' || ch == '-' || ch == '"' || ch == '\'')
            continue;

        if (!isxdigit(ch)) {
            free(tmp);
            return NULL;
        }

        tmp[j++] = (char)ch;
    }

    if (j == 0U) {
        free(tmp);
        return NULL;
    }

    if ((j % 2U) != 0U) {
        memmove(tmp + 1U, tmp, j);
        tmp[0] = '0';
        j++;
    }

    tmp[j] = '\0';
    return tmp;
}

static int read_file_bytes(const char *path, unsigned char **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "CONVERT: failed to open '%s': %s\n", path, strerror(errno));
        return 0;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "CONVERT: failed to seek '%s'\n", path);
        fclose(fp);
        return 0;
    }

    long len = ftell(fp);
    if (len < 0) {
        fprintf(stderr, "CONVERT: failed to determine size of '%s'\n", path);
        fclose(fp);
        return 0;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "CONVERT: failed to rewind '%s'\n", path);
        fclose(fp);
        return 0;
    }

    unsigned char *buf = NULL;
    if (len > 0) {
        buf = malloc((size_t)len);
        if (buf == NULL) {
            fprintf(stderr, "CONVERT: allocation failed\n");
            fclose(fp);
            return 0;
        }

        size_t got = fread(buf, 1U, (size_t)len, fp);
        if (got != (size_t)len) {
            fprintf(stderr, "CONVERT: failed to read '%s'\n", path);
            free(buf);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    *out = buf;
    *out_len = (size_t)len;
    return 1;
}

static void print_hex_bytes(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static void print_safe_ascii(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = buf[i];
        putchar((ch >= 32U && ch <= 126U) ? (int)ch : '.');
    }
}

static unsigned char *hex_to_bytes_alloc(const char *hex, size_t *out_len) {
    char *clean = normalize_hex(hex);
    if (clean == NULL)
        return NULL;

    size_t hex_len = strlen(clean);
    size_t len = hex_len / 2U;

    unsigned char *buf = malloc(len == 0U ? 1U : len);
    if (buf == NULL) {
        free(clean);
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        int hi = hex_value((unsigned char)clean[i * 2U]);
        int lo = hex_value((unsigned char)clean[i * 2U + 1U]);

        if (hi < 0 || lo < 0) {
            free(clean);
            free(buf);
            return NULL;
        }

        buf[i] = (unsigned char)((hi << 4) | lo);
    }

    free(clean);
    *out_len = len;
    return buf;
}

static int mode_hex_to_int(const char *hex) {
    char *clean = normalize_hex(hex);
    if (clean == NULL) {
        fprintf(stderr, "CONVERT: invalid hex input\n");
        return 1;
    }

    mpz_t n;
    mpz_init(n);

    if (mpz_set_str(n, clean, 16) != 0) {
        fprintf(stderr, "CONVERT: failed to parse hex input\n");
        mpz_clear(n);
        free(clean);
        return 1;
    }

    printf("[*] CONVERT: hex-to-int\n");
    printf("Hex: %s\n", clean);
    gmp_printf("Integer: %Zd\n", n);

    mpz_clear(n);
    free(clean);
    return 0;
}

static int mode_int_to_hex(const char *integer) {
    mpz_t n;
    mpz_init(n);

    if (mpz_set_str(n, integer, 10) != 0 || mpz_sgn(n) < 0) {
        fprintf(stderr, "CONVERT: invalid non-negative integer input\n");
        mpz_clear(n);
        return 1;
    }

    char *hex = mpz_get_str(NULL, 16, n);
    if (hex == NULL) {
        fprintf(stderr, "CONVERT: conversion failed\n");
        mpz_clear(n);
        return 1;
    }

    printf("[*] CONVERT: int-to-hex\n");
    gmp_printf("Integer: %Zd\n", n);
    printf("Hex: %s\n", hex);

    free(hex);
    mpz_clear(n);
    return 0;
}

static int mode_bytes_to_long(const char *path) {
    unsigned char *buf = NULL;
    size_t len = 0;

    if (!read_file_bytes(path, &buf, &len))
        return 1;

    mpz_t n;
    mpz_init(n);

    if (len == 0U)
        mpz_set_ui(n, 0U);
    else
        mpz_import(n, len, 1, 1U, 1, 0U, buf);

    printf("[*] CONVERT: bytes-to-long\n");
    printf("File: %s\n", path);
    printf("Bytes: %zu\n", len);
    printf("Hex: ");
    print_hex_bytes(buf, len);
    printf("\n");
    gmp_printf("Integer: %Zd\n", n);

    mpz_clear(n);
    free(buf);
    return 0;
}

static int mode_long_to_bytes(int argc, char **argv, int idx) {
    const char *integer = argv[idx + 1];
    const char *out_path = NULL;

    if (idx + 2 < argc) {
        if (idx + 4 == argc && strcmp(argv[idx + 2], "--out") == 0) {
            out_path = argv[idx + 3];
        } else {
            fprintf(stderr, "CONVERT: Usage: CONVERT --long-to-bytes <integer> [--out file]\n");
            return 1;
        }
    }

    mpz_t n;
    mpz_init(n);

    if (mpz_set_str(n, integer, 10) != 0 || mpz_sgn(n) < 0) {
        fprintf(stderr, "CONVERT: invalid non-negative integer input\n");
        mpz_clear(n);
        return 1;
    }

    size_t count = 0;
    unsigned char *buf = NULL;

    if (mpz_sgn(n) == 0) {
        buf = malloc(1U);
        if (buf == NULL) {
            mpz_clear(n);
            return 1;
        }
        buf[0] = 0U;
        count = 1U;
    } else {
        buf = mpz_export(NULL, &count, 1, 1U, 1, 0U, n);
        if (buf == NULL) {
            fprintf(stderr, "CONVERT: mpz_export failed\n");
            mpz_clear(n);
            return 1;
        }
    }

    printf("[*] CONVERT: long-to-bytes\n");
    gmp_printf("Integer: %Zd\n", n);
    printf("Bytes: %zu\n", count);
    printf("Hex: ");
    print_hex_bytes(buf, count);
    printf("\n");
    printf("ASCII: ");
    print_safe_ascii(buf, count);
    printf("\n");

    if (out_path != NULL) {
        FILE *fp = fopen(out_path, "wb");
        if (fp == NULL) {
            fprintf(stderr, "CONVERT: failed to open output '%s': %s\n", out_path, strerror(errno));
            free(buf);
            mpz_clear(n);
            return 1;
        }

        if (fwrite(buf, 1U, count, fp) != count) {
            fprintf(stderr, "CONVERT: failed to write output '%s'\n", out_path);
            fclose(fp);
            free(buf);
            mpz_clear(n);
            return 1;
        }

        fclose(fp);
        printf("Output: %s\n", out_path);
    }

    free(buf);
    mpz_clear(n);
    return 0;
}

static int mode_ascii_to_hex(const char *text) {
    const unsigned char *buf = (const unsigned char *)text;
    size_t len = strlen(text);

    printf("[*] CONVERT: ascii-to-hex\n");
    printf("ASCII: %s\n", text);
    printf("Hex: ");
    print_hex_bytes(buf, len);
    printf("\n");
    return 0;
}

static int mode_hex_to_ascii(const char *hex) {
    size_t len = 0;
    unsigned char *buf = hex_to_bytes_alloc(hex, &len);
    if (buf == NULL) {
        fprintf(stderr, "CONVERT: invalid hex input\n");
        return 1;
    }

    printf("[*] CONVERT: hex-to-ascii\n");
    printf("Hex: ");
    print_hex_bytes(buf, len);
    printf("\n");
    printf("ASCII: ");
    print_safe_ascii(buf, len);
    printf("\n");

    free(buf);
    return 0;
}

static int mode_base64_to_hex(const char *b64) {
    size_t in_len = strlen(b64);
    if (in_len > (size_t)INT_MAX) {
        fprintf(stderr, "CONVERT: base64 input too large\n");
        return 1;
    }

    size_t out_cap = ((in_len / 4U) + 1U) * 3U + 4U;
    unsigned char *out = malloc(out_cap);
    if (out == NULL)
        return 1;

    int out_len = EVP_DecodeBlock(out, (const unsigned char *)b64, (int)in_len);
    if (out_len < 0) {
        fprintf(stderr, "CONVERT: invalid base64 input\n");
        free(out);
        return 1;
    }

    size_t real_len = (size_t)out_len;
    while (in_len > 0U && b64[in_len - 1U] == '=') {
        real_len--;
        in_len--;
    }

    printf("[*] CONVERT: base64-to-hex\n");
    printf("Hex: ");
    print_hex_bytes(out, real_len);
    printf("\n");
    printf("ASCII: ");
    print_safe_ascii(out, real_len);
    printf("\n");

    free(out);
    return 0;
}

static int mode_hex_to_base64(const char *hex) {
    size_t len = 0;
    unsigned char *buf = hex_to_bytes_alloc(hex, &len);
    if (buf == NULL) {
        fprintf(stderr, "CONVERT: invalid hex input\n");
        return 1;
    }

    if (len > (size_t)((INT_MAX - 4) / 4 * 3)) {
        fprintf(stderr, "CONVERT: hex input too large for base64 conversion\n");
        free(buf);
        return 1;
    }

    size_t out_cap = 4U * ((len + 2U) / 3U) + 1U;
    unsigned char *out = malloc(out_cap);
    if (out == NULL) {
        free(buf);
        return 1;
    }

    int out_len = EVP_EncodeBlock(out, buf, (int)len);
    if (out_len < 0) {
        fprintf(stderr, "CONVERT: base64 encode failed\n");
        free(out);
        free(buf);
        return 1;
    }

    printf("[*] CONVERT: hex-to-base64\n");
    printf("Base64: %s\n", out);

    free(out);
    free(buf);
    return 0;
}

static int digest_to_int(const unsigned char digest[SHA256_DIGEST_LENGTH], const char *label) {
    mpz_t n;
    mpz_init(n);
    mpz_import(n, SHA256_DIGEST_LENGTH, 1, 1U, 1, 0U, digest);

    printf("[*] CONVERT: %s\n", label);
    printf("SHA256: ");
    print_hex_bytes(digest, SHA256_DIGEST_LENGTH);
    printf("\n");
    gmp_printf("Integer: %Zd\n", n);

    mpz_clear(n);
    return 0;
}

static int mode_sha256_to_int(const char *path) {
    unsigned char *buf = NULL;
    size_t len = 0;
    unsigned char digest[SHA256_DIGEST_LENGTH];

    if (!read_file_bytes(path, &buf, &len))
        return 1;

    SHA256(buf, len, digest);

    printf("File: %s\n", path);
    printf("Bytes: %zu\n", len);

    free(buf);
    return digest_to_int(digest, "sha256-to-int");
}

static int mode_sha256_text_to_int(const char *text) {
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char *)text, strlen(text), digest);

    printf("Text: %s\n", text);
    printf("Bytes: %zu\n", strlen(text));

    return digest_to_int(digest, "sha256-text-to-int");
}

int cmd_convert(int argc, char **argv) {
    int idx = 0;

    if (argc > 0 && is_command_name(argv[0]))
        idx = 1;

    if (idx >= argc) {
        convert_usage();
        return 1;
    }

    const char *mode = argv[idx];

    if (strcmp(mode, "--help") == 0 || strcmp(mode, "-h") == 0) {
        convert_usage();
        return 0;
    }

    if (idx + 1 >= argc) {
        fprintf(stderr, "CONVERT: missing value for %s\n", mode);
        convert_usage();
        return 1;
    }

    if (strcmp(mode, "--hex-to-int") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_hex_to_int(value);
        free(value);
        return rc;
    }

    if (strcmp(mode, "--int-to-hex") == 0 && idx + 2 == argc)
        return mode_int_to_hex(argv[idx + 1]);

    if (strcmp(mode, "--bytes-to-long") == 0 && idx + 2 == argc)
        return mode_bytes_to_long(argv[idx + 1]);

    if (strcmp(mode, "--long-to-bytes") == 0 && idx + 2 <= argc)
        return mode_long_to_bytes(argc, argv, idx);

    if (strcmp(mode, "--ascii-to-hex") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_ascii_to_hex(value);
        free(value);
        return rc;
    }

    if (strcmp(mode, "--hex-to-ascii") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_hex_to_ascii(value);
        free(value);
        return rc;
    }

    if (strcmp(mode, "--base64-to-hex") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_base64_to_hex(value);
        free(value);
        return rc;
    }

    if (strcmp(mode, "--hex-to-base64") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_hex_to_base64(value);
        free(value);
        return rc;
    }

    if (strcmp(mode, "--sha256-to-int") == 0 && idx + 2 == argc)
        return mode_sha256_to_int(argv[idx + 1]);

    if (strcmp(mode, "--sha256-text-to-int") == 0) {
        char *value = join_args_with_spaces(argc, argv, idx + 1);
        if (value == NULL)
            return 1;
        int rc = mode_sha256_text_to_int(value);
        free(value);
        return rc;
    }

    fprintf(stderr, "CONVERT: invalid arguments\n");
    convert_usage();
    return 1;
}

