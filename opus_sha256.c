#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "sha256.h"
#include "opus_sha256.h"   /* declares verify_sha256_hash + verify_sha256_sidecar */


/* Normalize hex string: strip whitespace, lowercase */
static void normalize_hex(char *s)
{
    char *w = s;
    for (char *r = s; *r; ++r) {
        if (isspace((unsigned char)*r)) continue;
        *w++ = (char)tolower((unsigned char)*r);
    }
    *w = '\0';
}

/* Returns:
 *   1 match
 *   0 mismatch
 *  -1 error (e.g. file I/O)
 */
int verify_sha256_hash(const char *filename, const char *expected_hex)
{
    char actual[65];
    char expected[65];

    if (sha256_file(filename, actual) != 0) {
        return -1;
    }

    strncpy(expected, expected_hex, sizeof(expected) - 1);
    expected[sizeof(expected) - 1] = '\0';

    normalize_hex(actual);
    normalize_hex(expected);

    if (strlen(expected) != 64) {
        return 0;
    }

    return (strcmp(actual, expected) == 0) ? 1 : 0;
}

/* Sidecar format: "<hash>  <filename>" */
int verify_sha256_sidecar(const char *filename, const char *sidecar_path)
{
    FILE *f = fopen(sidecar_path, "r");
    if (!f) {
        return -1;
    }

    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char *hash = strtok(line, " \t\r\n");
    if (!hash) {
        return -1;
    }

    return verify_sha256_hash(filename, hash);
}

/*
 * Main entry:
 *   SHA256 <file>
 *   SHA256 -verify <file> <hash>
 *   SHA256 -compare <file1> <file2>
 *   SHA256 -sidecar <file> <file.sha256>
 */
int opus_cmd_sha256(int argc, char **argv)
{
    if (argc < 2) {
        printf("SHA256: not enough arguments\n");
        printf("Usage:\n");
        printf("  SHA256 <file>\n");
        printf("  SHA256 -verify <file> <hash>\n");
        printf("  SHA256 -compare <file1> <file2>\n");
        printf("  SHA256 -sidecar <file> <file.sha256>\n");
        return -1;
    }

    if (strcmp(argv[1], "-verify") == 0) {
        if (argc < 4) {
            printf("SHA256 -verify: need <file> and <hash>\n");
            return -1;
        }

        const char *file = argv[2];
        const char *hash = argv[3];

        int res = verify_sha256_hash(file, hash);
        if (res < 0) {
            printf("SHA256: error reading '%s'\n", file);
            return -1;
        } else if (res == 1) {
            printf("SHA256 OK\n");
        } else {
            printf("SHA256 MISMATCH\n");
        }
        return (res == 1) ? 0 : 1;
    }

    if (strcmp(argv[1], "-compare") == 0) {
        if (argc < 4) {
            printf("SHA256 -compare: need <file1> and <file2>\n");
            return -1;
        }

        const char *file1 = argv[2];
        const char *file2 = argv[3];

        char h1[65], h2[65];

        if (sha256_file(file1, h1) != 0) {
            printf("SHA256: cannot read '%s'\n", file1);
            return -1;
        }
        if (sha256_file(file2, h2) != 0) {
            printf("SHA256: cannot read '%s'\n", file2);
            return -1;
        }

        normalize_hex(h1);
        normalize_hex(h2);

        if (strcmp(h1, h2) == 0) {
            printf("SHA256 MATCH\n");
            return 0;
        } else {
            printf("SHA256 DIFFER\n");
            printf("  %s: %s\n", file1, h1);
            printf("  %s: %s\n", file2, h2);
            return 1;
        }
    }

    if (strcmp(argv[1], "-sidecar") == 0) {
        if (argc < 4) {
            printf("SHA256 -sidecar: need <file> and <file.sha256>\n");
            return -1;
        }

        const char *file    = argv[2];
        const char *sidecar = argv[3];

        int res = verify_sha256_sidecar(file, sidecar);
        if (res < 0) {
            printf("SHA256: error reading sidecar '%s' or file '%s'\n", sidecar, file);
            return -1;
        } else if (res == 1) {
            printf("SHA256 OK (sidecar)\n");
        } else {
            printf("SHA256 MISMATCH (sidecar)\n");
        }
        return (res == 1) ? 0 : 1;
    }

    /* Default: SHA256 <file> */
    const char *file = argv[1];
    char hash[65];

    if (sha256_file(file, hash) != 0) {
        printf("SHA256: cannot read '%s'\n", file);
        return -1;
    }

    printf("SHA256(%s) = %s\n", file, hash);
    return 0;
}

