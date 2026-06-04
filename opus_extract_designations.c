#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "opus_extract_designations.h"

/* Compare by prefix */
static int cmp_prefix(const void *a, const void *b) {
    const designation_t *x = (const designation_t *)a;
    const designation_t *y = (const designation_t *)b;
    return x->prefix - y->prefix;
}

void opus_extract_designations(const char *filename) {
    if (!filename || filename[0] == '\0') {
        printf("[!] No filename loaded. Use O to open a file first.\n");
        return;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("[!] Error opening file");
        return;
    }

    printf("\n--- Designation Extractor (X-YYYY patterns anywhere) ---\n");
    printf("Scanning: %s\n\n", filename);

    /* Load entire file */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }
    long size = ftell(fp);
    if (size < 0) {
        perror("[!] ftell failed");
        fclose(fp);
        return;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }

    size_t file_size = (size_t)size;

    char *buf = malloc(file_size + 1);
    if (!buf) {
        printf("[!] Memory allocation failed.\n");
        fclose(fp);
        return;
    }
    size_t read_bytes = fread(buf, 1, file_size, fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    designation_t *list = NULL;
    size_t count = 0;

    /* Sliding window: digit '-' digit digit digit digit */
    for (long i = 0; i + 5 < (long)read_bytes; i++) {
        unsigned char c0 = (unsigned char)buf[i];
        unsigned char c1 = (unsigned char)buf[i+1];
        unsigned char c2 = (unsigned char)buf[i+2];
        unsigned char c3 = (unsigned char)buf[i+3];
        unsigned char c4 = (unsigned char)buf[i+4];
        unsigned char c5 = (unsigned char)buf[i+5];

        if (isdigit(c0) &&
            c1 == '-' &&
            isdigit(c2) &&
            isdigit(c3) &&
            isdigit(c4) &&
            isdigit(c5)) {

            int prefix = c0 - '0';
            int number =
                (c2 - '0') * 1000 +
                (c3 - '0') * 100 +
                (c4 - '0') * 10 +
                (c5 - '0');

            list = realloc(list, (count + 1) * sizeof(designation_t));
            if (!list) {
                printf("[!] Memory allocation failed.\n");
                free(buf);
                return;
            }

            /* We don't care about the name here, so just store a placeholder */
            snprintf(list[count].name, sizeof(list[count].name), "X");
            list[count].prefix = prefix;
            list[count].number = number;
            count++;

            /* Skip ahead past this pattern to avoid overlapping matches */
            i += 5;
        }
    }

    free(buf);

    if (count == 0) {
        printf("[!] No designations found.\n");
        return;
    }

    qsort(list, count, sizeof(designation_t), cmp_prefix);

    printf("Found %zu designations:\n\n", count);
    for (size_t k = 0; k < count; k++) {
        printf("%d-%04d\n", list[k].prefix, list[k].number);
    }

    printf("\n--- End of designation scan ---\n");

    free(list);
}

