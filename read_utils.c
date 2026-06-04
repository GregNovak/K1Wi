#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "opus_read.h"

ssize_t opus_read_bytes(const char *path,
                        uint8_t *buffer,
                        size_t offset,
                        size_t length,
                        bool *hit_eof)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    if (fseek(fp, (long)offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    size_t n = fread(buffer, 1, length, fp);

    if (hit_eof) {
        *hit_eof = (n < length || feof(fp));
    }

    fclose(fp);
    return (ssize_t)n;
}

void opus_print_hex_ascii_line(const uint8_t *buf,
                               size_t len,
                               size_t offset)
{
    printf("%08zx  ", offset);

    for (size_t i = 0; i < 16; i++) {
        if (i < len) printf("%02x ", buf[i]);
        else         printf("   ");
    }

    printf(" ");

    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        printf("%c", (c >= 32 && c <= 126) ? c : '.');
    }

    printf("\n");
}

