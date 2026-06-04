#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "opus_read.h"

static int read_page(const char *path,
                     size_t page_size,
                     size_t offset,
                     size_t limit,
                     bool *out_eof)
{
    uint8_t buf[4096];

    if (page_size == 0)
        page_size = 64;   /* default */

    if (page_size > sizeof(buf))
        page_size = sizeof(buf);

    size_t to_read = page_size;

    if (limit && offset >= limit) {
        *out_eof = true;
        return 0;
    }

    if (limit && offset + to_read > limit)
        to_read = limit - offset;

    bool eof = false;
    ssize_t n = opus_read_bytes(path, buf, offset, to_read, &eof);
    if (n <= 0) {
        *out_eof = true;
        return 0;
    }

    printf("\n[SAFE] offset 0x%08zx (%zu bytes)\n", offset, (size_t)n);

    /* hex+ASCII line printer already handles formatting */
    opus_print_hex_ascii_line(buf, (size_t)n, offset);

    *out_eof = eof || (limit && offset + (size_t)n >= limit);
    return (int)n;
}

int opus_read_safe(const char *path,
                   size_t page_size,
                   size_t limit,
                   bool hex,
                   bool ascii)
{
    (void)hex;   /* for now: we always print hex+ASCII */
    (void)ascii; /* later: allow hex-only / ascii-only */

    if (page_size == 0)
        page_size = 64;

    size_t current_offset = 0;
    bool eof = false;

    for (;;) {
        int n = read_page(path, page_size, current_offset, limit, &eof);
        if (n <= 0) {
            if (current_offset == 0)
                printf("[SAFE] no data read (empty file or error)\n");
            else
                printf("[SAFE] end of data\n");
            break;
        }

        current_offset += (size_t)n;

        if (eof) {
            printf("[SAFE] EOF reached at offset 0x%zx\n", current_offset);
            break;
        }

        printf("\n[SAFE] Commands: ENTER=next page, b=back, q=quit > ");
        int c = getchar();
        if (c == '\n' || c == '\r') {
            /* next page */
            continue;
        } else if (c == 'q' || c == 'Q') {
            printf("[SAFE] quit\n");
            break;
        } else if (c == 'b' || c == 'B') {
            if (current_offset >= page_size * 2) {
                current_offset -= page_size * 2;
            } else {
                current_offset = 0;
            }
            /* flush rest of line */
            int d;
            while ((d = getchar()) != '\n' && d != EOF) {}
            continue;
        } else {
            /* ignore unknown, just move on */
            int d;
            while ((d = getchar()) != '\n' && d != EOF) {}
            continue;
        }
    }

    return 0;
}

