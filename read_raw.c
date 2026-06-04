#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "opus_read.h"

int opus_read_raw(const char *path,
                  size_t offset,
                  size_t limit,
                  bool hex,
                  bool ascii)
{
    (void)ascii; /* for now: hex+ASCII combined */

    const size_t chunk = 16;
    uint8_t buf[16];
    bool eof = false;
    size_t total = 0;

    while (!eof && (limit == 0 || total < limit)) {
        size_t to_read = chunk;
        if (limit && (limit - total) < chunk) {
            to_read = limit - total;
        }

        ssize_t n = opus_read_bytes(path, buf, offset + total, to_read, &eof);
        if (n <= 0) break;

        if (hex) {
            opus_print_hex_ascii_line(buf, (size_t)n, offset + total);
        } else {
            fwrite(buf, 1, (size_t)n, stdout);
        }

        total += (size_t)n;
    }

    return 0;
}

