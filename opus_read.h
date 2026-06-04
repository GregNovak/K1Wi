#ifndef OPUS_READ_H
#define OPUS_READ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int opus_read_file(const char *path,
                   bool mode_raw,
                   bool mode_structured,
                   bool mode_safe,
                   size_t limit,
                   size_t offset,
                   size_t page_size,
                   bool ascii,
                   bool hex,
                   const char *force_format,
                   bool verbose,
                   bool summary);

int opus_read_raw(const char *path,
                  size_t offset,
                  size_t limit,
                  bool hex,
                  bool ascii);

int opus_read_structured(const char *path,
                         const char *force_format,
                         bool summary,
                         bool verbose);

int opus_read_safe(const char *path,
                   size_t page_size,
                   size_t limit,
                   bool hex,
                   bool ascii);

ssize_t opus_read_bytes(const char *path,
                        uint8_t *buffer,
                        size_t offset,
                        size_t length,
                        bool *hit_eof);

void opus_print_hex_ascii_line(const uint8_t *buf,
                               size_t len,
                               size_t offset);

#endif /* OPUS_READ_H */

