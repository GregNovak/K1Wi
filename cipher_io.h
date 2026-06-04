#ifndef OPUS_CIPHER_IO_H
#define OPUS_CIPHER_IO_H

#include "state.h"

int opus_load_cipher(const char *path, cipher_t *out);
uint8_t *opus_load_entire_file(const char *path, size_t *out_size);

#endif

