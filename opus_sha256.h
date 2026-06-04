#ifndef OPUS_SHA256_H
#define OPUS_SHA256_H

int verify_sha256_hash(const char *filename, const char *expected_hex);
int verify_sha256_sidecar(const char *filename, const char *sidecar_path);

#endif

