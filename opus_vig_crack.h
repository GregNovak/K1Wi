#ifndef OPUS_VIG_CRACK_H
#define OPUS_VIG_CRACK_H

// Maximum key length to consider during cracking
#ifndef MAX_VIG_KEYLEN
#define MAX_VIG_KEYLEN 20
#endif

// Crack a Vigenere cipher.
// Parameters:
//   cipher_raw: raw ciphertext (may include punctuation/spaces)
//   key_out: buffer to receive recovered key (A-Z, null-terminated)
//   plain_out: buffer to receive decrypted plaintext (A-Z only)
//   max_keylen: maximum key length to test (1..MAX_VIG_KEYLEN)
//
// Returns:
//   key length on success
//   -1 on failure
int vig_crack(const char *cipher_raw,
              char *key_out,
              char *plain_out,
              int max_keylen,
              int forced_keylen);

#endif

