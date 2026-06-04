/* rsa_knownpq.h */

#ifndef RSA_KNOWNPQ_H
#define RSA_KNOWNPQ_H

#include <gmp.h>
#include <stdbool.h>

/* Decrypt RSA ciphertext when p and q are already known.
 *  path: file containing N, e, c (same format as other RSA modules)
 *  p_str, q_str: decimal strings for p and q
 *
 * Returns true on success, false on failure (with messages printed).
 */
bool opus_rsa_knownpq(const char *path, const char *p_str, const char *q_str);

#endif /* RSA_KNOWNPQ_H */

