#ifndef OPUS_SECURE_DELETE_CORE_H
#define OPUS_SECURE_DELETE_CORE_H

#include <stdint.h>

typedef enum {
    OPUS_SD_MODE_NIST = 0,   /* single-pass zero overwrite */
    OPUS_SD_MODE_DOD3 = 1,   /* 3-pass: 0xFF, 0x00, random */
    OPUS_SD_MODE_CUSTOM = 2  /* reserved for future use */
} opus_sd_mode_t;

typedef struct {
    opus_sd_mode_t mode;
    int passes;              /* number of passes */
    const uint8_t *patterns; /* pattern array, length >= passes (NULL if random-only) */
    int verify;              /* 0 = no verify, 1 = verify (not yet implemented) */
} opus_sd_policy_t;

/* Fill a policy struct with a preset for the given mode. */
void opus_sd_policy_preset(opus_sd_mode_t mode, opus_sd_policy_t *out);

/* Core secure delete:
 *  - overwrites file contents according to policy
 *  - truncates to zero length
 *  - unlinks the file
 * Returns 0 on success, -1 on error (errno set).
 */
int opus_secure_delete_file(const char *path, const opus_sd_policy_t *policy);

#endif /* OPUS_SECURE_DELETE_CORE_H */

