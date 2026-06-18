#ifndef RSA_FACTOR_H
#define RSA_FACTOR_H

int opus_rsa_factor(const char *filename);
int opus_rsa_factor_with_time(const char *filename, unsigned long time_limit_minutes);

#endif

