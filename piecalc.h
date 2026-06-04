#ifndef PIECALC_H
#define PIECALC_H

#include <stddef.h>

#define PIECALC_MAX_CANDIDATES 5
int piecalc_list_symbols(const char *path,
                         int json_mode);

int piecalc_nearest_symbols(const char *path,
                            unsigned long long addr,
                            size_t top_n,
                            int json_mode);
                            
int opus_pie_calc(const char *path,
                  const char *leak_symbol,
                  unsigned long long leak_addr,
                  const char *target_symbol,
                  size_t top_n,
                  int json_mode,
                  int base_only,
                  int raw_mode,
                  int offset_only,
                  int verbose_mode);


#endif
