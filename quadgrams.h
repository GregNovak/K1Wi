#ifndef QUADGRAMS_H
#define QUADGRAMS_H

#include <stdbool.h>
#include "state.h"

/* Load quadgram model from a file */
bool load_quadgram_model(const char *path, quadgram_model_t *model);

/* Load default quadgram model (english_quadgrams.txt) */
int quadgrams_load_default(quadgram_model_t *model);

/* Free quadgram model resources */
void quadgrams_free(quadgram_model_t *model);

#endif

