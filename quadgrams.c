#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include "state.h"
#include "quadgrams.h"

bool load_quadgram_model(const char *path, quadgram_model_t *model)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    // Allocate table of size 26^4
    uint32_t size = 26 * 26 * 26 * 26;
    model->table_size = size;
    model->log_probs = malloc(sizeof(double) * size);
    if (!model->log_probs) {
        fclose(fp);
        return false;
    }

    // Initialize all entries to floor log prob
    model->floor_log_prob = log10(0.01 / size);
    for (uint32_t i = 0; i < size; i++) {
        model->log_probs[i] = model->floor_log_prob;
    }

    // Read quadgrams from file: "ABCD -3.456"
    char gram[5];
    double logp;

    while (fscanf(fp, "%4s %lf", gram, &logp) == 2) {
        int a = gram[0] - 'A';
        int b = gram[1] - 'A';
        int c = gram[2] - 'A';
        int d = gram[3] - 'A';

        if (a < 0 || b < 0 || c < 0 || d < 0 ||
            a > 25 || b > 25 || c > 25 || d > 25)
            continue;

        uint32_t idx = (uint32_t)((((a * 26) + b) * 26 + c) * 26 + d);
        model->log_probs[idx] = logp;
    }

    fclose(fp);
    return true;
}


/* Load the default quadgram file */
int quadgrams_load_default(quadgram_model_t *model)
{
    return load_quadgram_model("english_quadgrams.txt", model);
}

/* Free quadgram model resources */
void quadgrams_free(quadgram_model_t *model)
{
    if (model && model->log_probs) {
        free(model->log_probs);
        model->log_probs = NULL;
    }
}

