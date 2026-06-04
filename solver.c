// solver.c — regenerated, crib‑aware monoalphabetic solver
// Clean, modern, self‑contained hillclimber with forced substitutions

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include "solve.h"
#include "score.h"
#include "state.h"
#include "params.h"

#include "cipher_io.h"


#define ALPH 26

// ---------------- Quadgram Table ----------------

typedef struct {
    char quad[5];
    long count;
    double logp;
} QuadEntry;

typedef struct {
    QuadEntry *arr;
    size_t n;
    long total;
    double floor;
} QuadTable;

static int cmp_quad(const void *a, const void *b) {
    return strcmp(((QuadEntry*)a)->quad, ((QuadEntry*)b)->quad);
}

QuadTable *load_quadgrams(const char *fname) {
    FILE *f = fopen(fname, "r");
    if (!f) return NULL;

    QuadEntry *tmp = NULL;
    size_t cap = 0, n = 0;
    long total = 0;
    char q[64];
    long c;

    while (fscanf(f, "%63s %ld", q, &c) == 2) {
        if (strlen(q) != 4) continue;
        if (n + 1 > cap) {
            cap = cap ? cap * 2 : 1024;
            tmp = realloc(tmp, cap * sizeof(QuadEntry));
            if (!tmp) { fclose(f); return NULL; }
        }
        for (int i = 0; i < 4; i++)
            tmp[n].quad[i] = (char)toupper((unsigned char)q[i]);
        tmp[n].quad[4] = '\0';
        tmp[n].count = c;
        total += c;
        n++;
    }
    fclose(f);

    if (n == 0) { free(tmp); return NULL; }

    qsort(tmp, n, sizeof(QuadEntry), cmp_quad);

    QuadTable *qt = malloc(sizeof(QuadTable));
    qt->arr = tmp;
    qt->n = n;
    qt->total = total;
    qt->floor = log10(0.01 / (double)total);

    for (size_t i = 0; i < n; i++)
        qt->arr[i].logp = log10((double)qt->arr[i].count / (double)total);

    return qt;
}

static double quad_lookup(const QuadTable *qt, const char *quad) {
    size_t lo = 0, hi = qt->n;
    while (lo < hi) {
        size_t mid = (lo + hi) >> 1;
        int cmp = strcmp(qt->arr[mid].quad, quad);
        if (cmp == 0) return qt->arr[mid].logp;
        if (cmp < 0) lo = mid + 1;
        else hi = mid;
    }
    return qt->floor;
}

double quad_score(const QuadTable *qt, const char *text) {
    double s = 0.0;
    size_t L = strlen(text);
    char q[5];
    for (size_t i = 0; i + 3 < L; i++) {
        for (int j = 0; j < 4; j++)
            q[j] = (char)toupper((unsigned char)text[i + (size_t)j]);
        q[4] = '\0';
        s += quad_lookup(qt, q);
    }
    return s;
}

// ---------------- Key Structure ----------------

typedef struct {
    char map[ALPH];     // cipher 'A'+i → plain letter
    int fixed[ALPH];    // 1 = forced mapping
} Key;

void random_key(Key *k) {
    char letters[ALPH];
    for (int i = 0; i < ALPH; i++) letters[i] = (char)('A' + i);

    for (int i = ALPH - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char t = letters[i]; letters[i] = letters[j]; letters[j] = t;
    }
    for (int i = 0; i < ALPH; i++) {
        k->map[i] = letters[i];
        k->fixed[i] = 0;
    }
}

// ---------------- Forced Substitution Parsing ----------------

void apply_forced_spec(Key *k, const char *spec) {
    if (!spec) return;

    const char *p = spec;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        if (!isalpha(p[0]) || p[1] != '=' || !isalpha(p[2])) {
            while (*p && *p != ',') p++;
            if (*p == ',') p++;
            continue;
        }

	char cipher = (char)toupper((unsigned char)p[0]);
	char plain  = (char)toupper((unsigned char)p[2]);

        int ci = cipher - 'A';
        if (ci >= 0 && ci < ALPH) {
            k->map[ci] = plain;
            k->fixed[ci] = 1;
        }

        while (*p && *p != ',') p++;
        if (*p == ',') p++;
    }
}

// ---------------- Decoding ----------------

char *decode(const char *ct, const Key *k) {
    size_t L = strlen(ct);
    char *out = malloc(L + 1);
    for (size_t i = 0; i < L; i++) {
        unsigned char ch = (unsigned char)ct[i];
        if (isalpha(ch)) {
            int ci = toupper(ch) - 'A';
            char p = k->map[ci];
            out[i] = isupper(ch) ? p : (char)tolower((unsigned char)p);
        } else {
            out[i] = (char)ch;
        }
    }
    out[L] = '\0';
    return out;
}

// ---------------- Hillclimber ----------------

void hillclimb(const QuadTable *qt,
               const char *ct,
               Key *start,
               Key *best_out,
               double *best_score_out,
               int iterations,
               double temp,
               double cooling)
{
    Key cur = *start;
    Key best = cur;

    char *dec = decode(ct, &cur);
    double cur_score = quad_score(qt, dec);
    double best_score = cur_score;
    free(dec);

    for (int it = 0; it < iterations; it++) {
        int i, j;
        do { i = rand() % ALPH; } while (cur.fixed[i]);
        do { j = rand() % ALPH; } while (cur.fixed[j] || j == i);

        char t = cur.map[i];
        cur.map[i] = cur.map[j];
        cur.map[j] = t;

        dec = decode(ct, &cur);
        double s = quad_score(qt, dec);
        free(dec);

        double delta = s - cur_score;
        if (delta > 0 || exp(delta / temp) > ((double)rand() / RAND_MAX)) {
            cur_score = s;
            if (s > best_score) {
                best_score = s;
                best = cur;
            }
        } else {
            t = cur.map[i];
            cur.map[i] = cur.map[j];
            cur.map[j] = t;
        }

        temp *= cooling;
    }

    *best_out = best;
    *best_score_out = best_score;
}

// ---------------- Driver ----------------

int run_solver(const char *cipherfile,
               const char *quadfile,
               const char *forced_spec,
               int restarts,
               int iterations)
{
    FILE *f = fopen(cipherfile, "rb");
    if (!f) { fprintf(stderr, "Cannot read %s\n", cipherfile); return 1; }
	if (fseek(f, 0, SEEK_END) != 0) {
	    fclose(f);
	    return 1;
	}

	long sz = ftell(f);
	if (sz < 0) {
	    fclose(f);
	    return 1;
	}

	rewind(f);

	size_t file_size = (size_t)sz;
	char *ct = malloc(file_size + 1);
	if (!ct) {
	    fclose(f);
	    return 1;
	}

	size_t nread = fread(ct, 1, file_size, f);
    
	if (nread != (size_t)sz) {
    	fprintf(stderr, "Warning: fread read %zu bytes (expected %ld)\n", nread, sz);
	}

    ct[file_size] = '\0';
    fclose(f);

    QuadTable *qt = load_quadgrams(quadfile);
    if (!qt) { fprintf(stderr, "Failed to load quadgrams\n"); return 1; }

   srand((unsigned int)(time(NULL) ^ getpid()));

    Key global_best;
    double global_best_score = -1e300;

    for (int r = 0; r < restarts; r++) {
        Key k;
        random_key(&k);
        apply_forced_spec(&k, forced_spec);

        Key best_k;
        double best_s;

        hillclimb(qt, ct, &k, &best_k, &best_s, iterations, 1.0, 0.9996);

        if (best_s > global_best_score) {
            global_best_score = best_s;
            global_best = best_k;

            char *plain = decode(ct, &global_best);
            FILE *out = fopen("solved_preview.txt", "w");
            if (out) { fputs(plain, out); fclose(out); }
            printf("[restart %d] new best score %.4f\n", r, best_s);
            free(plain);
        }
    }

    char *final_plain = decode(ct, &global_best);
    FILE *fout = fopen("solved.txt", "w");
    if (fout) { fputs(final_plain, fout); fclose(fout); }

    printf("Final plaintext written to solved.txt\n");
    printf("Best key:\n");
    for (int i = 0; i < ALPH; i++)
        printf("%c→%c ", 'A'+i, global_best.map[i]);
    printf("\n");

    free(final_plain);
    free(ct);
    free(qt->arr);
    free(qt);

    return 0;
}



