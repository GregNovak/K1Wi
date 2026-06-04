#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include "opus_designation_analyze.h"

typedef struct {
    int prefix;   /* X */
    int suffix;   /* YYYY */
} desig_t;

typedef struct {
    int suffix;
    int count;
} suffix_stat_t;

typedef struct {
    int prefix;
    int count;
} prefix_stat_t;

/* ADD THIS HERE — move edge_t typedef up */
typedef struct {
    int from;
    int to;
    int count;
} edge_t;

/* NOW the comparator works */
static int cmp_edge_desc(const void *a, const void *b) {
    const edge_t *x = (const edge_t *)a;
    const edge_t *y = (const edge_t *)b;
    return y->count - x->count;
}

static int cmp_suffix_stat_desc(const void *a, const void *b) {
    const suffix_stat_t *x = (const suffix_stat_t *)a;
    const suffix_stat_t *y = (const suffix_stat_t *)b;
    if (y->count != x->count) return y->count - x->count;
    return x->suffix - y->suffix;
}

static int cmp_prefix_stat_desc(const void *a, const void *b) {
    const prefix_stat_t *x = (const prefix_stat_t *)a;
    const prefix_stat_t *y = (const prefix_stat_t *)b;
    if (y->count != x->count) return y->count - x->count;
    return x->prefix - y->prefix;
}

static int find_suffix_index(suffix_stat_t *arr, size_t n, int suffix) {
    for (size_t i = 0; i < n; i++) {
        if (arr[i].suffix == suffix) return (int)i;
    }
    return -1;
}

static int find_prefix_index(prefix_stat_t *arr, size_t n, int prefix) {
    for (size_t i = 0; i < n; i++) {
        if (arr[i].prefix == prefix) return (int)i;
    }
    return -1;
}

/* simple entropy estimate for suffix distribution */
static double compute_entropy(const suffix_stat_t *stats, size_t n, long total) {
    double H = 0.0;
    for (size_t i = 0; i < n; i++) {
        double p = (double)stats[i].count / (double)total;
        if (p > 0.0) H -= p * log2(p);
    }
    return H;
}

/* hypothesis: suffix % 26 => letter */
static void try_mod26_decode(const desig_t *seq, size_t n) {
    printf("Hypothesis: suffix %% 26 mapped to A-Z:\n");
    printf("Decoded (first 200 chars):\n");
    size_t limit = n < 200 ? n : 200;
    for (size_t i = 0; i < limit; i++) {
        int v = seq[i].suffix % 26;
        char ch = (char)('A' + v);
        putchar(ch);
    }
    printf("\n\n");
}

/* hypothesis: (suffix / 10) % 26 => letter */
static void try_div10_mod26_decode(const desig_t *seq, size_t n) {
    printf("Hypothesis: (suffix / 10) %% 26 mapped to A-Z:\n");
    printf("Decoded (first 200 chars):\n");
    size_t limit = n < 200 ? n : 200;
    for (size_t i = 0; i < limit; i++) {
        int v = (seq[i].suffix / 10) % 26;
        char ch = (char)('A' + v);
        putchar(ch);
    }
    printf("\n\n");
}

/* hypothesis: digit-sum % 26 => letter */
static int digit_sum(int x) {
    int s = 0;
    if (x < 0) x = -x;
    while (x > 0) {
        s += x % 10;
        x /= 10;
    }
    return s;
}

static void try_digit_sum_mod26_decode(const desig_t *seq, size_t n) {
    printf("Hypothesis: digit_sum(suffix) %% 26 mapped to A-Z:\n");
    printf("Decoded (first 200 chars):\n");
    size_t limit = n < 200 ? n : 200;
    for (size_t i = 0; i < limit; i++) {
        int v = digit_sum(seq[i].suffix) % 26;
        char ch = (char)('A' + v);
        putchar(ch);
    }
    printf("\n\n");
}

/* hypothesis: prefix as row, suffix bucket index as column => A-Z grid
   This is exploratory: we map each distinct suffix to an index and
   then combine (prefix, suffix_index) into 0..25 by a simple function. */
static void try_prefix_suffix_grid_decode(const desig_t *seq, size_t n,
                                          const suffix_stat_t *stats,
                                          size_t suffix_count) {
    printf("Hypothesis: prefix+suffix_bucket => A-Z grid (exploratory):\n");
    printf("Decoded (first 200 chars):\n");

    /* map suffix -> bucket index 0..suffix_count-1 by frequency order */
    /* here stats already represent suffixes but we need reverse map */
    /* build lookup: suffix -> rank index */
    int *suffix_to_rank = malloc(sizeof(int) * suffix_count);
    if (!suffix_to_rank) {
        printf("[!] Memory allocation failed.\n\n");
        return;
    }
    for (size_t i = 0; i < suffix_count; i++) {
        suffix_to_rank[i] = (int)i; /* position in stats array */
    }

    size_t limit = n < 200 ? n : 200;
    for (size_t i = 0; i < limit; i++) {
        int suffix = seq[i].suffix;
        int prefix = seq[i].prefix;

        int rank = -1;
        for (size_t j = 0; j < suffix_count; j++) {
            if (stats[j].suffix == suffix) {
                rank = (int)j;
                break;
            }
        }
        if (rank < 0) {
            putchar('?');
            continue;
        }

        /* simple grid mapping: (prefix * 7 + rank) % 26 */
        int v = (prefix * 7 + rank) % 26;
        char ch = (char)('A' + v);
        putchar(ch);
    }
    printf("\n\n");
    free(suffix_to_rank);
}

void opus_designation_analyze(const char *filename) {
    if (!filename || filename[0] == '\0') {
        printf("[!] No filename loaded. Use O to open a file first.\n");
        return;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("[!] Error opening file");
        return;
    }

    printf("\n--- Designation Analysis ---\n");
    printf("Scanning: %s\n\n", filename);

    /* load entire file */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }
    long size = ftell(fp);
    if (size < 0) {
        perror("[!] ftell failed");
        fclose(fp);
        return;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("[!] fseek failed");
        fclose(fp);
        return;
    }

    size_t file_size = (size_t)size;

    char *buf = malloc(file_size + 1);
    
    if (!buf) {
        printf("[!] Memory allocation failed.\n");
        fclose(fp);
        return;
    }

    size_t read_bytes = fread(buf, 1, file_size, fp);
    
    fclose(fp);
    buf[read_bytes] = '\0';

    /* collect sequence */
    desig_t *seq = NULL;
    size_t seq_len = 0;

    for (long i = 0; i + 5 < (long)read_bytes; i++) {
        unsigned char c0 = (unsigned char)buf[i];
        unsigned char c1 = (unsigned char)buf[i+1];
        unsigned char c2 = (unsigned char)buf[i+2];
        unsigned char c3 = (unsigned char)buf[i+3];
        unsigned char c4 = (unsigned char)buf[i+4];
        unsigned char c5 = (unsigned char)buf[i+5];

        if (isdigit(c0) &&
            c1 == '-' &&
            isdigit(c2) &&
            isdigit(c3) &&
            isdigit(c4) &&
            isdigit(c5)) {

            int prefix = c0 - '0';
            int suffix =
                (c2 - '0') * 1000 +
                (c3 - '0') * 100 +
                (c4 - '0') * 10 +
                (c5 - '0');

            desig_t *tmp = realloc(seq, (seq_len + 1) * sizeof(desig_t));
            if (!tmp) {
                printf("[!] Memory allocation failed.\n");
                free(buf);
                free(seq);
                return;
            }
            seq = tmp;
            seq[seq_len].prefix = prefix;
            seq[seq_len].suffix = suffix;
            seq_len++;

            i += 5;
        }
    }

    free(buf);

    if (seq_len == 0) {
        printf("[!] No designations found to analyze.\n");
        free(seq);
        return;
    }

    /* build prefix & suffix stats */
    suffix_stat_t *suffix_stats = NULL;
    size_t suffix_count = 0;

    prefix_stat_t *prefix_stats = NULL;
    size_t prefix_count = 0;

    for (size_t i = 0; i < seq_len; i++) {
        int s = seq[i].suffix;
        int p = seq[i].prefix;

        int si = find_suffix_index(suffix_stats, suffix_count, s);
        if (si == -1) {
            suffix_stat_t *tmp = realloc(suffix_stats, (suffix_count + 1) * sizeof(suffix_stat_t));
            if (!tmp) {
                printf("[!] Memory allocation failed.\n");
                free(seq);
                free(suffix_stats);
                free(prefix_stats);
                return;
            }
            suffix_stats = tmp;
            suffix_stats[suffix_count].suffix = s;
            suffix_stats[suffix_count].count = 1;
            suffix_count++;
        } else {
            suffix_stats[si].count++;
        }

        int pi = find_prefix_index(prefix_stats, prefix_count, p);
        if (pi == -1) {
            prefix_stat_t *tmp2 = realloc(prefix_stats, (prefix_count + 1) * sizeof(prefix_stat_t));
            if (!tmp2) {
                printf("[!] Memory allocation failed.\n");
                free(seq);
                free(suffix_stats);
                free(prefix_stats);
                return;
            }
            prefix_stats = tmp2;
            prefix_stats[prefix_count].prefix = p;
            prefix_stats[prefix_count].count = 1;
            prefix_count++;
        } else {
            prefix_stats[pi].count++;
        }
    }

    /* sort stats by frequency */
    qsort(suffix_stats, suffix_count, sizeof(suffix_stat_t), cmp_suffix_stat_desc);
    qsort(prefix_stats, prefix_count, sizeof(prefix_stat_t), cmp_prefix_stat_desc);

    long total = (long)seq_len;
    double H = compute_entropy(suffix_stats, suffix_count, total);

    printf("Total designations: %ld\n", total);
    printf("Unique suffixes: %zu\n", suffix_count);
    printf("Unique prefixes: %zu\n", prefix_count);
    printf("Suffix entropy (bits): %.4f\n\n", H);

    printf("Top suffixes by frequency:\n");
    printf("Rank | Suffix | Count | RelFreq\n");
    printf("-----+--------+-------+--------\n");
    size_t top = suffix_count < 16 ? suffix_count : 16;
    for (size_t i = 0; i < top; i++) {
        double rel = (double)suffix_stats[i].count / (double)total;
        printf("%4zu | %5d  | %5d | %.4f\n",
               i + 1,
               suffix_stats[i].suffix,
               suffix_stats[i].count,
               rel);
    }
    printf("\n");

    printf("Prefix usage:\n");
    printf("Prefix | Count | RelFreq\n");
    printf("-------+-------+--------\n");
    for (size_t i = 0; i < prefix_count; i++) {
        double rel = (double)prefix_stats[i].count / (double)total;
        printf("%6d | %5d | %.4f\n",
               prefix_stats[i].prefix,
               prefix_stats[i].count,
               rel);
    }
    printf("\n");

    /* simple prefix->suffix distribution dump for a few top prefixes */
    printf("Prefix -> Suffix distribution (first few prefixes):\n");
    size_t max_prefix_show = prefix_count < 5 ? prefix_count : 5;
    for (size_t pi = 0; pi < max_prefix_show; pi++) {
        int p = prefix_stats[pi].prefix;
        printf("Prefix %d:\n", p);
        /* collect suffix counts for this prefix */
        suffix_stat_t *local = NULL;
        size_t local_count = 0;
        for (size_t i = 0; i < seq_len; i++) {
            if (seq[i].prefix != p) continue;
            int s = seq[i].suffix;
            int idx = find_suffix_index(local, local_count, s);
            if (idx == -1) {
                suffix_stat_t *tmp = realloc(local, (local_count + 1) * sizeof(suffix_stat_t));
                if (!tmp) {
                    printf("[!] Memory allocation failed.\n");
                    free(local);
                    break;
                }
                local = tmp;
                local[local_count].suffix = s;
                local[local_count].count = 1;
                local_count++;
            } else {
                local[idx].count++;
            }
        }
        if (local_count > 0) {
            qsort(local, local_count, sizeof(suffix_stat_t), cmp_suffix_stat_desc);
            size_t show = local_count < 8 ? local_count : 8;
            for (size_t i = 0; i < show; i++) {
                printf("   %5d : %d\n", local[i].suffix, local[i].count);
            }
        }
        free(local);
        printf("\n");
    }

    /* adjacency: suffix -> next suffix counts (brief summary) */
    printf("Suffix adjacency (top transitions by count, limited view):\n");


    edge_t *edges = NULL;
    size_t edge_count = 0;

    for (size_t i = 0; i + 1 < seq_len; i++) {
        int a = seq[i].suffix;
        int b = seq[i+1].suffix;
        /* see if edge exists */
        size_t ei;
        int found = 0;
        for (ei = 0; ei < edge_count; ei++) {
            if (edges[ei].from == a && edges[ei].to == b) {
                edges[ei].count++;
                found = 1;
                break;
            }
        }
        if (!found) {
            edge_t *tmp = realloc(edges, (edge_count + 1) * sizeof(edge_t));
            if (!tmp) {
                printf("[!] Memory allocation failed.\n");
                free(edges);
                edges = NULL;
                edge_count = 0;
                break;
            }
            edges = tmp;
            edges[edge_count].from = a;
            edges[edge_count].to = b;
            edges[edge_count].count = 1;
            edge_count++;
        }
    }

    if (edge_count > 0) {

        qsort(edges, edge_count, sizeof(edge_t), cmp_edge_desc);
        size_t show = edge_count < 16 ? edge_count : 16;
        printf("From  ->  To   : Count\n");
        printf("------+-------:------\n");
        for (size_t i = 0; i < show; i++) {
            printf("%5d -> %5d : %d\n",
                   edges[i].from, edges[i].to, edges[i].count);
        }
        printf("\n");
    }

    free(edges);

    /* now try a few numeric->letter hypotheses on the raw sequence */
    try_mod26_decode(seq, seq_len);
    try_div10_mod26_decode(seq, seq_len);
    try_digit_sum_mod26_decode(seq, seq_len);
    try_prefix_suffix_grid_decode(seq, seq_len, suffix_stats, suffix_count);

    printf("--- End of designation analysis ---\n\n");

    free(seq);
    free(suffix_stats);
    free(prefix_stats);
}

