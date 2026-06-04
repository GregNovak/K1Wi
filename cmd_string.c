#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "cmd_string.h"
#include "string_helpers.h"
#include "opus_string_intel.h"
#include "cipher_io.h"   /* for opus_load_entire_file() */

/*
 * STRING COMMAND — OPUS
 *
 * Usage:
 *   STRING <text>
 *   STRING --file <path> [--min N] [--decode]
 *
 * Runs the universal string analyzer on the provided text,
 * or extracts multiple strings from a file.
 */

static void print_string_result(const OpusStringIntelResult *r, bool show_decode)
{
    printf("Length: %zu\n", r->length);
    printf("Printable: %s\n", r->is_printable ? "yes" : "no");
    printf("Entropy: %.4f\n", r->entropy);

    if (r->detected_type) {
        printf("Detected Type: %s\n", r->detected_type);
    }

    if (show_decode && r->decoded_output) {
        printf("\nDecoded Output:\n%s\n", r->decoded_output);
    }
}

static void print_usage(void)
{
    printf("Usage:\n");
    printf("  STRING <text>\n");
    printf("  STRING --file <path> [--min N] [--decode]\n");
    printf("\nAnalyze a string or extract strings from a file.\n");
}


/*
 * ============================================================
 *  TIER‑2 FEATURE:
 *  Multi‑Hit STRING Extraction from Files
 * ============================================================
 */


int cmd_string_file(const char *path, int min_len, bool decode)
{
    

    size_t fsize = 0;
    uint8_t *buf = opus_load_entire_file(path, &fsize);

    if (!buf) {
        printf("STRING: cannot open '%s'\n", path);
        return -1;
    }

    size_t run_len = 0;
    size_t run_start = 0;

    for (size_t i = 0; i < fsize; i++) {
        if (isprint(buf[i])) {
            if (run_len == 0)
                run_start = i;
            run_len++;
        } else {
            if (run_len >= (size_t)min_len) {
                printf("\n[STRING] offset 0x%08zx (%zu bytes)\n",
                       run_start, run_len);

                char *tmp = malloc(run_len + 1);
                memcpy(tmp, buf + run_start, run_len);
                tmp[run_len] = '\0';

                printf("  Raw: %s\n", tmp);

                OpusStringIntelResult r = opus_string_intel(tmp);
                print_string_result(&r, decode);

		if (r.decoded_output) {
		    free(r.decoded_output);
		}

                free(tmp);
            }
            run_len = 0;
        }
    }

    // Handle trailing run at EOF
    if (run_len >= (size_t)min_len) {
        printf("\n[STRING] offset 0x%08zx (%zu bytes)\n",
               run_start, run_len);

        char *tmp = malloc(run_len + 1);
        memcpy(tmp, buf + run_start, run_len);
        tmp[run_len] = '\0';

        printf("  Raw: %s\n", tmp);

        OpusStringIntelResult r = opus_string_intel(tmp);
        print_string_result(&r, decode);

	if (r.decoded_output) {
	    free(r.decoded_output);
	}
	
	free(tmp);
    }

    free(buf);
    return 0;
}



/*
 * ============================================================
 *  ORIGINAL STRING COMMAND (literal string analyzer)
 * ============================================================
 */
int cmd_string(int argc, char **argv)
{
    /* Tier-2: File-mode detection */
    if (argc >= 3 && strcmp(argv[1], "--file") == 0) {
        const char *path = argv[2];
        size_t min_len = 4;
        bool decode = false;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--min") == 0 && i + 1 < argc) {
                min_len = strtoull(argv[++i], NULL, 10);
            } else if (strcmp(argv[i], "--decode") == 0) {
                decode = true;
            }
        }

        if (min_len > INT_MAX) {
            fprintf(stderr, "STRING: --min value is too large\n");
            return 1;
        }

        return cmd_string_file(path, (int)min_len, decode);
    }

    /* ------------------------------
     * Literal string analysis mode
     * ------------------------------ */
    if (argc < 2) {
        fprintf(stderr, "STRING: missing argument\n");
        print_usage();
        return 1;
    }

    /* Join all arguments into a single string */
    size_t total_len = 0;
    for (int i = 1; i < argc; i++) {
        total_len += strlen(argv[i]) + 1;
    }

    char *input = malloc(total_len + 1);
    if (!input) {
        fprintf(stderr, "STRING: memory allocation failed\n");
        return 1;
    }

    input[0] = '\0';

    bool force_decode = false;

	for (int i = 1; i < argc; i++) {
	    if (strcmp(argv[i], "--decode") == 0) {
		force_decode = true;
		continue;
	    }

	    if (input[0] != '\0') {
		strcat(input, " ");
	    }

	    strcat(input, argv[i]);
	}

    /* Trim and normalize */
    str_trim(input);

    /* Remove surrounding quotes if present */
    size_t L = strlen(input);

    if (L >= 2 && input[0] == '"' && input[L - 1] == '"') {
        memmove(input, input + 1, L - 2);
        input[L - 2] = '\0';
        L -= 2;
    }

    /* Remove leading quote if still present */
    if (L > 0 && input[0] == '"') {
        memmove(input, input + 1, L);
        L = strlen(input);
    }

    /* Remove trailing quote if still present */
    if (L > 0 && input[L - 1] == '"') {
        input[L - 1] = '\0';
        L--;
    }

    /*
     * Remove trailing whitespace only.
     * Do NOT strip '=' or other Base64 chars.
     */
    L = strlen(input);

    while (L > 0 && isspace((unsigned char)input[L - 1])) {
        input[L - 1] = '\0';
        L--;
    }

    if (strlen(input) == 0) {
        fprintf(stderr, "STRING: empty input after trimming\n");
        free(input);
        return 1;
    }

    /* Run the universal analyzer */
    OpusStringIntelResult result = opus_string_intel(input);

    printf("\n");

    printf("Input: \"%s\"\n\n", input);
	
	print_string_result(&result, force_decode);

	printf("\n\n");
		
    free(input);

    if (result.decoded_output) {
        free(result.decoded_output);
    }

    return 0;
}


