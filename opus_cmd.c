#include "logging.h"
#include "piecalc.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "help.h"
#include "opus_cmd.h"
#include "version.h"


/* Forward declarations of command functions. */
int cmd_extract(opus_context *ctx, int argc, char **argv);
int cmd_entropy(opus_context *ctx, int argc, char **argv);

int cmd_magic(opus_context *ctx, int argc, char **argv);
int cmd_vig(opus_context *ctx, int argc, char **argv);
int cmd_sub(opus_context *ctx, int argc, char **argv);
int cmd_rsa(opus_context *ctx, int argc, char **argv);
int cmd_elf(opus_context *ctx, int argc, char **argv);
int cmd_help(opus_context *ctx, int argc, char **argv);
int cmd_menu(opus_context *ctx, int argc, char **argv);
int cmd_about(opus_context *ctx, int argc, char **argv);
int cmd_exit(opus_context *ctx, int argc, char **argv);
int cmd_piecalc(opus_context *ctx, int argc, char **argv);
int cmd_lyzer(opus_context *ctx, int argc, char **argv);

/* Case-insensitive compare, ASCII. */
static int ci_equal(const char *a, const char *b)
{
    unsigned char ca, cb;
    while (*a && *b) {
        ca = (unsigned char)*a++;
        cb = (unsigned char)*b++;
        ca = (unsigned char)toupper(ca);
        cb = (unsigned char)toupper(cb);
        if (ca != cb)
            return 0;
    }
    return (*a == '\0' && *b == '\0');
}

/* Core command registry. */
static const opus_command OPUS_COMMANDS[] = {
    /* Extraction / Forensics */
    { "LYZER",    "L",   "Forensics",  "Image forensics full scan",            cmd_lyzer },
    { "EXTRACT",  "X",   "Extraction", "Recursive extraction engine",          cmd_extract },
    { "ENTROPY",  "E",   "Forensics",  "Compute global/block-level entropy",   cmd_entropy },

    { "MAGIC",    NULL,  "Forensics",  "Magic byte detector",                  cmd_magic },

    /* Cryptanalysis */
    { "VIG",      NULL,  "Crypto",     "Vigenere cipher solver",               cmd_vig },
    { "SUB",      NULL,  "Crypto",     "Substitution cipher solver",           cmd_sub },
    { "RSA-FACTOR", NULL,"RSA",       "Fermat / classical factorization",           cmd_rsa },

    /* Binary / Misc examples */
    { "ELFINFO",      NULL,  "Binary",     "Inspect ELF header and sections",      cmd_elf },


    { "PIECALC",  NULL,  "Exploit",    "Calculate PIE base and runtime symbols", cmd_piecalc },

    /* Utility */

    /* Utility */
    { "HELP",     "H",   "Utility",    "Show command reference",               cmd_help },
    { "MENU",     "M",   "Utility",    "Show main menu",                       cmd_menu },
    { "ABOUT",    NULL,  "Utility",    "Show K1Wi version/build info",         cmd_about },
    { "EXIT",     "Z",   "Utility",    "Exit K1Wi",                            cmd_exit },
};

#define OPUS_CMD_COUNT (sizeof(OPUS_COMMANDS)/sizeof(OPUS_COMMANDS[0]))

const opus_command *opus_cmd_table(size_t *out_count)
{
    if (out_count)
        *out_count = OPUS_CMD_COUNT;
    return OPUS_COMMANDS;
}

const opus_command *opus_cmd_find(const char *token)
{
    if (!token)
        return NULL;

    for (size_t i = 0; i < OPUS_CMD_COUNT; i++) {
        const opus_command *cmd = &OPUS_COMMANDS[i];
        if (ci_equal(token, cmd->name))
            return cmd;
        if (cmd->alias && ci_equal(token, cmd->alias))
            return cmd;
    }
    return NULL;
}

int opus_cmd_dispatch(opus_context *ctx, int argc, char **argv)
{
    if (argc <= 0 || !argv || !argv[0]) {
        /* empty input; nothing to do */
        return 0;
    }

    const opus_command *cmd = opus_cmd_find(argv[0]);
    if (!cmd || !cmd->fn) {
        opus_log_warn("Unknown command: %s", argv[0]); /* or fprintf(stderr, ...) */
        return -1;
    }

    return cmd->fn(ctx, argc, argv);
}

/* Simple grouped HELP output. */
void opus_cmd_print_help(void)
{
    size_t n = 0;
    const opus_command *table = opus_cmd_table(&n);
    const char *current_cat = NULL;

    for (size_t i = 0; i < n; i++) {
        const opus_command *cmd = &table[i];
        if (!current_cat || strcmp(current_cat, cmd->category) != 0) {
            current_cat = cmd->category;
            printf("\n%s:\n", current_cat ? current_cat : "Commands");
        }
        if (cmd->alias)
            printf("  %-8s (%-2s)  %s\n", cmd->name, cmd->alias, cmd->help);
        else
            printf("  %-8s       %s\n", cmd->name, cmd->help);
    }
    printf("\n");
    printf("Additional supported commands:\n");
    printf("  File:   READ CREATE COPY DEL MD5 SHA256 SEARCH STRING\n");
    printf("  RSA:    RSA-RHO RSA-ECM RSA-WIENER RSA-SMALL-E RSA-KNOWNPQ RSA-CHECKPQ RSA-DFROMPQ RSA-MINI\n");
    printf("  Binary: PIETIME\n");
    printf("  Safe:   WIPEFS --dry-run / WIPEFS <path> --max-bytes <N> --yes\n");
    printf("\nUse HELP <command> for detailed command pages where available.\n");
    printf("Use MENU to view command categories.\n");
    printf("\n");
}

/* Simple MENU output – just categories, for now. */
void opus_cmd_print_menu(void)
{
    printf("=============== K1Wi MENU ===============\n");

    size_t n = 0;
    const opus_command *table = opus_cmd_table(&n);
    const char *seen[16];
    size_t seen_count = 0;

    for (size_t i = 0; i < n; i++) {
        const char *cat = table[i].category ? table[i].category : "Misc";
        int already = 0;
        for (size_t j = 0; j < seen_count; j++) {
            if (strcmp(seen[j], cat) == 0) {
                already = 1;
                break;
            }
        }
        if (!already && seen_count < sizeof(seen)/sizeof(seen[0])) {
            seen[seen_count++] = cat;
            printf(" - %s\n", cat);
        }
    }

    printf("=========================================\n");
}

/* Command wrappers that hook into the helpers above. */

int cmd_help(opus_context *ctx, int argc, char **argv)
{
    (void)ctx;

    if (argc >= 3 && argv[2] != NULL) {
        opus_help_specific(argv[2]);
        return 0;
    }

    opus_cmd_print_help();
    return 0;
}
int cmd_menu(opus_context *ctx, int argc, char **argv)
{
    (void)ctx; (void)argc; (void)argv;
    opus_cmd_print_menu();
    return 0;
}
int cmd_about(opus_context *ctx, int argc, char **argv)
{
    (void)ctx;
    (void)argc;
    (void)argv;

    printf("\n");

    printf("========================================\n");
    printf("              %s v%s                    \n", OPUS_FRAMEWORK, OPUS_VERSION);
    printf("           Release: %s                  \n", OPUS_RELEASE_NAME);
    printf("========================================\n");

    printf("\n");

    printf("Integrated exploit-analysis and\n");
    printf("binary research toolkit\n");

    printf("\n");

	printf("Core Features:\n");
	printf("  - Digital forensics and artifact analysis\n");
	printf("  - Binary reverse engineering (ELF/PIE)\n");
	printf("  - Image and steganography analysis\n");
	printf("  - Cryptanalysis and RSA research tools\n");
	printf("  - Extraction, carving, and automation\n");

    printf("\n");

    printf("\"Flightless. Not helpless.\"\n");

    printf("\n");

    return 0;
}
