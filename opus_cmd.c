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
    printf("\n");
    printf("K1Wi Command Reference\n");
    printf("Use: HELP <command> for detailed command pages where available.\n");
    printf("\n");

    printf("File Tools:\n");
    printf("  READ        File reader with raw, safe, and structured modes\n");
    printf("  CREATE      Create secure empty file\n");
    printf("  COPY        Forensic copy with SHA-256 and MD5 verification\n");
    printf("  DEL         Secure delete file\n");
    printf("  MD5         Compute, verify, or compare MD5 hashes\n");
    printf("  SHA256      Compute, verify, or compare SHA-256 hashes\n");
    printf("  SEARCH      Search for byte/text patterns in files\n");
    printf("  STRING      Analyze text or extract strings from files\n");
    printf("  WIPEFS      Bounded free-space wipe; requires safety flags\n");
    printf("\n");

    printf("Forensics and Extraction:\n");
    printf("  AUTO        Input detection and parser for RSA, ECC, hashes, encodings, and encrypted data\n");
    printf("  LYZER   (L)  Image forensics and steganography analysis\n");
    printf("  EXTRACT (X)  Recursive extraction engine\n");
    printf("  ENTROPY (E)  Shannon entropy calculator\n");
    printf("  MAGIC        Magic byte detector\n");
    printf("\n");

    printf("RSA Tools:\n");
    printf("  RSA-FACTOR    Fermat / classical factorization\n");
    printf("  RSA-RHO       Pollard Rho factorization\n");
    printf("  RSA-ECM       Elliptic Curve Method factorization\n");
    printf("  RSA-WIENER    Wiener small private exponent attack\n");
    printf("  RSA-SMALL-E   Small exponent attack check\n");
    printf("  RSA-KNOWNPQ   Decrypt with known p and q\n");
    printf("  RSA-CHECKPQ   Validate p and q\n");
    printf("  RSA-DFROMPQ   Compute d from p, q, and e\n");
    printf("  RSA-MINI      Mini RSA solver / small-e helper\n  RSA-ROOTS     Exact root / even-exponent helper\n  RSA-KEY       Decrypt with PEM private key\n");
    printf("\n");

    printf("Binary and PIE Tools:\n");
    printf("  ELFINFO     ELF Symbol & Section Viewer\n");
    printf("  PIECALC     PIE Base Calculator\n");
    printf("  PIETIME     PIE Runtime Address Analyzer\n");
    printf("\n");

    printf("Cryptanalysis Tools:\n");
    printf("  VIGAN       Vigenere key-length analyzer\n");
    printf("  VIGCRACK    Vigenere auto solver\n");
    printf("  VIGSOLVE    Vigenere fixed-length key solver\n");
    printf("  VIGREFINE   Vigenere key refiner\n");
    printf("  VIGAUTO     Vigenere full pipeline\n");
    printf("  SOLVE       Substitution solver\n");
    printf("  MONO        Monoalphabetic solver\n");
    printf("  DIGRAPH     Digraph and trigraph analysis\n");
    printf("  CAESAR      Caesar bruteforce analyzer\n");
    printf("\n");

    printf("Utility:\n");
    printf("  CONVERT     Numeric / encoding conversion helper\n");
    printf("  NUMCONV     Alias for CONVERT\n");
    printf("  HELP    (H)  Show command reference\n");
    printf("  MENU    (M)  Show main menu\n");
    printf("  ABOUT        Show K1Wi version/build info\n");
    printf("  VERSION      Show version banner\n");
    printf("  TIME         Show system time\n");
    printf("  EXIT    (Z)  Exit K1Wi\n");
    printf("\n");

    printf("Safety note:\n");
    printf("  WIPEFS refuses destructive mode unless --max-bytes and --yes are supplied.\n");
    printf("  Example: WIPEFS testdata/wipefs_sandbox --max-bytes 1048576 --yes\n");
    printf("\n");
}

/* Simple MENU output – just categories, for now. */
void opus_cmd_print_menu(void)
{
    printf("=============== K1Wi MENU ===============\n");
    printf("\n");

    printf("File Tools\n");
    printf("  READ CREATE COPY DEL MD5 SHA256 SEARCH STRING WIPEFS\n");
    printf("\n");

    printf("Forensics / Extraction\n");
    printf("  LYZER EXTRACT ENTROPY MAGIC\n");
    printf("\n");

    printf("RSA Tools\n");
    printf("  RSA-FACTOR RSA-RHO RSA-ECM RSA-WIENER RSA-SMALL-E\n");
    printf("  RSA-KNOWNPQ RSA-CHECKPQ RSA-DFROMPQ RSA-MINI\n");
    printf("\n");

    printf("Binary / PIE Tools\n");
    printf("  ELFINFO PIECALC PIETIME\n");
    printf("\n");

    printf("Cryptanalysis\n");
    printf("  VIGAN VIGCRACK VIGSOLVE VIGREFINE VIGAUTO\n");
    printf("  SOLVE MONO DIGRAPH CAESAR\n");
    printf("\n");

    printf("Utility\n");
    printf("  CONVERT NUMCONV HELP MENU ABOUT VERSION TIME EXIT\n");    printf("\n");

    printf("Use HELP <command> for details.\n");
    printf("WIPEFS requires --dry-run or --max-bytes <N> --yes.\n");

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
