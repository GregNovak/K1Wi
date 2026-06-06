#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "help.h"

/* ===========================
   HELP TEXT DEFINITIONS
   =========================== */
static const char *help_search_lines[] = {
    "SEARCH — File Pattern Search",
    "",
    "Usage:",
    "  SEARCH <file> <pattern> [flags]",
    "  SEARCH --hex <file> <hex-bytes>",
    "  SEARCH <file> <pattern> --before N --after N",
    "",
    "Description:",
    "  Search a file for ASCII or hexadecimal patterns. Supports sliding-window",
    "  matching, overlapping hits, multi-pattern search, and context extraction.",
    "  Flags may appear anywhere in the argument list.",
    "",
    "Options:",
    "  --hex              Interpret the pattern as hexadecimal bytes",
    "  --ascii            Force ASCII mode (default if AUTO)",
    "  --before N         Show N bytes of ASCII context before each match",
    "  --after N          Show N bytes of ASCII context after each match",
    "  --before-hex N     Show N bytes of hex context before each match",
    "  --after-hex N      Show N bytes of hex context after each match",
    "  --patterns FILE    Load multiple patterns from FILE (one per line)",
    "  --flag             Enable flag-only output mode (minimal formatting)",
    "",
    "Examples:",
    "  SEARCH dump.bin flag",
    "  SEARCH dump.bin flag --before 16 --after 16",
    "  SEARCH dump.bin 66 6C 61 67 --hex",
    "  SEARCH --hex dump.bin 66 6C 61 67",
    "  SEARCH dump.bin --hex 66 6C 61 67",
    "  SEARCH dump.bin --patterns patterns.txt",
    "  SEARCH dump.bin flag --before-hex 20 --after-hex 20\n"
};

static const char *help_elfinfo_lines[] = {
    "ELFINFO - ELF Symbol & Section Viewer",
    "",
    "Usage:",
    "  ELFINFO -IN <binary>"
};

static const char *help_magic_lines[] = {
    "MAGIC - Magic Byte Detector",
    "",
    "Usage:",
    "  MAGIC <file>"
};

static const char *help_md5_lines[] = {
    "MD5 - MD5 Hash Utility",
    "",
    "Usage:",
    "  MD5 <file>",
    "  MD5 -verify <file> <hash>",
    "  MD5 -compare <file1> <file2>"
};

static const char *help_sha256_lines[] = {
    "SHA256 - SHA-256 Hash Utility",
    "",
    "Usage:",
    "  SHA256 <file>",
    "  SHA256 -verify <file> <hash>",
    "  SHA256 -compare <file1> <file2>"
};

static const char *help_rsa_factor_lines[] = {
    "RSA-FACTOR - Fermat / Classical Factorization",
    "",
    "Usage:",
    "  RSA-FACTOR <rsa_file>"
};


static const char *help_vigsolve_lines[] = {
    "VIGSOLVE - Vigenere Key Solver (fixed length)",
    "",
    "Usage:",
    "  VIGSOLVE -in <ciphertext> -out <plaintext> -keylen <n>",
    "",
    "Description:",
    "  Attempts to solve a Vigenere cipher using a fixed key length.",
    "  Uses frequency scoring and hillclimb refinement.",
    "",
    "Options:",
    "  -in <file>        Input ciphertext file",
    "  -out <file>       Output plaintext file",
    "  -keylen <n>       Key length to use",
    "  -alpha <set>      Optional alphabet override (default: A-Z)"
};

static const char *help_vigan_lines[] = {
    "VIGAN - Vigenere Key-Length Analyzer",
    "",
    "Usage:",
    "  VIGAN -in <ciphertext>",
    "",
    "Description:",
    "  Computes Index of Coincidence and Friedman estimates to",
    "  determine likely Vigenere key lengths."
};

static const char *help_vigcrack_lines[] = {
    "VIGCRACK - Vigenere Auto Solver",
    "",
    "Usage:",
    "  VIGCRACK -in <ciphertext> -out <plaintext>",
    "",
    "Description:",
    "  Attempts full automatic Vigenere solving using IC, frequency",
    "  analysis, hillclimbing, and refinement."
};

static const char *help_piecalc_lines[] = {
    "PIECALC - PIE Base Calculator",
    "",
    "Usage:",
    "  PIECALC -IN <binary> -LEAK <addr> -SYMB <leaked_symbol> -TARGET <target_symbol>",
    "  PIECALC -IN <binary> -LEAK <addr> -GUESS -TARGET <target_symbol>",
    "",
    "Description:",
    "  Computes PIE base addresses and target runtime addresses from ELF symbols.",
    "  Use -SYMB when the leaked symbol is known. Use -GUESS to estimate the",
    "  leaked symbol from page-offset similarity.",
    "",
    "Options:",
    "  -IN <binary>          ELF binary to analyze",
    "  -LEAK <addr>          Runtime leaked address",
    "  -SYMB <symbol>        Known leaked symbol name",
    "  -GUESS                Guess leaked symbol from low address bits",
    "  -TARGET <symbol>      Target symbol to resolve",
    "",
    "Examples:",
    "  PIECALC -IN chall -LEAK 0x5555555553c0 -SYMB main -TARGET check_win",
    "  PIECALC -IN chall -LEAK 0xf010 -SYMB cmd_piecalc -TARGET main",
    "  PIECALC -IN chall -LEAK 0xf010 -GUESS -TARGET main"
};

static const char *help_string_lines[] = {
    "STRING - Universal String Analyzer",
    "",
    "Usage:",
    "  STRING <text>",
    "  STRING --decode <text>",
    "  STRING --file <file>",
    "  STRING --file <file> --decode",
    "",
    "Description:",
    "  Detects and analyzes strings including Base64, Hex, URLs,",
    "  hashes, credentials, JWTs, emails, UTF-8, ROT13, and more.",
    "",
    "Options:",
    "  --decode          Force decoded output display",
    "  --file <file>     Analyze printable strings inside a file",
    "  --min <n>         Minimum string length in file mode",
    "",
    "Examples:",
    "  STRING SGVsbG8=",
    "  STRING --decode SGVsbG8=",
    "  STRING 48656c6c6f",
    "  STRING --file dump.bin --decode"
};

static const char *help_entropy_lines[] = {
    "ENTROPY - Entropy Analysis Utility",
    "",
    "Usage:",
    "  ENTROPY",
    "  ENTROPY <file>",
    "  ENTROPY --global <file>",
    "  ENTROPY --window <file>",
    "  ENTROPY --heatmap <file>",
    "",
    "Description:",
    "  Computes Shannon entropy for files and binary regions.",
    "  Supports global entropy, sliding-window analysis, and",
    "  block-level heatmap visualization.",
    "",
    "Examples:",
    "  ENTROPY sample.bin",
    "  ENTROPY --window sample.bin",
    "  ENTROPY --heatmap sample.bin"
};

static const char *help_rsa_knownpq_lines[] = {
    "RSA-KNOWNPQ - RSA Decryption Using Known Primes",
    "",
    "Usage:",
    "  RSA-KNOWNPQ <rsa_file> <p> <q>",
    "",
    "Description:",
    "  Uses provided RSA primes p and q to compute phi(n),",
    "  derive the private exponent d, and decrypt ciphertext.",
    "",
    "Example:",
    "  RSA-KNOWNPQ rsa.txt 61 53"
};

static const char *help_rsa_small_e_lines[] = {
    "RSA-SMALL-E - Small Exponent RSA Attack",
    "",
    "Usage:",
    "  RSA-SMALL-E <rsa_file>",
    "",
    "Description:",
    "  Attempts low public exponent attacks against RSA",
    "  ciphertexts when plaintext^e < n.",
    "",
    "Example:",
    "  RSA-SMALL-E rsa_small_e3.txt"
};

static const char *help_rsa_wiener_lines[] = {
    "RSA-WIENER - Wiener RSA Attack",
    "",
    "Usage:",
    "  RSA-WIENER <rsa_file>",
    "",
    "Description:",
    "  Attempts Wiener's continued-fraction attack against",
    "  RSA keys with unusually small private exponents.",
    "",
    "Example:",
    "  RSA-WIENER rsa_weak_d.txt"
};

static const char *help_rsa_ecm_lines[] = {
    "RSA-ECM - Elliptic Curve Factorization",
    "",
    "Usage:",
    "  RSA-ECM <rsa_file>",
    "",
    "Description:",
    "  Attempts factorization using Lenstra ECM.",
    "  Effective against some weak RSA moduli.",
    "",
    "Example:",
    "  RSA-ECM rsa_values.txt"
};
/* ===========================
   HELP TABLE
   =========================== */
static const help_entry_t help_table[] = {
    { "SEARCH",      help_search_lines,      sizeof(help_search_lines)/sizeof(char*) },
    { "PIECALC",     help_piecalc_lines,     sizeof(help_piecalc_lines)/sizeof(char*) },
    { "VIGSOLVE",    help_vigsolve_lines,    sizeof(help_vigsolve_lines)/sizeof(char*) },
    { "VIGAN",       help_vigan_lines,       sizeof(help_vigan_lines)/sizeof(char*) },
    { "VIGCRACK",    help_vigcrack_lines,    sizeof(help_vigcrack_lines)/sizeof(char*) },

    { "STRING",      help_string_lines,      sizeof(help_string_lines)/sizeof(char*) },
    { "ENTROPY",     help_entropy_lines,     sizeof(help_entropy_lines)/sizeof(char*) },

    { "RSA-KNOWNPQ", help_rsa_knownpq_lines, sizeof(help_rsa_knownpq_lines)/sizeof(char*) },
    { "RSA-SMALL-E", help_rsa_small_e_lines, sizeof(help_rsa_small_e_lines)/sizeof(char*) },
    { "RSA-WIENER",  help_rsa_wiener_lines,  sizeof(help_rsa_wiener_lines)/sizeof(char*) },
    { "RSA-ECM",     help_rsa_ecm_lines,     sizeof(help_rsa_ecm_lines)/sizeof(char*) },
    { "ELFINFO",     help_elfinfo_lines,     sizeof(help_elfinfo_lines)/sizeof(char*)  },
    { "MAGIC",       help_magic_lines,       sizeof(help_magic_lines)/sizeof(char*) },
    { "MD5",         help_md5_lines,         sizeof(help_md5_lines)/sizeof(char*)},
    { "SHA256",      help_sha256_lines,      sizeof(help_sha256_lines)/sizeof(char*)},
    { "RSA-FACTOR",  help_rsa_factor_lines,  sizeof(help_rsa_factor_lines)/sizeof(char*)},
};

static const size_t help_count = sizeof(help_table) / sizeof(help_table[0]);

/* ===========================
   GENERAL HELP
   =========================== */

static const char *general_help_lines[] = {
    "HELP - Opus Help System",
    "",
    "Usage:",
    "  HELP <command>",
    "",
    "Examples:",
    "  HELP VIGSOLVE",
    "  HELP RSA-FACTOR",
    "  HELP WIPEFS",
    "",
    "Use MENU to view all available commands."
};

static const size_t general_help_count =
    sizeof(general_help_lines) / sizeof(general_help_lines[0]);

/* ===========================
   PUBLIC HELP FUNCTIONS
   =========================== */

void opus_help_general(void)
{
    for (size_t i = 0; i < general_help_count; i++)
        printf("%s\n", general_help_lines[i]);
}

void opus_help_specific(const char *cmd)
{
    if (!cmd || strlen(cmd) == 0) {
        opus_help_general();
        return;
    }

    for (size_t i = 0; i < help_count; i++) {
        if (strcasecmp(cmd, help_table[i].cmd) == 0) {
            for (size_t j = 0; j < help_table[i].line_count; j++)
                printf("%s\n", help_table[i].lines[j]);
            return;
        }
    }

    printf("No help available for '%s'. Use MENU to see commands.\n", cmd);
}

