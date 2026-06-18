/*

Codename: Opus

---------- K1Wi v1.1.0 -----------

*/

#define _POSIX_C_SOURCE 200809L
#include "opus_extract.h"
#include "state.h"

#include "solver.h"
#include <pthread.h>
#include <strings.h>   

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <errno.h> 
#include <math.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <termios.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include "opus_cmd.h"
#include "secure_delete_cmds.h"
#include "opus_extract.h"
#include "entropy.h"
#include "md5.h"
#include "logging.h"
#include "task_pool.h"


#include "opus_extract_designations.h"
#include "opus_designation_decoder.h"
#include "opus_designation_solve.h"
#include "opus_designation_analyze.h"
#include "opus_solve.h"
#include "mini_rsa.h"
#include "rsa_factor.h"
#include "rsa_rho.h"
#include "elfinfo.h"
#include "file_copy.h"
#include "vigenere.h"
#include "opus_vig_crack.h"
#include "rsa_wiener.h"
#include "rsa_knownpq.h" 

#include "score.h" 
#include "params.h"
#include "solve.h"
#include "quadgrams.h"
#include "piecalc.h"
#include "stego_analyze.h"

#include "jpeg_stego.h"

#include "rs_analysis.h"
#include "dct_analysis.h"
#include "jpeg_huff_fingerprint.h" 
#include "file_carver.h"
#include "string_intel.h"
#include "parse_numbers.h"

#include "entropy_heatmap.h"
#include "entropy.h"
#include "rsa_small_e.h"
#include "rsa_ecm.h"
#include "rsa_checkpq.h"
#include "wipefs_cmds.h"
#include "forensic_cmds.h"
#include "opus_commands.h"
#include "help.h"
#include "rsa_dfrompq.h"
#include "embedded_sig.h"

#include "sha256.h"
#include "opus_sha256.h"
#include "format_utils.h"
#include "opus_read.h"
#include "search.h"
#include "cli.h"
#include <math.h>
#include <stdbool.h>

#define CLR_RESET  "\033[0m"

#define CLR_RED    "\033[31m"
#define CLR_GREEN  "\033[32m"
#define CLR_YELLOW "\033[33m"
#define CLR_BLUE   "\033[34m"
#define CLR_CYAN   "\033[36m"

#define CLR_BOLD   "\033[1m"


int cmd_piecalc(opus_context *ctx, int argc, char **argv);
void run_entropy_heatmap(const char *path);
void opus_entropy_window_file(const char *path, size_t block_size);

static int is_printable_ascii(unsigned char c) {
    return (c >= 32 && c <= 126);
}

static double ascii_printable_ratio(const unsigned char *s, size_t len) {
    if (len == 0) return 0.0;
    size_t p = 0;
    for (size_t i = 0; i < len; i++) {
        if (is_printable_ascii(s[i]) || s[i] == '\n' || s[i] == '\t')
            p++;
    }
    return (double)p / (double)len;
}

static double shannon_entropy(const unsigned char *buf, size_t len) {
    if (len == 0) return 0.0;
    int counts[256] = {0};
    for (size_t i = 0; i < len; i++) counts[(unsigned char)buf[i]]++;
    double H = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        double p = (double)counts[i] / (double)len;
        H -= p * (log(p) / log(2.0));
    }
    return H;
}

static int is_valid_utf8(const unsigned char *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned char c = s[i];
        if (c <= 0x7F) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= len) return 0;
            if ((s[i+1] & 0xC0) != 0x80) return 0;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= len) return 0;
            if ((s[i+1] & 0xC0) != 0x80) return 0;
            if ((s[i+2] & 0xC0) != 0x80) return 0;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= len) return 0;
            if ((s[i+1] & 0xC0) != 0x80) return 0;
            if ((s[i+2] & 0xC0) != 0x80) return 0;
            if ((s[i+3] & 0xC0) != 0x80) return 0;
            i += 4;
        } else {
            return 0;
        }
    }
    return 1;
}

static int looks_like_base64_strict(const char *s) {
    size_t len = strlen(s);
    if (len == 0 || (len % 4) != 0) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '+' || c == '/' || c == '=')) return 0;
    }
    return 1;
}

static int looks_like_binary_strict(const char *s) {
    size_t len = strlen(s);
    if (len == 0 || (len % 8) != 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] != '0' && s[i] != '1') return 0;
    }
    return 1;
}





int cmd_string(int argc, char **argv);

 


int run_solver_from_opus(const char *cipher_path, const char *forced_spec);

void fileDeleteCmd(const char *args);
int secure_delete_file(const char *filename, int standard);
void fileDeleteCmd(const char *args);
double *opus_entropy_windowed(const char *path, size_t block_size, size_t *out_count);

typedef struct {
    const char *name;
    const char *synopsis;
    const char *description;
    const char *options;
    const char *examples;
} opus_manpage_t;

// Solver params default (params.c)
solve_params_t default_solve_params(void);

static void randomize_vig_key(char *key);
static void cmd_vigencrypt(int argc, char **argv);
static void vigenere_encrypt_letters(const char *plain, int len,
                                     const char *key, int keylen,
                                     char *out);

int cmd_vigenere(int argc, char **argv);
void cmd_vigcrack(const char *infile, const char *outfile, int forced_keylen);

static void cmd_vig_analyze(const cipher_t *cipher);
int opus_pie_time_cli(int argc, char **argv);


static char solve_caesar_column(const char *text, size_t len, int keylen, int col);
static int vig_solve_key_ic(const cipher_t *cipher, int keylen, char *out_key);
static int vig_guess_keylen_ic(const cipher_t *cipher, int max_len);

int verify_sha256_hash(const char *, const char *);
int verify_sha256_sidecar(const char *, const char *);


/* Step 4: Vigenere refinement */
static void vigenere_decrypt_letters(const char *cipher, size_t len,
                                     const char *key, size_t klen,
                                     char *out_plain);
static double vig_score_with_key(const cipher_t *cipher,
                                 const char *key,
                                 const quadgram_model_t *model);
static int vig_refine_key_hillclimb(const cipher_t *cipher,
                                    char *key,
                                    int iterations,
                                    const quadgram_model_t *model,
                                    int verbose);




void center(const char *s); 
void opus_banner(void); 
void opus_menu(void); 

void get_command(char *input, char *cmd, int *argc, char **argv);

pthread_mutex_t status_lock = PTHREAD_MUTEX_INITIALIZER;
int active_solver_tasks = 0;
char last_solver_progress[256] = "";
double last_score = 0.0;


int cmd_vigenere(int argc, char **argv);
int isStrictDecimalList(const char *s);

int cmd_piecalc(opus_context *ctx, int argc, char **argv);
int cmd_version(const OpusCLI *cli, int argc, char **argv);

static void dispatch_forensic(int argc, char **argv)
{
    // No subcommand?
    if (argc < 2) {
        forensicCmd("");
        return;
    }

    // Reconstruct args string from argv[1..]
    size_t len = 0;
    for (int i = 1; i < argc; i++)
        len += strlen(argv[i]) + 1;

    char *buf = malloc(len + 1);
    if (!buf) {
        fprintf(stderr, "Memory allocation failed.\n");
        return;
    }

    buf[0] = '\0';
    for (int i = 1; i < argc; i++) {
        strcat(buf, argv[i]);
        if (i + 1 < argc)
            strcat(buf, " ");
    }

    forensicCmd(buf);
    free(buf);
}

void opus_banner(void) {
    printf("\n\n");

    printf("==================================================\n");
    printf("                 K1Wi Framework\n");
    printf("      Reverse Engineering • Forensics • Crypto\n");
    printf("==================================================\n");

    printf("\n");
    printf("Version: 1.1.0\n");
    printf("\n");
}

void opus_menu(void)
{
    const char *current_category = NULL;

    printf("==================================================\n");
    printf("                K1Wi MAIN MENU                      \n");
    printf("==================================================\n\n");

    for (size_t i = 0; i < opus_commands_count; i++) {
        const opus_cmd_t *cmd = &opus_commands[i];

        if (!current_category || strcmp(current_category, cmd->category) != 0) {
            current_category = cmd->category;
            printf("%s:\n\n", current_category);
        }

        printf("  %-15s %s\n", cmd->name, cmd->description);


    }

    printf("\n====================================================\n");
}

static const double ENGLISH_FREQ_PCT[26] = {
    8.17, 1.49, 2.78, 4.25, 12.70,
    2.23, 2.02, 6.09, 6.97, 0.15,
    0.77, 4.03, 2.41, 6.75, 7.51,
    1.93, 0.10, 5.99, 6.33, 9.06,
    2.76, 0.98, 2.36, 0.15, 1.97,
    0.07
};



void center(const char *s) {
    struct winsize w;
    memset(&w, 0, sizeof(w));

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != 0 || w.ws_col == 0) {
        w.ws_col = 80;
    }

    int width = (int)w.ws_col;
    int len = (int)strlen(s);
    int pad = (width - len) / 2;
    if (pad < 0) pad = 0;

    printf("%*s%s\n", pad, "", s);
}



/* solver task context (file-scope so worker functions can see it) */
typedef struct {
    cipher_t cipher;
    quadgram_model_t *model;
    solve_params_t params;
    char *forced_spec;   // optional forced substitutions
} SolverTaskCtx;


typedef struct {
    char *cmd;
    char *arg1;
    char *arg2;
    char *rest;
} opus_command_t;


//========= Magic Bytes Analyzer ============

typedef struct {
    const char *name;
    const unsigned char *magic;
    size_t length;
} MagicEntry;

unsigned char png_magic[]   = {0x89, 'P', 'N', 'G'};
unsigned char jpg_magic[]   = {0xFF, 0xD8, 0xFF};
unsigned char gif_magic[]   = {'G','I','F'};
unsigned char bmp_magic[]   = {'B','M'};
unsigned char zip_magic[]   = {0x50,0x4B,0x03,0x04};
unsigned char pdf_magic[]   = {'%','P','D','F'};
unsigned char elf_magic[]   = {0x7F,'E','L','F'};

MagicEntry magic_table[] = {
    {"PNG", png_magic, sizeof(png_magic)},
    {"JPEG", jpg_magic, sizeof(jpg_magic)},
    {"GIF", gif_magic, sizeof(gif_magic)},
    {"BMP", bmp_magic, sizeof(bmp_magic)},
    {"ZIP", zip_magic, sizeof(zip_magic)},
    {"PDF", pdf_magic, sizeof(pdf_magic)},
    {"ELF", elf_magic, sizeof(elf_magic)},
};

void detect_magic(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file");
        return;
    }

    unsigned char buffer[32];
    size_t read_bytes = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);

    if (read_bytes == 0) {
        printf("File is empty or unreadable.\n");
        return;
    }

    int found = 0;
    for (size_t i = 0; i < sizeof(magic_table)/sizeof(MagicEntry); i++) {
        if (read_bytes >= magic_table[i].length &&
            memcmp(buffer, magic_table[i].magic, magic_table[i].length) == 0) {
            printf("Detected format: %s\n", magic_table[i].name);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("Unknown format. First bytes: ");
        for (size_t i = 0; i < read_bytes; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }
}
//------- End Magic Bytes --------------------


static void print_grouped_min_rows_autofit(char **items, size_t count, size_t min_rows)
{
    if (!items || count == 0) {
        printf("(none)\n");
        return;
    }

    if (min_rows < 1) min_rows = 1;

    /* Get terminal width */
    struct winsize w;
    memset(&w, 0, sizeof(w));

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != 0 || w.ws_col == 0) {
        w.ws_col = 80;
    }

    int term_width = (int)w.ws_col;

    /* First: compute theoretical max columns based on min_rows */
    size_t cols = (count + min_rows - 1) / min_rows;

    /* Compute max width of each column */
    size_t *col_width = calloc(cols, sizeof(size_t));
    if (!col_width) return;

    for (size_t c = 0; c < cols; c++) {
        for (size_t r = 0; r < min_rows; r++) {
            size_t idx = r * cols + c;
            if (idx < count) {
                size_t len = strlen(items[idx]);
                if (len > col_width[c]) col_width[c] = len;
            }
        }
    }

    /* Now shrink columns if they exceed terminal width */
    int total_width = 0;
    for (size_t c = 0; c < cols; c++)
        total_width += (int)col_width[c] + 2;

    /* Reduce columns until it fits */
    while (cols > 1 && total_width > term_width) {
        cols--;
        total_width = 0;
        for (size_t c = 0; c < cols; c++)
            total_width += (int)col_width[c] + 2;
    }

    /* Print row by row */
    for (size_t r = 0; r < min_rows; r++) {
        for (size_t c = 0; c < cols; c++) {
            size_t idx = r * cols + c;
            if (idx < count) {
                printf("%-*s", (int)col_width[c] + 2, items[idx]);
            }
        }
        printf("\n");
    }

    free(col_width);
}


/* ---------------------------------------------------------
 * FORENSIC command dispatcher
 * --------------------------------------------------------- */

//==============================================================
//                 IMAGE ANALYZER (CTF-Grade)
//==============================================================

void analyze_image_file(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Error opening file");
        return;
    }

    print_block_header("Image Analysis");


	// ---------- File size ----------
	if (fseek(fp, 0, SEEK_END) != 0) {
	    fclose(fp);
	    return;
	}

	long fsize = ftell(fp);
	if (fsize < 0) {
	    fclose(fp);
	    return;
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
	    fclose(fp);
	    return;
	}

	size_t file_size = (size_t)fsize;

	char buf_kv[64];
	snprintf(buf_kv, sizeof(buf_kv), "%zu bytes", file_size);
	print_kv("File size:", buf_kv);

	// ---------- Read buffer ----------
	unsigned char *buf = malloc(file_size);
    if (!buf) {
        printf("Memory error\n");
        fclose(fp);
        return;
    }

    fread(buf, 1, file_size, fp);
    fclose(fp);

    // ---------- Entropy ----------
    double freq[256] = {0};
    for (size_t i = 0; i < file_size; i++) freq[buf[i]]++;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)file_size;
            entropy -= p * log2(p);
        }
    }

    snprintf(buf_kv, sizeof(buf_kv), "%.4f bits/byte", entropy);
    print_kv("Entropy:", buf_kv);

    // ---------- ASCII Strings ----------
    print_block_header("ASCII Strings (min 4 chars)");

    size_t strings_cap = 1024;
    size_t scount = 0;
    char **strings = malloc(strings_cap * sizeof(char*));
    if (!strings) {
        printf("Memory error\n");
        free(buf);
        return;
    }

    char tmp[256];
    size_t run = 0;

    for (size_t i = 0; i < file_size; i++) {
        if (buf[i] >= 32 && buf[i] <= 126) {
            if (run < sizeof(tmp) - 1) {
               tmp[run++] = (char)buf[i];
            }
        } else {
            if (run >= 4) {
                tmp[run] = '\0';

                if (scount >= strings_cap) {
                    strings_cap *= 2;
                    char **new_strings = realloc(strings, strings_cap * sizeof(char*));
                    if (!new_strings) {
                        printf("Memory error\n");
                        for (size_t j = 0; j < scount; j++) free(strings[j]);
                        free(strings);
                        free(buf);
                        return;
                    }
                    strings = new_strings;
                }

                strings[scount++] = strdup(tmp);
            }
            run = 0;
        }
    }

    // Final flush
    if (run >= 4) {
        tmp[run] = '\0';

        if (scount >= strings_cap) {
            strings_cap *= 2;
            char **new_strings = realloc(strings, strings_cap * sizeof(char*));
            if (!new_strings) {
                printf("Memory error\n");
                for (size_t j = 0; j < scount; j++) free(strings[j]);
                free(strings);
                free(buf);
                return;
            }
            strings = new_strings;
        }

        strings[scount++] = strdup(tmp);
    }

    print_grouped_min_rows_autofit(strings, scount, 6);

    for (size_t i = 0; i < scount; i++) free(strings[i]);
    free(strings);

    // ---------- Footer Scan ----------
    print_block_header("Footer Scan (Embedded Files)");

    long *jpeg_offsets = malloc(sizeof(long) * 4096);
    size_t jcount = 0;

    for (long i = 0; i < fsize - 4; i++) {
        if (buf[i] == 0xFF && buf[i+1] == 0xD8)
            jpeg_offsets[jcount++] = i;
    }

    print_offsets_grouped(jpeg_offsets, jcount, 2);
    free(jpeg_offsets);

    free(buf);
}


//======= K1Wi Core Code END =============

// ---------------------------------------------------------
// Enhanced String Analyzer Helper Functions (Decoders)
// ---------------------------------------------------------


// ---------------- Base64 Detection ----------------

static bool looks_like_base64(const char *s) {
    size_t len = strlen(s);
    if (len < 8 || (len % 4) != 0) return false;

    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!(isalnum(c) || c == '+' || c == '/' || c == '=')) {
            return false;
        }
    }
    return true;
}

static unsigned char *b64_decode(const char *input, size_t *out_len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    size_t len = strlen(input);
    unsigned char *buffer = malloc(len);
    if (!buffer) return NULL;

    int decoded = BIO_read(bio, buffer, (int)len);
    BIO_free_all(bio);

    if (decoded <= 0) {
        free(buffer);
        return NULL;
    }

    *out_len = (size_t)decoded;
    return buffer;
}

// ---------------- Hex Decode ----------------

static unsigned char *hex_decode(const char *s, size_t *out_len) {
    size_t len = strlen(s);
    *out_len = len / 2;

    unsigned char *buf = malloc(*out_len);
    if (!buf) return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        sscanf(&s[i * 2], "%2hhx", &buf[i]);
    }
    return buf;
}

// ---------------- Binary Decode ----------------

static unsigned char *binary_decode(const char *s, size_t *out_len) {
    size_t len = strlen(s);
    *out_len = len / 8;

    unsigned char *buf = malloc(*out_len);
    if (!buf) return NULL;

    for (size_t i = 0; i < *out_len; i++) {
        unsigned char val = 0;
        for (int b = 0; b < 8; b++) {
            val = (unsigned char)((val << 1) | (unsigned char)(s[i * 8 + (size_t)b] == '1'));
        }
        buf[i] = val;
    }
    return buf;
}



// ---------------- Octal ASCII Decode ----------------

static unsigned char *octal_ascii_decode(const char *s, size_t *out_len) {
    unsigned char *buf = malloc(strlen(s));
    if (!buf) return NULL;

    *out_len = 0;
    const char *p = s;
    while (*p) {
        int v = (int)strtol(p, NULL, 8);
        buf[(*out_len)++] = (unsigned char)v;
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
    }
    return buf;
}





#define max_Length_Filename 512  
#define max_Length_Command 64

char command[max_Length_Command];
char filename[max_Length_Filename];

FILE *fptr; 
FILE *fileNewCreate; 



void fileOpenPrompt(void); 
int cmd_open(int argc, char **argv);

void toUpperStr(char *s);

void fileOpenPrompt(void);
int cmd_open(int argc, char **argv);

void fileClose(FILE *fp);
void systemTime(void);
int fileCreate(const char *path);

void fileName(void);
void fileDelete(void);
void clearScreen(void);

int readFile(const char *filename);
void fileRead(void);
void ctf_Analyzer(const char *mode);
int opus_lyzer_file(const char *path, const char *mode);
int isHex(const char *s);
int isBase64(const char *s);
int isPrintableASCII(const char *s);
int isMD5(const char *s);
int isBinaryString(const char *s);
int isAsciiCode(const char *s);
int isHexWithPrefix(const char *s);
int isOctalCode(const char *s);

void hexToAscii(const char *hexStr,
                char *outBuf,
                size_t outSize);

void digraphTrigraphAnalyzer(void);

void caesarMenu(void);
void frequencyAnalyzer(void);
void monoSubstitute(void);
void print_status_inline(void);



/**
 * Load and normalize ciphertext:
 *  - reads file
 *  - keeps only A–Z
 *  - converts to uppercase
 */
static int load_normalized_ciphertext(const char *path, cipher_t *cipher)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        printf("Error: could not open cipher file '%s'\n", path);
        return 0;
    }

    // First pass: count alphabetic characters
    long count = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        if (isalnum((unsigned char)ch) || ch == '_' || ch == '{' || ch == '}') 
 	{
            count++;
        }
    }

    if (count <= 0) {
        printf("Error: cipher file '%s' contains no alphabetic characters\n", path);
        fclose(fp);
        return 0;
    }

    // Allocate buffer
    char *buf = malloc((size_t)count + 1);
    if (!buf) {
        printf("Error: out of memory loading ciphertext\n");
        fclose(fp);
        return 0;
    }

    // Second pass: fill buffer with A–Z uppercase
    rewind(fp);
    long idx = 0;
    while ((ch = fgetc(fp)) != EOF) {
        if (isalnum((unsigned char)ch) || ch == '_' || ch == '{' || ch == '}') {
	
            buf[idx++] = (char)toupper((unsigned char)ch);
        }
    }
    buf[idx] = '\0';

    fclose(fp);

    cipher->text   = buf;
    cipher->length = (size_t)idx;

    printf("Loaded ciphertext from '%s' (%zu letters, A–Z only)\n",
           path, cipher->length);

    return 1;
}

typedef struct {
    char seq[4];   // up to 3 letters + null terminator
    int count;     // raw count
    double percent; // relative frequency percentage
} NGram;

int compareNGram(const void *a, const void *b) {
    return ((NGram*)b)->count - ((NGram*)a)->count;
}

typedef struct {
    char letter;
    int count;
    double percent;
} FreqEntry;

/* simple thread-safe progress message queue */
typedef struct Msg {
    struct Msg *next;
    char *text;
} Msg;

/* status snapshot for UI */



static int last_restart = -1;

static Msg *msg_head = NULL;
static Msg *msg_tail = NULL;
static pthread_mutex_t msg_lock = PTHREAD_MUTEX_INITIALIZER;

void get_command(char *input, char *cmd, int *argc, char *argv[])
{
    *argc = 0;

    char *token = strtok(input, " \t");
    if (!token) {
        cmd[0] = '\0';
        return;
    }

    /* command goes into cmd AND argv[0] */
    strcpy(cmd, token);
    argv[(*argc)++] = cmd;

    /* remaining tokens go into argv[1..] */
    while ((token = strtok(NULL, " \t")) != NULL) {
        argv[(*argc)++] = token;
    }
}


uint8_t *opus_load_entire_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return NULL;
}

long size = ftell(fp);
if (size < 0) {
    fclose(fp);
    return NULL;
}

	if (fseek(fp, 0, SEEK_SET) != 0) {
	    fclose(fp);
	    return NULL;
	}

	size_t file_size = (size_t)size;

	uint8_t *buf = malloc(file_size);
	if (!buf) {
	    fclose(fp);
	    return NULL;
	}

	if (fread(buf, 1, file_size, fp) != file_size) {
	    fclose(fp);
	    free(buf);
	    return NULL;
	}

	fclose(fp);
	*out_len = file_size;
	return buf;
}

int opus_write_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    if (fwrite(buf, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

/* enqueue a copy of the message (called from worker threads) */
void post_progress_msg_internal(const char *s) {
    if (!s) return;
    Msg *m = malloc(sizeof(Msg));
    if (!m) return;
    m->text = strdup(s);
    if (!m->text) { free(m); return; }
    m->next = NULL;
    pthread_mutex_lock(&msg_lock);
    if (msg_tail) msg_tail->next = m; else msg_head = m;
    msg_tail = m;
    pthread_mutex_unlock(&msg_lock);
}

/* flush queued messages to the Opus UI (call from main thread) */
void flush_progress_msgs(void) {
    Msg *list = NULL;
    pthread_mutex_lock(&msg_lock);
    list = msg_head;
    msg_head = msg_tail = NULL;
    pthread_mutex_unlock(&msg_lock);

    for (Msg *m = list; m != NULL; ) {
        printf("%s", m->text);
        free(m->text);
        Msg *tmp = m;
        m = m->next;
        free(tmp);
    }
}

/* print status on the line above the prompt without disturbing the prompt line */
void print_status_above_prompt(void) {
    static char last_snapshot[256] = "";
    static int last_tasks = -1;
    char snapshot[256];
    int tasks = 0;
    int restart = -1;
    double score = 0.0;

    pthread_mutex_lock(&status_lock);
    tasks = active_solver_tasks;
    strncpy(snapshot, last_solver_progress, sizeof(snapshot)-1);
    snapshot[sizeof(snapshot)-1] = '\0';
    restart = last_restart;
    score = last_score;
    pthread_mutex_unlock(&status_lock);

    /* only redraw when something changed */
    if (tasks == last_tasks && strcmp(snapshot, last_snapshot) == 0) return;

    last_tasks = tasks;
    strncpy(last_snapshot, snapshot, sizeof(last_snapshot)-1);
    last_snapshot[sizeof(last_snapshot)-1] = '\0';

    /* Save cursor, move up one line, clear it, print status, restore cursor */
    printf("\033[s");        /* save cursor */
    printf("\033[1A");       /* move cursor up 1 line */
    printf("\033[2K");       /* clear entire line */
    if (tasks > 0) {
        if (restart >= 0) {
            printf("[Solver:%d restart %d best %.4f] %s", tasks, restart, score, snapshot);
        } else {
            printf("[Solver:%d] %s", tasks, snapshot[0] ? snapshot : "(no progress)");
        }
    } else {
        if (snapshot[0]) printf("[No solver] %s", snapshot);
        else printf("[No solver tasks]");
    }
    printf("\n");           /* ensure the status line ends with newline */
    printf("\033[u");       /* restore cursor (back to prompt line) */
    fflush(stdout);
}

int cmd_search(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: SEARCH <file> <pattern|--patterns file> "
               "[--hex|--ascii] [--before N] [--after N] "
               "[--before-hex N] [--after-hex N] [--flag]\n");
        return 0;
    }

    const char *file = NULL;
    const char *pattern = NULL;
    const char *patterns_file = NULL;

    search_mode_t mode = SEARCH_MODE_AUTO;

    size_t before = 0;
    size_t after = 0;
    size_t before_hex = 0;
    size_t after_hex = 0;
    bool flag_mode = false;

    /* Parse args in any order:
       - collect flags
       - first non-flag  -> file
       - second non-flag -> pattern (or patterns file if --patterns was seen)
    */

    int expect_patterns_file = 0;
    int expect_before = 0;
    int expect_after = 0;
    int expect_before_hex = 0;
    int expect_after_hex = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        /* Handle "expect value" states first */
        if (expect_patterns_file) {
            patterns_file = arg;
            expect_patterns_file = 0;
            continue;
        }
        if (expect_before) {
            before = (size_t)strtoull(arg, NULL, 10);
            expect_before = 0;
            continue;
        }
        if (expect_after) {
            after = (size_t)strtoull(arg, NULL, 10);
            expect_after = 0;
            continue;
        }
        if (expect_before_hex) {
            before_hex = (size_t)strtoull(arg, NULL, 16);
            expect_before_hex = 0;
            continue;
        }
        if (expect_after_hex) {
            after_hex = (size_t)strtoull(arg, NULL, 16);
            expect_after_hex = 0;
            continue;
        }

        /* Flags */
        if (strncmp(arg, "--", 2) == 0) {
            if (strcasecmp(arg, "--hex") == 0) {
                mode = SEARCH_MODE_HEX;
            }
            else if (strcasecmp(arg, "--ascii") == 0) {
                mode = SEARCH_MODE_ASCII;
            }
            else if (strcasecmp(arg, "--before") == 0) {
                expect_before = 1;
            }
            else if (strcasecmp(arg, "--after") == 0) {
                expect_after = 1;
            }
            else if (strcasecmp(arg, "--before-hex") == 0) {
                expect_before_hex = 1;
            }
            else if (strcasecmp(arg, "--after-hex") == 0) {
                expect_after_hex = 1;
            }
            else if (strcasecmp(arg, "--flag") == 0) {
                flag_mode = true;
            }
            else if (strcasecmp(arg, "--patterns") == 0) {
                expect_patterns_file = 1;
            }
            else {
                printf("Unknown flag: %s\n", arg);
                return 0;
            }
            continue;
        }

        /* Positional args: file and pattern */
        if (!file) {
            file = arg;
        } else if (!pattern && !patterns_file) {
            pattern = arg;
        } else if (!pattern && patterns_file) {
            /* If --patterns was used, we already captured patterns_file,
               so this extra positional is unexpected. */
            printf("Unexpected extra argument: %s\n", arg);
            return 0;
        } else {
            printf("Unexpected extra argument: %s\n", arg);
            return 0;
        }
    }

    if (!file) {
        printf("[-] Missing file argument\n");
        return 0;
    }

    if (!patterns_file && !pattern) {
        printf("[-] Missing pattern argument\n");
        return 0;
    }

    /* AUTO mode default: ASCII unless user explicitly chose HEX */
    if (mode == SEARCH_MODE_AUTO) {
        mode = SEARCH_MODE_ASCII;
    }

    if (patterns_file) {
        opus_search_multi(file,
                          pattern,        /* unused when patterns_file != NULL */
                          patterns_file,
                          mode,
                          before,
                          after,
                          before_hex,
                          after_hex,
                          flag_mode);
    } else {
        opus_search(file,
                    pattern,
                    mode,
                    before,
                    after,
                    before_hex,
                    after_hex,
                    flag_mode);
    }

    return 0;
}






/* ======== MAIN FUNCTION STARTS HERE ======== */
/* =========================================== */



static int k1wi_auto_hex_token_len(const char *buf, size_t want_len)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (*p) {
        while (*p && !isxdigit(*p)) {
            p++;
        }

        const unsigned char *start = p;
        size_t len = 0;

        while (*p && isxdigit(*p)) {
            len++;
            p++;
        }

        if (len == want_len) {
            int left_ok = (start == (const unsigned char *)buf) || !isxdigit((unsigned char)*(start - 1));
            int right_ok = (*p == '\0') || !isxdigit(*p);

            if (left_ok && right_ok) {
                return 1;
            }
        }
    }

    return 0;
}

static int k1wi_auto_hex_blob_present(const char *buf)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (*p) {
        while (*p && !isxdigit(*p)) {
            p++;
        }

        size_t len = 0;

        while (*p && isxdigit(*p)) {
            len++;
            p++;
        }

        if (len >= 32U && (len % 2U) == 0U) {
            return 1;
        }
    }

    return 0;
}



static int k1wi_auto_is_base64_char(unsigned char c)
{
    return isalnum(c) || c == '+' || c == '/' || c == '=';
}

static int k1wi_auto_base64_blob_present(const char *buf)
{
    const unsigned char *p = (const unsigned char *)buf;

    while (*p) {
        while (*p && !k1wi_auto_is_base64_char(*p)) {
            p++;
        }

        size_t len = 0;
        size_t pad = 0;
        size_t non_alnum_symbol = 0;
        size_t non_hex_char = 0;

        while (*p && k1wi_auto_is_base64_char(*p)) {
            if (*p == '=') {
                pad++;
            }

            if (*p == '+' || *p == '/' || *p == '=') {
                non_alnum_symbol++;
            }

            if (!isxdigit(*p)) {
                non_hex_char++;
            }

            len++;
            p++;
        }

        if (len >= 16U && (len % 4U) == 0U && pad <= 2U) {
            /*
             * Avoid treating raw MD5/SHA-style pure hex strings as base64.
             * Base64 should include padding/symbols or at least non-hex letters.
             */
            if (non_hex_char > 0U && (non_alnum_symbol > 0U || len >= 24U)) {
                return 1;
            }
        }
    }

    return 0;
}



static void k1wi_auto_print_field_preview(const char *name,
                                          const char *buf,
                                          const char *const *labels,
                                          size_t label_count,
                                          int *printed_header)
{
    size_t i;

    if (!name || !buf || !labels || !printed_header) {
        return;
    }

    for (i = 0; i < label_count; i++) {
        const char *hit = strstr(buf, labels[i]);
        const char *start;
        const char *end;
        size_t len;

        if (!hit) {
            continue;
        }

        start = hit + strlen(labels[i]);

        while (*start == ' ' || *start == '\t' || *start == '\r' ||
               *start == '\n' || *start == ':' || *start == '=' ||
               *start == '"' || *start == '\'') {
            start++;
        }

        end = start;

        while (*end != '\0' &&
               *end != ' ' &&
               *end != '\t' &&
               *end != '\r' &&
               *end != '\n' &&
               *end != ',' &&
               *end != '"' &&
               *end != '\'' &&
               *end != '}' &&
               *end != ']' &&
               *end != ';') {
            end++;
        }

        len = (size_t)(end - start);

        if (len == 0U) {
            continue;
        }

        if (!*printed_header) {
            printf("\nField previews\n");
            printf("------------------\n");
            *printed_header = 1;
        }

        printf("%-21s: ", name);

        if (len <= 40U) {
            printf("%.*s\n", (int)len, start);
        } else {
            printf("%.*s...%.*s\n",
                   20,
                   start,
                   12,
                   end - 12);
        }

        return;
    }
}


int k1wi_auto_analyze_file(const char *path)
{
    FILE *fp = NULL;
    long size = 0;
    char *buf = NULL;

    int has_rsa_n = 0;
    int has_rsa_e = 0;
    int has_rsa_d = 0;
    int has_rsa_p = 0;
    int has_rsa_q = 0;
    int has_rsa_phi = 0;
    int has_rsa_c = 0;
    int has_generic_ciphertext = 0;
    int has_ecc_point = 0;
    int has_iv = 0;
    int has_encrypted_flag = 0;
    int has_md5 = 0;
    int has_sha1 = 0;
    int has_sha256 = 0;
    int has_sha512 = 0;
    int has_hex_blob = 0;
    int has_base64_blob = 0;
    int printed_preview_header = 0;

    if (!path || path[0] == '\0') {
        fprintf(stderr, "AUTO: missing input file.\n");
        return 1;
    }

    fp = fopen(path, "rb");
    if (!fp) {
        perror("AUTO");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        fprintf(stderr, "AUTO: failed to seek input file.\n");
        return 1;
    }

    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        fprintf(stderr, "AUTO: failed to determine input size.\n");
        return 1;
    }

    rewind(fp);

    buf = calloc((size_t)size + 1U, 1U);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "AUTO: memory allocation failed.\n");
        return 1;
    }

    if (size > 0 && fread(buf, 1U, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        fprintf(stderr, "AUTO: failed to read input file.\n");
        return 1;
    }

    fclose(fp);

    has_rsa_n = strstr(buf, "n =") != NULL ||
                strstr(buf, "N =") != NULL ||
                strstr(buf, "\"n\"") != NULL ||
                strstr(buf, "\"N\"") != NULL ||
                strstr(buf, "modulus") != NULL ||
                strstr(buf, "Modulus") != NULL;

    has_rsa_e = strstr(buf, "e =") != NULL ||
                strstr(buf, "E =") != NULL ||
                strstr(buf, "\"e\"") != NULL ||
                strstr(buf, "\"E\"") != NULL;

    has_rsa_d = strstr(buf, "d =") != NULL ||
                strstr(buf, "D =") != NULL ||
                strstr(buf, "\"d\"") != NULL ||
                strstr(buf, "\"D\"") != NULL ||
                strstr(buf, "private exponent") != NULL ||
                strstr(buf, "Private exponent") != NULL;

    has_rsa_p = strstr(buf, "p =") != NULL ||
                strstr(buf, "P =") != NULL ||
                strstr(buf, "\"p\"") != NULL ||
                strstr(buf, "\"P\"") != NULL;

    has_rsa_q = strstr(buf, "q =") != NULL ||
                strstr(buf, "Q =") != NULL ||
                strstr(buf, "\"q\"") != NULL ||
                strstr(buf, "\"Q\"") != NULL;

    has_rsa_phi = strstr(buf, "phi") != NULL ||
                  strstr(buf, "Phi") != NULL ||
                  strstr(buf, "totient") != NULL ||
                  strstr(buf, "Totient") != NULL;

    has_rsa_c = strstr(buf, "c =") != NULL ||
                strstr(buf, "ct =") != NULL ||
                strstr(buf, "ciphertext =") != NULL ||
                strstr(buf, "ciphertext:") != NULL;

    has_generic_ciphertext = strstr(buf, "ciphertext") != NULL ||
                             strstr(buf, "encrypted") != NULL ||
                             strstr(buf, "encrypted_flag") != NULL ||
                             strstr(buf, "Encrypted flag") != NULL;

    has_ecc_point = strstr(buf, "Point(x=") != NULL ||
                    strstr(buf, "Point(") != NULL ||
                    strstr(buf, "public key") != NULL ||
                    strstr(buf, "Public key") != NULL;

    has_iv = strstr(buf, "iv") != NULL || strstr(buf, "IV") != NULL;
    has_encrypted_flag = strstr(buf, "encrypted_flag") != NULL ||
                         strstr(buf, "Encrypted flag") != NULL ||
                         strstr(buf, "encrypted flag") != NULL;

    has_md5 = strstr(buf, "MD5") != NULL ||
              strstr(buf, "md5") != NULL ||
              (!has_iv && k1wi_auto_hex_token_len(buf, 32U));

    has_sha1 = strstr(buf, "SHA1") != NULL ||
               strstr(buf, "sha1") != NULL ||
               k1wi_auto_hex_token_len(buf, 40U);

    has_sha256 = strstr(buf, "SHA256") != NULL ||
                 strstr(buf, "sha256") != NULL ||
                 k1wi_auto_hex_token_len(buf, 64U);

    has_sha512 = strstr(buf, "SHA512") != NULL ||
                 strstr(buf, "sha512") != NULL ||
                 k1wi_auto_hex_token_len(buf, 128U);

    has_hex_blob = strstr(buf, "hex:") != NULL ||
                   strstr(buf, "HEX:") != NULL ||
                   strstr(buf, "hex =") != NULL ||
                   k1wi_auto_hex_blob_present(buf);

    has_base64_blob = strstr(buf, "base64") != NULL ||
                      strstr(buf, "Base64") != NULL ||
                      strstr(buf, "BASE64") != NULL ||
                      k1wi_auto_base64_blob_present(buf);

    printf("\nK1Wi AUTO Analysis\n");
    printf("------------------\n");
    printf("Input file: %s\n", path);
    printf("Bytes read : %ld\n", size);

    printf("\nDetected fields\n");
    printf("------------------\n");
    printf("RSA modulus n        : %s\n", has_rsa_n ? "yes" : "no");
    printf("RSA exponent e       : %s\n", has_rsa_e ? "yes" : "no");
    printf("RSA private d        : %s\n", has_rsa_d ? "yes" : "no");
    printf("RSA prime p          : %s\n", has_rsa_p ? "yes" : "no");
    printf("RSA prime q          : %s\n", has_rsa_q ? "yes" : "no");
    printf("RSA phi/totient      : %s\n", has_rsa_phi ? "yes" : "no");
    printf("RSA ciphertext field : %s\n", has_rsa_c ? "yes" : "no");
    printf("Generic ciphertext   : %s\n", has_generic_ciphertext ? "yes" : "no");
    printf("ECC point/public key : %s\n", has_ecc_point ? "yes" : "no");
    printf("IV / nonce field     : %s\n", has_iv ? "yes" : "no");
    printf("Encrypted flag field : %s\n", has_encrypted_flag ? "yes" : "no");
    printf("MD5 hash             : %s\n", has_md5 ? "yes" : "no");
    printf("SHA1 hash            : %s\n", has_sha1 ? "yes" : "no");
    printf("SHA256 hash          : %s\n", has_sha256 ? "yes" : "no");
    printf("SHA512 hash          : %s\n", has_sha512 ? "yes" : "no");
    printf("Hex blob             : %s\n", has_hex_blob ? "yes" : "no");
    printf("Base64 blob          : %s\n", has_base64_blob ? "yes" : "no");


    {
        static const char *const rsa_n_labels[] = { "n =", "N =", "modulus", "Modulus" };
        static const char *const rsa_e_labels[] = { "e =", "E =" };
        static const char *const rsa_d_labels[] = { "d =", "D =", "private exponent", "Private exponent" };
        static const char *const rsa_c_labels[] = { "c =", "ct =", "ciphertext =", "ciphertext:" };
        static const char *const iv_labels[] = { "'iv':", "\"iv\":", "iv =", "IV =" };
        static const char *const encrypted_flag_labels[] = { "encrypted_flag", "Encrypted flag", "encrypted flag" };
        static const char *const md5_labels[] = { "MD5:", "md5:", "MD5 =", "md5 =" };
        static const char *const sha256_labels[] = { "SHA256:", "sha256:", "SHA256 =", "sha256 =" };
        static const char *const base64_labels[] = { "base64:", "Base64:", "BASE64:", "base64 =", "Base64 =", "BASE64 =" };
        static const char *const hex_labels[] = { "hex:", "HEX:", "hex =", "HEX =" };

        if (has_rsa_n) {
            k1wi_auto_print_field_preview("RSA modulus n", buf, rsa_n_labels,
                                          sizeof(rsa_n_labels) / sizeof(rsa_n_labels[0]),
                                          &printed_preview_header);
        }

        if (has_rsa_e) {
            k1wi_auto_print_field_preview("RSA exponent e", buf, rsa_e_labels,
                                          sizeof(rsa_e_labels) / sizeof(rsa_e_labels[0]),
                                          &printed_preview_header);
        }

        if (has_rsa_d) {
            k1wi_auto_print_field_preview("RSA private d", buf, rsa_d_labels,
                                          sizeof(rsa_d_labels) / sizeof(rsa_d_labels[0]),
                                          &printed_preview_header);
        }

        if (has_rsa_c) {
            k1wi_auto_print_field_preview("RSA ciphertext", buf, rsa_c_labels,
                                          sizeof(rsa_c_labels) / sizeof(rsa_c_labels[0]),
                                          &printed_preview_header);
        }

        if (has_iv) {
            k1wi_auto_print_field_preview("IV / nonce", buf, iv_labels,
                                          sizeof(iv_labels) / sizeof(iv_labels[0]),
                                          &printed_preview_header);
        }

        if (has_encrypted_flag) {
            k1wi_auto_print_field_preview("Encrypted flag", buf, encrypted_flag_labels,
                                          sizeof(encrypted_flag_labels) / sizeof(encrypted_flag_labels[0]),
                                          &printed_preview_header);
        }

        if (has_md5) {
            k1wi_auto_print_field_preview("MD5", buf, md5_labels,
                                          sizeof(md5_labels) / sizeof(md5_labels[0]),
                                          &printed_preview_header);
        }

        if (has_sha256) {
            k1wi_auto_print_field_preview("SHA256", buf, sha256_labels,
                                          sizeof(sha256_labels) / sizeof(sha256_labels[0]),
                                          &printed_preview_header);
        }

        if (has_base64_blob) {
            k1wi_auto_print_field_preview("Base64", buf, base64_labels,
                                          sizeof(base64_labels) / sizeof(base64_labels[0]),
                                          &printed_preview_header);
        }

        if (has_hex_blob) {
            k1wi_auto_print_field_preview("Hex", buf, hex_labels,
                                          sizeof(hex_labels) / sizeof(hex_labels[0]),
                                          &printed_preview_header);
        }
    }

    printf("\nAssessment\n");
    printf("------------------\n");

    if (has_rsa_n && has_rsa_d && has_rsa_c) {
        printf("Detected type: RSA private exponent decrypt candidate\n");
        printf("Recommendation: Use N and d with ciphertext to recover plaintext, or provide e/p/q for validation.\n");
    } else if (has_rsa_n && has_rsa_d) {
        printf("Detected type: RSA private exponent data\n");
        printf("Recommendation: Provide ciphertext to decrypt, or provide e/p/q for validation and key reconstruction.\n");
    } else if (has_rsa_p && has_rsa_q && has_rsa_e) {
        printf("Detected type: RSA key reconstruction data\n");
        printf("Recommendation: Use RSA-DFROMPQ or RSA-KNOWNPQ when ciphertext is available.\n");
    } else if (has_rsa_n && has_rsa_e && has_rsa_c) {
        printf("Detected type: RSA challenge data\n");
        printf("Recommendation: Try RSA tools such as RSA-FACTOR, RSA-SMALL-E, RSA-WIENER, or future RSA-ROOTS.\n");
    } else if (has_ecc_point && (has_iv || has_encrypted_flag)) {
        printf("Detected type: ECC / ECDH-style encrypted challenge data\n");
        printf("Recommendation: Extract curve parameters before attempting ECC analysis.\n");
    } else if (has_md5 || has_sha1 || has_sha256 || has_sha512 || has_hex_blob || has_base64_blob) {
        printf("Detected type: hash / encoded data\n");
        printf("Recommendation: Use MD5, SHA256, STRING, or decoding helpers depending on the field.\n");
    } else if (has_generic_ciphertext || has_iv || has_encrypted_flag) {
        printf("Detected type: encrypted payload data\n");
        printf("Recommendation: Identify cipher, key source, IV/nonce, and encoding.\n");
    } else {
        printf("Detected type: unknown / mixed input\n");
        printf("Recommendation: Use STRING, MAGIC, ENTROPY, or add more AUTO detectors.\n");
    }

    free(buf);
    return 0;
}


int opus_repl(void)
{

 
   
    char input[1024];
    char cmd[64];
    int argc = 0;
    char *argv[32];



    /* initial UI */
    printf("\n");
    opus_banner();
    opus_menu();
    printf("\n");

   

    /* clear any pending stdin bytes so select() isn't immediately ready */
    tcflush(STDIN_FILENO, TCIFLUSH);

    /* initialize worker pool: 4 threads by default */
    if (pool_init(4) != 0) {
        fprintf(stderr, "Warning: task pool init failed, continuing without background tasks\n");
    }



    /* keep a snapshot so we only print status when it changes */
    char last_status_snapshot[256] = "";
    int last_tasks_snapshot = -1;
    int last_restart_snapshot = -1;
    double last_score_snapshot = 0.0;

    /* main loop: update status on timeouts, print prompt only when input is ready */
    while (1) {
           	   	 
        /* print any pending solver progress messages (full lines) */
        flush_progress_msgs();

        /* build current status snapshot */
        char cur_snapshot[256];
        int cur_tasks;
        int cur_restart;
        double cur_score;
        pthread_mutex_lock(&status_lock);
        cur_tasks = active_solver_tasks;
        strncpy(cur_snapshot, last_solver_progress, sizeof(cur_snapshot) - 1);
        cur_snapshot[sizeof(cur_snapshot) - 1] = '\0';
        cur_restart = last_restart;
        cur_score = last_score;
        pthread_mutex_unlock(&status_lock);

        /* only print status if something changed */
        if (cur_tasks != last_tasks_snapshot ||
            cur_restart != last_restart_snapshot ||
            fabs(cur_score - last_score_snapshot) > 1e-9 ||
            strcmp(cur_snapshot, last_status_snapshot) != 0) {

            if (cur_tasks > 0) {
                if (cur_restart >= 0)
                    printf("[Solver:%d restart %d best %.4f] %s\n",
                           cur_tasks, cur_restart, cur_score,
                           cur_snapshot[0] ? cur_snapshot : "(no progress)");
                else
                    printf("[Solver:%d] %s\n",
                           cur_tasks,
                           cur_snapshot[0] ? cur_snapshot : "(no progress)");
            } else {
                if (cur_snapshot[0]) printf("[No solver] %s\n", cur_snapshot);
                else printf("[No solver tasks]\n");
            }

            /* remember snapshot */
            last_tasks_snapshot = cur_tasks;
            last_restart_snapshot = cur_restart;
            last_score_snapshot = cur_score;
            strncpy(last_status_snapshot, cur_snapshot, sizeof(last_status_snapshot) - 1);
            last_status_snapshot[sizeof(last_status_snapshot) - 1] = '\0';
        }

/* wait for input with timeout so we can refresh status periodically */

        fd_set rfds;

        /* show prompt and block until input arrives */
        printf("\nK1Wi Command: ");
        fflush(stdout);

        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);

        /* block indefinitely until stdin is ready */
        int sel = select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
        if (sel < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

   
/* -----------------------------------------------------------
 * SAFE INPUT READ (getline) — prevents EXTRACT overflow issues
 * ----------------------------------------------------------- */
	/* SAFE INPUT READ (getline) — prevents EXTRACT overflow issues */
	if (!FD_ISSET(STDIN_FILENO, &rfds))
	    continue;

	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen = getline(&line, &linecap, stdin);

	if (linelen < 0) {
	    if (feof(stdin)) {
		printf("\nEOF on stdin, exiting\n");
		free(line);
		break;
	    }
	    perror("getline");
	    free(line);
	    continue;
	}

	/* strip newline(s) */
	while (linelen > 0 && (line[linelen - 1] == '\n' || line[linelen - 1] == '\r')) {
	    line[--linelen] = '\0';
	}

	/* copy into your existing input buffer */
	strncpy(input, line, sizeof(input) - 1);
	input[sizeof(input) - 1] = '\0';

	free(line);


        /* parse into cmd + argv */
        get_command(input, cmd, &argc, argv);



        /* uppercase ONLY the command token */
        for (char *p = cmd; *p; ++p)
            *p = (char)toupper((unsigned char)*p);

/*------------ COMMAND DISPATCH ------------- */
//=============================================//

        if (strcmp(cmd, "Z") == 0 || strcmp(cmd, "EXIT") == 0) {
            printf("\nExiting Program\n\n");
            pool_cancel_all();
            pool_shutdown();
            break;
        }
        else if (strcmp(cmd, "T") == 0 || strcmp(cmd, "TIME") == 0) {
            systemTime();
        }
        else if (strcmp(cmd, "OPEN") == 0) {
            cmd_open(argc, argv);
        }
        else if (strcmp(cmd, "CREATE") == 0) {
            if (argc < 2) {
                printf("Usage: CREATE <filename>\n");
                continue;
            }
            const char *path = argv[1];
            fileCreate(path);
        }
        else if (strcmp(cmd, "COPY") == 0) {
            if (argc < 3) {
                printf("Usage: COPY <src> <dst>\n");
                continue;
            }

            const char *src = argv[1];
            const char *dst = argv[2];

            log_info("COPY command: %s -> %s", src, dst);

            int rc = opus_file_copy(src, dst);
            if (rc == 0)
                printf("COPY: success\n");
            else
                printf("COPY: failed\n");

            continue;
        }
        
        else if (strcmp(cmd, "SEARCH") == 0) {
        cmd_search(argc, argv);
	}
	else if (strcmp(cmd, "DEL") == 0) {
	    /* p points to the raw line buffer returned by getline */
	    char *p = line;
	    while (*p && isspace((unsigned char)*p)) p++;

	    /* get the first token (command) without destroying the original line buffer */
	    char *first = strtok(p, " \t");
	    if (first && strcasecmp(first, "DEL") == 0) {
		/* find remainder of the original line after the command token */
		char *rest = NULL;
		char *cmd_pos = strstr(p, first);
		if (cmd_pos) {
		    char *after = cmd_pos + strlen(first);
		    while (*after && isspace((unsigned char)*after)) after++;
		    rest = (*after) ? after : NULL;
		}

		/* make a heap copy of the remainder so we don't touch `line` */
		char *argcopy = rest ? strdup(rest) : NULL;
		fileDeleteCmd(argcopy);   /* fileDeleteCmd must free argcopy when done */
		free(argcopy);

		/* do NOT free(line) here — the main loop frees it in the common cleanup */
		continue;
	    }

	    /* defensive fallback: call interactive if tokenization behaved unexpectedly */
	    fileDelete();
	    continue;
	}

	else if (strcmp(cmd, "WIPEFS") == 0) {
	    char args_buf[4096] = {0};

	    for (int i = 1; i < argc; i++) {
		if (i > 1) {
		    strncat(args_buf, " ", sizeof(args_buf) - strlen(args_buf) - 1);
		}

		strncat(args_buf, argv[i], sizeof(args_buf) - strlen(args_buf) - 1);
	    }

	    wipeFsCmd(args_buf);
	    continue;
	}
	

        else if (strcmp(cmd, "CLR") == 0 || strcmp(cmd, "CLEAR") == 0) {
            clearScreen();
        }
        else if (strcmp(cmd, "SPLASH") == 0) {
            opus_banner();
        }
	else if (strcmp(cmd, "VERSION") == 0 || strcmp(cmd, "ABOUT") == 0) {
        cmd_version(NULL, argc, argv);
        continue;
	}
        else if (strcmp(cmd, "M") == 0 || strcmp(cmd, "MENU") == 0) {
            opus_menu();
        }
	

        else if (strcmp(cmd, "AUTO") == 0) {
            const char *path = NULL;

            if (argc >= 2) {
                path = argv[1];
            }

            if (!path) {
                char input_path[4096];

                printf("Enter input file: ");
                if (!fgets(input_path, sizeof(input_path), stdin)) {
                    printf("Input error.\n");
                    continue;
                }

                input_path[strcspn(input_path, "\r\n")] = '\0';

                if (input_path[0] == '\0') {
                    printf("AUTO: no input file provided.\n");
                    continue;
                }

                k1wi_auto_analyze_file(input_path);
            } else {
                k1wi_auto_analyze_file(path);
            }

            continue;
        }

    else if (strcmp(cmd, "R") == 0 || strcmp(cmd, "READ") == 0) {

    char path_buf[4096];

    /* If user supplied a path (argc >= 2), use it directly */
    if (argc >= 2) {
        strncpy(path_buf, argv[1], sizeof(path_buf) - 1);
        path_buf[sizeof(path_buf) - 1] = '\0';
    } else {
        /* Otherwise prompt for it */
        printf("Enter file path: ");
        if (!fgets(path_buf, sizeof(path_buf), stdin)) {
            printf("Input error.\n");
            continue;
        }
        path_buf[strcspn(path_buf, "\r\n")] = '\0';
    }

    /* Mode selection */
    printf("Mode [r=raw, s=safe, t=structured] (default r): ");
    int c = getchar();
    while (c == '\n' || c == '\r')
        c = getchar();

    bool mode_raw        = true;
    bool mode_safe       = false;
    bool mode_structured = false;

    if (c == 's' || c == 'S') {
        mode_raw  = false;
        mode_safe = true;
    } else if (c == 't' || c == 'T') {
        mode_raw        = false;
        mode_structured = true;
    }

    /* flush rest of line */
    int d;
    while ((d = getchar()) != '\n' && d != EOF) {}

    /* defaults for now — we’ll expose these as flags later */
    size_t limit         = 0;
    size_t offset        = 0;
    size_t page_size     = 64;
    bool ascii           = true;
    bool hex             = true;
    const char *force_format = NULL;
    bool verbose         = false;
    bool summary         = false;

    opus_read_file(path_buf,
                   mode_raw,
                   mode_structured,
                   mode_safe,
                   limit,
                   offset,
                   page_size,
                   ascii,
                   hex,
                   force_format,
                   verbose,
                   summary);

    continue;
}

else if (strcmp(cmd, "LYZER") == 0) {
    const char *path = NULL;
    const char *mode = "SUMMARY";

    if (argc >= 2) {
        path = argv[1];
    }

    if (argc >= 3) {
        mode = argv[2];

        if (strcasecmp(mode, "--full") == 0 ||
            strcasecmp(mode, "full") == 0 ||
            strcasecmp(mode, "--verbose") == 0 ||
            strcasecmp(mode, "verbose") == 0) {
            mode = "ALL";
        } else if (strcasecmp(mode, "--summary") == 0 ||
                   strcasecmp(mode, "summary") == 0) {
            mode = "SUMMARY";
        } else if (strcasecmp(mode, "--quiet") == 0 ||
                   strcasecmp(mode, "quiet") == 0) {
            mode = "QUIET";
        }
    }

    if (!path) {
        char input_path[4096];

        printf("Enter Filename: ");
        if (!fgets(input_path, sizeof(input_path), stdin)) {
            printf("Input error.\n");
            continue;
        }

        input_path[strcspn(input_path, "\r\n")] = '\0';

        if (input_path[0] == '\0') {
            printf("LYZER: missing file path\n");
            continue;
        }

        path = input_path;
    }

    int rc = opus_lyzer_file(path, mode);

    if (rc != 0) {
        printf("LYZER: completed with warnings/errors (%d)\n", rc);
    }

    continue;
}

else if (strcasecmp(cmd, "STRING") == 0) {
    cmd_string(argc, argv);
    continue;
}

	else if (strcmp(cmd, "MD5") == 0) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  MD5 <file>\n");
        printf("  MD5 -in <file>\n");
        printf("  MD5 -verify <file> <hash>\n");
        printf("  MD5 -compare <file1> <file2>\n");
        printf("  MD5 -sidecar <file> <file.md5>\n");
        continue;
    }

    /* MD5 -in <file> */
    if (strcmp(argv[1], "-in") == 0) {
        if (argc < 3) {
            printf("MD5 -in: need <file>\n");
            continue;
        }

        char digest[33];
        if (opus_md5_file(argv[2], digest) == true)
            printf("MD5(%s) = %s\n", argv[2], digest);
        else
            printf("MD5: failed to read %s\n", argv[2]);

        continue;
    }

    /* MD5 <file> */
    if (argc == 2) {
        char digest[33];
        if (opus_md5_file(argv[1], digest) == true)
            printf("MD5(%s) = %s\n", argv[1], digest);
        else
            printf("MD5: failed to read %s\n", argv[1]);

        continue;
    }

    /* MD5 -verify <file> <hash> */
    if (strcmp(argv[1], "-verify") == 0) {
        if (argc < 4) {
            printf("MD5 -verify: need <file> <hash>\n");
            continue;
        }

        char digest[33];
        if (opus_md5_file(argv[2], digest) != true) {
            printf("MD5: failed to read %s\n", argv[2]);
            continue;
        }

        if (strcasecmp(digest, argv[3]) == 0)
            printf("MD5 OK\n");
        else
            printf("MD5 MISMATCH\n");

        continue;
    }

    /* MD5 -compare <file1> <file2> */
    if (strcmp(argv[1], "-compare") == 0) {
        if (argc < 4) {
            printf("MD5 -compare: need <file1> <file2>\n");
            continue;
        }

        char h1[33], h2[33];

        if (opus_md5_file(argv[2], h1) != true) {
            printf("MD5: failed to read %s\n", argv[2]);
            continue;
        }

        if (opus_md5_file(argv[3], h2) != true) {
            printf("MD5: failed to read %s\n", argv[3]);
            continue;
        }

        if (strcasecmp(h1, h2) == 0) {
            printf("MD5 MATCH\n");
        } else {
            printf("MD5 DIFFER\n");
            printf("  %s: %s\n", argv[2], h1);
            printf("  %s: %s\n", argv[3], h2);
        }

        continue;
    }

    /* MD5 -sidecar <file> <file.md5> */
    if (strcmp(argv[1], "-sidecar") == 0) {
        if (argc < 4) {
            printf("MD5 -sidecar: need <file> <file.md5>\n");
            continue;
        }

        char digest[33];
        if (opus_md5_file(argv[2], digest) != true) {
            printf("MD5: failed to read %s\n", argv[2]);
            continue;
        }

        FILE *fp = fopen(argv[3], "r");
        if (!fp) {
            printf("MD5: error reading sidecar '%s'\n", argv[3]);
            continue;
        }

        char expected[128];
        if (!fgets(expected, sizeof(expected), fp)) {
            fclose(fp);
            printf("MD5: error reading sidecar '%s'\n", argv[3]);
            continue;
        }
        fclose(fp);

        expected[strcspn(expected, " \t\r\n")] = '\0';

        if (strcasecmp(digest, expected) == 0)
            printf("MD5 OK (sidecar)\n");
        else
            printf("MD5 MISMATCH (sidecar)\n");

        continue;
    }

    printf("MD5: unknown option '%s'\n", argv[1]);
    continue;
}
	else if (strcmp(cmd, "SHA256") == 0) {
	    if (argc < 2) {
		printf("Usage:\n");
		printf("  SHA256 <file>\n");
		printf("  SHA256 -verify <file> <hash>\n");
		printf("  SHA256 -compare <file1> <file2>\n");
		printf("  SHA256 -sidecar <file> <file.sha256>\n");
		continue;
	    }

	    /* SHA256 <file> */
	    if (argc == 2) {
		char out[65];
		if (sha256_file(argv[1], out) != 0) {
		    printf("SHA256: cannot read '%s'\n", argv[1]);
		    continue;
		}
		printf("SHA256(%s) = %s\n", argv[1], out);
		continue;
	    }

	    /* SHA256 -verify <file> <hash> */
	    if (strcmp(argv[1], "-verify") == 0) {
		if (argc < 4) {
		    printf("SHA256 -verify: need <file> <hash>\n");
		    continue;
		}
		int res = verify_sha256_hash(argv[2], argv[3]);
		if (res < 0) {
		    printf("SHA256: error reading '%s'\n", argv[2]);
		} else if (res == 1) {
		    printf("SHA256 OK\n");
		} else {
		    printf("SHA256 MISMATCH\n");
		}
		continue;
	    }

	    /* SHA256 -compare <file1> <file2> */
	    if (strcmp(argv[1], "-compare") == 0) {
		if (argc < 4) {
		    printf("SHA256 -compare: need <file1> <file2>\n");
		    continue;
		}
		char h1[65], h2[65];
		if (sha256_file(argv[2], h1) != 0) {
		    printf("SHA256: cannot read '%s'\n", argv[2]);
		    continue;
		}
		if (sha256_file(argv[3], h2) != 0) {
		    printf("SHA256: cannot read '%s'\n", argv[3]);
		    continue;
		}
		if (strcmp(h1, h2) == 0) {
		    printf("SHA256 MATCH\n");
		} else {
		    printf("SHA256 DIFFER\n");
		    printf("  %s: %s\n", argv[2], h1);
		    printf("  %s: %s\n", argv[3], h2);
		}
		continue;
	    }

	    /* SHA256 -sidecar <file> <file.sha256> */
	    if (strcmp(argv[1], "-sidecar") == 0) {
		if (argc < 4) {
		    printf("SHA256 -sidecar: need <file> <file.sha256>\n");
		    continue;
		}
		int res = verify_sha256_sidecar(argv[2], argv[3]);
		if (res < 0) {
		    printf("SHA256: error reading sidecar '%s'\n", argv[3]);
		} else if (res == 1) {
		    printf("SHA256 OK (sidecar)\n");
		} else {
		    printf("SHA256 MISMATCH (sidecar)\n");
		}
		continue;
	    }

	    printf("SHA256: unknown option '%s'\n", argv[1]);
	    continue;
	}

	else if (strcmp(cmd, "ENTROPY") == 0) {

	    if (argc >= 2) {
		const char *path = NULL;
		int mode = 1;

		if (strcmp(argv[1], "--global") == 0) {
		    mode = 1;
		    if (argc < 3) {
		        printf("Usage: ENTROPY --global <file>\n");
		        continue;
		    }
		    path = argv[2];
		} else if (strcmp(argv[1], "--window") == 0) {
		    mode = 2;
		    if (argc < 3) {
		        printf("Usage: ENTROPY --window <file>\n");
		        continue;
		    }
		    path = argv[2];
		} else if (strcmp(argv[1], "--heatmap") == 0) {
		    mode = 3;
		    if (argc < 3) {
		        printf("Usage: ENTROPY --heatmap <file>\n");
		        continue;
		    }
		    path = argv[2];
		} else {
		    path = argv[1];
		}

		if (mode == 1) {
		    double H = opus_entropy_file(path);
		    if (H < 0.0)
		        printf("Failed to read file.\n");
		    else
		        printf("Global entropy: %.6f bits/byte\n", H);
		    continue;
		}

		if (mode == 2) {
		    size_t block_size = 1024;
		    size_t count = 0;

		    double *blocks = opus_entropy_windowed(path, block_size, &count);
		    if (!blocks) {
			printf("Failed to compute windowed entropy.\n");
			continue;
		    }

		    printf("\nSliding-window entropy (block size %zu bytes):\n", block_size);
		    for (size_t i = 0; i < count; i++) {
			size_t offset = i * block_size;
			printf("  Block %5zu (offset %10zu): %.4f bits/byte\n",
			       i, offset, blocks[i]);
		    }

		    free(blocks);
		    continue;
		}

		if (mode == 3) {
		    run_entropy_heatmap(path);
		    continue;
		}
	    }

	    printf("\nEntropy Modes:\n");
	    printf("  1) Global entropy (whole file)\n");
	    printf("  2) Sliding-window entropy\n");
	    printf("  3) Heatmap analysis\n");

	    printf("Select mode: ");

	    char mode_buf[16];
	    if (!fgets(mode_buf, sizeof(mode_buf), stdin)) {
		printf("Input error.\n");
		continue;
	    }

	    int mode = atoi(mode_buf);

	    char path[4096];
	    printf("Enter file path: ");
	    if (!fgets(path, sizeof(path), stdin)) {
		printf("Input error.\n");
		continue;
	    }
	    path[strcspn(path, "\r\n")] = '\0';

	    if (mode == 1) {
		double H = opus_entropy_file(path);
		if (H < 0.0)
		    printf("Failed to read file.\n");
		else
		    printf("Global entropy: %.6f bits/byte\n", H);
	    }

	    else if (mode == 2) {
		size_t block_size = 1024;

		printf("Block size in bytes (default 1024): ");
		char bs_buf[64];
		if (fgets(bs_buf, sizeof(bs_buf), stdin)) {
		    bs_buf[strcspn(bs_buf, "\r\n")] = '\0';
		    if (bs_buf[0] != '\0') {
		        char *endp = NULL;
		        unsigned long v = strtoul(bs_buf, &endp, 10);
		        if (endp != bs_buf && *endp == '\0' && v > 0)
		            block_size = (size_t)v;
		    }
		}

		size_t count = 0;
		double *blocks = opus_entropy_windowed(path, block_size, &count);
		if (!blocks) {
		    printf("Failed to compute windowed entropy.\n");
		    continue;
		}

		printf("\nSliding-window entropy (block size %zu bytes):\n", block_size);
		for (size_t i = 0; i < count; i++) {
		    size_t offset = i * block_size;
		    printf("  Block %5zu (offset %10zu): %.4f bits/byte\n\n",
		           i, offset, blocks[i]);
		}

		free(blocks);
	    }
		else if (mode == 3) {
		    size_t block_size = 1024;

		    printf("Block size in bytes (default 1024): ");
		    char bs_buf[64];
		    if (fgets(bs_buf, sizeof(bs_buf), stdin)) {
			bs_buf[strcspn(bs_buf, "\r\n")] = '\0';
			if (bs_buf[0] != '\0') {
			    char *endp = NULL;
			    unsigned long v = strtoul(bs_buf, &endp, 10);
			    if (endp != bs_buf && *endp == '\0' && v > 0)
				block_size = (size_t)v;
			}
		    }

		    struct entropy_heatmap map = {0};

		    if (opus_entropy_heatmap_analyze(path, block_size, &map) != 0) {
			printf("Failed to analyze entropy heatmap.\n");
			continue;
		    }

		    opus_entropy_heatmap_render_color(&map);   /* NEW */
		    opus_entropy_heatmap_print(&map);          /* existing table */
		    opus_entropy_heatmap_detect_anomalies(&map);
		    opus_entropy_heatmap_free(&map);

		}


	    else {
		printf("Unknown mode.\n");
	    }

	    printf("\n");
	}

	else if (strcmp(cmd, "EXTRACT") == 0) {
	    if (argc < 2) {
		printf("Usage: EXTRACT [--recursive] <file>\n");
		continue;
	    }

	    const char *path = NULL;

	    for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--recursive") == 0 ||
		    strcmp(argv[i], "-r") == 0) {
		    continue;
		}

		path = argv[i];
		break;
	    }

	    if (!path) {
		printf("Usage: EXTRACT [--recursive] <file>\n");
		continue;
	    }

	    int rc = opus_extract_recursive(path);

	    if (rc == 0)
		printf("EXTRACT: completed successfully\n");
	    else
		printf("EXTRACT: failed with code %d\n", rc);

	    /* -----------------------------------------
	     * FLUSH stdin to remove stray bytes caused
	     * by massive EXTRACT output
	     * ----------------------------------------- */
	    int c;
	    while ((c = getchar()) != '\n' && c != EOF);

	    continue;
	} else if (strcmp(cmd, "MAGIC") == 0) {
	    if (argc < 2) {
		printf("Usage: MAGIC <file>\n");
		continue;
	    }

    detect_magic(argv[1]);
    continue;
}


	else if (strcmp(cmd, "HELP") == 0) {
	    if (argc == 1)
		opus_help_general();
	    else
		opus_help_specific(argv[1]);
	    continue;
	}


        else if (strcmp(cmd, "VIG") == 0) {
            cmd_vigenere(argc, argv);
        }
        else if (strcmp(cmd, "VIGAN") == 0) {
    	const char *infile = NULL;

    	for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            infile = argv[++i];
        }
       }

    	if (!infile) {
        printf("Usage: VIGAN -in <cipherfile>\n");
        continue;
    	}
	    cipher_t cipher;
    	if (!load_normalized_ciphertext(infile, &cipher)) {
        continue;
    	}

   	 cmd_vig_analyze(&cipher);

   	free(cipher.text);
    	continue;
	}
	
	else if (strcmp(cmd, "VIGCRACK") == 0) {
	    // Expect: VIGCRACK -in cipher.txt -out plain.txt [-keylen N]
	    const char *infile = NULL;
	    const char *outfile = NULL;
	    int forced_keylen = 0;

	    for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
		    infile = argv[++i];
		} else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
		    outfile = argv[++i];
		} else if (strcmp(argv[i], "-keylen") == 0 && i + 1 < argc) {
		    forced_keylen = atoi(argv[++i]);
		}
	    }

	    if (!infile || !outfile) {
		printf("Usage: VIGCRACK -in <cipherfile> -out <plainfile> [-keylen N]\n");
		continue;
	    }

	    cmd_vigcrack(infile, outfile, forced_keylen);
	    continue;
	}

        else if (strcmp(cmd, "VIGSOLVE") == 0) {
    	const char *infile = NULL;
    	const char *outfile = "vigsolve_out.txt";
    	int keylen = 0;

    	for (int i = 0; i < argc; i++) {
          if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            infile = argv[++i];
          } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            outfile = argv[++i];
          } else if (strcmp(argv[i], "-keylen") == 0 && i + 1 < argc) {
            keylen = atoi(argv[++i]);
         }
        }

     	if (!infile || keylen <= 0) {
          printf("Usage: VIGSOLVE -in <cipherfile> -keylen <N> [-out <plainfile>]\n");
          continue;
        }

        cipher_t cipher_norm;
        if (!load_normalized_ciphertext(infile, &cipher_norm)) {
          continue;
        }

    	char key[256];
    	if (!vig_solve_key_ic(&cipher_norm, keylen, key)) {
          free(cipher_norm.text);
         continue;
    	}

	   printf("[VIGSOLVE] Recovered key (length %d): %s\n", keylen, key);

    	free(cipher_norm.text);

        size_t in_len = 0;
    	uint8_t *in_buf = opus_load_entire_file(infile, &in_len);
    	if (!in_buf) {
        printf("[VIGSOLVE] Failed to read input file: %s\n", infile);
        continue;
    	}

    	char key_norm[256];
    	size_t klen = vigenere_normalize_key(key, key_norm, sizeof(key_norm));
    	if (klen == 0) {
        printf("[VIGSOLVE] Error: recovered key has no letters?\n");
        free(in_buf);
        continue;
    	}

    	uint8_t *out_buf = malloc(in_len);
    	if (!out_buf) {
          printf("[VIGSOLVE] Memory allocation failed\n");
          free(in_buf);
          continue;
    	}

    	if (vigenere_apply_buffer(in_buf, out_buf, in_len, key_norm, VIGENERE_MODE_DECRYPT) != 0) {
        printf("[VIGSOLVE] Error applying Vigenere cipher\n");
        free(in_buf);
        free(out_buf);
        continue;
    	}

    	if (opus_write_file(outfile, out_buf, in_len) != 0) {
        printf("[VIGSOLVE] Failed to write output file: %s\n", outfile);
        free(in_buf);
        free(out_buf);
        continue;
    	}

    	printf("[VIGSOLVE] Decrypted plaintext written to '%s'\n", outfile);

    	free(in_buf);
    	free(out_buf);
   
   	 continue;
	
	}	

	else if (strcmp(cmd, "VIGREFINE") == 0) {
    	const char *infile = NULL;
    	const char *outfile = "vigrefine_out.txt";
    	const char *seedkey = NULL;
    	int keylen = 0;
    	int iterations = 50000;

   	for (int i = 0; i < argc; i++) {
          if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            infile = argv[++i];
          } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            outfile = argv[++i];
          } else if (strcmp(argv[i], "-keylen") == 0 && i + 1 < argc) {
            keylen = atoi(argv[++i]);
          } else if (strcmp(argv[i], "-iters") == 0 && i + 1 < argc) {
            iterations = atoi(argv[++i]);
          } else if (strcmp(argv[i], "-seed") == 0 && i + 1 < argc) {
            seedkey = argv[++i];
        }
       }

	if (!infile || keylen <= 0) {
        printf("Usage: VIGREFINE -in <cipherfile> -keylen <N> "
               "[-iters <count>] [-seed KEY] [-out <plainfile>]\n");
        continue;
    }

    /* Load normalized ciphertext for scoring */
    cipher_t cipher_norm;
    if (!load_normalized_ciphertext(infile, &cipher_norm)) {
        continue;
    }

    /* Load quadgram model (same as MONO) */
    quadgram_model_t model;
    if (!load_quadgram_model("english_quadgrams.txt", &model)) {
        printf("[VIGREFINE] Error: could not load quadgram model\n");
        free(cipher_norm.text);
        continue;
    }

    char key[256];

    if (seedkey) {
        size_t slen = strlen(seedkey);
        if ((int)slen != keylen) {
            printf("[VIGREFINE] Seed key length %zu does not match keylen %d\n",
                   slen, keylen);
            free(cipher_norm.text);
            continue;
        }
        if (slen >= sizeof(key)) slen = sizeof(key) - 1;
        memcpy(key, seedkey, slen);
        key[slen] = '\0';
    } else {
        /* Use IC/chi-square solver (Step 3) as seed */
        if (!vig_solve_key_ic(&cipher_norm, keylen, key)) {
            printf("[VIGREFINE] Failed to derive initial key.\n");
            free(cipher_norm.text);
            continue;
        }
        printf("[VIGREFINE] Seed key from VIGSOLVE: %s\n", key);
    }

    /* Refine key with hillclimb + quadgrams */
   if (!vig_refine_key_hillclimb(&cipher_norm, key, iterations, &model, 0)) {
        free(cipher_norm.text);
        continue;
    }

    free(cipher_norm.text);

    /* Decrypt original file with refined key */
    size_t in_len = 0;
    uint8_t *in_buf = opus_load_entire_file(infile, &in_len);
    if (!in_buf) {
        printf("[VIGREFINE] Failed to read input file: %s\n", infile);
        continue;
    }

    char key_norm[256];
    size_t klen = vigenere_normalize_key(key, key_norm, sizeof(key_norm));
    if (klen == 0) {
        printf("[VIGREFINE] Error: refined key has no letters?\n");
        free(in_buf);
        continue;
    }

    uint8_t *out_buf = malloc(in_len);
    if (!out_buf) {
        printf("[VIGREFINE] Memory allocation failed\n");
        free(in_buf);
        continue;
    }

    if (vigenere_apply_buffer(in_buf, out_buf, in_len, key_norm,
                              VIGENERE_MODE_DECRYPT) != 0) {
        printf("[VIGREFINE] Error applying Vigenere cipher\n");
        free(in_buf);
        free(out_buf);
        continue;
    }

    if (opus_write_file(outfile, out_buf, in_len) != 0) {
        printf("[VIGREFINE] Failed to write output file: %s\n", outfile);
        free(in_buf);
        free(out_buf);
        continue;
    }

    printf("[VIGREFINE] Refined key: %s\n", key);
    printf("[VIGREFINE] Decrypted plaintext written to '%s'\n", outfile);

    free(in_buf);
    free(out_buf);
    continue;
	}
	else if (!strcmp(cmd, "VIGENCRYPT")) {
	cmd_vigencrypt(argc, argv);
	}

	else if (!strcmp(cmd, "PIETIME")) {
	    opus_pie_time_cli(argc, argv);
	}

        else if (strcmp(cmd, "CAESAR") == 0) {
            caesarMenu();
        }
        else if (strcmp(cmd, "FREQ") == 0) {
            frequencyAnalyzer();
        }
	else if (strcmp(cmd, "MONO") == 0) {

	    fileName();

	    size_t clen = 0;
	    uint8_t *cbuf = opus_load_entire_file(filename, &clen);
	    if (!cbuf) {
		printf("Error: could not read file '%s'\n", filename);
		continue;
	    }



	    // ------------------------------------------------------------
	    // LOAD QUADGRAM MODEL (this is Step 4)
	    // ------------------------------------------------------------
	    quadgram_model_t model;

	    if (!load_quadgram_model("english_quadgrams.txt", &model)) {
		printf("Error: could not load quadgram model\n");
		free(cbuf);
		continue;
	    }

	    // ------------------------------------------------------------
	    // SOLVER PARAMETERS
	    // ------------------------------------------------------------
	    solve_params_t params = {
		.max_iters      = 2000000,
		.start_temp     = 5.0,
		.end_temp       = 0.1,
		.plateau_limit  = 5000,
		.verbose        = 1,
		.log_interval   = 1000,
		.random_seed = (uint64_t)time(NULL),

		.use_initial_key = 0,
		.initial_key    = {0}
	    };

		char seedbuf[128];
		printf("Enter seed key (cipher->plain, 26 letters, blank for random): ");
		if (!fgets(seedbuf, sizeof(seedbuf), stdin)) {
	    	seedbuf[0] = '\0';
		}

	    size_t len = strlen(seedbuf);
	    if (len > 0 && seedbuf[len - 1] == '\n') {
		seedbuf[len - 1] = '\0';
		len--;
	    }

	    if (len == 26) {
		params.use_initial_key = 1;
		memcpy(params.initial_key, seedbuf, 26);
		printf("Using provided seed key.\n");
	    } else {
		params.use_initial_key = 0;
		printf("Using random initial key.\n");
	    }

	    // ------------------------------------------------------------
	    // RUN SOLVER
	    // ------------------------------------------------------------
	

	    // ------------------------------------------------------------
	    // OUTPUT RESULTS
	    // ------------------------------------------------------------

	    free(cbuf);
	    continue;
	}
	else if (strcmp(cmd, "VIGAUTO") == 0) {
	    const char *infile = NULL;
	    const char *outfile = "vigauto_out.txt";
	    int maxlen = 20;
	    int iterations = 50000;

	    for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
		    infile = argv[++i];
		} else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
		    outfile = argv[++i];
		} else if (strcmp(argv[i], "-maxlen") == 0 && i + 1 < argc) {
		    maxlen = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-iters") == 0 && i + 1 < argc) {
		    iterations = atoi(argv[++i]);
		}
	    }

    if (!infile) {
        printf("Usage: VIGAUTO -in <cipherfile> "
               "[-maxlen N] [-iters count] [-out <plainfile>]\n");
        continue;
    }

    /* Step 1: load normalized ciphertext */
    cipher_t cipher_norm;
    if (!load_normalized_ciphertext(infile, &cipher_norm)) {
        continue;
    }

    /* Step 2: guess key length */
    int keylen = vig_guess_keylen_ic(&cipher_norm, maxlen);
    if (keylen <= 0) {
        free(cipher_norm.text);
        continue;
    }

    /* Step 3: initial key via IC/chi-square column solve */
    char key[256];
    if (!vig_solve_key_ic(&cipher_norm, keylen, key)) {
        printf("[VIGAUTO] Failed to derive initial key.\n");
        free(cipher_norm.text);
        continue;
    }
    printf("[VIGAUTO] Seed key from VIGSOLVE logic: %s\n", key);

    /* Step 4: load quadgram model */
    quadgram_model_t model;
    if (!load_quadgram_model("english_quadgrams.txt", &model)) {
        printf("[VIGAUTO] Error: could not load quadgram model\n");
        free(cipher_norm.text);
        continue;
    }

    /* Step 5: refine key with hillclimb */
    if (!vig_refine_key_hillclimb(&cipher_norm, key, iterations, &model, 0)) {
        free(cipher_norm.text);
        continue;
    }

    printf("[VIGAUTO] Final refined key: %s\n", key);
    free(cipher_norm.text);

    /* Step 6: decrypt original file with refined key */
    size_t in_len = 0;
    uint8_t *in_buf = opus_load_entire_file(infile, &in_len);
    if (!in_buf) {
        printf("[VIGAUTO] Failed to read input file: %s\n", infile);
        continue;
    }

    char key_norm[256];
    size_t klen = vigenere_normalize_key(key, key_norm, sizeof(key_norm));
    if (klen == 0) {
        printf("[VIGAUTO] Error: refined key has no letters?\n");
        free(in_buf);
        continue;
    }

    uint8_t *out_buf = malloc(in_len);
    if (!out_buf) {
        printf("[VIGAUTO] Memory allocation failed\n");
        free(in_buf);
        continue;
    }

    if (vigenere_apply_buffer(in_buf, out_buf, in_len,
                              key_norm, VIGENERE_MODE_DECRYPT) != 0) {
        printf("[VIGAUTO] Error applying Vigenere cipher\n");
        free(in_buf);
        free(out_buf);
        continue;
    }

    if (opus_write_file(outfile, out_buf, in_len) != 0) {
        printf("[VIGAUTO] Failed to write output file: %s\n", outfile);
        free(in_buf);
        free(out_buf);
        continue;
    }

    printf("[VIGAUTO] Decrypted plaintext written to '%s'\n", outfile);

    free(in_buf);
    free(out_buf);
    continue;
	}

	else if (strcmp(cmd, "PIECALC") == 0) {
	    cmd_piecalc(NULL, argc, argv);
	    continue;
	}

	else if (strcmp(cmd, "ELFINFO") == 0) {
    	const char *infile = NULL;

    	for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-IN") == 0 && i + 1 < argc) {
            infile = argv[++i];
        }
    	}

    	if (!infile) {
        printf("Usage: ELFINFO -IN <binary>\n");
        continue;
    	}

	    opus_elfinfo_print(infile);
    	continue;
	}	
        else if (strcmp(cmd, "DESIG") == 0) {
            opus_extract_designations(filename);
        }
        else if (strcmp(cmd, "DESIGDEC") == 0) {
            opus_decode_designations(filename);
        }
        else if (strcmp(cmd, "DESIGSOLVE") == 0) {
            opus_designation_solve(filename);
        }
        else if (strcmp(cmd, "DESIGANALYZE") == 0) {
            opus_designation_analyze(filename);
        }
        else if (strcmp(cmd, "RSA-MINI") == 0) {
	    if (argc != 2) {
		printf("Usage: RSA-MINI <rsa_file>\n");
		continue;
	    }

    int rc = opus_mini_rsa(argv[1]);

    if (rc == 0)
        fprintf(stderr, "rsa-mini: failed\n");
    else
        fprintf(stderr, "rsa-mini: success\n");
}
        else if (strcmp(cmd, "RSA-FACTOR") == 0) {
    if (argc != 2) {
        printf("Usage: RSA-FACTOR <rsa_file>\n");
        continue;
    }

    const char *fname = argv[1];

    printf("[*] Input file: %s\n", fname);

        if (opus_rsa_factor(fname))
        printf("\nrsa-factor: success\n\n");
	else
	    printf("\nrsa-factor: failed\n\n");

    continue;
	}
	else if (strcmp(cmd, "RSA-RHO") == 0) {
	    if (argc != 2) {
		printf("Usage: RSA-RHO <rsa_file>\n");
		continue;
	    }

	    const char *fname = argv[1];

	    printf("[*] Input file: %s\n", fname);

	    if (opus_rsa_rho(fname))
		printf("\nrsa-rho: success\n\n");
	    else
		printf("\nrsa-rho: failed\n\n");

	    continue;
	}
        else if (strcmp(cmd, "RSA-WIENER") == 0) {
    		if (argc != 2) {
        	printf("Usage: RSA-WIENER <rsa_file>\n");
        	continue;
    	}
	    const char *path = argv[1];
	    printf("[*] Input file: %s\n", path);
	    mpz_t N, e, c, d, m;
	    mpz_inits(N, e, c, d, m, NULL);

	    if (parse_rsa_file(path, N, e, c) != 0) {
		printf("rsa-wiener: failed to parse RSA file\n");
		mpz_clears(N, e, c, d, m, NULL);
		continue;
	    }

	    printf("[*] RSA-WIENER: starting Wiener attack\n");

	    if (opus_rsa_wiener_attack(N, e, d) != 0) {
		printf("[-] RSA-WIENER: Wiener attack failed (d not small)\n");
		mpz_clears(N, e, c, d, m, NULL);
		continue;
	    }

	    printf("[+] RSA-WIENER: recovered d\n");

	    /* m = c^d mod N */
	    
	    mpz_powm(m, c, d, N);

	    opus_print_plaintext_from_bigint(m);
	    putchar('\n');

	    mpz_clears(N, e, c, d, m, NULL);
	    continue;
	}
	else if (strcmp(cmd, "RSA-SMALL-E") == 0) {
    		if (argc != 2) {
        	printf("Usage: RSA-SMALL-E <rsa_file>\n");
        	continue;
    	}
	    const char *path = argv[1];

	    mpz_t N, e, c, m;
	    mpz_inits(N, e, c, m, NULL);

	    if (parse_rsa_file(path, N, e, c) != 0) {
		printf("rsa-small-e: failed to parse RSA file\n");
		mpz_clears(N, e, c, m, NULL);
		continue;
	    }

	    unsigned long e_ul = mpz_get_ui(e);

	    printf("[*] RSA-SMALL-E: checking for small exponent attack (e = %lu)\n", e_ul);

	    if (e_ul == 0 || e_ul > 64) {
		printf("[-] RSA-SMALL-E: exponent too large or invalid\n");
		mpz_clears(N, e, c, m, NULL);
		continue;
	    }

	    if (rsa_small_e_attack(m, c, e_ul)) {
		printf("[+] RSA-SMALL-E: recovered plaintext via integer %lu-th root\n", e_ul);
		opus_print_plaintext_from_bigint(m);
	    } else {
		printf("[-] RSA-SMALL-E: attack not applicable (no exact root)\n");
	    }

	    mpz_clears(N, e, c, m, NULL);
	}
	else if (strcmp(cmd, "RSA-ROOTS") == 0) {
    		if (argc != 2) {
        	printf("Usage: RSA-ROOTS <rsa_file>\n");
        	continue;
    	}
	    const char *path = argv[1];

	    mpz_t N, e, c, m;
	    mpz_inits(N, e, c, m, NULL);

	    if (parse_rsa_file(path, N, e, c) != 0) {
		printf("rsa-roots: failed to parse RSA file\n");
		mpz_clears(N, e, c, m, NULL);
		continue;
	    }

	    unsigned long e_ul = mpz_get_ui(e);

	    printf("[*] RSA-ROOTS: checking exact integer root path\n");
	    gmp_printf("[*] N = %Zd\n", N);
	    gmp_printf("[*] e = %Zd\n", e);
	    gmp_printf("[*] c = %Zd\n", c);

	    if (mpz_even_p(e)) {
		printf("[!] RSA-ROOTS: even public exponent detected\n");
		printf("[!] RSA-ROOTS: normal RSA private exponent may not exist if gcd(e, phi(n)) != 1\n");
	    }

	    if (e_ul == 0 || e_ul > 64 || mpz_cmp_ui(e, e_ul) != 0) {
		printf("[-] RSA-ROOTS: exponent too large or invalid for exact integer root helper\n");
		printf("[*] RSA-ROOTS: modular root support with known p/q is planned for a later expansion\n");
		mpz_clears(N, e, c, m, NULL);
		continue;
	    }

	    if (rsa_small_e_attack(m, c, e_ul)) {
		printf("[+] RSA-ROOTS: recovered plaintext via exact integer %lu-th root\n", e_ul);
		opus_print_plaintext_from_bigint(m);
	    } else {
		printf("[-] RSA-ROOTS: no exact integer %lu-th root found\n", e_ul);
		printf("[*] RSA-ROOTS: if p and q are known, modular root recovery may still be possible\n");
	    }

	    mpz_clears(N, e, c, m, NULL);
	}
	else if (strcmp(cmd, "RSA-KNOWNPQ") == 0) {
    		if (argc != 4) {
        	printf("Usage: RSA-KNOWNPQ <rsa_file> <p> <q>\n");
        	continue;
    	}
            const char *path = argv[1];
            const char *p_str = argv[2];
            const char *q_str = argv[3];

            printf("[*] RSA-KNOWNPQ: starting known-pq decryption\n");
            if (opus_rsa_knownpq(path, p_str, q_str)) {
                printf("rsa-knownpq: success\n");
            } else {
                printf("rsa-knownpq: failed\n");
            }
        }
	else if (strcmp(cmd, "RSA-CHECKPQ") == 0) {
	    if (argc != 3) {
		printf("Usage: RSA-CHECKPQ <p> <q>\n");
		fflush(stdout);
		continue;
	    }

	    opus_rsa_checkpq(argv[1], argv[2]);
	}
	else if (strcmp(cmd, "RSA-DFROMPQ") == 0) {
	    if (argc != 4) {
		printf("Usage: RSA-DFROMPQ <p> <q> <e>\n");
		continue;
	    }

	    if (opus_rsa_dfrompq(argv[1], argv[2], argv[3])) {
		printf("rsa-dfrompq: success\n");
	    } else {
		printf("rsa-dfrompq: failed\n");
	    }
	}

	else if (strcmp(cmd, "RSA-ECM") == 0) {
    		if (argc != 2) {
        	printf("Usage: RSA-ECM <rsa_file>\n");
        continue;
    	}	
	    const char *path = argv[1];

	    mpz_t N, e, c, f, q;
	    mpz_inits(N, e, c, f, q, NULL);

	    if (parse_rsa_file(path, N, e, c) != 0) {
		printf("rsa-ecm: failed to parse RSA file\n");
		mpz_clears(N, e, c, f, q, NULL);
		continue;
	    }

	    printf("[*] RSA-ECM: starting ECM factorization\n");

	    if (!opus_rsa_ecm_factor(N, f)) {
		printf("[-] RSA-ECM: no factor found (within bounds)\n");
		mpz_clears(N, e, c, f, q, NULL);
		continue;
	    }

	    mpz_fdiv_q(q, N, f);

	    gmp_printf("[+] RSA-ECM: found factor f = %Zd\n", f);
	    gmp_printf("[+] RSA-ECM: cofactor q = %Zd\n", q);

	    // from here you can compute phi, d, and decrypt like RSA-FACTOR
	    mpz_clears(N, e, c, f, q, NULL);
	}


	else if (strcasecmp(cmd, "FORENSIC") == 0) {
	    dispatch_forensic(argc, argv);
	    continue;
	}

	else if (strcmp(cmd, "SOLVE") == 0) {

	    if (argc < 2) {
		printf("Usage: solve <cipherfile> [forced_spec]\n");
		continue;
	    }

	    const char *cipherfile   = argv[1];
	    const char *forced_spec  = (argc >= 3) ? argv[2] : NULL;

	    if (forced_spec)
		printf("Launching solver on '%s' with forced substitutions: %s\n",
		       cipherfile, forced_spec);
	    else
		printf("Launching solver on '%s'...\n", cipherfile);

	    run_solver_from_opus(cipherfile, forced_spec);
	    continue;
	}


        else if (strcmp(cmd, "X") == 0 || strcmp(cmd, "EXTRACT") == 0) {
            fileName();
            printf("\nRunning recursive extraction on: %s\n", filename);

		/* call the public wrapper instead of the internal extract_layers */
		if (opus_extract_recursive(filename) != 0) {
		    fprintf(stderr, "EXTRACT: failed for %s\n", filename);
		} else {
		    fprintf(stderr, "EXTRACT: completed for %s\n", filename);
		}

        }
        else if (strcmp(cmd, "DIGRAPH") == 0) {
            digraphTrigraphAnalyzer();
        }
        else {
            printf("Unknown command: %s\n", cmd);
        }
	
}
        /* --- end command dispatch --- */

return 0;

}




void toUpperStr(char *s) 
{
    for (; *s; ++s) 
    {
      *s = (char)toupper((unsigned char)*s);
    }
}
void run_entropy_heatmap(const char *path) {
    struct entropy_heatmap map;
    if (opus_entropy_heatmap_analyze(path, 4096, &map)== 0) {
        opus_entropy_heatmap_print(&map);
        opus_entropy_heatmap_free(&map);
    }
}
// Temporary stubs so the linker is happy.
// These will be replaced as we implement each module.

void run_rs_analysis(const char *path) {
    rs_result_t res;
    if (opus_rs_analyze_file(path, &res) == 0) {
        opus_rs_print_result(&res);
    } else {
        printf("\n--- RS Analysis ---\n");
        printf("Error: could not analyze file for RS statistics.\n");
    }
}

void run_file_carver(const char *path) {
    opus_carve_result_t res;
    /* For now, carve into a fixed subdir next to K1Wi. */
    const char *outdir = "carved";

    printf("\n--- File Carver ---\n");
    printf("Input file: %s\n", path);
    printf("Output dir: %s\n", outdir);

    if (opus_file_carve(path, outdir, &res) == 0) {
        printf("Carver summary: %d files carved, %d errors.\n",
               res.files_carved, res.errors);
    } else {
        printf("Carver error: failed to process input file.\n");
    }
}

static const char *confidence_label(opus_secret_confidence_t confidence)
{
    switch (confidence) {
        case OPUS_SECRET_HIGH:
            return "HIGH";
        case OPUS_SECRET_MEDIUM:
            return "MEDIUM";
        case OPUS_SECRET_LOW:
        default:
            return "LOW";
    }
}

static const char *confidence_color(opus_secret_confidence_t confidence)
{
    switch (confidence) {
        case OPUS_SECRET_HIGH:
            return CLR_RED;

        case OPUS_SECRET_MEDIUM:
            return CLR_YELLOW;

        default:
            return CLR_GREEN;
    }
}
void run_embedded_signature_scan(const char *path)
{
    embedded_sig_report_t report;

    printf("\n--- Embedded Signatures ---\n");

    if (embedded_sig_scan_file(path, &report) != 0) {
        printf("Embedded signature scan error: could not analyze file.\n");
        return;
    }

    if (report.count == 0) {
        printf("No embedded signatures found.\n");
        return;
    }

    for (int i = 0; i < report.count; i++) {
        printf("  [0x%08zx] %s\n",
               report.hits[i].offset,
               report.hits[i].type);
    }
}

void run_string_file(const char *path) {
    opus_string_report_t rep;

    printf("\n--- String Intelligence ---\n");

    if (opus_string_file(path, &rep) == 0) {
        printf("Summary: ASCII=%d UTF8=%d Base64=%d URL=%d Email=%d Suspicious=%d\n",
               rep.ascii_count,
               rep.utf8_count,
               rep.base64_count,
               rep.url_count,
               rep.email_count,
               rep.suspicious_count);

        if (rep.suspicious_hit_count > 0) {
            printf("\nHigh-Value Findings:\n");

	for (int i = 0; i < rep.suspicious_hit_count; i++) {
	    const char *s = rep.suspicious_hits[i].text;

	    printf("  %s[%s]%s [0x%08zx] %s",
		   confidence_color(rep.suspicious_hits[i].confidence),
		   confidence_label(rep.suspicious_hits[i].confidence),
		   CLR_RESET,
		   rep.suspicious_hits[i].offset,
		   rep.suspicious_hits[i].type);

	    if (rep.suspicious_hits[i].score > 0) {
		printf(" (%d/100)", rep.suspicious_hits[i].score);
	    }

	    printf("\n");

	    printf("      %.40s%s\n",
		   s,
		   strlen(s) > 40 ? "..." : "");
	}
        }
    } else {
        printf("String Intelligence error: could not analyze file.\n");
    }
}

void run_jpeg_huffman_fingerprint(const char *path) {
    jpeg_huff_fingerprint_t fp;
    if (opus_jpeg_huffman_fingerprint(path, &fp) == 0) {
        opus_jpeg_huffman_print(&fp);
    } else {
        printf("\n--- JPEG Huffman Fingerprint ---\n");
        printf("Error: could not read JPEG Huffman tables (not a JPEG or libjpeg error).\n");
    }
}

void run_dct_analysis(const char *path) {
    dct_summary_t sum;
    if (opus_dct_analyze_file(path, &sum) == 0) {
        opus_dct_print_summary(&sum);
    } else {
        printf("\n--- JPEG DCT Coefficient Analysis ---\n");
        printf("Error: could not analyze DCT coefficients (not a JPEG or libjpeg error).\n");
    }
}


static void k1wi_json_print_escaped(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;

    putchar('"');

    if (text) {
        while (*p) {
            switch (*p) {
                case '\\': printf("\\\\"); break;
                case '"':  printf("\\\""); break;
                case '\b': printf("\\b");  break;
                case '\f': printf("\\f");  break;
                case '\n': printf("\\n");  break;
                case '\r': printf("\\r");  break;
                case '\t': printf("\\t");  break;
                default:
                    if (*p < 0x20U) {
                        printf("\\u%04x", (unsigned int)*p);
                    } else {
                        putchar((int)*p);
                    }
                    break;
            }

            p++;
        }
    }

    putchar('"');
}

static const char *k1wi_lyzer_format_from_magic(const unsigned char *magic, size_t n)
{
    if (n >= 2U && magic[0] == 0xffU && magic[1] == 0xd8U) {
        return "JPEG";
    }

    if (n >= 8U &&
        magic[0] == 0x89U && magic[1] == 'P' &&
        magic[2] == 'N' && magic[3] == 'G') {
        return "PNG";
    }

    if (n >= 6U &&
        magic[0] == 'G' && magic[1] == 'I' && magic[2] == 'F') {
        return "GIF";
    }

    if (n >= 4U &&
        magic[0] == 'P' && magic[1] == 'K' &&
        magic[2] == 0x03U && magic[3] == 0x04U) {
        return "ZIP";
    }

    if (n >= 4U &&
        magic[0] == 0x7fU && magic[1] == 'E' &&
        magic[2] == 'L' && magic[3] == 'F') {
        return "ELF";
    }

    return "UNKNOWN";
}

static void k1wi_lyzer_json_summary(const char *path)
{
    FILE *fp = NULL;
    unsigned char magic[16] = {0};
    unsigned long long counts[256] = {0};
    unsigned char buf[4096];
    size_t magic_len = 0U;
    size_t nread = 0U;
    unsigned long long total = 0ULL;
    double entropy = 0.0;
    const char *format = "UNKNOWN";
    const char *assessment = "LOW";
    int read_error = 0;

    fp = fopen(path, "rb");
    if (!fp) {
        printf("{\n");
        printf("  \"tool\": \"LYZER\",\n");
        printf("  \"mode\": \"json\",\n");
        printf("  \"file\": ");
        k1wi_json_print_escaped(path);
        printf(",\n");
        printf("  \"error\": \"could not open file\"\n");
        printf("}\n");
        return;
    }

    magic_len = fread(magic, 1U, sizeof(magic), fp);
    format = k1wi_lyzer_format_from_magic(magic, magic_len);

    rewind(fp);

    while ((nread = fread(buf, 1U, sizeof(buf), fp)) > 0U) {
        size_t i;

        total += (unsigned long long)nread;

        for (i = 0U; i < nread; i++) {
            counts[buf[i]]++;
        }
    }

    if (ferror(fp)) {
        read_error = 1;
    }

    fclose(fp);

    if (!read_error && total > 0ULL) {
        size_t i;

        for (i = 0U; i < 256U; i++) {
            if (counts[i] > 0ULL) {
                double probability = (double)counts[i] / (double)total;
                entropy -= probability * (log(probability) / log(2.0));
            }
        }
    }

    if (entropy >= 7.5) {
        assessment = "HIGH";
    } else if (entropy >= 6.5) {
        assessment = "MEDIUM";
    }

    printf("{\n");
    printf("  \"tool\": \"LYZER\",\n");
    printf("  \"mode\": \"json\",\n");
    printf("  \"file\": ");
    k1wi_json_print_escaped(path);
    printf(",\n");
    printf("  \"format\": ");
    k1wi_json_print_escaped(format);
    printf(",\n");
    printf("  \"size_bytes\": %llu,\n", total);
    printf("  \"entropy\": %.4f,\n", entropy);
    printf("  \"assessment\": ");
    k1wi_json_print_escaped(assessment);
    printf(",\n");
    printf("  \"error\": ");
    if (read_error) {
        k1wi_json_print_escaped("read error");
    } else {
        printf("null");
    }
    printf("\n");
    printf("}\n");
}


static void ctf_Analyzer_run(const char *path, const char *mode)
{
    if (!path || path[0] == '\0') {
        fprintf(stderr, "LYZER: missing file path\n");
        return;
    }

    snprintf(filename, sizeof(filename), "%s", path);

    bool is_jpeg = false;

    FILE *fp = fopen(filename, "rb");
    if (fp) {
        unsigned char magic[2] = {0};
        if (fread(magic, 1, 2, fp) == 2) {
            is_jpeg = (magic[0] == 0xFF && magic[1] == 0xD8);
        }
        fclose(fp);
    }


    if (mode &&
        (strcasecmp(mode, "JSON") == 0 ||
         strcasecmp(mode, "--json") == 0 ||
         strcasecmp(mode, "json") == 0)) {
        k1wi_lyzer_json_summary(filename);
        return;
    }

    if (mode && strcasecmp(mode, "QUIET") == 0) {
        printf("\nK1Wi LYZER Quiet\n");
        printf("----------------\n");
        printf("File: %s\n", filename);

        detect_magic(filename);

        struct stego_report rep;
        if (opus_stego_analyze_file(filename, &rep) == 0) {
            printf("Entropy:    %.4f bits/byte\n", rep.entropy);
            printf("Chi-square: %.4f\n", rep.chi_square);

            if (rep.entropy >= 7.5) {
                printf("Assessment: HIGH entropy; review with --full\n");
            } else if (rep.entropy >= 6.5) {
                printf("Assessment: MEDIUM entropy; review if unexpected\n");
            } else {
                printf("Assessment: LOW entropy\n");
            }
        }

        printf("Next step:  Run LYZER %s --full for complete analysis.\n", filename);
        return;
    }

    if (mode && strcasecmp(mode, "SUMMARY") == 0) {
        printf("\nK1Wi LYZER Summary\n");
        printf("------------------\n");
        printf("File: %s\n", filename);

        detect_magic(filename);

        struct stego_report rep;
        if (opus_stego_analyze_file(filename, &rep) == 0) {
            printf("\nStego Summary\n");
            printf("-------------\n");
            printf("Bytes analyzed:   %zu\n", rep.bytes_analyzed);
            printf("Entropy:          %.4f bits/byte\n", rep.entropy);
            printf("Chi-square:       %.4f\n", rep.chi_square);

            if (rep.entropy >= 7.5) {
                printf("Assessment:       HIGH entropy; review with --full\n");
            } else if (rep.entropy >= 6.5) {
                printf("Assessment:       MEDIUM entropy; review if unexpected\n");
            } else {
                printf("Assessment:       LOW entropy\n");
            }
        }

        printf("\nNext steps:\n");
        printf("  Run LYZER %s --full for complete analysis.\n", filename);
        printf("  Run LYZER %s --verbose for detailed analysis.\n", filename);
        return;
    }

    putchar('\n');
    systemTime();
    putchar('\n');

    detect_magic(filename);
    analyze_image_file(filename);

    struct stego_report rep;
    if (opus_stego_analyze_file(filename, &rep) == 0) {
        opus_print_stego_report(&rep);
    }

    if (mode) {
        if (strcasecmp(mode, "H") == 0 || strcasecmp(mode, "ALL") == 0) {
            run_entropy_heatmap(filename);
        }

        if (strcasecmp(mode, "R") == 0 || strcasecmp(mode, "ALL") == 0) {
            run_rs_analysis(filename);
        }

        if (strcasecmp(mode, "E") == 0 || strcasecmp(mode, "ALL") == 0) {
            run_embedded_signature_scan(filename);
        }

        if (strcasecmp(mode, "C") == 0 || strcasecmp(mode, "ALL") == 0) {
            run_file_carver(filename);
        }

        if (strcasecmp(mode, "S") == 0 || strcasecmp(mode, "ALL") == 0) {
            run_string_file(filename);
        }

        if (strcasecmp(mode, "J") == 0 || strcasecmp(mode, "ALL") == 0) {
            if (is_jpeg) {
                run_jpeg_huffman_fingerprint(filename);
            } else {
                printf("\n--- JPEG Huffman Fingerprint ---\n");
                printf("Skipped: input is not a JPEG.\n");
            }
        }

        if (strcasecmp(mode, "D") == 0 || strcasecmp(mode, "ALL") == 0) {
            if (is_jpeg) {
                run_dct_analysis(filename);
            } else {
                printf("\n--- JPEG DCT Coefficient Analysis ---\n");
                printf("Skipped: input is not a JPEG.\n");
            }
        }
    }
}

void ctf_Analyzer(const char *mode)
{
    fileName();
    ctf_Analyzer_run(filename, mode);
}

int opus_lyzer_file(const char *path, const char *mode)
{
    ctf_Analyzer_run(path, mode ? mode : "SUMMARY");
    return 0;
}



/* Compute Index of Coincidence using only A–Z letters */
static double compute_ic_letters(const char *text, size_t len)
{
    long counts[26] = {0};
    long n = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c >= 'A' && c <= 'Z') {
            counts[c - 'A']++;
            n++;
        }
    }

    if (n <= 1) return 0.0;

    long num = 0;
    for (int i = 0; i < 26; i++) {
        num += counts[i] * (counts[i] - 1);
    }

    return (double)num / (double)(n * (n - 1));
}

/* Friedman estimate for key length (rough) */
static double friedman_estimate_keylen(const char *text, size_t len)
{
    double ic = compute_ic_letters(text, len);
    if (ic <= 0.0) return 0.0;

    /* English approx: K_r ≈ 0.0385 (random), K_p ≈ 0.0667 (plain) */
    double K_r = 0.0385;
    double K_p = 0.0667;

    double num = K_p - K_r;
    double den = ic - K_r;
    if (den <= 0.0) return 0.0;

    return num / den;
}

/* Average column IC for a given assumed key length */
static double avg_ic_for_keylen(const char *text, size_t len, int keylen)
{
    if (keylen <= 0) return 0.0;

    double total_ic = 0.0;
    int used_cols = 0;

    for (int k = 0; k < keylen; k++) {
        /* collect letters from positions i ≡ k (mod keylen) */
        char buf[8192];
        size_t bidx = 0;

        for (size_t i = (size_t)k; i < len; i += (size_t)keylen) {
            unsigned char c = (unsigned char)text[i];
            if (c >= 'A' && c <= 'Z') {
                if (bidx < sizeof(buf) - 1)
                    buf[bidx++] = (char)c;
            }
        }
        buf[bidx] = '\0';

        if (bidx > 1) {
            double ic = compute_ic_letters(buf, bidx);
            total_ic += ic;
            used_cols++;
        }
    }

    if (used_cols == 0) return 0.0;
    return total_ic / used_cols;
}

static void cmd_vig_analyze(const cipher_t *cipher)
{
    const char *text = cipher->text;
    size_t len = cipher->length;

    printf("\n[VIG-ANALYZE] Cipher length: %zu characters\n", len);

    double ic = compute_ic_letters(text, len);
    printf("[VIG-ANALYZE] Overall IC (letters only): %.6f\n", ic);

    double k_friedman = friedman_estimate_keylen(text, len);
    if (k_friedman > 0.0) {
        printf("[VIG-ANALYZE] Friedman estimated key length: %.2f\n", k_friedman);
    } else {
        printf("[VIG-ANALYZE] Friedman estimate not meaningful (IC too low/degenerate)\n");
    }

    printf("\n[VIG-ANALYZE] Average column IC by assumed key length:\n");
    printf(" len | avg_IC\n");
    printf("-----+--------\n");

    int max_len = 20;
    if ((int)len < max_len) max_len = (int)len;

    for (int L = 1; L <= max_len; L++) {
        double aic = avg_ic_for_keylen(text, len, L);
        printf(" %3d | %.6f\n", L, aic);
    }

    printf("\n[VIG-ANALYZE] Higher avg_IC near %.03f suggests plausible key lengths.\n", 0.0667);
}
static void randomize_vig_key(char *key)
{
    int klen = (int)strlen(key);
    if (klen <= 0) return;

    int changes = 1 + (rand() % 3);

    for (int c = 0; c < changes; c++) {
        int pos = rand() % klen;
        char old = key[pos];
        char new_letter;
        do {
            new_letter = (char)('A' + (rand() % 26));
        } while (new_letter == old);

        key[pos] = new_letter;
    }
}

static void vigenere_encrypt_letters(const char *plain, int len,
                                     const char *key, int keylen,
                                     char *out)
{
    for (int i = 0; i < len; i++) {
        int p = plain[i] - 'A';
        int k = key[i % keylen] - 'A';
        out[i] = (char)('A' + ((p + k) % 26));
    }
    out[len] = '\0';
}

static void cmd_vigencrypt(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: VIGENCRYPT -in <plainfile> -key <KEY> -out <cipherfile>\n");
        return;
    }

    const char *infile = NULL;
    const char *outfile = NULL;
    const char *key = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-in") && i + 1 < argc) infile = argv[++i];
        else if (!strcmp(argv[i], "-out") && i + 1 < argc) outfile = argv[++i];
        else if (!strcmp(argv[i], "-key") && i + 1 < argc) key = argv[++i];
    }

    if (!infile || !outfile || !key) {
        printf("Usage: VIGENCRYPT -in <plainfile> -key <KEY> -out <cipherfile>\n");
        return;
    }

    FILE *fi = fopen(infile, "r");
    if (!fi) {
        printf("Error: could not open plaintext file '%s'\n", infile);
        return;
    }

    // Read file into memory
    fseek(fi, 0, SEEK_END);
    long fsize = ftell(fi);
    if (fsize < 0) {
        fclose(fi);
        printf("Error: could not stat file '%s'\n", infile);
        return;
    }
    rewind(fi);

    char *raw = malloc((size_t)fsize + 1);
    if (!raw) {
        fclose(fi);
        printf("Error: out of memory reading '%s'\n", infile);
        return;
    }

    size_t read = fread(raw, 1, (size_t)fsize, fi);
    fclose(fi);
    raw[read] = '\0';

    // Normalize to A–Z letters only, uppercase
    char *plain = malloc(read + 1);
    if (!plain) {
        free(raw);
        printf("Error: out of memory normalizing '%s'\n", infile);
        return;
    }

    int plen = 0;
    for (size_t i = 0; i < read; i++) {
        if (isalpha((unsigned char)raw[i])) {
            plain[plen++] = (char)toupper((unsigned char)raw[i]);
        }
    }
    plain[plen] = '\0';
    free(raw);

    int keylen = (int)strlen(key);
    if (keylen <= 0) {
        free(plain);
        printf("Error: key must be non-empty\n");
        return;
    }

    char *cipher = malloc((size_t)plen + 1U);
    if (!cipher) {
        free(plain);
        printf("Error: out of memory for ciphertext\n");
        return;
    }

    vigenere_encrypt_letters(plain, plen, key, keylen, cipher);

    FILE *fo = fopen(outfile, "w");
    if (!fo) {
        printf("Error: could not open output file '%s'\n", outfile);
        free(plain);
        free(cipher);
        return;
    }

    fprintf(fo, "%s\n", cipher);
    fclose(fo);

    printf("[VIGENCRYPT] Ciphertext written to '%s' (%d letters)\n", outfile, plen);

    free(plain);
    free(cipher);
}



void cmd_vigcrack(const char *infile, const char *outfile, int forced_keylen)
{
    printf("[VIGCRACK] Cracking Vigenere cipher from '%s'\n", infile);

    /* Step 1: load normalized ciphertext */
    cipher_t cipher_norm;
    if (!load_normalized_ciphertext(infile, &cipher_norm)) {
        return;
    }

    printf("[VIGCRACK] Cipher length: %zu letters\n", cipher_norm.length);
    size_t preview = cipher_norm.length < 120 ? cipher_norm.length : 120;
    printf("[VIGCRACK] Cipher preview (first %zu chars):\n", preview);
    fwrite(cipher_norm.text, 1, preview, stdout);
    printf("\n");

    /* Step 2: key length selection */
    int keylen;
    if (forced_keylen > 0) {
        keylen = forced_keylen;
        printf("[VIGCRACK] Using forced key length: %d\n", keylen);
    } else {
        keylen = vig_guess_keylen_ic(&cipher_norm, 20);
        if (keylen <= 0) {
            printf("[VIGCRACK] ERROR: could not determine key length.\n");
            free(cipher_norm.text);
            return;
        }
        printf("[VIGCRACK] Guessed key length: %d\n", keylen);
    }

    /* Step 3: initial key via IC/chi-square */
    char key[256];
    if (!vig_solve_key_ic(&cipher_norm, keylen, key)) {
        printf("[VIGCRACK] ERROR: failed to derive initial key.\n");
        free(cipher_norm.text);
        return;
    }
    printf("[VIGCRACK] Initial key guess: %s\n", key);

  
	/* Step 4: load quadgram model */
	quadgram_model_t model;
	if (!load_quadgram_model("english_quadgrams.txt", &model)) {
	    printf("[VIGCRACK] Error: could not load quadgram model\n");
	    free(cipher_norm.text);
	    return;
	}

	/* Step 5: multi-restart refinement */
	int iterations = 50000;
	int restarts   = 20;

	char best_key_global[256];
	double best_score_global = -1e300;

	/* Start from the IC/chi-square key once */
	char work_key[256];
	strncpy(work_key, key, sizeof(work_key) - 1);
	work_key[sizeof(work_key) - 1] = '\0';

	printf("[VIGREFINE] Starting multi-restart refinement (%d restarts, %d iters each)\n",
	       restarts, iterations);

	for (int r = 0; r < restarts; r++) {
	    char cur_key[256];

	    if (r == 0) {
		/* First restart: use the IC-derived seed as-is */
		strncpy(cur_key, work_key, sizeof(cur_key) - 1);
		cur_key[sizeof(cur_key) - 1] = '\0';
	    } else {
		/* Subsequent restarts: perturb the previous global best (or original seed) */
		strncpy(cur_key, best_score_global > -1e299 ? best_key_global : work_key,
		        sizeof(cur_key) - 1);
		cur_key[sizeof(cur_key) - 1] = '\0';
		randomize_vig_key(cur_key);
	    }

	    if (!vig_refine_key_hillclimb(&cipher_norm, cur_key, iterations, &model, 0)) {
		printf("[VIGREFINE] Restart %d: refinement failed\n", r);
		continue;
	    }

	    double s = vig_score_with_key(&cipher_norm, cur_key, &model);
	    printf("[VIGREFINE] Restart %d: key=%s score=%.4f\n", r, cur_key, s);

	    if (s > best_score_global) {
		best_score_global = s;
		strncpy(best_key_global, cur_key, sizeof(best_key_global) - 1);
		best_key_global[sizeof(best_key_global) - 1] = '\0';
	    }
	}

	if (best_score_global <= -1e299) {
	    printf("[VIGREFINE] ERROR: no successful restarts.\n");
	    free(cipher_norm.text);
	    return;
	}

	/* Use the global best key */
	strncpy(key, best_key_global, sizeof(key) - 1);
	key[sizeof(key) - 1] = '\0';

	printf("[VIGREFINE] Global best key over %d restarts: %s (score %.4f)\n",
	       restarts, key, best_score_global);
	printf("[VIGCRACK] Refined key: %s\n", key);


    /* Step 6: decrypt using final key */
    char *plaintext = malloc(cipher_norm.length + 1);
    if (!plaintext) {
        printf("[VIGCRACK] ERROR: out of memory.\n");
        quadgrams_free(&model);
        free(cipher_norm.text);
        return;
    }

vigenere_decrypt_letters(cipher_norm.text,
                         cipher_norm.length,
                         key, (size_t)keylen, plaintext);

    /* Step 7: write plaintext to file */
    if (opus_write_file(outfile, (uint8_t *)plaintext, cipher_norm.length) == 0) {
        printf("[VIGCRACK] Decrypted plaintext written to '%s'\n", outfile);
    } else {
        printf("[VIGCRACK] ERROR: failed to write '%s'\n", outfile);
    }

    /* Cleanup */
    free(plaintext);
    quadgrams_free(&model);
    free(cipher_norm.text);
}



static char solve_caesar_column(const char *text, size_t len, int keylen, int col)
{
    int letter_pos = 0;
    int counts[26] = {0};
    int total = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];
        if (c >= 'A' && c <= 'Z') {
            if ((letter_pos % keylen) == col) {
                counts[c - 'A']++;
                total++;
            }
            letter_pos++;
        }
    }

    if (total == 0) {
        return 'A';
    }

    double best_score = 1e300;
    int best_shift = 0;

    for (int shift = 0; shift < 26; shift++) {
        double chi = 0.0;
        for (int cidx = 0; cidx < 26; cidx++) {
            int plain_idx = (cidx - shift + 26) % 26;
            double observed = (double)counts[cidx];
            double expected = (double)total * (ENGLISH_FREQ_PCT[plain_idx] / 100.0);
            if (expected > 0.0) {
                double diff = observed - expected;
                chi += (diff * diff) / expected;
            }
        }
        if (chi < best_score) {
            best_score = chi;
            best_shift = shift;
        }
    }

    return (char)('A' + best_shift);
}

static int vig_solve_key_ic(const cipher_t *cipher, int keylen, char *out_key)
{
    if (keylen <= 0 || keylen > 256) {
        printf("[VIGSOLVE] Invalid key length: %d\n", keylen);
        return 0;
    }

    for (int col = 0; col < keylen; col++) {
        out_key[col] = solve_caesar_column(cipher->text, cipher->length, keylen, col);
    }
    out_key[keylen] = '\0';

    return 1;
}

/* Decrypt a normalized A–Z ciphertext with a Vigenere key into A–Z plaintext. */
static void vigenere_decrypt_letters(const char *cipher, size_t len,
                                     const char *key, size_t klen,
                                     char *out_plain)
{
    size_t ki = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)cipher[i];
        if (c >= 'A' && c <= 'Z') {
            unsigned char k = (unsigned char)key[ki % klen];
            int pc = (c - 'A' - (k - 'A') + 26) % 26;
            out_plain[i] = (char)('A' + pc);
            ki++;
        } else {
            out_plain[i] = cipher[i];  /* should not really happen in normalized text */
        }
    }
    out_plain[len] = '\0';
}


/* Score plaintext produced by a given Vigenere key using quadgrams. */
static double vig_score_with_key(const cipher_t *cipher,
                                 const char *key,
                                 const quadgram_model_t *model)
{
    size_t len = cipher->length;
    char *plain = malloc(len + 1);
    if (!plain) return -1e300;  /* very bad score */

    size_t klen = strlen(key);
    vigenere_decrypt_letters(cipher->text, len, key, klen, plain);

    /* score_plaintext expects char * + len + model */
    double score = score_plaintext(plain, (uint32_t)len, model);

    free(plain);
    return score;
}

/* Hillclimb refinement over Vigenere keys using quadgram scoring. */
static int vig_refine_key_hillclimb(const cipher_t *cipher,
                                    char *key,
                                    int iterations,
                                    const quadgram_model_t *model,
                                    int verbose)
{
    if (iterations <= 0) iterations = 50000;

    int klen = (int)strlen(key);
    if (klen <= 0) {
        printf("[VIGREFINE] Empty key, cannot refine.\n");
        return 0;
    }

    /* normalize key to A–Z upper just in case */
    for (int i = 0; i < klen; i++) {
        if (key[i] >= 'a' && key[i] <= 'z')
            key[i] = (char)(key[i] - 'a' + 'A');
    }

    char best_key[256];
    if (klen >= (int)sizeof(best_key)) {
        printf("[VIGREFINE] Key too long.\n");
        return 0;
    }
    memcpy(best_key, key, (size_t)klen + 1U);

    double best_score = vig_score_with_key(cipher, best_key, model);
    printf("[VIGREFINE] Initial key '%s' score: %.4f\n", best_key, best_score);

    char trial_key[256];
    memcpy(trial_key, best_key, (size_t)klen + 1U);

    for (int iter = 0; iter < iterations; iter++) {
        int pos = rand() % klen;
        char old = trial_key[pos];

        /* pick a new letter different from old */
        char new_letter;
        do {
            new_letter = (char)('A' + (rand() % 26));
        } while (new_letter == old);

        trial_key[pos] = new_letter;

        double trial_score = vig_score_with_key(cipher, trial_key, model);

        if (trial_score > best_score) {
            best_score = trial_score;
            memcpy(best_key, trial_key, (size_t)klen + 1U);
        } else {
            /* revert */
            trial_key[pos] = old;
        }

	if (verbose && (iter + 1) % 5000 == 0) {
    printf("[VIGREFINE] iter %d best_score=%.4f best_key=%s\n",
           iter + 1, best_score, best_key);
}
    }

    memcpy(key, best_key, (size_t)klen + 1U);
    printf("[VIGREFINE] Final best key: %s (score %.4f)\n", key, best_score);
    return 1;
}

/* Guess Vigenere key length using column IC.
 * Considers lengths 1..max_len (capped by cipher length).
 * Returns best key length, or 0 on failure.
 */
static int vig_guess_keylen_ic(const cipher_t *cipher, int max_len)
{
    const char *text = cipher->text;
    size_t len = cipher->length;

    if (len < 2) return 0;
    if (max_len <= 0) max_len = 20;
    if ((int)len < max_len) max_len = (int)len;

    double overall_ic = compute_ic_letters(text, len);
    printf("[VIGAUTO] Overall IC: %.6f\n", overall_ic);

    int best_L = 0;
    double best_ic = 0.0;

    printf("[VIGAUTO] Scanning key lengths 1..%d\n", max_len);
    printf(" len | avg_IC\n");
    printf("-----+--------\n");

    for (int L = 1; L <= max_len; L++) {
        double aic = avg_ic_for_keylen(text, len, L);
        printf(" %3d | %.6f\n", L, aic);

        if (aic > best_ic) {
            best_ic = aic;
            best_L = L;
        }
    }

    if (best_L <= 0) {
        printf("[VIGAUTO] Failed to find plausible key length.\n");
        return 0;
    }

    printf("[VIGAUTO] Best key length by column IC: %d (avg_IC=%.6f)\n",
           best_L, best_ic);

    return best_L;
}


/* stringAnalyzerFromBuffer: non-interactive wrapper that reuses shared parsers.
 * - 'buf' is treated as read-only.
 * - Uses parse_and_print_numeric_tokens() for numeric token lists.
 * - Does not call strtok() on the caller buffer.
 */
void stringAnalyzerFromBuffer(const char *buf) {
    if (!buf) {
        printf("No input\n");
        return;
    }

    /* small local copy for detection helpers that may expect a mutable string */
    char working[8192];
    strncpy(working, buf, sizeof(working));
    working[sizeof(working) - 1] = '\0';

    /* If you have centralized parser: use it for token lists and mixed numeric input */
    if (isHexWithPrefix(working)) {
        printf("Looks like hex with 0x prefix. Decoded ASCII: ");
        /* parse_and_print_numeric_tokens handles "0x41 0x42" and similar */
        if (parse_and_print_numeric_tokens(working) != 0) {
            printf("[failed to decode]");
        }
        printf("\n");
        return;
    }

    if (isHex(working)) {
        /* contiguous hex like "48656c6c6f" or space-separated tokens */
        printf("Looks like hex. Decoded ASCII: ");
        if (parse_and_print_numeric_tokens(working) != 0) {
            printf("[failed to decode]");
        }
        printf("\n");
        return;
    }

    /* Fallback: try the unified numeric parser (decimal lists, binary lists, octal, etc.) */
    if (parse_and_print_numeric_tokens(working) == 0) {
        printf("\n");
        return;
    }

    /* Nothing matched */
    printf("Unknown format\n");
}

static bool isA1Z26(const char *s)
{
    bool has_valid = false;

    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (isspace(c) || c == '{' || c == '}')
            continue;

        if (!isdigit(c))
            return false;

        // Parse number
        int val = atoi(&s[i]);
        if (val < 1 || val > 26)
            return false;

        has_valid = true;

        // Skip full number token
        while (isdigit((unsigned char)s[i+1]))
            i++;
    }

    return has_valid;
}

static unsigned char *a1z26_decode(const char *s, size_t *out_len)
{
    unsigned char *buf = malloc(strlen(s) + 1);
    *out_len = 0;

    for (size_t i = 0; s[i]; i++) {
        if (isspace((unsigned char)s[i]) || s[i] == '{' || s[i] == '}')
            continue;

        if (isdigit((unsigned char)s[i])) {
            int val = atoi(&s[i]);
            if (val >= 1 && val <= 26) {
                buf[(*out_len)++] = (unsigned char)('A' + val - 1);
            }

            while (isdigit((unsigned char)s[i+1]))
                i++;
        }
    }

    return buf;
}
static void decode_escapes(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < outsz; i++) {
        if (in[i] == '\\' && in[i+1]) {
            char c = in[i+1];

            if (c == 'n') { out[o++] = '\n'; i++; }
            else if (c == 't') { out[o++] = '\t'; i++; }
            else if (c == '\\') { out[o++] = '\\'; i++; }
            else if (c == 'x' &&
                     isxdigit((unsigned char)in[i+2]) &&
                     isxdigit((unsigned char)in[i+3])) {
                char buf[3] = { in[i+2], in[i+3], 0 };
                out[o++] = (char)strtoul(buf, NULL, 16);
                i += 3;
            } else {
                out[o++] = in[i];
            }
        } else {
            out[o++] = in[i];
        }
    }
    out[o] = '\0';
}


//============= String Analyzer ==================
//================================================
void stringAnalyzer(void)
{
    char input[8192];
    printf("Enter string to analyze: ");
    if (!fgets(input, sizeof(input), stdin))
        return;

    input[strcspn(input, "\r\n")] = '\0';

    char working[8192];
    strncpy(working, input, sizeof(working));
    working[sizeof(working) - 1] = '\0';

    printf("\n=== STRING ANALYZER ===\n");
    printf("Input: %s\n", working);

	/* Handle empty input cleanly */
	if (working[0] == '\0') {
	    printf("[Empty input]\n");
	    printf("=== END STRING ANALYZER ===\n\n");
	    return;
	}


    size_t out_len = 0;
    unsigned char *decoded = NULL;

    /* Normalize: strip spaces for Base64 detection */
    char b64clean[8192];
    {
        size_t j = 0;
        for (size_t i = 0; working[i]; i++)
            if (!isspace((unsigned char)working[i]))
                b64clean[j++] = working[i];
        b64clean[j] = '\0';
    }

    /* 0. UTF-8 heuristic (non-ASCII heavy) */
    {
        size_t len = strlen(working);
        unsigned char *buf = (unsigned char *)working;
        if (len > 0 && is_valid_utf8(buf, len)) {
            double ascii_ratio = ascii_printable_ratio(buf, len);
            if (ascii_ratio < 0.7) {
                printf("[UTF-8 Text]\n");
                printf("=== END STRING ANALYZER ===\n\n");
                return;
            }
        }
    }

    /* 1. Hex with prefix (0x##) */
    if (isHexWithPrefix(working)) {
        printf("[Hex w/ prefix] → ");
        if (parse_and_print_numeric_tokens(working) != 0)
            printf("[decode failed]");
        printf("\n=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 2. MD5 */
    if (isMD5(working)) {
        printf("[MD5] → Looks like an MD5 hash\n");
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 3. Space-separated binary (8-bit tokens only) */
    {
        bool has_bit = false, valid = true;
        for (size_t i = 0; working[i]; i++) {
            if (working[i] == '0' || working[i] == '1') {
                has_bit = true;
            } else if (!isspace((unsigned char)working[i])) {
                valid = false;
                break;
            }
        }

        if (valid && has_bit && strchr(working, ' ')) {
            printf("[Binary → ASCII] → ");
            char *copy = strdup(working);
            char *tok = strtok(copy, " ");
            decoded = malloc(strlen(working));
            out_len = 0;

            while (tok) {
                if (strlen(tok) != 8) {
                    printf("[decode failed]\n");
                    free(copy);
                    free(decoded);
                    printf("=== END STRING ANALYZER ===\n\n");
                    return;
                }
                unsigned char v = 0;
                for (int i = 0; i < 8; i++)
                    v = (unsigned char)((v << 1) | (tok[i] == '1'));
                decoded[out_len++] = v;
                tok = strtok(NULL, " ");
            }

            double ratio = ascii_printable_ratio(decoded, out_len);
            if (ratio > 0.5) {
                printf("%.*s\n", (int)out_len, decoded);
            } else {
                printf(" ");
                for (size_t i = 0; i < out_len; i++)
                    printf("%02X", decoded[i]);
                printf("\n");
            }

            free(copy);
            free(decoded);
            printf("=== END STRING ANALYZER ===\n\n");
            return;
        }
    }

    /* 4. Pure binary (no spaces, strict) */
    if (looks_like_binary_strict(working)) {
        printf("[Binary] → ");
        decoded = binary_decode(working, &out_len);
        if (decoded) {
            double ratio = ascii_printable_ratio(decoded, out_len);
            if (ratio > 0.5) {
                printf("[ASCII] %.*s\n", (int)out_len, decoded);
            } else {
                for (size_t i = 0; i < out_len; i++)
                    printf(" %02X", decoded[i]);
                printf("\n");
            }
            free(decoded);
        } else {
            printf("[decode failed]\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 5. A1Z26 (1–26 → A–Z) */
    if (isA1Z26(working)) {
        printf("[A1Z26] → ");
        decoded = a1z26_decode(working, &out_len);
        if (decoded) {
            printf("%.*s\n", (int)out_len, decoded);
            free(decoded);
        } else {
            printf("[decode failed]\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }
/* Suppress hex detection for long alphabetic strings */
{
    bool all_alpha = true;
    for (size_t i = 0; working[i]; i++) {
        if (!isalpha((unsigned char)working[i])) {
            all_alpha = false;
            break;
        }
    }

    if (all_alpha && strlen(working) > 8) {
        printf("[ASCII Text]\n");
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }
}

    /* 6. Hex (continuous or spaced, but stricter) */
    if (isHex(working) || isStrictHex(working)) {
        printf("[Hex] → ");
        decoded = hex_decode(working, &out_len);
        if (decoded) {
            double ratio = ascii_printable_ratio(decoded, out_len);
            if (ratio > 0.5) {
                printf("[ASCII] %.*s\n", (int)out_len, decoded);
            } else {
                for (size_t i = 0; i < out_len; i++)
                    printf(" %02X", decoded[i]);
                printf("\n");
            }
            free(decoded);
        } else {
            printf("[decode failed]\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 7. Base64 (after hex, stricter) */
    if (looks_like_base64_strict(b64clean) || isBase64(b64clean) || looks_like_base64(b64clean)) {
        printf("[Base64] → ");
        decoded = b64_decode(b64clean, &out_len);
        if (decoded) {
            double ratio = ascii_printable_ratio(decoded, out_len);
            if (ratio > 0.8 || is_valid_utf8(decoded, out_len)) {
                printf("%.*s\n", (int)out_len, decoded);
            } else {
                for (size_t i = 0; i < out_len; i++)
                    printf(" %02X", decoded[i]);
                printf("\n");
            }
            free(decoded);
        } else {
            printf("[decode failed]\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 8. Octal ASCII */
    if (isOctalCode(working)) {
        printf("[Octal ASCII] → ");
        decoded = octal_ascii_decode(working, &out_len);
        if (decoded) {
            printf("%.*s\n", (int)out_len, decoded);
            free(decoded);
        } else {
            printf("[decode failed]\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }

    /* 9. Decimal ASCII */
    if (isStrictDecimalList(working) || isAsciiCode(working)) {
        printf("[Decimal ASCII] → ");
        char *copy = strdup(working);
        char *tok = strtok(copy, " ");
        decoded = malloc(strlen(working));
        out_len = 0;

        while (tok) {
            int v = atoi(tok);
            if (v < 0 || v > 255) {
                printf("[decode failed]\n");
                free(copy);
                free(decoded);
                printf("=== END STRING ANALYZER ===\n\n");
                return;
            }
            decoded[out_len++] = (unsigned char)v;
            tok = strtok(NULL, " ");
        }

        printf("%.*s\n", (int)out_len, decoded);
        free(copy);
        free(decoded);
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }
/* ---------------------------------------------------------
 * Escaped ASCII (handles \xNN, \n, \t, etc.)
 * --------------------------------------------------------- */
{
    char dec[8192];
    decode_escapes(working, dec, sizeof(dec));
       
    size_t dlen = strlen(dec);
    double ratio = ascii_printable_ratio((unsigned char*)dec, dlen);
    double H = shannon_entropy((unsigned char*)dec, dlen);

    if (ratio > 0.85 && H < 4.5) {
        printf("[Escaped ASCII] → %s\n", dec);
        printf("=== END STRING ANALYZER ===\n\n");
        return;
    }
}

    /* 10. Printable ASCII with entropy check */
    {
        size_t len = strlen(working);
        unsigned char *buf = (unsigned char *)working;
        double ratio = ascii_printable_ratio(buf, len);
        double H = shannon_entropy(buf, len);
        if (ratio > 0.85 && H < 4.5 && len >= 3) {
            printf("[ASCII Text]\n");
            printf("=== END STRING ANALYZER ===\n\n");
            return;
        }
    }

    /* 11. Fallback */
    {
        int r = parse_and_print_numeric_tokens(working);
        if (r == 0) {
            printf("\n[Fallback decode above]\n");
            printf("Unknown numeric format\n");
        } else {
            printf("Unknown format\n");
        }
        printf("=== END STRING ANALYZER ===\n\n");
    }
}

//========= END stringAnalyzer ==============





//-- String Analyzer Helper functions ---

int isHexWithPrefix(const char *s) 
{ 

 // Accept tokens like "0x70" 
   size_t len = strlen(s); 
   char *copy = malloc(len + 1); 
 	
 	if (!copy) return 0; 
         memcpy(copy, s, len + 1); 
 
 char *token = strtok(copy, " "); 
 
 int ok = 1; 
 
 while (token != NULL) 
 { 
   if (!(strlen(token) > 2 && token[0] == '0' && token[1] == 'x')) 
 { 
   ok = 0; 
   break; 
 } 
 
 token = strtok(NULL, " "); 
 
 } 
 
 free(copy); 
 
 return ok;

}
int isHex(const char *s) 
{
    // Check if the string is all hex digits or space-separated hex tokens
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == ' ') continue;
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
    
    // Accept tokens like "0x70" 
    size_t len = strlen(s); 
    char *copy = malloc(len + 1); 
    if (!copy) return 0; 
    memcpy(copy, s, len + 1);
    char *token = strtok(copy, " ");
    int ok = 1; 
    while (token != NULL) { 
    if (!(strlen(token) > 2 && token[0] == '0' && token[1] == 'x')) 
    { 
      ok = 0; 
      break; 
    } 
    
    token = strtok(NULL, " "); 
    } 
    free(copy); 
    return ok;
    
}

int isBase64(const char *s) 
{
    size_t len = strlen(s);
    if (len % 4 != 0) return 0;

    int hasNonHex = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!(isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=')) {
            return 0; // invalid character
        }
        if (!(isdigit((unsigned char)c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            hasNonHex = 1; // found something outside hex range
        }
    }
    return hasNonHex; // must have at least one non-hex character
}
int isPrintableASCII(const char *s) {
    if (!s || !*s) return 0;

    /* Reject if it contains numeric tokens */
    int has_digit = 0;
    for (const char *p = s; *p; ++p) {
        if (isdigit((unsigned char)*p)) {
            has_digit = 1;
            break;
        }
    }
    if (has_digit)
        return 0;

    /* Now check if all characters are printable ASCII */
    for (const char *p = s; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c < 32 || c > 126)
            return 0;
    }

    return 1;
}


int isMD5(const char *s) 
{
    size_t len = strlen(s);
    if (len != 32) return 0;  // MD5 is always 32 hex chars
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

int isBinaryString(const char *s) 
{
    for (size_t i = 0; i < strlen(s); i++) 
    {
        if (s[i] != '0' && s[i] != '1' && s[i] != ' ')
            return 0;
    }
  
    return 1;
}
int isAsciiCode(const char *s) 
{
    // Accept digits and spaces only
    for (size_t i = 0; i < strlen(s); i++) {
        if (!(isdigit((unsigned char)s[i]) || s[i] == ' ')) {
            return 0;
        }
    }
    return 1;
}
int isOctalCode(const char *s) {
    if (!s || !*s) return 0;

    char *copy = strdup(s);
    if (!copy) return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, " ", &save);

    while (tok) {
        // Reject if any digit is 8 or 9
        for (char *p = tok; *p; ++p) {
            if (*p < '0' || *p > '7') {
                free(copy);
                return 0;
            }
        }

        // Convert octal → decimal
        char *endp = NULL;
        long v = strtol(tok, &endp, 8);
        if (*endp != '\0' || v < 0 || v > 255) {
            free(copy);
            return 0;
        }

        tok = strtok_r(NULL, " ", &save);
    }

    free(copy);
    return 1;
}


void hexToAscii(const char *hexStr, char *outBuf, size_t outSize) {
    size_t len = strlen(hexStr);
    if (len % 2 != 0) {
        fprintf(stderr, "Error: hex string length must be even\n");
        outBuf[0] = '\0';
        return;
    }

    size_t outLen = len / 2;
    if (outLen >= outSize) {
        fprintf(stderr, "Error: output buffer too small\n");
        outBuf[0] = '\0';
        return;
    }

    for (size_t i = 0; i < outLen; i++) {
        char byteStr[3];
        byteStr[0] = hexStr[i*2];
        byteStr[1] = hexStr[i*2 + 1];
        byteStr[2] = '\0';
        unsigned char value = (unsigned char) strtol(byteStr, NULL, 16);
        outBuf[i] = (char)value;
    }
    outBuf[outLen] = '\0';
}




/* Strict hex validator:
 * - Accepts either:
 *      (A) contiguous even-length hex string: "414243"
 *      (B) space-separated hex tokens: "41 42 43"
 * - Rejects:
 *      - odd-length contiguous hex
 *      - tokens containing non-hex chars
 *      - tokens longer than 2 chars (unless contiguous mode)
 *      - mixed formats
 */



void digraphTrigraphAnalyzer() {
    char line[8192];
    int digraphCounts[26][26] = {0};
    int trigraphCounts[26][26][26] = {0};
    int totalDigraphs = 0, totalTrigraphs = 0;

    // Common English digraphs and trigraphs
    const char *commonDigraphs[] = {"TH","HE","IN","ER","AN","RE","ON","AT","EN","ND"};
    const char *commonTrigraphs[] = {"THE","AND","ING","ENT","ION","HER","FOR","THA","NTH","INT"};

    printf("Enter ciphertext to analyze (end with blank line):\n");
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n') break; // stop on blank line
        size_t len = strlen(line);
        for (size_t i = 0; i < len; i++) {
            if (isalpha((unsigned char)line[i])) {
                line[i] = (char)toupper((unsigned char)line[i]);
            }
        }
        // Count digraphs
        for (size_t i = 0; i + 1 < len; i++){
            if (isalpha(line[i]) && isalpha(line[i+1])) {
                int a = line[i] - 'A';
                int b = line[i+1] - 'A';
                digraphCounts[a][b]++;
                totalDigraphs++;
            }
        }
        // Count trigraphs
       for (size_t i = 0; i + 2 < len; i++) {
            if (isalpha(line[i]) && isalpha(line[i+1]) && isalpha(line[i+2])) {
                int a = line[i] - 'A';
                int b = line[i+1] - 'A';
                int c = line[i+2] - 'A';
                trigraphCounts[a][b][c]++;
                totalTrigraphs++;
            }
        }
    }

    // Collect digraphs into array
    NGram digraphList[26*26];
    int digraphSize = 0;
    for (int a = 0; a < 26; a++) {
        for (int b = 0; b < 26; b++) {
            if (digraphCounts[a][b] > 0) {
                digraphList[digraphSize].seq[0] = (char)('A' + a);
                digraphList[digraphSize].seq[1] = (char)('A'+ b);
                digraphList[digraphSize].seq[2] = '\0';
                digraphList[digraphSize].count = digraphCounts[a][b];
                digraphList[digraphSize].percent = (100.0 * digraphCounts[a][b]) / totalDigraphs;
                digraphSize++;
            }
        }
    }
    qsort(digraphList, (size_t)digraphSize, sizeof(NGram), compareNGram);

    // Collect trigraphs into array
    NGram trigraphList[26*26*26];
    int trigraphSize = 0;
    for (int a = 0; a < 26; a++) {
        for (int b = 0; b < 26; b++) {
            for (int c = 0; c < 26; c++) {
                if (trigraphCounts[a][b][c] > 0) {
                    trigraphList[trigraphSize].seq[0] = (char)('A'+ a);
                    trigraphList[trigraphSize].seq[1] = (char)('A'+ b);
                    trigraphList[trigraphSize].seq[2] = (char)('A'+ c);
                    trigraphList[trigraphSize].seq[3] = '\0';
                    trigraphList[trigraphSize].count = trigraphCounts[a][b][c];
                    trigraphList[trigraphSize].percent = (100.0 * trigraphCounts[a][b][c]) / totalTrigraphs;
                    trigraphSize++;
                }
            }
        }
    }
 qsort(trigraphList, (size_t)trigraphSize, sizeof(NGram), compareNGram);

    // Print top 10 digraphs with English comparison
printf("\nTop Digraphs (cipher vs English):\n");
printf("Seq | Count | %%   | English %% | Note\n");
printf("----+-------+-----+------------+-----------------\n");
for (int i = 0; i < digraphSize && i < 10; i++) {
    double englishPercent = 0.0;
    const char *note = "";
    for (int j = 0; j < 10; j++) {
        if (strcmp(digraphList[i].seq, commonDigraphs[j]) == 0) {
            // expected English percentages
            double englishValues[10] = {3.56,3.07,2.43,2.05,1.99,1.85,1.76,1.49,1.45,1.35};
            englishPercent = englishValues[j];
            note = "common in English";
            break;
        }
    }
    printf("%-3s | %5d | %4.2f | %6.2f    | %s\n",
           digraphList[i].seq,
           digraphList[i].count,
           digraphList[i].percent,
           englishPercent,
           note);
}

// Print top 10 trigraphs with English comparison
printf("\nTop Trigraphs (cipher vs English):\n");
printf("Seq  | Count | %%   | English %% | Note\n");
printf("-----+-------+-----+------------+-----------------\n");
for (int i = 0; i < trigraphSize && i < 10; i++) {
    double englishPercent = 0.0;
    const char *note = "";
    for (int j = 0; j < 10; j++) {
        if (strcmp(trigraphList[i].seq, commonTrigraphs[j]) == 0) {
            double englishValues[10] = {1.81,0.73,0.72,0.42,0.42,0.36,0.34,0.33,0.33,0.32};
            englishPercent = englishValues[j];
            note = "common in English";
            break;
        }
    }
    printf("%-4s | %5d | %4.2f | %6.2f    | %s\n", trigraphList[i].seq, trigraphList[i].count, trigraphList[i].percent, englishPercent, note);
	}
}

//--- End string Analyzer Helper functions ---


//=============== CyptoAnalysis ================

void caesarMenu() {
    char input[8192];
    printf("Enter ciphertext to crack: ");
    if (fgets(input, sizeof(input), stdin) == NULL) return;
    input[strcspn(input, "\r\n")] = '\0'; // trim newline

    size_t len = strlen(input);
    char decodedLine[8192];

    printf("\nAttempting Caesar cipher crack (backward shifts)...\n");
    for (int shift = 1; shift < 26; shift++) {
        int pos = 0;
        for (size_t i = 0; i < len; i++) {
            char c = input[i];
            if (isalpha((unsigned char)c)) {
                char base = isupper((unsigned char)c) ? 'A' : 'a';
                decodedLine[pos++] = (c - base - shift + 26) % 26 + base;
            } else {
                decodedLine[pos++] = c;
            }
        }
        decodedLine[pos] = '\0';
        printf("Shift %2d: %s", shift, decodedLine);
        if (strstr(decodedLine, "CTF{") != NULL) {
            printf(" <-- possible flag!");
        }
        printf("\n");
    }

    printf("\nAttempting Caesar cipher crack (forward shifts)...\n");
    for (int shift = 1; shift < 26; shift++) {
        int pos = 0;
        for (size_t i = 0; i < len; i++) {
            char c = input[i];
            if (isalpha((unsigned char)c)) {
                char base = isupper((unsigned char)c) ? 'A' : 'a';
                decodedLine[pos++] = (c - base + shift) % 26 + base;
            } else {
                decodedLine[pos++] = c;
            }
        }
        decodedLine[pos] = '\0';
        printf("Shift %2d: %s", shift, decodedLine);
        if (strstr(decodedLine, "CTF{") != NULL) {
            printf(" <-- possible flag!");
        }
        printf("\n");
    }
}

void frequencyAnalyzer() 
{
    char line[8192];
    int freq[26] = {0};
    int totalLetters = 0;

    // Standard English frequencies (approximate percentages)
    double englishFreq[26] = {
        8.17, // A
        1.49, // B
        2.78, // C
        4.25, // D
        12.70,// E
        2.23, // F
        2.02, // G
        6.09, // H
        6.97, // I
        0.15, // J
        0.77, // K
        4.03, // L
        2.41, // M
        6.75, // N
        7.51, // O
        1.93, // P
        0.10, // Q
        5.99, // R
        6.33, // S
        9.06, // T
        2.76, // U
        0.98, // V
        2.36, // W
        0.15, // X
        1.97, // Y
        0.07  // Z
    };

    printf("Enter ciphertext to analyze (end with blank line):\n");
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == '\n') break; // stop on blank line
        for (int i = 0; line[i]; i++) {
            char c = line[i];
            if (isalpha((unsigned char)c)) {
                c = (char)toupper((unsigned char)c);
                freq[c - 'A']++;
                totalLetters++;
            }
        }
    }

    // Build entries
    FreqEntry entries[26];
    for (int i = 0; i < 26; i++) {
        entries[i].letter = (char)('A' + i);
        entries[i].count = freq[i];
        entries[i].percent = totalLetters ? (100.0 * freq[i]) / totalLetters : 0.0;
    }

    // Sort descending by ciphertext frequency
    for (int i = 0; i < 25; i++) {
        for (int j = i+1; j < 26; j++) {
            if (entries[j].count > entries[i].count) {
                FreqEntry tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    // Print results with English reference
    printf("\nLetter frequency analysis (sorted):\n");
    printf("Cipher | Count | %%   | English %%\n");
    printf("-------+-------+-----+-----------\n");
    for (int i = 0; i < 26; i++) {
        if (entries[i].count > 0) {
            int idx = entries[i].letter - 'A';
            printf("   %c   | %5d | %4.2f | %6.2f\n",
                   entries[i].letter,
                   entries[i].count,
                   entries[i].percent,
                   englishFreq[idx]);
        }
    }
    printf("\nTotal letters counted: %d\n", totalLetters);
  }

//---------- END Frequency Analysis -----------------

void monoSubstitute(void) {
    char key[128];
    char input[8192];

    printf("Enter 26-letter substitution key (plaintext A..Z -> ciphertext letter): ");
    if (fgets(key, sizeof(key), stdin) == NULL) return;
    key[strcspn(key, "\r\n")] = '\0';

    // Trim whitespace
    char *start = key;
    while (*start && isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end-1))) end--;
    *end = '\0';

    if (strlen(start) != 26) {
        printf("Error: key must be exactly 26 letters (you provided %zu).\n", strlen(start));
        return;
    }

    bool seen[26] = {0};
    for (int i = 0; i < 26; i++) {
        if (!isalpha((unsigned char)start[i])) {
            printf("Error: key must contain only letters.\n");
            return;
        }
        int idx = toupper((unsigned char)start[i]) - 'A';
        if (seen[idx]) {
            printf("Error: duplicate letter '%c' in key.\n", start[i]);
            return;
        }
        seen[idx] = true;
    }

    // Build decode map: decodeMap[cipher - 'A'] = plaintext letter
    char decodeMap[26];
    for (int i = 0; i < 26; i++) decodeMap[i] = 0;
    for (int i = 0; i < 26; i++) {
        char cipher = (char)toupper((unsigned char)start[i]); // ciphertext letter for plaintext 'A'+i
        decodeMap[cipher - 'A'] = (char)('A' + i);
    }

    // Print mapping for debugging
    printf("Decoding map (cipher -> plain):\n");
    for (int i = 0; i < 26; i++) {
        char c = (char)('A' + i);
        char p = decodeMap[i] ? decodeMap[i] : '?';
        printf("%c -> %c  ", c, p);
        if ((i+1) % 6 == 0) printf("\n");
    }
    printf("\nEnter ciphertext to decode (end with blank line):\n");

    while (fgets(input, sizeof(input), stdin)) {
        if (input[0] == '\n') break;
        input[strcspn(input, "\r\n")] = '\0';
        for (int i = 0; input[i]; i++) {
            unsigned char c = (unsigned char)input[i];
            if (isalpha(c)) {
                int idx = toupper(c) - 'A';
                char mapped = decodeMap[idx];
                if (mapped == 0) putchar(c);
                else putchar(isupper(c) ? mapped : tolower((unsigned char)mapped));
            } else {
                putchar(c);
            }
        }
        putchar('\n');
    }
}



//============ End CryptoAnalysis ================

//------------ VIGENERE --------------------------

int cmd_vigenere(int argc, char **argv)
{
    const char *in_path  = NULL;
    const char *out_path = NULL;
    const char *key_raw  = NULL;
    vigenere_mode_t mode = VIGENERE_MODE_DECRYPT;

    /* Parse arguments */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0) {
            mode = VIGENERE_MODE_DECRYPT;
        } else if (strcmp(argv[i], "-e") == 0) {
            mode = VIGENERE_MODE_ENCRYPT;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_raw = argv[++i];
        } else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            in_path = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            printf("[VIG] Unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    if (!in_path || !out_path || !key_raw) {
        printf("Usage: VIG -d|-e -k KEY -in infile -out outfile\n");
        return -1;
    }

    /* Normalize key */
    char key_norm[256];
    size_t key_len = vigenere_normalize_key(key_raw, key_norm, sizeof(key_norm));
    if (key_len == 0) {
        printf("[VIG] Error: key contains no letters\n");
        return -1;
    }

    /* Read input file (Opus sandbox-safe) */
    size_t in_len = 0;
    uint8_t *in_buf = opus_load_entire_file(in_path, &in_len);
    if (!in_buf) {
        printf("[VIG] Failed to read input file: %s\n", in_path);
        return -1;
    }

    uint8_t *out_buf = malloc(in_len);
    if (!out_buf) {
        free(in_buf);
        printf("[VIG] Memory allocation failed\n");
        return -1;
    }

    /* Apply Vigenere */
    if (vigenere_apply_buffer(in_buf, out_buf, in_len, key_norm, mode) != 0) {
        printf("[VIG] Error applying Vigenere cipher\n");
        free(in_buf);
        free(out_buf);
        return -1;
    }

    /* Write output file (K1Wi sandbox-safe) */
    if (opus_write_file(out_path, out_buf, in_len) != 0) {
        printf("[VIG] Failed to write output file: %s\n", out_path);
        free(in_buf);
        free(out_buf);
        return -1;
    }

    printf("[VIG] Success. Output written to %s\n", out_path);

    free(in_buf);
    free(out_buf);
    return 0;
}


/* inline status updater: prints on one line and updates in place */
void print_status_inline(void) {
    static char last_snapshot[256] = "";
    static int last_tasks = -1;
    char snapshot[256];
    int tasks = 0;
    int restart = -1;
    double score = 0.0;

    pthread_mutex_lock(&status_lock);
    tasks = active_solver_tasks;
    strncpy(snapshot, last_solver_progress, sizeof(snapshot)-1);
    snapshot[sizeof(snapshot)-1] = '\0';
    restart = last_restart;
    score = last_score;
    pthread_mutex_unlock(&status_lock);

    /* only redraw when something changed */
    if (tasks == last_tasks && strcmp(snapshot, last_snapshot) == 0) return;

    /* remember current state */
    last_tasks = tasks;
    strncpy(last_snapshot, snapshot, sizeof(last_snapshot)-1);
    last_snapshot[sizeof(last_snapshot)-1] = '\0';

    /* clear line and print inline status without newline */
    printf("\r\033[2K"); /* return carriage and clear line */
    if (tasks > 0) {
        if (restart >= 0) {
            printf("[Solver:%d restart %d best %.4f] %s", tasks, restart, score, snapshot);
        } else {
            printf("[Solver:%d] %s", tasks, snapshot[0] ? snapshot : "(no progress)");
        }
    } else {
        if (snapshot[0]) printf("[No solver] %s", snapshot);
        else printf("[No solver tasks]");
    }
    fflush(stdout);
}


int readFile(const char *path)
{
    
    FILE *fp = fopen(path, "r");  // open file in read mode
    if (fp == NULL) {
        perror("Error opening file");
        return 1;  // non-zero means failure
    }

	int ch;
	while ((ch = fgetc(fp)) != EOF) {
		putchar(ch);
	    }

    fclose(fp);  // close file
    return 0;    // success
}
int opus_read_file(const char *path, bool mode_raw, bool mode_structured, bool mode_safe, size_t limit, size_t offset, size_t page_size, bool ascii, bool hex, const char *force_format, bool verbose, bool summary)
{

	 (void)mode_raw; 
	 (void)mode_structured; 
	 (void)mode_safe; 
	 (void)limit; 
	 (void)offset; 
	 (void)page_size; 
	 (void)ascii; 
	 (void)hex; 
	 (void)force_format; 
	 (void)verbose; 
	 (void)summary;
	 
	 
    if (mode_structured) {
        return opus_read_structured(path, force_format, summary, verbose);
    } else if (mode_safe) {
        return opus_read_safe(path, page_size, limit, hex, ascii);
    } else {
        /* default to raw if nothing else set */
        return opus_read_raw(path, offset, limit, hex, ascii);
    }
}

int fileCreate(const char *path) {
   if (!path || path[0] == '\0') { 
     printf("Error: no filename provided.\n"); 
     return -1;
    }
    size_t len = strlen(path);
    if (path[len - 1] == '/') {
        printf("Error: '%s' is a directory path, not a file.\n", path);
        return -1;
    }

    if (access(path, F_OK) == 0) {
        printf("Error: file '%s' already exists. Refusing to overwrite.\n", path);
        return -1;
    }

    int flags = O_CREAT | O_EXCL;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    mode_t old_umask = umask(0077);
    int fd = open(path, flags, 0600);
    umask(old_umask);

    if (fd < 0) {
        perror("fileCreate");
        return -1;
    }

    close(fd);
    printf("Created secure empty file: %s\n", path);
    return 0;
}

void fileName()
{

	printf("Enter Filename: ");
	
	if(fgets(filename, max_Length_Filename, stdin) != NULL)
	{
	 filename[strcspn (filename, "\r\n")] = '\0';
	
	 printf("\n");
	}


}
void systemTime()
{

	time_t System_time; 
	System_time = time(NULL);
	char* current_time_string = ctime(&System_time); 
	
	printf("\n\nSystem Time: %s\n\n", current_time_string); 
}

void fileOpenPrompt()
{
    char fname[512];
    printf("Enter filename to open: ");
    if (fgets(fname, sizeof(fname), stdin) == NULL) return;
    fname[strcspn(fname, "\r\n")] = '\0';

    FILE *fp = fopen(fname, "r");
    if (!fp) {
        perror("Error opening file");
        return;
    }

    printf("File opened successfully: %s\n", fname);
    fclose(fp);

    strncpy(filename, fname, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';
}
int cmd_open(int argc, char **argv)
{
    char fname[512];

    if (argc >= 2) {
        // Use the filename from the command
        strncpy(fname, argv[1], sizeof(fname) - 1);
        fname[sizeof(fname) - 1] = '\0';
    } else {
        // No filename provided → prompt
        printf("Enter filename to open: ");
        if (fgets(fname, sizeof(fname), stdin) == NULL)
            return 0;

        fname[strcspn(fname, "\r\n")] = '\0';
    }

    FILE *fp = fopen(fname, "r");
    if (!fp) {
        perror("Error opening file");
        return -1;
    }

    printf("File opened successfully: %s\n", fname);
    fclose(fp);

    strncpy(filename, fname, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';

    return 0;
}

void fileClose(FILE *fp) 
{

    if (fp != NULL) 
    {
        fclose(fp);
        printf("File closed successfully\n");
    } 
    else 
    {
        printf("No file to close\n");
    }
}

void fileDelete(void)
{
    char buf[64];
    char args_buf[1024];

    printf("Enter the name of the file to securely delete: ");
    if (fgets(filename, sizeof(filename), stdin) == NULL) {
        printf("No filename provided.\n");
        return;
    }

    filename[strcspn(filename, "\r\n")] = '\0';

    if (filename[0] == '\0') {
        printf("No filename provided.\n");
        return;
    }

    if (filename[0] == '/' || strstr(filename, "..")) {
        printf("Unsafe filename. Deletion aborted.\n");
        return;
    }

    printf("Choose deletion standard:\n");
    printf("  1 = DoD-style 3-pass overwrite\n");
    printf("  2 = NIST-style single-pass zero overwrite\n");
    printf("  3 = Custom pass count (1-33)\n");
    printf("Selection: ");

    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        printf("No selection. Deletion aborted.\n");
        return;
    }

    if (buf[0] == '1') {
        snprintf(args_buf, sizeof(args_buf), "%s -s 1", filename);
    } else if (buf[0] == '2') {
        snprintf(args_buf, sizeof(args_buf), "%s -s 2", filename);
    } else if (buf[0] == '3') {
        int passes;

        printf("Enter custom pass count (1-33): ");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            printf("No custom pass count. Deletion aborted.\n");
            return;
        }

        passes = atoi(buf);
        if (passes < 1 || passes > 33) {
            printf("Error: custom pass count must be between 1 and 33.\n");
            return;
        }

        snprintf(args_buf, sizeof(args_buf), "%s -p %d", filename, passes);
    } else {
        printf("Invalid selection. Deletion aborted.\n");
        return;
    }

    fileDeleteCmd(args_buf);
}


void fileSearch(void)
{
	printf("fileSearch() Function call works!\n");
}
void clearScreen(void)
{
  int __rc = system("clear");
  (void)__rc;
}

