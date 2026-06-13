#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include "opus_cmd.h"
#include "piecalc.h"

#define C_RESET   "\x1b[0m"
#define C_CYAN    "\x1b[96m"
#define C_GREEN   "\x1b[92m"
#define C_YELLOW  "\x1b[93m"
#define C_RED     "\x1b[91m"
#define C_MAGENTA "\x1b[95m"
 

#define PIE_PAGE_MASK 0xFFFULL

/* ------------------ Types & globals for guessing mode ------------------ */

typedef struct {
    char name[64];
    uint64_t offset;    /* st_value from symbol */
    uint64_t distance;  /* |leak_low - (st_value & PIE_PAGE_MASK)| */
} pie_guess_candidate_t;

/* These are populated only during guess mode */
static pie_guess_candidate_t *g_candidates = NULL;
static size_t g_candidate_count = 0;

static int piecalc_fseek_elfoff(FILE *f, Elf64_Off off)
{
    if (off > (Elf64_Off)LONG_MAX) {
        return -1;
    }

    return fseek(f, (long)off, SEEK_SET);
}

static int parse_u64_strict(const char *s, unsigned long long *out)
{
    char *end = NULL;

    if (!s || !out) {
        return -1;
    }

    *out = strtoull(s, &end, 0);

    if (end == s || *end != '\0') {
        return -1;
    }

    return 0;
}


/* Comparator for qsort() */
static int cmp_candidates(const void *a, const void *b)
{
    const pie_guess_candidate_t *A = a;
    const pie_guess_candidate_t *B = b;

    if (A->distance < B->distance)
        return -1;

    if (A->distance > B->distance)
        return 1;

    return 0;
}

/* ------------------ Utility: confidence based on low-12 distance -------- */

static int piecalc_confidence(uint64_t distance)
{
    if (distance == 0)
        return 100;

    if (distance > 0xFFF)
        return 0;

    double pct = 100.0 - ((double)distance * 100.0 / 4095.0);

    if (pct < 0)
        pct = 0;

    return (int)pct;
}


/* ------------------ Utility: ignore junk compiler symbols --------------- */

static int bad_symbol(const char *name)
{
    static const char *bad[] = {
        "_init",
        "_fini",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__do_global_dtors_aux",
        "__libc_csu_init",
        "__libc_csu_fini",
        "_start"
    };

    size_t count = sizeof(bad) / sizeof(bad[0]);

    for (size_t i = 0; i < count; i++) {

        if (strcmp(name, bad[i]) == 0)
            return 1;
    }

    return 0;
}


/* ------------------ Utility: basic symbol lookup by name ---------------- */

static int find_func_offset(const char *path,
                            const char *name_want,
                            uint64_t *out_value)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        printf("[PIECALC] Cannot open '%s'\n", path);
        return -1;
    }

    Elf64_Ehdr eh;

    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        printf("[PIECALC] Failed to read ELF header\n");
        fclose(f);
        return -1;
    }

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("[PIECALC] '%s' is not a supported ELF64 file\n", path);
        fclose(f);
        return -1;
    }

    if (piecalc_fseek_elfoff(f, eh.e_shoff) != 0) {
        printf("[PIECALC] Failed to seek to section headers\n");
        fclose(f);
        return -1;
    }

    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));

    if (!shdrs) {
        fclose(f);
        return -1;
    }

    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        printf("[PIECALC] Failed to read section headers\n");
        free(shdrs);
        fclose(f);
        return -1;
    }




    int found = 0;

    for (int i = 0; i < eh.e_shnum && !found; i++) {

        if (shdrs[i].sh_type != SHT_SYMTAB &&
            shdrs[i].sh_type != SHT_DYNSYM)
            continue;

        Elf64_Shdr symsec = shdrs[i];
        Elf64_Shdr strsec = shdrs[symsec.sh_link];

        char *strtab = malloc(strsec.sh_size);

        if (!strtab)
            continue;

        if (piecalc_fseek_elfoff(f, strsec.sh_offset) != 0) {
            free(strtab);
            continue;
        }

        if (fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        size_t count = symsec.sh_size / sizeof(Elf64_Sym);

        Elf64_Sym *syms = malloc(symsec.sh_size);

        if (!syms) {
            free(strtab);
            continue;
        }

        if (piecalc_fseek_elfoff(f, symsec.sh_offset) != 0) {
            free(strtab);
            free(syms);
            continue;
        }

        if (fread(syms, sizeof(Elf64_Sym), count, f) != count) {
            free(strtab);
            free(syms);
            continue;
        }

        for (size_t j = 0; j < count; j++) {

            Elf64_Sym s = syms[j];

            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC)
                continue;

            if (s.st_value == 0)
                continue;

	const char *name = strtab + s.st_name;

	if (!name || name[0] == '\0')
	    continue;

	if (bad_symbol(name))
	    continue;

	if (strcmp(name, name_want) == 0){
                *out_value = s.st_value;
                found = 1;
                break;
            }
        }

        free(syms);
        free(strtab);
    }

    free(shdrs);
    fclose(f);

    if (!found) {
        printf("[PIECALC] Symbol '%s' not found in '%s'\n",
               name_want, path);
        return -1;
    }

    return 0;
}

/* ------------------ Guessing engine: build & sort candidates ------------ */
static int guess_leak_symbol(const char *path,
                             unsigned long long leak_addr,
                             char *out_name,
                             size_t out_name_size,
                             uint64_t *out_offset,
                             uint64_t *out_distance)
{
    free(g_candidates);
    g_candidates = NULL;
    g_candidate_count = 0;

    FILE *f = fopen(path, "rb");


    if (!f) {
        printf("[PIECALC] Cannot open '%s' for guessing\n", path);
        return -1;
    }

    Elf64_Ehdr eh;

    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        printf("[PIECALC] Failed to read ELF header\n");
        fclose(f);
        return -1;
    }

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("[PIECALC] '%s' is not a supported ELF64 file\n", path);
        fclose(f);
        return -1;
    }

    if (piecalc_fseek_elfoff(f, eh.e_shoff) != 0) {
        printf("[PIECALC] Failed to seek to section headers\n");
        fclose(f);
        return -1;
    }

    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));

    if (!shdrs) {
        fclose(f);
        return -1;
    }

    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        printf("[PIECALC] Failed to read section headers\n");
        free(shdrs);
        fclose(f);
        return -1;
    }
    
    uint64_t text_addr = 0;
uint64_t text_size = 0;

/*
 * Read section-header string table
 */
Elf64_Shdr shstr = shdrs[eh.e_shstrndx];

char *shstrtab = malloc(shstr.sh_size);

if (!shstrtab) {
    free(shdrs);
    fclose(f);
    return -1;
}

if (fseek(f, (long)shstr.sh_offset, SEEK_SET) != 0) {
    free(shstrtab);
    free(shdrs);
    fclose(f);
    return -1;
}

if (fread(shstrtab, 1, shstr.sh_size, f) != shstr.sh_size) {
    free(shstrtab);
    free(shdrs);
    fclose(f);
    return -1;
}

/*
 * Locate .text section
 */
for (int i = 0; i < eh.e_shnum; i++) {

    const char *secname =
        shstrtab + shdrs[i].sh_name;

    if (strcmp(secname, ".text") == 0) {

        text_addr = shdrs[i].sh_addr;
        text_size = shdrs[i].sh_size;
        break;
    }
}

free(shstrtab);

    uint64_t leak_low = leak_addr & 0xFFF;

    pie_guess_candidate_t *candidates = NULL;
    size_t cand_count = 0;

    for (int i = 0; i < eh.e_shnum; i++) {

        if (shdrs[i].sh_type != SHT_SYMTAB &&
            shdrs[i].sh_type != SHT_DYNSYM)
            continue;

        Elf64_Shdr symsec = shdrs[i];
        Elf64_Shdr strsec = shdrs[symsec.sh_link];

        char *strtab = malloc(strsec.sh_size);

        if (!strtab)
            continue;

        if (piecalc_fseek_elfoff(f, strsec.sh_offset) != 0) {
            free(strtab);
            continue;
        }

        if (fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        size_t count = symsec.sh_size / sizeof(Elf64_Sym);

        Elf64_Sym *syms = malloc(symsec.sh_size);

        if (!syms) {
            free(strtab);
            continue;
        }

        if (piecalc_fseek_elfoff(f, symsec.sh_offset) != 0) {
            free(strtab);
            free(syms);
            continue;
        }

        if (fread(syms, sizeof(Elf64_Sym), count, f) != count) {
            free(strtab);
            free(syms);
            continue;
        }

        for (size_t j = 0; j < count; j++) {

            Elf64_Sym s = syms[j];

            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC)
                continue;

            if (s.st_value == 0)
                continue;

	const char *name = strtab + s.st_name;

	if (!name || name[0] == '\0')
	    continue;

	if (bad_symbol(name))
	    continue;

	/*
	 * Ignore symbols outside executable .text section
	 */
	if (s.st_value < text_addr ||
	    s.st_value >= (text_addr + text_size))
	    continue;

	uint64_t sym_low = s.st_value & 0xFFF;
            uint64_t diff =
                (leak_low > sym_low)
                    ? (leak_low - sym_low)
                    : (sym_low - leak_low);

            pie_guess_candidate_t *tmp =
                realloc(candidates,
                        (cand_count + 1) * sizeof(*tmp));

            if (!tmp) {
                free(candidates);
                free(syms);
                free(strtab);
                free(shdrs);
                fclose(f);
                return -1;
            }

            candidates = tmp;

            strncpy(candidates[cand_count].name,
                    name,
                    sizeof(candidates[cand_count].name) - 1);

            candidates[cand_count]
                .name[sizeof(candidates[cand_count].name) - 1] = '\0';

            candidates[cand_count].offset = s.st_value;
            candidates[cand_count].distance = diff;

            cand_count++;
        }

        free(syms);
        free(strtab);
    }

    free(shdrs);
    fclose(f);

    if (cand_count == 0) {
	printf("[PIECALC] No suitable function symbols found\n");	
	printf("[PIECALC] Binary may be stripped or missing symbols\n");
        free(candidates);
        return -1;
    }

    qsort(candidates,
          cand_count,
          sizeof(*candidates),
          cmp_candidates);

    if (out_name && out_name_size > 0) {
        strncpy(out_name,
                candidates[0].name,
                out_name_size - 1);

        out_name[out_name_size - 1] = '\0';
    }

    if (out_offset)
        *out_offset = candidates[0].offset;

    if (out_distance)
        *out_distance = candidates[0].distance;

    g_candidates = candidates;
    g_candidate_count = cand_count;

    return 0;
}

int piecalc_list_symbols(const char *path, int json_mode)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        printf("[PIECALC] Cannot open '%s'\n", path);
        return -1;
    }

    Elf64_Ehdr eh;
    size_t printed_count = 0;

    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        printf("[PIECALC] Failed to read ELF header\n");
        fclose(f);
        return -1;
    }

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("[PIECALC] '%s' is not a supported ELF64 file\n", path);
        fclose(f);
        return -1;
    }

    if (json_mode) {
        printf("{\n");
        printf("  \"binary\": \"%s\",\n", path);
        printf("  \"symbols\": [\n");
    }

    if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0) {
        printf("[PIECALC] Failed to seek to section headers\n");
        fclose(f);
        return -1;
    }

    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));

    if (!shdrs) {
        fclose(f);
        return -1;
    }

    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        printf("[PIECALC] Failed to read section headers\n");
        free(shdrs);
        fclose(f);
        return -1;
    }

    for (int i = 0; i < eh.e_shnum; i++) {

        if (shdrs[i].sh_type != SHT_SYMTAB &&
            shdrs[i].sh_type != SHT_DYNSYM) {
            continue;
        }

        Elf64_Shdr symsec = shdrs[i];

        if (symsec.sh_link >= eh.e_shnum) {
            continue;
        }

        Elf64_Shdr strsec = shdrs[symsec.sh_link];

        if (strsec.sh_size == 0 || strsec.sh_size > ((size_t)-1) - 1) {
            continue;
        }

        char *strtab = calloc((size_t)strsec.sh_size + 1, 1);

        if (!strtab) {
            continue;
        }

        if (fseek(f, (long)strsec.sh_offset, SEEK_SET) != 0) {
            free(strtab);
            continue;
        }

        if (fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        size_t count = symsec.sh_size / sizeof(Elf64_Sym);

        Elf64_Sym *syms = malloc(symsec.sh_size);

        if (!syms) {
            free(strtab);
            continue;
        }

        if (fseek(f, (long)symsec.sh_offset, SEEK_SET) != 0) {
            free(syms);
            free(strtab);
            continue;
        }

        if (fread(syms, sizeof(Elf64_Sym), count, f) != count) {
            free(syms);
            free(strtab);
            continue;
        }

        for (size_t j = 0; j < count; j++) {

            Elf64_Sym s = syms[j];

            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC) {
                continue;
            }

            if (s.st_value == 0) {
                continue;
            }

            if (s.st_name >= strsec.sh_size) {
                continue;
            }

            const char *name = strtab + s.st_name;

            if (name[0] == '\0') {
                continue;
            }

            if (bad_symbol(name)) {
                continue;
            }

            if (json_mode) {
                if (printed_count > 0) {
                    printf(",\n");
                }

                printf("    {\"name\": \"%s\", \"offset\": \"0x%llx\"}",
                       name,
                       (unsigned long long)s.st_value);

                printed_count++;
            } else {
                printf("%-24s 0x%llx\n",
                       name,
                       (unsigned long long)s.st_value);
            }
        }

        free(syms);
        free(strtab);
    }

    if (json_mode) {
        printf("\n");
        printf("  ]\n");
        printf("}\n");
    }

    free(shdrs);
    fclose(f);

    return 0;
}


int opus_pie_calc(const char *path,
                  const char *leak_symbol,
                  unsigned long long leak_addr,
                  const char *target_symbol,
                  size_t top_n,
                  int json_mode,
                  int base_only,
                  int raw_mode,
                  int offset_only,
                  int verbose_mode)
{
    uint64_t leak_offset = 0;
    uint64_t target_offset = 0;

    char guessed_name[64];
    uint64_t guessed_distance = 0;

    /*
     * OFFSET ONLY MODE
     * Does not need leak address or PIE base.
     */
    if (offset_only) {

        if (find_func_offset(path, target_symbol, &target_offset) != 0) {
            return -1;
        }

        if (json_mode) {
            printf("{\n");
            printf("  \"target_offset\": \"0x%llx\"\n",
                   (unsigned long long)target_offset);
            printf("}\n");
        } else {
            printf("0x%llx\n",
                   (unsigned long long)target_offset);
        }

        return 0;
    }

    if (!json_mode && !raw_mode) {
        printf("\n");
        printf(C_MAGENTA "========== PIE CALCULATOR ==========\n" C_RESET);
    }

    /*
     * Resolve leak symbol.
     */
    if (leak_symbol == NULL) {

        if (verbose_mode && !json_mode && !raw_mode) {
            printf("[DEBUG] Attempting leak symbol guess...\n");
        }

        int rc = guess_leak_symbol(path,
                                   leak_addr,
                                   guessed_name,
                                   sizeof(guessed_name),
                                   &leak_offset,
                                   &guessed_distance);

        if (verbose_mode && !json_mode && !raw_mode) {
            printf("[DEBUG] guess_leak_symbol rc=%d\n", rc);
        }

        if (rc != 0) {
            if (verbose_mode && !json_mode && !raw_mode) {
                printf("[DEBUG] leak_addr = 0x%llx\n", leak_addr);
                printf("[DEBUG] path = %s\n", path);
            }
            return -1;
        }

        leak_symbol = guessed_name;

        int conf = piecalc_confidence(guessed_distance);

        if (!json_mode && !raw_mode) {

            printf(C_YELLOW "[*]" C_RESET
                   " Guessed leak symbol: %s\n",
                   leak_symbol);

            printf(C_YELLOW "[*]" C_RESET
                   " Confidence: %d%%\n",
                   conf);

            if (conf < 25) {
                printf(C_RED
                       "[!] WARNING: very low confidence guess\n"
                       C_RESET);
            } else if (conf < 50) {
                printf(C_YELLOW
                       "[!] Warning: unreliable symbol match\n"
                       C_RESET);
            }
        }

        if (!json_mode && !raw_mode && g_candidate_count > 0) {

            printf("\n");
            printf(C_CYAN "[TOP CANDIDATES]" C_RESET "\n");

            size_t max_show = top_n;

            if (max_show == 0) {
                max_show = PIECALC_MAX_CANDIDATES;
            }

            if (g_candidate_count < max_show) {
                max_show = g_candidate_count;
            }

            for (size_t i = 0; i < max_show; i++) {
                printf("  %-24s off=0x%llx dist=0x%llx conf=%d%%\n",
                       g_candidates[i].name,
                       (unsigned long long)g_candidates[i].offset,
                       (unsigned long long)g_candidates[i].distance,
                       piecalc_confidence(g_candidates[i].distance));
            }

            printf("\n");
        }

    } else {

        if (verbose_mode && !json_mode && !raw_mode) {
            printf("[DEBUG] Using supplied leak symbol: %s\n",
                   leak_symbol);
        }

        if (find_func_offset(path,
                             leak_symbol,
                             &leak_offset) != 0) {
            return -1;
        }
    }

    /*
     * Resolve target symbol.
     */
    if (find_func_offset(path,
                         target_symbol,
                         &target_offset) != 0) {
        return -1;
    }

    uint64_t pie_base =
        (leak_addr - leak_offset) & ~PIE_PAGE_MASK;

    uint64_t final_addr =
        pie_base + target_offset;

    if (raw_mode) {

        if (base_only) {
            printf("0x%llx\n",
                   (unsigned long long)pie_base);
        } else {
            printf("0x%llx\n",
                   (unsigned long long)final_addr);
        }

        return 0;
    }

    if (base_only) {

        if (json_mode) {
            printf("{\n");
            printf("  \"pie_base\": \"0x%llx\"\n",
                   (unsigned long long)pie_base);
            printf("}\n");
        } else {
            printf("0x%llx\n",
                   (unsigned long long)pie_base);
        }

        return 0;
    }

    if (json_mode) {

        printf("{\n");
        printf("  \"binary\": \"%s\",\n", path);
        printf("  \"leak_addr\": \"0x%llx\",\n", leak_addr);
        printf("  \"leak_symbol\": \"%s\",\n", leak_symbol);
        printf("  \"leak_offset\": \"0x%llx\",\n",
               (unsigned long long)leak_offset);
        printf("  \"target_symbol\": \"%s\",\n", target_symbol);
        printf("  \"target_offset\": \"0x%llx\",\n",
               (unsigned long long)target_offset);
        printf("  \"pie_base\": \"0x%llx\",\n",
               (unsigned long long)pie_base);
        printf("  \"final_address\": \"0x%llx\",\n",
               (unsigned long long)final_addr);
        printf("  \"confidence\": %d\n",
               piecalc_confidence(guessed_distance));
        printf("}\n");

    } else {

        printf("\n");

        printf(C_CYAN "[LEAK]" C_RESET "\n");
        printf("  Runtime Leak : 0x%llx\n", leak_addr);
        printf("  Leak Symbol  : %s\n", leak_symbol);
        printf("  Leak Offset  : 0x%llx\n",
               (unsigned long long)leak_offset);

        printf("\n");

        printf(C_GREEN "[TARGET]" C_RESET "\n");
        printf("  Target Symbol: %s\n", target_symbol);
        printf("  Target Offset: 0x%llx\n",
               (unsigned long long)target_offset);

        printf("\n");

        printf(C_MAGENTA "[RESULT]" C_RESET "\n");
        printf("  PIE Base     : 0x%llx\n",
               (unsigned long long)pie_base);
        printf("  Final Address: 0x%llx\n",
               (unsigned long long)final_addr);

        printf("\n");
    }

    return 0;
}

int piecalc_nearest_symbols(const char *path,
                            unsigned long long addr,
                            size_t top_n,
                            int json_mode)
{
    FILE *f = fopen(path, "rb");

    if (!f) {
        printf("[PIECALC] Cannot open '%s'\n", path);
        return -1;
    }

    Elf64_Ehdr eh;

    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        printf("[PIECALC] Failed to read ELF header\n");
        fclose(f);
        return -1;
    }

    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        printf("[PIECALC] '%s' is not a supported ELF64 file\n", path);
        fclose(f);
        return -1;
    }

    if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0) {
        printf("[PIECALC] Failed to seek to section headers\n");
        fclose(f);
        return -1;
    }

    Elf64_Shdr *shdrs = calloc(eh.e_shnum, sizeof(Elf64_Shdr));

    if (!shdrs) {
        fclose(f);
        return -1;
    }

    if (fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum) {
        printf("[PIECALC] Failed to read section headers\n");
        free(shdrs);
        fclose(f);
        return -1;
    }

    pie_guess_candidate_t *candidates = NULL;
    size_t cand_count = 0;

    for (int i = 0; i < eh.e_shnum; i++) {

        if (shdrs[i].sh_type != SHT_SYMTAB &&
            shdrs[i].sh_type != SHT_DYNSYM) {
            continue;
        }

        Elf64_Shdr symsec = shdrs[i];
        Elf64_Shdr strsec = shdrs[symsec.sh_link];

        char *strtab = malloc(strsec.sh_size);

        if (!strtab) {
            continue;
        }

        if (fseek(f, (long)strsec.sh_offset, SEEK_SET) != 0) {
            free(strtab);
            continue;
        }

        if (fread(strtab, 1, strsec.sh_size, f) != strsec.sh_size) {
            free(strtab);
            continue;
        }

        size_t count = symsec.sh_size / sizeof(Elf64_Sym);

        Elf64_Sym *syms = malloc(symsec.sh_size);

        if (!syms) {
            free(strtab);
            continue;
        }

        if (fseek(f, (long)symsec.sh_offset, SEEK_SET) != 0) {
            free(syms);
            free(strtab);
            continue;
        }

        if (fread(syms, sizeof(Elf64_Sym), count, f) != count) {
            free(syms);
            free(strtab);
            continue;
        }

        for (size_t j = 0; j < count; j++) {

            Elf64_Sym s = syms[j];

            if (ELF64_ST_TYPE(s.st_info) != STT_FUNC) {
                continue;
            }

            if (s.st_value == 0) {
                continue;
            }

            const char *name = strtab + s.st_name;

            if (!name || name[0] == '\0') {
                continue;
            }

            if (bad_symbol(name)) {
                continue;
            }

            uint64_t sym_addr = s.st_value;
            uint64_t needle = (uint64_t)addr;

            uint64_t diff =
                (needle > sym_addr)
                    ? (needle - sym_addr)
                    : (sym_addr - needle);

            pie_guess_candidate_t *tmp =
                realloc(candidates,
                        (cand_count + 1) * sizeof(*tmp));

            if (!tmp) {
                free(candidates);
                free(syms);
                free(strtab);
                free(shdrs);
                fclose(f);
                return -1;
            }

            candidates = tmp;

            strncpy(candidates[cand_count].name,
                    name,
                    sizeof(candidates[cand_count].name) - 1);

            candidates[cand_count]
                .name[sizeof(candidates[cand_count].name) - 1] = '\0';

            candidates[cand_count].offset = sym_addr;
            candidates[cand_count].distance = diff;

            cand_count++;
        }

        free(syms);
        free(strtab);
    }

    free(shdrs);
    fclose(f);

    if (cand_count == 0) {
        printf("[PIECALC] No suitable function symbols found\n");
        free(candidates);
        return -1;
    }

    qsort(candidates,
          cand_count,
          sizeof(*candidates),
          cmp_candidates);

    if (top_n == 0) {
        top_n = PIECALC_MAX_CANDIDATES;
    }

    if (cand_count < top_n) {
        top_n = cand_count;
    }

if (json_mode) {
    printf("{\n");
    printf("  \"binary\": \"%s\",\n", path);
    printf("  \"query\": \"0x%llx\",\n", addr);
    printf("  \"matches\": [\n");

    for (size_t i = 0; i < top_n; i++) {
        printf("    {\"name\": \"%s\", \"offset\": \"0x%llx\", \"distance\": \"0x%llx\"}%s\n",
               candidates[i].name,
               (unsigned long long)candidates[i].offset,
               (unsigned long long)candidates[i].distance,
               (i + 1 < top_n) ? "," : "");
    }

    printf("  ]\n");
    printf("}\n");
} else {
    printf("[NEAREST SYMBOLS]\n");

    for (size_t i = 0; i < top_n; i++) {
        printf("  %-24s off=0x%llx dist=0x%llx\n",
               candidates[i].name,
               (unsigned long long)candidates[i].offset,
               (unsigned long long)candidates[i].distance);
    }
}

free(candidates);

return 0;
}


int cmd_piecalc(opus_context *ctx, int argc, char **argv)
{

    int json_mode = 0;
    int raw_mode = 0;
    int offset_only = 0;
    int base_only = 0;
    int verbose_mode = 0;
    int list_mode = 0;
    int nearest_mode = 0;
    
    unsigned long long nearest_addr = 0;
    size_t top_n = 5;
    
    (void)ctx;
    
	if (argc <= 2) {
	    printf("Usage:\n");
	    printf("  PIECALC --bin <file> --leak <addr> --target <symbol>\n");
	    printf("  PIECALC --bin <file> --leak <addr> --leak-symbol <symbol> --target <symbol>\n");
	    printf("  PIECALC --bin <file> --target <symbol> --offset-only\n");
	    printf("  PIECALC --bin <file> --list\n");
	    printf("  PIECALC --bin <file> --nearest <addr>\n");
	    printf("\n");
	    printf("Options:\n");
	    printf("  --leak-symbol <sym>  Use known leaked symbol instead of guessing\n");
	    printf("  --target <sym>       Symbol to resolve at runtime\n");
	    printf("  --top <n>            Show top N leak-symbol candidates\n");
	    printf("  --json               Emit JSON output\n");
	    printf("  --raw                Emit only the resolved address\n");
	    printf("  --base-only          Emit only PIE base\n");
	    printf("  --offset-only        Emit only target ELF offset\n");
	    printf("  --verbose            Show debug diagnostics\n");
	    printf("  --list               List function symbols and offsets\n");
	    printf("  --nearest <addr>     Show nearest symbols to offset/address\n");
	    return -1;
	}

    const char *bin = NULL;
    const char *target = NULL;
    const char *leak_symbol = NULL;
    
    unsigned long long leak = 0;

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "--bin") == 0 && i + 1 < argc) {
            bin = argv[++i];
        }
	else if (strcmp(argv[i], "--leak") == 0 && i + 1 < argc) {

	    if (parse_u64_strict(argv[++i], &leak) != 0) {
           printf("[PIECALC] Invalid leak address: %s\n", argv[i]);
          return -1;
	 }
	}	
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
            target = argv[++i];
        }
        else if (strcmp(argv[i], "--json") == 0) {
    	    json_mode = 1;
	}
	else if (strcmp(argv[i], "--leak-symbol") == 0 && i + 1 < argc) {
    	    leak_symbol = argv[++i];
	}
	else if (strcmp(argv[i], "--base-only") == 0) {
    	    base_only = 1;
	}
	else if (strcmp(argv[i], "--raw") == 0) {
    	    raw_mode = 1;
	}
	else if (strcmp(argv[i], "--offset-only") == 0) {
    	    offset_only = 1;
	}
	else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
	    unsigned long long parsed_top = 0;

	    if (parse_u64_strict(argv[++i], &parsed_top) != 0 || parsed_top == 0) {
	        printf("[PIECALC] Invalid --top value: %s\n", argv[i]);
         return -1;
        }

    top_n = (size_t)parsed_top;
}
	else if (strcmp(argv[i], "--verbose") == 0) {
	    verbose_mode = 1;
	}
	else if (strcmp(argv[i], "--list") == 0) {
    	    list_mode = 1;
	}	
	else if (strcmp(argv[i], "--nearest") == 0) {
    nearest_mode = 1;

    if (i + 1 >= argc) {
        nearest_addr = 0;
    } else {
        if (parse_u64_strict(argv[++i], &nearest_addr) != 0) {
            printf("[PIECALC] Invalid nearest address: %s\n", argv[i]);
            return -1;
        }
    }
}

} /* end argument parsing loop */

if (list_mode) {
    if (!bin) {
        printf("[PIECALC] Missing required arguments\n");
        printf("Try: PIECALC --bin <file> --list\n");
        return -1;
    }

    return piecalc_list_symbols(bin, json_mode);
}

if (nearest_mode) {
    if (!bin || nearest_addr == 0) {
        printf("[PIECALC] Missing required arguments\n");
        printf("Try: PIECALC --bin <file> --nearest <addr>\n");
        return -1;
    }

  return piecalc_nearest_symbols(bin, nearest_addr, top_n, json_mode);
}

if (offset_only) {
    if (!bin || !target) {
        printf("[PIECALC] Missing required arguments\n");
        printf("Try: PIECALC --bin <file> --target <symbol> --offset-only\n");
        return -1;
    }
} else {
    if (!bin || !target || leak == 0) {
        printf("[PIECALC] Missing required arguments\n");
        printf("Try: PIECALC --bin <file> --leak <addr> --target <symbol>\n");
        return -1;
    }
}

return opus_pie_calc(bin,
                     leak_symbol,
                     leak,
                     target,
                     top_n,
                     json_mode,
                     base_only,
                     raw_mode,
                     offset_only,
                     verbose_mode);
}
