#define ZIP_SIG_EOCD    0x06054b50u
#define ZIP_SIG_CENHDR  0x02014b50u

#define ELF_MAGIC0 0x7f
#define ELF_MAGIC1 'E'
#define ELF_MAGIC2 'L'
#define ELF_MAGIC3 'F'
#define EI_CLASS   4
#define EI_DATA    5
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include "opus_read.h"


#ifndef C_RESET
#define C_RESET  "\x1b[0m"
#define C_RED    "\x1b[31m"
#define C_GREEN  "\x1b[32m"
#define C_YELLOW "\x1b[33m"
#define C_BLUE   "\x1b[34m"
#define C_CYAN   "\x1b[36m"
#define C_DIM    "\x1b[2m"
#endif


/* Forward declarations for format-specific printers.
 * You can move these to dedicated headers later.
 */
static int opus_read_structured_png(const char *path, bool summary, bool verbose);
static int opus_read_structured_jpeg(const char *path, bool summary, bool verbose);
static int opus_read_structured_zip(const char *path, bool summary, bool verbose);

static int opus_read_structured_elf(const char *path, bool summary, bool verbose);
static int opus_read_structured_riff(const char *path, bool summary, bool verbose);


static bool is_elf_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;

    unsigned char magic[4];
    if (fread(magic, 1, 4, fp) != 4) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    return magic[0] == 0x7f &&
           magic[1] == 'E' &&
           magic[2] == 'L' &&
           magic[3] == 'F';
}

static const char *detect_format(const char *path)
{
    /* Format detection currently checks ELF magic first, then falls back to
    * extension-based heuristics for structured read modes.
    */
     
         if (is_elf_file(path))
        return "elf";

     
     
    const char *dot = strrchr(path, '.');
    if (!dot || dot[1] == '\0')
        return NULL;

    if (!strcasecmp(dot, ".png"))  return "png";
    if (!strcasecmp(dot, ".jpg"))  return "jpeg";
    if (!strcasecmp(dot, ".jpeg")) return "jpeg";
    if (!strcasecmp(dot, ".zip"))  return "zip";
    if (!strcasecmp(dot, ".elf"))  return "elf";
    if (!strcasecmp(dot, ".exe"))  return "elf";   /* crude, but placeholder */
    if (!strcasecmp(dot, ".wav"))  return "riff";

    return NULL;
}

int opus_read_structured(const char *path,
                         const char *force_format,
                         bool summary,
                         bool verbose)
{
    const char *fmt = force_format;

    if (!fmt || !*fmt) {
        fmt = detect_format(path);
    }

   if (!fmt) {
       printf("[STRUCTURED] No recognized file signature for '%s'.\n", path);
       printf("            Try SAFE mode for sanitized text, or RAW for hex view.\n");
       return -1;
    }


    if (!strcasecmp(fmt, "png")) {
        return opus_read_structured_png(path, summary, verbose);
    } else if (!strcasecmp(fmt, "jpeg") || !strcasecmp(fmt, "jpg")) {
        return opus_read_structured_jpeg(path, summary, verbose);
    } else if (!strcasecmp(fmt, "zip")) {
        return opus_read_structured_zip(path, summary, verbose);
    } else if (!strcasecmp(fmt, "elf")) {
        return opus_read_structured_elf(path, summary, verbose);
    } else if (!strcasecmp(fmt, "riff") || !strcasecmp(fmt, "wav")) {
        return opus_read_structured_riff(path, summary, verbose);
    }

    printf("[STRUCTURED] Unsupported format '%s' for '%s'\n", fmt, path);
    return -1;
}

/* --- Stub implementations: fill these in later with real parsers --- */



/* PNG signature is 8 bytes */
static const uint8_t PNG_SIG[8] = {
    0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A
};

static uint32_t read_u32_be(FILE *fp, long *offset)
{
    uint8_t buf[4];
    if (fread(buf, 1, 4, fp) != 4)
        return 0;

    if (offset)
        *offset += 4;

    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8)  |
           ((uint32_t)buf[3]);
}

static int opus_read_structured_png(const char *path, bool summary, bool verbose)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf("[STRUCTURED][PNG] cannot open '%s'\n", path);
        return -1;
    }

    uint8_t sig[8];
    long offset = 0;

    if (fread(sig, 1, 8, fp) != 8) {
        printf("[STRUCTURED][PNG] '%s': too short for PNG signature\n", path);
        fclose(fp);
        return -1;
    }
    offset += 8;

    if (memcmp(sig, PNG_SIG, 8) != 0) {
        printf("[STRUCTURED][PNG] '%s': invalid PNG signature\n", path);
        fclose(fp);
        return -1;
    }

    printf(C_CYAN "[STRUCTURED][PNG] %s\n" C_RESET, path);

    if (!summary) {
        printf("  Signature OK\n");
	printf("  " C_BLUE "Chunk table:\n" C_RESET);
	printf("    %-10s %-10s %-6s %-8s\n", "Offset", "Length", "Type", "Notes");

    }

    int chunk_index = 0;
    int seen_IHDR = 0;
    int seen_IEND = 0;

    for (;;) {
        long chunk_start = offset;

        uint32_t length = read_u32_be(fp, &offset);
        char type[5] = {0};

        if (fread(type, 1, 4, fp) != 4) {
            printf("    0x%08lx  %-10s %-6s %-8s\n",
                   chunk_start, "?", "????", "truncated");
            break;
        }
        offset += 4;

        /* Skip chunk data */
        if (fseek(fp, length, SEEK_CUR) != 0) {
            printf("    0x%08lx  %-10u %-6s %-8s\n",
                   chunk_start, length, type, "trunc-data");
            break;
        }
        offset += length;

        /* Read CRC */
        uint32_t crc = read_u32_be(fp, &offset);
        (void)crc; /* CRC validation can be added later */

        const char *note = "";

        if (memcmp(type, "IHDR", 4) == 0) {
            seen_IHDR = 1;
            note = "header";
        } else if (memcmp(type, "IDAT", 4) == 0) {
            note = "image-data";
        } else if (memcmp(type, "IEND", 4) == 0) {
            seen_IEND = 1;
            note = "end";
        } else if (type[0] & 0x20) {
            note = "ancillary";
        } else {
            note = "critical";
        }

        if (!summary) {
            printf("    " C_YELLOW "0x%08lx" C_RESET "  %-10u " C_GREEN "%-6.4s" C_RESET " %-8s\n",
       	    chunk_start, length, type, note);

        }

        chunk_index++;

        if (memcmp(type, "IEND", 4) == 0) {
            break;
        }

        /* Safety: avoid infinite loops on corrupt files */
        if (chunk_index > 10000) {
            printf("    [STRUCTURED][PNG] too many chunks, aborting\n");
            break;
        }
    }

    if (summary) {
        printf("  Chunks: %d, IHDR: %s, IEND: %s\n",
               chunk_index,
               seen_IHDR ? "yes" : "no",
               seen_IEND ? "yes" : "no");
    } else if (verbose) {
        printf("  Total chunks: %d\n", chunk_index);
        printf("  IHDR present: %s\n", seen_IHDR ? "yes" : "no");
        printf("  IEND present: %s\n", seen_IEND ? "yes" : "no");
    }

    fclose(fp);
    return 0;
}

static int opus_read_structured_jpeg(const char *path, bool summary, bool verbose)
{
    (void)summary;
    (void)verbose;
    printf("[STRUCTURED][JPEG] not implemented yet for '%s'\n", path);
    return 0;
}

/* ========================= ZIP STRUCTURED PARSER ========================= */



static uint16_t zip_read_u16_le(FILE *fp, long *offset)
{
    uint8_t b[2];
    if (fread(b, 1, 2, fp) != 2)
        return 0;
    if (offset) *offset += 2;
    return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

static uint32_t zip_read_u32_le(FILE *fp, long *offset)
{
    uint8_t b[4];
    if (fread(b, 1, 4, fp) != 4)
        return 0;
    if (offset) *offset += 4;
    return (uint32_t)b[0] |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

/* Scan backwards up to 64k to find EOCD */
static long zip_find_eocd(FILE *fp)
{
    if (fseek(fp, 0, SEEK_END) != 0)
        return -1;

    long size = ftell(fp);
    if (size < 22)
        return -1;

    long max_back = (size < 65557) ? size : 65557;
    long start = size - max_back;

    if (fseek(fp, start, SEEK_SET) != 0)
        return -1;

    uint8_t *buf = malloc((size_t)max_back);
    if (!buf)
        return -1;

    if (fread(buf, 1, (size_t)max_back, fp) != (size_t)max_back) {
        free(buf);
        return -1;
    }

    for (long i = max_back - 22; i >= 0; i--) {
        if (buf[i]     == 0x50 &&
            buf[i + 1] == 0x4b &&
            buf[i + 2] == 0x05 &&
            buf[i + 3] == 0x06) {
            long pos = start + i;
            free(buf);
            return pos;
        }
    }

    free(buf);
    return -1;
}

static int opus_read_structured_zip(const char *path, bool summary, bool verbose)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf("[STRUCTURED][ZIP] cannot open '%s'\n", path);
        return -1;
    }

    long eocd_off = zip_find_eocd(fp);
    if (eocd_off < 0) {
        printf("[STRUCTURED][ZIP] '%s': EOCD not found (not a ZIP or corrupt)\n", path);
        fclose(fp);
        return -1;
    }

    if (fseek(fp, eocd_off, SEEK_SET) != 0) {
        printf("[STRUCTURED][ZIP] '%s': seek to EOCD failed\n", path);
        fclose(fp);
        return -1;
    }

    long offset = eocd_off;
    uint32_t sig = zip_read_u32_le(fp, &offset);
    if (sig != ZIP_SIG_EOCD) {
        printf("[STRUCTURED][ZIP] '%s': EOCD signature mismatch\n", path);
        fclose(fp);
        return -1;
    }

    uint16_t disk_no            = zip_read_u16_le(fp, &offset);
    uint16_t disk_cdir          = zip_read_u16_le(fp, &offset);
    uint16_t entries_this_disk  = zip_read_u16_le(fp, &offset);
    uint16_t entries_total      = zip_read_u16_le(fp, &offset);
    uint32_t cdir_size          = zip_read_u32_le(fp, &offset);
    uint32_t cdir_offset        = zip_read_u32_le(fp, &offset);
    uint16_t comment_len        = zip_read_u16_le(fp, &offset);

    (void)disk_no;
    (void)disk_cdir;
    (void)comment_len;

    printf(C_CYAN "[STRUCTURED][ZIP] %s\n" C_RESET, path);
    printf("  Central directory offset: 0x%08x\n", cdir_offset);
    printf("  Central directory size:   %u bytes\n", cdir_size);
    printf("  Entries (this disk):      %u\n", entries_this_disk);
    printf("  Entries (total):          %u\n", entries_total);

    if (summary) {
        fclose(fp);
        return 0;
    }

    if (fseek(fp, (long)cdir_offset, SEEK_SET) != 0) {
        printf("  [ZIP] failed to seek to central directory\n");
        fclose(fp);
        return -1;
    }

	printf("  " C_BLUE "Central directory entries:\n" C_RESET);
	printf("    %-6s %-10s %-10s %-6s %-10s %s\n",
       "Idx", "CompSize", "Uncomp", "Meth", "LocalOff", "Name");


    for (uint16_t i = 0; i < entries_total; i++) {
        long entry_off = ftell(fp);
        offset = entry_off;

        uint32_t csig = zip_read_u32_le(fp, &offset);
        if (csig != ZIP_SIG_CENHDR) {
           printf("    " C_RED "[ZIP] entry %u: bad signature at 0x%08lx" C_RESET "\n", i, entry_off);

            break;
        }

        /* Skip fields we don't need */
        zip_read_u16_le(fp, &offset); /* ver_made */
        zip_read_u16_le(fp, &offset); /* ver_needed */
        zip_read_u16_le(fp, &offset); /* flags */
        uint16_t method = zip_read_u16_le(fp, &offset);
        zip_read_u16_le(fp, &offset); /* mod_time */
        zip_read_u16_le(fp, &offset); /* mod_date */
        zip_read_u32_le(fp, &offset); /* crc32 */
        uint32_t comp_size   = zip_read_u32_le(fp, &offset);
        uint32_t uncomp_size = zip_read_u32_le(fp, &offset);
        uint16_t name_len    = zip_read_u16_le(fp, &offset);
        uint16_t extra_len   = zip_read_u16_le(fp, &offset);
        uint16_t comment_len2= zip_read_u16_le(fp, &offset);
        zip_read_u16_le(fp, &offset); /* disk_start */
        zip_read_u16_le(fp, &offset); /* int_attr */
        zip_read_u32_le(fp, &offset); /* ext_attr */
        uint32_t local_off   = zip_read_u32_le(fp, &offset);

        char name_buf[256];
        size_t to_read = (name_len < sizeof(name_buf)-1) ? name_len : sizeof(name_buf)-1;

        if (fread(name_buf, 1, to_read, fp) != to_read) {
            printf("    [ZIP] entry %u: truncated name\n", i);
            break;
        }
        name_buf[to_read] = '\0';

        if (name_len > to_read)
            fseek(fp, (long)(name_len - to_read), SEEK_CUR);

        fseek(fp, extra_len + comment_len2, SEEK_CUR);

       printf("    %-6u %-10u %-10u %-6u " C_YELLOW "0x%08x" C_RESET " " C_GREEN "%s" C_RESET "\n",
       i, comp_size, uncomp_size, method, local_off, name_buf);

        if (verbose) {
            /* Add verbose fields here if desired */
        }
    }

    fclose(fp);
    return 0;
}

/* ========================= ELF STRUCTURED PARSER ========================= */



static uint16_t elf_read_u16(FILE *fp, bool be)
{
    uint8_t b[2];
    if (fread(b, 1, 2, fp) != 2)
        return 0;
    if (be)
        return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
    else
        return (uint16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
}

static uint32_t elf_read_u32(FILE *fp, bool be)
{
    uint8_t b[4];
    if (fread(b, 1, 4, fp) != 4)
        return 0;
    if (be)
        return ((uint32_t)b[0] << 24) |
               ((uint32_t)b[1] << 16) |
               ((uint32_t)b[2] << 8)  |
               ((uint32_t)b[3]);
    else
        return (uint32_t)b[0] |
               ((uint32_t)b[1] << 8) |
               ((uint32_t)b[2] << 16) |
               ((uint32_t)b[3] << 24);
}

static uint64_t elf_read_u64(FILE *fp, bool be)
{
    uint8_t b[8];
    if (fread(b, 1, 8, fp) != 8)
        return 0;
    if (be) {
        return ((uint64_t)b[0] << 56) |
               ((uint64_t)b[1] << 48) |
               ((uint64_t)b[2] << 40) |
               ((uint64_t)b[3] << 32) |
               ((uint64_t)b[4] << 24) |
               ((uint64_t)b[5] << 16) |
               ((uint64_t)b[6] << 8)  |
               ((uint64_t)b[7]);
    } else {
        return (uint64_t)b[0]        |
               ((uint64_t)b[1] << 8) |
               ((uint64_t)b[2] << 16)|
               ((uint64_t)b[3] << 24)|
               ((uint64_t)b[4] << 32)|
               ((uint64_t)b[5] << 40)|
               ((uint64_t)b[6] << 48)|
               ((uint64_t)b[7] << 56);
    }
}

static int opus_read_structured_elf(const char *path, bool summary, bool verbose)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        printf(C_RED "[STRUCTURED][ELF] cannot open '%s'\n" C_RESET, path);
        return -1;
    }

    uint8_t e_ident[16];
    if (fread(e_ident, 1, 16, fp) != 16) {
        printf(C_RED "[STRUCTURED][ELF] '%s': too short for ELF header\n" C_RESET, path);
        fclose(fp);
        return -1;
    }

    if (e_ident[0] != ELF_MAGIC0 ||
        e_ident[1] != ELF_MAGIC1 ||
        e_ident[2] != ELF_MAGIC2 ||
        e_ident[3] != ELF_MAGIC3) {
        printf(C_RED "[STRUCTURED][ELF] '%s': invalid ELF magic\n" C_RESET, path);
        fclose(fp);
        return -1;
    }

    uint8_t elf_class = e_ident[EI_CLASS];
    uint8_t elf_data  = e_ident[EI_DATA];
    bool be = (elf_data == ELFDATA2MSB);

    if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64) {
        printf(C_RED "[STRUCTURED][ELF] '%s': unsupported ELF class\n" C_RESET, path);
        fclose(fp);
        return -1;
    }

    /* Common fields after e_ident */
    uint16_t e_type    = elf_read_u16(fp, be);
    uint16_t e_machine = elf_read_u16(fp, be);
    uint32_t e_version = elf_read_u32(fp, be);
    (void)e_type;
    (void)e_machine;
    (void)e_version;

    uint64_t e_entry     = 0;
    uint64_t e_phoff     = 0;
    uint64_t e_shoff     = 0;
    uint32_t e_flags     = 0;
    uint16_t e_ehsize    = 0;
    uint16_t e_phentsize = 0;
    uint16_t e_phnum     = 0;
    uint16_t e_shentsize = 0;
    uint16_t e_shnum     = 0;
    uint16_t e_shstrndx  = 0;

    if (elf_class == ELFCLASS32) {
        e_entry     = elf_read_u32(fp, be);
        e_phoff     = elf_read_u32(fp, be);
        e_shoff     = elf_read_u32(fp, be);
        e_flags     = elf_read_u32(fp, be);
        e_ehsize    = elf_read_u16(fp, be);
        e_phentsize = elf_read_u16(fp, be);
        e_phnum     = elf_read_u16(fp, be);
        e_shentsize = elf_read_u16(fp, be);
        e_shnum     = elf_read_u16(fp, be);
        e_shstrndx  = elf_read_u16(fp, be);
    } else { /* ELFCLASS64 */
        e_entry     = elf_read_u64(fp, be);
        e_phoff     = elf_read_u64(fp, be);
        e_shoff     = elf_read_u64(fp, be);
        e_flags     = elf_read_u32(fp, be);
        e_ehsize    = elf_read_u16(fp, be);
        e_phentsize = elf_read_u16(fp, be);
        e_phnum     = elf_read_u16(fp, be);
        e_shentsize = elf_read_u16(fp, be);
        e_shnum     = elf_read_u16(fp, be);
        e_shstrndx  = elf_read_u16(fp, be);
    }

    /* Silence unused-for-now fields */
    (void)e_phoff;
    (void)e_flags;
    (void)e_ehsize;
    (void)e_phentsize;
    (void)e_phnum;

    printf(C_CYAN "[STRUCTURED][ELF] %s\n" C_RESET, path);

    printf("  Class:      " C_GREEN "%s\n" C_RESET,
           elf_class == ELFCLASS32 ? "ELF32" :
           elf_class == ELFCLASS64 ? "ELF64" : "Unknown");

    printf("  Endianness: " C_GREEN "%s\n" C_RESET,
           elf_data == ELFDATA2LSB ? "Little" :
           elf_data == ELFDATA2MSB ? "Big" : "Unknown");

    printf("  Entry point:        " C_YELLOW "0x%llx\n" C_RESET,
           (unsigned long long)e_entry);

    printf("  Section header off: " C_YELLOW "0x%llx\n" C_RESET,
           (unsigned long long)e_shoff);

    printf("  Section header num: %u\n", e_shnum);
    printf("  Section header size:%u\n", e_shentsize);
    printf("  Shstrndx:           %u\n", e_shstrndx);

    if (summary || e_shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum) {
        fclose(fp);
        return 0;
    }

    /* Read section header string table to resolve names */
    if (fseek(fp, (long)(e_shoff + (uint64_t)e_shstrndx * e_shentsize), SEEK_SET) != 0) {
        printf(C_RED "  [ELF] failed to seek to shstrtab header\n" C_RESET);
        fclose(fp);
        return -1;
    }

    uint64_t shstrtab_offset = 0;
    uint64_t shstrtab_size   = 0;

    if (elf_class == ELFCLASS32) {
        (void)elf_read_u32(fp, be); /* sh_name */
        (void)elf_read_u32(fp, be); /* sh_type */
        (void)elf_read_u32(fp, be); /* sh_flags */
        (void)elf_read_u32(fp, be); /* sh_addr */
        shstrtab_offset = elf_read_u32(fp, be);
        shstrtab_size   = elf_read_u32(fp, be);
    } else {
        (void)elf_read_u32(fp, be); /* sh_name */
        (void)elf_read_u32(fp, be); /* sh_type */
        (void)elf_read_u64(fp, be); /* sh_flags */
        (void)elf_read_u64(fp, be); /* sh_addr */
        shstrtab_offset = elf_read_u64(fp, be);
        shstrtab_size   = elf_read_u64(fp, be);
    }

    if (shstrtab_size == 0) {
        printf("  [ELF] empty shstrtab\n");
        fclose(fp);
        return 0;
    }

    if (fseek(fp, (long)shstrtab_offset, SEEK_SET) != 0) {
        printf(C_RED "  [ELF] failed to seek to shstrtab data\n" C_RESET);
        fclose(fp);
        return -1;
    }

    char *shstrtab = malloc((size_t)shstrtab_size);
    if (!shstrtab) {
        printf(C_RED "  [ELF] failed to allocate shstrtab\n" C_RESET);
        fclose(fp);
        return -1;
    }

    if (fread(shstrtab, 1, (size_t)shstrtab_size, fp) != shstrtab_size) {
        printf(C_RED "  [ELF] failed to read shstrtab\n" C_RESET);
        free(shstrtab);
        fclose(fp);
        return -1;
    }

    printf("  " C_BLUE "Sections:\n" C_RESET);
    printf("    %-4s %-18s %-10s %-10s\n", "Idx", "Name", "Offset", "Size");

    for (uint16_t i = 0; i < e_shnum; i++) {
        uint64_t sh_off = e_shoff + (uint64_t)i * e_shentsize;
        if (fseek(fp, (long)sh_off, SEEK_SET) != 0) {
            printf(C_RED "    [ELF] failed to seek to section %u\n" C_RESET, i);
            break;
        }

        uint32_t sh_name = elf_read_u32(fp, be);
        uint32_t sh_type = elf_read_u32(fp, be);
        (void)sh_type;

        uint64_t sh_flags, sh_addr, sh_offset, sh_size;
        if (elf_class == ELFCLASS32) {
            sh_flags  = elf_read_u32(fp, be);
            sh_addr   = elf_read_u32(fp, be);
            sh_offset = elf_read_u32(fp, be);
            sh_size   = elf_read_u32(fp, be);
        } else {
            sh_flags  = elf_read_u64(fp, be);
            sh_addr   = elf_read_u64(fp, be);
            sh_offset = elf_read_u64(fp, be);
            sh_size   = elf_read_u64(fp, be);
        }
        (void)sh_flags;
        (void)sh_addr;

        const char *name = "";
        if (sh_name < shstrtab_size) {
            name = shstrtab + sh_name;
        }

        printf("    %-4u " C_GREEN "%-18s" C_RESET " "
               C_YELLOW "0x%08llx" C_RESET " "
               C_YELLOW "0x%08llx" C_RESET "\n",
               i, name,
               (unsigned long long)sh_offset,
               (unsigned long long)sh_size);

        if (verbose) {
            /* Future: print flags, type, etc. */
        }
    }

    free(shstrtab);
    fclose(fp);
    return 0;
}





static int opus_read_structured_riff(const char *path, bool summary, bool verbose)
{
    (void)summary;
    (void)verbose;
    printf("[STRUCTURED][RIFF] not implemented yet for '%s'\n", path);
    return 0;
}

