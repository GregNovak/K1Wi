#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "file_carver.h"


/* Simple magic signatures */
typedef struct magic_sig {
    const char *name;
    const uint8_t *magic;
    size_t magic_len;
    const char *ext;
} magic_sig_t;

/* JPEG, PNG, ZIP, PDF */
static const uint8_t JPEG_MAGIC[] = { 0xFF, 0xD8, 0xFF };
static const uint8_t PNG_MAGIC[]  = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n' };
static const uint8_t ZIP_MAGIC[]  = { 'P', 'K', 0x03, 0x04 };
static const uint8_t PDF_MAGIC[]  = { '%', 'P', 'D', 'F' };

static const magic_sig_t SIGS[] = {
    { "JPEG", JPEG_MAGIC, sizeof(JPEG_MAGIC), ".jpg" },
    { "PNG",  PNG_MAGIC,  sizeof(PNG_MAGIC),  ".png" },
    { "ZIP",  ZIP_MAGIC,  sizeof(ZIP_MAGIC),  ".zip" },
    { "PDF",  PDF_MAGIC,  sizeof(PDF_MAGIC),  ".pdf" },
};
static const size_t NSIGS = sizeof(SIGS) / sizeof(SIGS[0]);

/* Ensure output directory exists (best effort). */
static void ensure_outdir(const char *outdir)
{
    struct stat st;
    if (stat(outdir, &st) == 0 && S_ISDIR(st.st_mode)) return;

    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        perror("opus_file_carve mkdir");
    }
}

/* Check if buffer at position i starts with sig->magic. */
static int match_magic(const uint8_t *buf, size_t buflen, size_t i, const magic_sig_t *sig)
{
    if (i + sig->magic_len > buflen) return 0;
    return (memcmp(buf + i, sig->magic, sig->magic_len) == 0);
}

/* Find next header at or after start_offset. Returns index or buflen if none. */
static size_t find_next_header(const uint8_t *buf, size_t buflen, size_t start_offset)
{
    for (size_t i = start_offset; i < buflen; i++) {
        for (size_t s = 0; s < NSIGS; s++) {
            if (match_magic(buf, buflen, i, &SIGS[s])) {
                return i;
            }
        }
    }
    return buflen;
}

int opus_file_carve(const char *path, const char *outdir, opus_carve_result_t *res)
{
    if (res) memset(res, 0, sizeof(*res));
    if (!path || !outdir) return -1;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("opus_file_carve fopen");
        if (res) res->errors++;
        return -1;
    }

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("opus_file_carve fseek");
        fclose(fp);
        if (res) res->errors++;
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        perror("opus_file_carve ftell");
        fclose(fp);
        if (res) res->errors++;
        return -1;
    }
    rewind(fp);

    size_t buflen = (size_t)sz;
    uint8_t *buf = (uint8_t *)malloc(buflen);
    if (!buf) {
        fprintf(stderr, "opus_file_carve: out of memory\n");
        fclose(fp);
        if (res) res->errors++;
        return -1;
    }

    if (fread(buf, 1, buflen, fp) != buflen) {
        fprintf(stderr, "opus_file_carve: short read\n");
        free(buf);
        fclose(fp);
        if (res) res->errors++;
        return -1;
    }
    fclose(fp);

    ensure_outdir(outdir);

    int carved = 0;
    size_t offset = 0;
    int file_index = 0;

    while (offset < buflen) {
        size_t hdr = find_next_header(buf, buflen, offset);
        if (hdr >= buflen) break;

        /* Identify which signature matched at hdr */
        const magic_sig_t *sig = NULL;
        for (size_t s = 0; s < NSIGS; s++) {
            if (match_magic(buf, buflen, hdr, &SIGS[s])) {
                sig = &SIGS[s];
                break;
            }
        }
        if (!sig) {
            /* Shouldn't happen, but advance one byte to avoid infinite loop */
            offset = hdr + 1;
            continue;
        }

        /* Determine end of this file: next header or EOF */
        size_t next_hdr = find_next_header(buf, buflen, hdr + sig->magic_len);
        size_t end = (next_hdr > hdr) ? next_hdr : buflen;
        size_t len = end - hdr;

        /* Build output filename: outdir/base_index.ext */
        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/carve_%03d%s",
                 outdir, file_index, sig->ext);

        FILE *outf = fopen(outpath, "wb");
        if (!outf) {
            perror("opus_file_carve fopen out");
            if (res) res->errors++;
        } else {
            if (fwrite(buf + hdr, 1, len, outf) != len) {
                fprintf(stderr, "opus_file_carve: short write to %s\n", outpath);
                if (res) res->errors++;
            } else {
                carved++;
               /* verbose only later */
               // printf("[CARVER] Carved %s file at offset %zu (len %zu) -> %s\n", sig->name, offset, len, outpath);
            }
            fclose(outf);
        }

        file_index++;
        offset = end;
    }

    free(buf);

    if (res) res->files_carved = carved;
    if (carved == 0) {
    
    	/* no output here; opus_extract.c prints the report summary */
      
        
    } else {
        /* verbose only later */
        //printf("[CARVER] Total carved files: %d\n", carved);
    }

    return 0;
}

