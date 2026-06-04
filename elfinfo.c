// elfinfo.c
//
// Clean, warning-free ELF symbol loader for Opus.
// Supports both 32-bit and 64-bit ELF.
// Provides:
//   - opus_elfinfo_print()
//   - opus_elf_load_functions()
//
// No dynamic allocations except file buffer.
// No unused functions or variables.
// No warnings under -Wall -Wextra.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <elf.h>
#include <inttypes.h>

#include "elfinfo.h"

/* -------------------------------------------------------------
 * Read entire file into memory
 * ------------------------------------------------------------- */
static int read_entire_file(const char *path, unsigned char **buf_out, size_t *size_out)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;

    FILE *f = fopen(path, "rb");
	if (!f) {
	    return -1;
	}

	if (st.st_size < 0) {
	    fclose(f);
	    return -1;
	}

	size_t file_size = (size_t)st.st_size;   

	unsigned char *buf = malloc(file_size);
	if (!buf) {
	    fclose(f);
	    return -1;
	}

	size_t n = fread(buf, 1, file_size, f);
	fclose(f);

	if (n != file_size) {
	    free(buf);
	    return -1;
	}

	*buf_out = buf;
	*size_out = file_size;
    return 0;
}

/* -------------------------------------------------------------
 * Validate ELF header
 * ------------------------------------------------------------- */
static int elf_is_valid(const unsigned char *buf, size_t size)
{
    if (size < EI_NIDENT)
        return 0;

    if (buf[EI_MAG0] != ELFMAG0 ||
        buf[EI_MAG1] != ELFMAG1 ||
        buf[EI_MAG2] != ELFMAG2 ||
        buf[EI_MAG3] != ELFMAG3)
        return 0;

    if (buf[EI_CLASS] != ELFCLASS32 &&
        buf[EI_CLASS] != ELFCLASS64)
        return 0;

    return 1;
}

/* -------------------------------------------------------------
 * Load function symbols (64-bit)
 * ------------------------------------------------------------- */
static int load_functions_elf64(const unsigned char *buf, size_t size,
                                elf_symbol_t *funcs, int *count, int max)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;

    if (size < sizeof(Elf64_Ehdr))
        return -1;

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return -1;

    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf64_Shdr) > size)
        return -1;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + eh->e_shoff);

    int out = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
            continue;

        if (sh->sh_offset + sh->sh_size > size)
            continue;

        const Elf64_Sym *syms = (const Elf64_Sym *)(buf + sh->sh_offset);
        size_t sym_count = sh->sh_size / sizeof(Elf64_Sym);

        if (sh->sh_link >= eh->e_shnum)
            continue;

        const Elf64_Shdr *str_sh = &shdrs[sh->sh_link];
        if (str_sh->sh_offset + str_sh->sh_size > size)
            continue;

        const char *strs = (const char *)(buf + str_sh->sh_offset);

        for (size_t s = 0; s < sym_count; s++) {
            const Elf64_Sym *sym = &syms[s];

            if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                continue;
            if (sym->st_name == 0)
                continue;
            if (sym->st_value == 0)
                continue;

            const char *name = strs + sym->st_name;
            if (!name || !*name)
                continue;

            if (out < max) {
                strncpy(funcs[out].name, name, sizeof(funcs[out].name) - 1);
                funcs[out].name[sizeof(funcs[out].name) - 1] = '\0';
                funcs[out].offset = sym->st_value;
                out++;
            }
        }
    }

    *count = out;
    return 0;
}

/* -------------------------------------------------------------
 * Load function symbols (32-bit)
 * ------------------------------------------------------------- */
static int load_functions_elf32(const unsigned char *buf, size_t size,
                                elf_symbol_t *funcs, int *count, int max)
{
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)buf;

    if (size < sizeof(Elf32_Ehdr))
        return -1;

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return -1;

    if (eh->e_shoff + (size_t)eh->e_shnum * sizeof(Elf32_Shdr) > size)
        return -1;

    const Elf32_Shdr *shdrs = (const Elf32_Shdr *)(buf + eh->e_shoff);

    int out = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const Elf32_Shdr *sh = &shdrs[i];

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
            continue;

        if (sh->sh_offset + sh->sh_size > size)
            continue;

        const Elf32_Sym *syms = (const Elf32_Sym *)(buf + sh->sh_offset);
        size_t sym_count = sh->sh_size / sizeof(Elf32_Sym);

        if (sh->sh_link >= eh->e_shnum)
            continue;

        const Elf32_Shdr *str_sh = &shdrs[sh->sh_link];
        if (str_sh->sh_offset + str_sh->sh_size > size)
            continue;

        const char *strs = (const char *)(buf + str_sh->sh_offset);

        for (size_t s = 0; s < sym_count; s++) {
            const Elf32_Sym *sym = &syms[s];

            if (ELF32_ST_TYPE(sym->st_info) != STT_FUNC)
                continue;
            if (sym->st_name == 0)
                continue;
            if (sym->st_value == 0)
                continue;

            const char *name = strs + sym->st_name;
            if (!name || !*name)
                continue;

            if (out < max) {
                strncpy(funcs[out].name, name, sizeof(funcs[out].name) - 1);
                funcs[out].name[sizeof(funcs[out].name) - 1] = '\0';
                funcs[out].offset = sym->st_value;
                out++;
            }
        }
    }

    *count = out;
    return 0;
}

/* -------------------------------------------------------------
 * Public API: load functions
 * ------------------------------------------------------------- */
int opus_elf_load_functions(const char *path,
                            elf_symbol_t *funcs,
                            int *count,
                            int max)
{
    *count = 0;

    unsigned char *buf = NULL;
    size_t size = 0;

    if (read_entire_file(path, &buf, &size) != 0)
        return -1;

    if (!elf_is_valid(buf, size)) {
        free(buf);
        return -1;
    }

    int cls = buf[EI_CLASS];
    int rc = 0;

    if (cls == ELFCLASS64)
        rc = load_functions_elf64(buf, size, funcs, count, max);
    else
        rc = load_functions_elf32(buf, size, funcs, count, max);

    free(buf);
    return rc;
}


/* -------------------------------------------------------------
 * Helpers: safe range checks
 * ------------------------------------------------------------- */
static int range_ok(size_t off, size_t len, size_t size)
{
    if (off > size) return 0;
    if (len > size - off) return 0;
    return 1;
}

/* -------------------------------------------------------------
 * Print ELF64 info: headers, segments, dynamic
 * ------------------------------------------------------------- */
static void print_elf64_info(const unsigned char *buf, size_t size, const char *path)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;

    if (size < sizeof(Elf64_Ehdr))
        return;

    printf("ELFINFO: %s (64-bit)\n", path);
    printf("  Entry:   0x%016" PRIx64 "\n", (uint64_t)eh->e_entry);
    printf("  Type:    0x%04x\n", (unsigned)eh->e_type);
    printf("  Machine: 0x%04x\n", (unsigned)eh->e_machine);
    printf("  Sections: %u\n", eh->e_shnum);
    printf("  Segments: %u\n", eh->e_phnum);

    /* Program headers (segments) */
    if (eh->e_phoff != 0 && eh->e_phnum > 0) {
        if (!range_ok((size_t)eh->e_phoff,
                      (size_t)eh->e_phnum * sizeof(Elf64_Phdr),
                      size))
            return;

        const Elf64_Phdr *ph = (const Elf64_Phdr *)(buf + eh->e_phoff);

        printf("  Program headers:\n");
        printf("    %-3s %-10s %-10s %-10s %-8s\n",
               "Idx", "Type", "Offset", "Vaddr", "Flags");

        for (uint16_t i = 0; i < eh->e_phnum; i++) {
            const Elf64_Phdr *p = &ph[i];
            printf("    %-3u 0x%08x 0x%08" PRIx64 " 0x%08" PRIx64 " 0x%02x\n",
                   i,
                   (unsigned)p->p_type,
                   (uint64_t)p->p_offset,
                   (uint64_t)p->p_vaddr,
                   (unsigned)p->p_flags);
        }
    }

    /* Dynamic section (DT_NEEDED, RPATH/RUNPATH, SONAME, etc.) */
    if (eh->e_phoff != 0 && eh->e_phnum > 0) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(buf + eh->e_phoff);
        const Elf64_Dyn  *dyn = NULL;
        size_t dyn_count = 0;
        const char *strtab = NULL;

        for (uint16_t i = 0; i < eh->e_phnum; i++) {
            const Elf64_Phdr *p = &ph[i];
            if (p->p_type == PT_DYNAMIC) {
                if (!range_ok((size_t)p->p_offset, (size_t)p->p_filesz, size))
                    break;
                dyn = (const Elf64_Dyn *)(buf + p->p_offset);
                dyn_count = p->p_filesz / sizeof(Elf64_Dyn);
                break;
            }
        }

        if (dyn && dyn_count > 0) {
            Elf64_Addr strtab_addr = 0;

            /* First pass: find STRTAB address */
            for (size_t i = 0; i < dyn_count; i++) {
                if (dyn[i].d_tag == DT_STRTAB) {
                    strtab_addr = dyn[i].d_un.d_ptr;
                    break;
                }
            }

            /* Map STRTAB address to file offset via PT_LOAD */
            if (strtab_addr != 0) {
                const Elf64_Phdr *ph2 = (const Elf64_Phdr *)(buf + eh->e_phoff);
                for (uint16_t i = 0; i < eh->e_phnum; i++) {
                    const Elf64_Phdr *p = &ph2[i];
                    if (p->p_type != PT_LOAD)
                        continue;
                    if (strtab_addr >= p->p_vaddr &&
                        strtab_addr <  p->p_vaddr + p->p_memsz) {
                        size_t off = (size_t)(strtab_addr - p->p_vaddr + p->p_offset);
                        if (off < size)
                            strtab = (const char *)(buf + off);
                        break;
                    }
                }
            }

            printf("  Dynamic section:\n");
            for (size_t i = 0; i < dyn_count; i++) {
                const Elf64_Dyn *d = &dyn[i];
                if (d->d_tag == DT_NULL)
                    break;

                if (d->d_tag == DT_NEEDED && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    NEEDED: %s\n", name);
                } else if ((d->d_tag == DT_RPATH || d->d_tag == DT_RUNPATH) && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    %s: %s\n",
                           d->d_tag == DT_RPATH ? "RPATH" : "RUNPATH",
                           name);
                } else if (d->d_tag == DT_SONAME && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    SONAME: %s\n", name);
                }
            }
        }
    }
}


/* -------------------------------------------------------------
 * Print symbols (64-bit)
 * ------------------------------------------------------------- */
static void print_symbols_elf64(const unsigned char *buf, size_t size)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return;

    if (!range_ok(eh->e_shoff,
                  (size_t)eh->e_shnum * sizeof(Elf64_Shdr),
                  size))
        return;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + eh->e_shoff);

    printf("  Symbol tables:\n");

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr *sh = &shdrs[i];

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
            continue;

        if (!range_ok(sh->sh_offset, sh->sh_size, size))
            continue;

        const Elf64_Sym *syms = (const Elf64_Sym *)(buf + sh->sh_offset);
        size_t sym_count = sh->sh_size / sizeof(Elf64_Sym);

        if (sh->sh_link >= eh->e_shnum)
            continue;

        const Elf64_Shdr *str_sh = &shdrs[sh->sh_link];
        if (!range_ok(str_sh->sh_offset, str_sh->sh_size, size))
            continue;

        const char *strs = (const char *)(buf + str_sh->sh_offset);

        printf("    [%u] %s (%zu symbols)\n",
               i,
               (sh->sh_type == SHT_SYMTAB ? "SYMTAB" : "DYNSYM"),
               sym_count);

        printf("      %-30s %-10s %-10s\n", "Name", "Value", "Size");

        for (size_t s = 0; s < sym_count; s++) {
            const Elf64_Sym *sym = &syms[s];
            if (sym->st_name == 0)
                continue;

            const char *name = strs + sym->st_name;
            if (!name || !*name)
                continue;

            printf("      %-30s 0x%08" PRIx64 " %-10" PRIu64 "\n",
                   name,
                   (uint64_t)sym->st_value,
                   (uint64_t)sym->st_size);
        }
    }
}

/* -------------------------------------------------------------
 * Print symbols (32-bit)
 * ------------------------------------------------------------- */
static void print_symbols_elf32(const unsigned char *buf, size_t size)
{
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)buf;

    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        return;

    if (!range_ok(eh->e_shoff,
                  (size_t)eh->e_shnum * sizeof(Elf32_Shdr),
                  size))
        return;

    const Elf32_Shdr *shdrs = (const Elf32_Shdr *)(buf + eh->e_shoff);

    printf("  Symbol tables:\n");

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Elf32_Shdr *sh = &shdrs[i];

        if (sh->sh_type != SHT_SYMTAB && sh->sh_type != SHT_DYNSYM)
            continue;

        if (!range_ok(sh->sh_offset, sh->sh_size, size))
            continue;

        const Elf32_Sym *syms = (const Elf32_Sym *)(buf + sh->sh_offset);
        size_t sym_count = sh->sh_size / sizeof(Elf32_Sym);

        if (sh->sh_link >= eh->e_shnum)
            continue;

        const Elf32_Shdr *str_sh = &shdrs[sh->sh_link];
        if (!range_ok(str_sh->sh_offset, str_sh->sh_size, size))
            continue;

        const char *strs = (const char *)(buf + str_sh->sh_offset);

        printf("    [%u] %s (%zu symbols)\n",
               i,
               (sh->sh_type == SHT_SYMTAB ? "SYMTAB" : "DYNSYM"),
               sym_count);

        printf("      %-30s %-10s %-10s\n", "Name", "Value", "Size");

        for (size_t s = 0; s < sym_count; s++) {
            const Elf32_Sym *sym = &syms[s];
            if (sym->st_name == 0)
                continue;

            const char *name = strs + sym->st_name;
            if (!name || !*name)
                continue;

            printf("      %-30s 0x%08" PRIx32 " %-10" PRIu32 "\n",
                   name,
                   (uint32_t)sym->st_value,
                   (uint32_t)sym->st_size);
        }
    }
}



/* -------------------------------------------------------------
 * Print ELF32 info: headers, segments, dynamic
 * ------------------------------------------------------------- */
static void print_elf32_info(const unsigned char *buf, size_t size, const char *path)
{
    const Elf32_Ehdr *eh = (const Elf32_Ehdr *)buf;

    if (size < sizeof(Elf32_Ehdr))
        return;

    printf("ELFINFO: %s (32-bit)\n", path);
    printf("  Entry:   0x%08" PRIx32 "\n", (uint32_t)eh->e_entry);
    printf("  Type:    0x%04x\n", (unsigned)eh->e_type);
    printf("  Machine: 0x%04x\n", (unsigned)eh->e_machine);
    printf("  Sections: %u\n", eh->e_shnum);
    printf("  Segments: %u\n", eh->e_phnum);

    /* Program headers (segments) */
    if (eh->e_phoff != 0 && eh->e_phnum > 0) {
        if (!range_ok((size_t)eh->e_phoff,
                      (size_t)eh->e_phnum * sizeof(Elf32_Phdr),
                      size))
            return;

        const Elf32_Phdr *ph = (const Elf32_Phdr *)(buf + eh->e_phoff);

        printf("  Program headers:\n");
        printf("    %-3s %-10s %-10s %-10s %-8s\n",
               "Idx", "Type", "Offset", "Vaddr", "Flags");

        for (uint16_t i = 0; i < eh->e_phnum; i++) {
            const Elf32_Phdr *p = &ph[i];
            printf("    %-3u 0x%08x 0x%08" PRIx32 " 0x%08" PRIx32 " 0x%02x\n",
                   i,
                   (unsigned)p->p_type,
                   (uint32_t)p->p_offset,
                   (uint32_t)p->p_vaddr,
                   (unsigned)p->p_flags);
        }
    }

    /* Dynamic section (DT_NEEDED, RPATH/RUNPATH, SONAME, etc.) */
    if (eh->e_phoff != 0 && eh->e_phnum > 0) {
        const Elf32_Phdr *ph = (const Elf32_Phdr *)(buf + eh->e_phoff);
        const Elf32_Dyn  *dyn = NULL;
        size_t dyn_count = 0;
        const char *strtab = NULL;

        for (uint16_t i = 0; i < eh->e_phnum; i++) {
            const Elf32_Phdr *p = &ph[i];
            if (p->p_type == PT_DYNAMIC) {
                if (!range_ok((size_t)p->p_offset, (size_t)p->p_filesz, size))
                    break;
                dyn = (const Elf32_Dyn *)(buf + p->p_offset);
                dyn_count = p->p_filesz / sizeof(Elf32_Dyn);
                break;
            }
        }

        if (dyn && dyn_count > 0) {
            Elf32_Addr strtab_addr = 0;

            /* First pass: find STRTAB address */
            for (size_t i = 0; i < dyn_count; i++) {
                if (dyn[i].d_tag == DT_STRTAB) {
                    strtab_addr = dyn[i].d_un.d_ptr;
                    break;
                }
            }

            /* Map STRTAB address to file offset via PT_LOAD */
            if (strtab_addr != 0) {
                const Elf32_Phdr *ph2 = (const Elf32_Phdr *)(buf + eh->e_phoff);
                for (uint16_t i = 0; i < eh->e_phnum; i++) {
                    const Elf32_Phdr *p = &ph2[i];
                    if (p->p_type != PT_LOAD)
                        continue;
                    if (strtab_addr >= p->p_vaddr &&
                        strtab_addr <  p->p_vaddr + p->p_memsz) {
                        size_t off = (size_t)(strtab_addr - p->p_vaddr + p->p_offset);
                        if (off < size)
                            strtab = (const char *)(buf + off);
                        break;
                    }
                }
            }

            printf("  Dynamic section:\n");
            for (size_t i = 0; i < dyn_count; i++) {
                const Elf32_Dyn *d = &dyn[i];
                if (d->d_tag == DT_NULL)
                    break;

                if (d->d_tag == DT_NEEDED && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    NEEDED: %s\n", name);
                } else if ((d->d_tag == DT_RPATH || d->d_tag == DT_RUNPATH) && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    %s: %s\n",
                           d->d_tag == DT_RPATH ? "RPATH" : "RUNPATH",
                           name);
                } else if (d->d_tag == DT_SONAME && strtab) {
                    const char *name = strtab + d->d_un.d_val;
                    printf("    SONAME: %s\n", name);
                }
            }
        }
    }
}


/* -------------------------------------------------------------
 * Public API: print ELF info
 * ------------------------------------------------------------- */
int opus_elfinfo_print(const char *path)
{
    unsigned char *buf = NULL;
    size_t size = 0;

    if (read_entire_file(path, &buf, &size) != 0)
        return -1;

    if (!elf_is_valid(buf, size)) {
        free(buf);
        return -1;
    }

    int cls = buf[EI_CLASS];

	if (cls == ELFCLASS64) {
	    print_elf64_info(buf, size, path);
	    print_symbols_elf64(buf, size);
	} else {
	    print_elf32_info(buf, size, path);
	    print_symbols_elf32(buf, size);
	}


    free(buf);
    return 0;
}

