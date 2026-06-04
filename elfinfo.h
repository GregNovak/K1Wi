// elfinfo.h

#ifndef ELFINFO_H
#define ELFINFO_H

#include <stdint.h>
#include <stddef.h>

int opus_elfinfo_print(const char *path);

typedef struct {
    char     name[64];   // function name
    uint64_t offset;     // static offset from ELF base
} elf_symbol_t;

// Load function symbols from an ELF file (used by PIECALC / PIETIME)
int opus_elf_load_functions(const char *path,
                            elf_symbol_t *funcs,
                            int *count,
                            int max);

#endif

