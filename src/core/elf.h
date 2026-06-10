/* ELF64 parser and loader
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Parses aarch64-linux ELF64 executables (static and dynamic), extracts PT_LOAD
 * segments, and copies them into guest memory.
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

/* ELF64 structures (from Linux ABI) */

#define EI_NIDENT 16

/* ELF magic */
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

/* e_ident indices */
#define EI_CLASS 4
#define EI_DATA 5

/* EI_CLASS values */
#define ELFCLASS64 2

/* EI_DATA values */
#define ELFDATA2LSB 1

/* e_type */
#define ET_EXEC 2
#define ET_DYN 3

/* e_machine */
#define EM_X86_64 62
#define EM_AARCH64 183

/* Program header types */
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4

/* Program header flags */
#define PF_X 1
#define PF_W 2
#define PF_R 4

typedef struct {
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} elf64_ehdr_t;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} elf64_phdr_t;

/* Loaded ELF info */

#define ELF_MAX_SEGMENTS 16

typedef struct {
    /* From ELF header */
    uint64_t entry;     /* e_entry: program entry point */
    uint16_t e_type;    /* ET_EXEC or ET_DYN */
    uint16_t e_machine; /* EM_AARCH64 or EM_X86_64 */
    uint16_t phnum;     /* Number of program headers */
    uint16_t phentsize; /* Size of each program header */

    /* PT_LOAD segment bounds (for page table coverage) */
    uint64_t load_min; /* Lowest loaded GPA (page-aligned) */
    uint64_t load_max; /* Highest loaded GPA + memsz (page-aligned up) */

    /* Program headers location in guest memory (for AT_PHDR auxv) */
    uint64_t phdr_gpa; /* GPA of program headers in guest memory */

    /* PT_INTERP: dynamic linker path (empty if statically linked) */
    char interp_path[256];

    /* Segment details */
    int num_segments;
    struct {
        uint64_t gpa;    /* Guest physical address */
        uint64_t offset; /* File offset (p_offset, for /proc/self/maps) */
        uint64_t filesz; /* Bytes to load from file */
        uint64_t memsz;  /* Total memory size (filesz + bss) */
        int flags;       /* PF_R, PF_W, PF_X */
    } segments[ELF_MAX_SEGMENTS];
} elf_info_t;

/* API */

/* Load and parse an ELF64 file. Validates header, extracts PT_LOAD info.
 * Returns 0 on success, -1 on failure. Does NOT copy to guest yet.
 */
int elf_load(const char *path, elf_info_t *info);
int elf_load_quiet(const char *path, elf_info_t *info);

/* Copy ELF segments into guest memory. Call after elf_load() and guest_init().
 * Also copies program headers into guest memory for AT_PHDR. load_base is added
 * to all virtual addresses (0 for ET_EXEC at link addr, non-zero for ET_DYN
 * loaded at a chosen base). infra_lo and infra_hi delimit the runtime infra
 * reserve (page-table pool, shim text, shim_data, vDSO). Any PT_LOAD or PT_PHDR
 * copy whose destination intersects [infra_lo, infra_hi) is rejected: those
 * writes go through host_base directly and would otherwise bypass the EL1-only
 * page-table protection on shim_data. Pass 0,0 only when the guest_t is not yet
 * built.
 * Returns 0 on success, -1 on failure.
 */
int elf_map_segments(const elf_info_t *info,
                     const char *path,
                     void *guest_base,
                     uint64_t guest_size,
                     uint64_t load_base,
                     uint64_t infra_lo,
                     uint64_t infra_hi);

/* Resolve a PT_INTERP path against a sysroot directory. Tries three strategies:
 *   1. sysroot + interp_path  (standard /lib/ld-musl-*.so.1)
 *   2. sysroot/lib/basename(interp_path)  (store-style paths)
 *   3. interp_path as-is  (no sysroot or fallback)
 * Writes the resolved path into out (must be at least out_sz bytes).
 */
void elf_resolve_interp(const char *sysroot,
                        const char *interp_path,
                        char *out,
                        size_t out_sz);

/* Translate ELF program-header flags (PF_R=4, PF_W=2, PF_X=1) into the
 * R=1/W=2/X=4 bitset shared by both MEM_PERM_R/W/X (page-table permissions) and
 * LINUX_PROT_READ/WRITE/EXEC (mmap prot bits).
 *
 * READ is implicit: every loaded segment gets the R bit even if PF_R is absent,
 * mirroring the kernel's behavior for ELF loading.
 */
static inline int elf_pf_to_prot(int pf)
{
    int r = 1; /* always readable */
    if (pf & PF_W)
        r |= 2;
    if (pf & PF_X)
        r |= 4;
    return r;
}
