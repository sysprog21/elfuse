/*
 * ELF64 parser and loader
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reads aarch64-linux ELF64 executables, validates the header, extracts PT_LOAD
 * segments, and copies them into guest memory.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "core/elf.h"
#include "debug/log.h"
#include "utils.h"

int elf_load_fd(int fd, const char *display_path, elf_info_t *info)
{
    memset(info, 0, sizeof(*info));

    elf64_ehdr_t ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        log_error("%s: failed to read ELF header", display_path);
        return -1;
    }

    /* Reject non-ELF inputs before interpreting the rest of the header. */
    if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3) {
        log_error("%s: not an ELF file", display_path);
        return -1;
    }

    /* elfuse only implements the 64-bit Linux ABI. */
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        log_error("%s: not a 64-bit ELF", display_path);
        return -1;
    }

    /* aarch64-linux user binaries are little-endian in the supported mode. */
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        log_error("%s: not little-endian", display_path);
        return -1;
    }

    /* x86_64 is recognized so callers can report a clear unsupported-arch
     * diagnostic instead of a generic parse failure.
     */
    if (ehdr.e_machine != EM_AARCH64 && ehdr.e_machine != EM_X86_64) {
        log_error("%s: unsupported architecture (e_machine=%u)", display_path,
                  ehdr.e_machine);
        return -1;
    }

    /* ET_DYN is accepted for PIE executables and interpreters; callers choose
     * the load base that keeps them away from elfuse's reserved regions.
     */
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        log_error("%s: not an executable (e_type=%u)", display_path,
                  ehdr.e_type);
        return -1;
    }

    info->entry = ehdr.e_entry;
    info->e_type = ehdr.e_type;
    info->e_machine = ehdr.e_machine;
    info->phnum = ehdr.e_phnum;
    info->phentsize = ehdr.e_phentsize;
    info->load_min = UINT64_MAX;
    info->load_max = 0;

    /* Program headers drive both memory mappings and auxv AT_PHDR. */
    if (ehdr.e_phnum == 0) {
        log_error("%s: no program headers", display_path);
        return -1;
    }
    if (ehdr.e_phentsize < sizeof(elf64_phdr_t)) {
        log_error("%s: e_phentsize too small (%u < %zu)", display_path,
                  ehdr.e_phentsize, sizeof(elf64_phdr_t));
        return -1;
    }
    /* Linux kernel caps program headers at 64KiB. Reject pathological inputs
     * before allocating to avoid attacker-controlled large allocations.
     */
    if ((size_t) ehdr.e_phnum * ehdr.e_phentsize > 65536) {
        log_error("%s: program header table too large (%u * %u)", display_path,
                  ehdr.e_phnum, ehdr.e_phentsize);
        return -1;
    }

    size_t ph_total = (size_t) ehdr.e_phnum * ehdr.e_phentsize;
    uint8_t *ph_buf = malloc(ph_total);
    if (!ph_buf) {
        perror("malloc");
        return -1;
    }

    if (pread(fd, ph_buf, ph_total, ehdr.e_phoff) != (ssize_t) ph_total) {
        log_error("%s: failed to read program headers", display_path);
        free(ph_buf);
        return -1;
    }

    /* Collect only the program headers that affect process startup. */
    int seg_count = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf64_phdr_t *ph =
            (const elf64_phdr_t *) (ph_buf + (size_t) i * ehdr.e_phentsize);

        /* PT_INTERP stores the dynamic linker path in the file, not in a
         * loadable segment, so read it before closing the ELF.
         */
        if (ph->p_type == PT_INTERP) {
            size_t interp_len = ph->p_filesz;
            if (interp_len >= sizeof(info->interp_path)) {
                log_error("%s: PT_INTERP path too long (%zu >= %zu)",
                          display_path, interp_len, sizeof(info->interp_path));
                free(ph_buf);
                return -1;
            }
            if (interp_len > 0) {
                ssize_t n =
                    pread(fd, info->interp_path, interp_len, ph->p_offset);
                /* interp_len includes the NUL from the ELF file. On short
                 * read, clear the path (unusable). On full read,
                 * force-terminate as insurance.
                 */
                if (n < (ssize_t) interp_len)
                    info->interp_path[0] = '\0';
                else
                    info->interp_path[interp_len - 1] = '\0';
            }
        }

        if (ph->p_type == PT_LOAD) {
            if (seg_count >= ELF_MAX_SEGMENTS) {
                log_error("%s: too many PT_LOAD segments", display_path);
                free(ph_buf);
                return -1;
            }

            info->segments[seg_count].gpa = ph->p_vaddr;
            info->segments[seg_count].offset = ph->p_offset;
            info->segments[seg_count].filesz = ph->p_filesz;
            info->segments[seg_count].memsz = ph->p_memsz;
            info->segments[seg_count].flags = (int) ph->p_flags;
            seg_count++;

            /* Track load bounds */
            if (ph->p_vaddr < info->load_min)
                info->load_min = ph->p_vaddr;
            uint64_t seg_end = ph->p_vaddr + ph->p_memsz;
            if (seg_end < ph->p_vaddr)
                seg_end = UINT64_MAX; /* overflow */
            if (seg_end > info->load_max)
                info->load_max = seg_end;
        }
    }

    info->num_segments = seg_count;

    if (seg_count == 0) {
        log_error("%s: no PT_LOAD segments", display_path);
        free(ph_buf);
        return -1;
    }

    /* Store program header file offset for later phdr_gpa calculation. The
     * loader places program headers at the same GPA as they would be in the
     * first PT_LOAD segment (they are typically within it).
     */
    info->phdr_gpa = info->load_min + ehdr.e_phoff;

    free(ph_buf);
    return 0;
}

int elf_load(const char *path, elf_info_t *info)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    int rc = elf_load_fd(fd, path, info);
    close(fd);
    return rc;
}

int elf_map_segments_fd(const elf_info_t *info,
                        int fd,
                        const char *display_path,
                        void *guest_base,
                        uint64_t guest_size,
                        uint64_t load_base,
                        uint64_t infra_lo,
                        uint64_t infra_hi)
{
    /* Half-open intersection test for [a, a+alen) and [b, b+blen). When
     * infra_lo == infra_hi the caller opted out (early bring-up before guest_t
     * is wired up); the host-side writes that follow still get the existing
     * guest_size bound check.
     */
    bool infra_active = infra_lo < infra_hi;

    /* Re-read ELF header to get phoff */
    elf64_ehdr_t ehdr;
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        return -1;
    }

    /* Read and parse program headers again to get file offsets. The size was
     * already bound-checked during elf_load(); recheck defensively in case the
     * header sizes changed since (e.g. corrupt file races).
     */
    size_t ph_total = (size_t) ehdr.e_phnum * ehdr.e_phentsize;
    if (ph_total == 0 || ph_total > 65536) {
        return -1;
    }
    uint8_t *ph_buf = malloc(ph_total);
    if (!ph_buf) {
        return -1;
    }

    if (pread(fd, ph_buf, ph_total, ehdr.e_phoff) != (ssize_t) ph_total) {
        free(ph_buf);
        return -1;
    }

    /* Copy program headers into guest memory at phdr_gpa + load_base (needed
     * for AT_PHDR auxv entry). Fail hard if they do not fit. A missing copy
     * would leave AT_PHDR pointing at uninitialized memory, crashing the
     * dynamic linker.
     *
     * phdr_gpa + load_base may wrap via 2's complement for high-VA binaries.
     * The bounds check below catches invalid results.
     */
    uint64_t phdr_dest = info->phdr_gpa + load_base;
    if (phdr_dest + ph_total < phdr_dest || phdr_dest + ph_total > guest_size) {
        log_error(
            "%s: program headers at 0x%llx exceed guest memory "
            "(size 0x%llx)",
            display_path, (unsigned long long) (phdr_dest + ph_total),
            (unsigned long long) guest_size);
        free(ph_buf);
        return -1;
    }
    if (infra_active && phdr_dest < infra_hi &&
        phdr_dest + ph_total > infra_lo) {
        log_error(
            "%s: program headers at 0x%llx overlap infra reserve "
            "[0x%llx, 0x%llx)",
            display_path, (unsigned long long) phdr_dest,
            (unsigned long long) infra_lo, (unsigned long long) infra_hi);
        free(ph_buf);
        return -1;
    }
    memcpy((uint8_t *) guest_base + phdr_dest, ph_buf, ph_total);

    /* Copy PT_LOAD contents after AT_PHDR is in place; ET_DYN segments are
     * relocated by load_base before writing into guest memory.
     */
    int seg_idx = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum && seg_idx < info->num_segments;
         i++) {
        const elf64_phdr_t *ph =
            (const elf64_phdr_t *) (ph_buf + (size_t) i * ehdr.e_phentsize);

        if (ph->p_type != PT_LOAD)
            continue;

        /* p_vaddr + load_base may wrap via 2's complement for high-VA binaries
         * (see comment above). Bounds check below catches invalid results.
         */
        uint64_t gpa = ph->p_vaddr + load_base, filesz = ph->p_filesz;
        uint64_t memsz = ph->p_memsz;

        /* A segment cannot contain more initialized file data than its
         * in-memory extent.
         */
        if (filesz > memsz) {
            log_error(
                "%s: segment at 0x%llx has filesz > memsz "
                "(0x%llx > 0x%llx)",
                display_path, (unsigned long long) gpa,
                (unsigned long long) filesz, (unsigned long long) memsz);
            free(ph_buf);
            return -1;
        }

        /* Keep the mapped segment inside the configured IPA-sized guest slab.
         */
        if (memsz > guest_size || gpa > guest_size - memsz) {
            log_error("%s: segment at 0x%llx+0x%llx exceeds guest memory",
                      display_path, (unsigned long long) gpa,
                      (unsigned long long) memsz);
            free(ph_buf);
            return -1;
        }

        /* PT_LOAD with memsz == 0 maps no bytes, but the page-tail zero extent
         * below still rounds up to the next page boundary. For an unaligned gpa
         * that means a crafted ELF could splat zeros across the tail of a
         * previously loaded segment in the same page, or trip the infra-overlap
         * check with no live mapping behind it. Linux ignores zero-memsz
         * PT_LOADs; mirror that here.
         */
        if (memsz == 0) {
            seg_idx++;
            continue;
        }

        /* The host memset zeros up to the next page boundary AFTER the segment
         * ends, so the infra-overlap check has to use the same rounded extent.
         * The end is PAGE_ALIGN_UP(gpa + memsz) rather than gpa +
         * PAGE_ALIGN_UP(memsz) because gpa is not always page-aligned (e.g.
         * ld.so's RW segment at vaddr 0x2f650): with the older bytes-from-gpa
         * formula the page covering the last memsz byte kept its mid-page tail
         * untouched, and execve into a dynamic-linked target then read stale
         * state from the prior incarnation of the same interpreter at offsets
         * ld.so allocates from beyond memsz (e.g. the first link_map in
         * _dl_new_object).
         */
        uint64_t zero_len = PAGE_ALIGN_UP(gpa + memsz) - gpa;
        if (gpa + zero_len > guest_size)
            zero_len = guest_size - gpa;
        if (infra_active && gpa < infra_hi && gpa + zero_len > infra_lo) {
            log_error(
                "%s: segment at 0x%llx+0x%llx (zero-extent 0x%llx) overlaps "
                "infra reserve [0x%llx, 0x%llx)",
                display_path, (unsigned long long) gpa,
                (unsigned long long) memsz, (unsigned long long) zero_len,
                (unsigned long long) infra_lo, (unsigned long long) infra_hi);
            free(ph_buf);
            return -1;
        }

        /* Zero only the tail beyond filesz: the BSS portion [filesz, memsz)
         * plus the page-padding [memsz, zero_len) that Linux guarantees clean
         * for dynamic linkers allocating from the last mapped page's tail.
         * Skipping the file-data range avoids writing zeros that the fread
         * below would immediately overwrite; for typical shared libraries that
         * is a hundreds-of-KiB win per segment.
         */
        if (zero_len > filesz)
            memset((uint8_t *) guest_base + gpa + filesz, 0, zero_len - filesz);

        if (filesz > 0) {
            if (pread(fd, (uint8_t *) guest_base + gpa, filesz, ph->p_offset) !=
                (ssize_t) filesz) {
                log_error(
                    "%s: short read for segment at 0x%llx "
                    "(expected %llu)",
                    display_path, (unsigned long long) gpa,
                    (unsigned long long) filesz);
                free(ph_buf);
                return -1;
            }
        }

        seg_idx++;
    }

    free(ph_buf);
    return 0;
}

int elf_map_segments(const elf_info_t *info,
                     const char *path,
                     void *guest_base,
                     uint64_t guest_size,
                     uint64_t load_base,
                     uint64_t infra_lo,
                     uint64_t infra_hi)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror(path);
        return -1;
    }
    int rc = elf_map_segments_fd(info, fd, path, guest_base, guest_size,
                                 load_base, infra_lo, infra_hi);
    close(fd);
    return rc;
}

void elf_resolve_interp(const char *sysroot,
                        const char *interp_path,
                        char *out,
                        size_t out_sz)
{
    if (sysroot) {
        /* Strategy 1: sysroot + full interp path */
        snprintf(out, out_sz, "%s%s", sysroot, interp_path);
        if (access(out, F_OK) == 0)
            return;

        /* Strategy 2: sysroot/lib/basename. Handles store-style interpreter
         * paths such as /.../lib/ld-musl-aarch64.so.1
         */
        const char *base = strrchr(interp_path, '/');
        base = base ? base + 1 : interp_path;
        snprintf(out, out_sz, "%s/lib/%s", sysroot, base);
        if (access(out, F_OK) == 0)
            return;
    }
    /* Strategy 3: use interp_path as-is */
    str_copy_trunc(out, interp_path, out_sz);
}

int elf_read_shebang_fd(int fd,
                        char *interp_out,
                        size_t interp_sz,
                        char *arg_out,
                        size_t arg_sz)
{
    char buf[512];
    ssize_t nread = pread(fd, buf, sizeof(buf) - 1, 0);

    if (nread < 0) {
        return -errno;
    }
    if (nread < 2 || buf[0] != '#' || buf[1] != '!') {
        return 0; /* Not a shebang script */
    }
    buf[nread] = '\0';

    /* Ignore script bytes after the first line (find \n or \r). If the shebang
     * line is longer than our 511-byte buffer (no EOL found but buffer is
     * full), reject it.
     */
    char *eol = strpbrk(buf + 2, "\r\n");
    if (!eol) {
        if (nread == (ssize_t) (sizeof(buf) - 1)) {
            return -ENOEXEC; /* Shebang line too long */
        }
    } else {
        *eol = '\0';
    }

    char *ptr = buf + 2;
    while (*ptr == ' ' || *ptr == '\t') {
        ptr++;
    }

    /* Strip trailing whitespace/newlines of the whole shebang line */
    size_t len = strlen(ptr);
    while (len > 0 && (ptr[len - 1] == ' ' || ptr[len - 1] == '\t' ||
                       ptr[len - 1] == '\r' || ptr[len - 1] == '\n')) {
        ptr[--len] = '\0';
    }

    if (len == 0) {
        return -ENOEXEC; /* Empty shebang interpreter */
    }

    /* Parse interpreter path and single optional argument */
    char *interp = ptr;
    char *space = strpbrk(ptr, " \t");
    char *arg = NULL;
    if (space) {
        *space = '\0';
        arg = space + 1;
        /* Strip leading space of the argument */
        while (*arg == ' ' || *arg == '\t') {
            arg++;
        }
        /* Strip trailing space/newlines/tabs of the argument */
        size_t arg_len = strlen(arg);
        while (arg_len > 0 &&
               (arg[arg_len - 1] == ' ' || arg[arg_len - 1] == '\t' ||
                arg[arg_len - 1] == '\r' || arg[arg_len - 1] == '\n')) {
            arg[--arg_len] = '\0';
        }
        if (strlen(arg) == 0) {
            arg = NULL;
        }
    }

    if (str_copy_trunc(interp_out, interp, interp_sz) >= interp_sz) {
        return -ENOEXEC; /* Buffer too small */
    }

    if (str_copy_trunc(arg_out, arg ? arg : "", arg_sz) >= arg_sz) {
        return -ENOEXEC; /* Buffer too small */
    }

    return 1; /* Successfully parsed shebang */
}

int elf_read_shebang(const char *host_path,
                     char *interp_out,
                     size_t interp_sz,
                     char *arg_out,
                     size_t arg_sz)
{
    int fd = open(host_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    int rc = elf_read_shebang_fd(fd, interp_out, interp_sz, arg_out, arg_sz);
    close_keep_errno(fd);
    return rc;
}
