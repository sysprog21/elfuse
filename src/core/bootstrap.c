/*
 * Guest bootstrap helpers
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Hypervisor/Hypervisor.h>
#include <Hypervisor/hv_vcpu.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hvutil.h"
#include "utils.h"

#include "core/bootstrap.h"
#include "core/rosetta.h"
#include "core/shim-globals.h"
#include "core/stack.h"
#include "core/startup-trace.h"
#include "core/vdso.h"

#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/linux-wire.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#include "debug/log.h"
#include "core/mmap-fastpath.h"

/* Worst case: 7 fixed regions (shim, shim-data, vDSO, brk, stack, mmap RX, mmap
 * RW) plus up to ELF_MAX_SEGMENTS for both the executable and the interpreter.
 */
#define MAX_BOOT_REGIONS (8 + 2 * ELF_MAX_SEGMENTS)

static bool append_boot_region(mem_region_t *regions,
                               int *nregions,
                               uint64_t gpa_start,
                               uint64_t gpa_end,
                               int perms)
{
    if (*nregions >= MAX_BOOT_REGIONS)
        return false;

    regions[*nregions] = (mem_region_t) {
        .gpa_start = gpa_start, .gpa_end = gpa_end, .perms = perms};
    (*nregions)++;
    return true;
}

/* Emit one mem_region_t per PT_LOAD segment of an ELF image, offset by the
 * caller-supplied load base.
 *
 * Returns false if the boot region array fills up.
 */
static bool append_elf_segment_regions(mem_region_t *regions,
                                       int *nregions,
                                       const elf_info_t *info,
                                       uint64_t load_base)
{
    for (int i = 0; i < info->num_segments; i++) {
        uint64_t seg_start = info->segments[i].gpa + load_base;
        uint64_t seg_end = seg_start + info->segments[i].memsz;
        if (!append_boot_region(regions, nregions, seg_start, seg_end,
                                elf_pf_to_prot(info->segments[i].flags))) {
            return false;
        }
    }
    return true;
}

/* Register one semantic guest_region_t per PT_LOAD segment of an ELF image.
 * va_load_base controls the guest-visible range, gpa_load_base controls the
 * backing GPA recorded in region metadata, and path is used for /proc/self/maps
 * reporting.
 */
static void register_elf_segment_regions(guest_t *g,
                                         const elf_info_t *info,
                                         uint64_t va_load_base,
                                         uint64_t gpa_load_base,
                                         const char *path)
{
    for (int i = 0; i < info->num_segments; i++) {
        uint64_t seg_start = info->segments[i].gpa + va_load_base;
        uint64_t seg_end = seg_start + info->segments[i].memsz;
        uint64_t seg_gpa = info->segments[i].gpa + gpa_load_base;
        guest_region_add_ex_gpa(g, seg_start, seg_end, seg_gpa,
                                elf_pf_to_prot(info->segments[i].flags),
                                LINUX_MAP_PRIVATE, info->segments[i].offset,
                                path, -1);
    }
}

/* Publish shim, shim-data, heap, stack-guard, and stack regions to
 * /proc/self/maps view, and invalidate the null page and stack-guard PTEs.
 * Shared by guest_bootstrap_prepare and guest_bootstrap_rosetta_post_reset; the
 * caller registers ELF or rosetta segments separately because those differ
 * between aarch64 and rosetta guests.
 */
static void register_runtime_regions(guest_t *g, size_t shim_bin_len)
{
    guest_region_add(g, g->shim_base, g->shim_base + shim_bin_len,
                     LINUX_PROT_READ | LINUX_PROT_EXEC, LINUX_MAP_PRIVATE, 0,
                     "[shim]");

    /* shim_data is mapped privileged-only (AP[2:1]=00) in the page tables; the
     * EL1 shim has full RW but EL0 cannot read or write. Report PROT_NONE in
     * /proc/self/maps so guest tooling treats it as inaccessible, matching what
     * dereferencing the GVA actually does (translation fault -> EL0 SIGSEGV
     * path).
     */
    guest_region_add(g, g->shim_data_base, g->shim_data_base + BLOCK_2MIB,
                     LINUX_PROT_NONE, LINUX_MAP_PRIVATE, 0, "[shim-data]");

    if (g->brk_base < g->brk_current) {
        guest_region_add(g, g->brk_base, g->brk_current,
                         LINUX_PROT_READ | LINUX_PROT_WRITE,
                         LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0, "[heap]");
    }

    guest_invalidate_ptes(g, g->stack_base, g->stack_base + STACK_GUARD_SIZE);
    guest_region_add(g, g->stack_base, g->stack_base + STACK_GUARD_SIZE,
                     LINUX_PROT_NONE, LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                     0, "[stack-guard]");
    guest_region_add(g, g->stack_base + STACK_GUARD_SIZE, g->stack_top,
                     LINUX_PROT_READ | LINUX_PROT_WRITE,
                     LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0, "[stack]");
    guest_invalidate_ptes(g, 0, 0x1000);
}

/* ELF/shim/stack bytes are populated directly in the slab before their page
 * tables become live. Mark their semantic backing regardless of requested
 * permissions: a read-only file segment is still nonzero and must be scrubbed
 * if a later MAP_FIXED lazy-anonymous mapping reuses the same slab block.
 * Synthetic page-table coverage for unallocated mmap space has no semantic
 * region and therefore remains clean.
 */
static void mark_registered_backing_dirty(guest_t *g)
{
    for (int i = 0; i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->end <= r->start)
            continue;
        uint64_t len = r->end - r->start;
        if (r->gpa_base > g->guest_size || len > g->guest_size - r->gpa_base)
            continue;
        guest_dirty_mark_range(g, r->gpa_base, r->gpa_base + len);
    }
}

int guest_bootstrap_probe_elf(const char *elf_path, elf_info_t *info)
{
    memset(info, 0, sizeof(*info));

    FILE *f = fopen(elf_path, "rb");
    if (!f)
        return -1;

    elf64_ehdr_t ehdr;
    size_t nread = fread(&ehdr, 1, sizeof(ehdr), f);
    fclose(f);
    if (nread < sizeof(ehdr))
        return -1;

    if (ehdr.e_ident[0] != ELFMAG0 || ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 || ehdr.e_ident[3] != ELFMAG3)
        return -1;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
        return -1;

    info->e_machine = ehdr.e_machine;
    info->e_type = ehdr.e_type;
    return 0;
}

static void invalidate_exec_segments(const elf_info_t *info,
                                     void *host_base,
                                     uint64_t load_base)
{
    for (int i = 0; i < info->num_segments; i++) {
        if (info->segments[i].flags & PF_X) {
            void *host_addr =
                (uint8_t *) host_base + info->segments[i].gpa + load_base;
            sys_icache_invalidate(host_addr, info->segments[i].memsz);
        }
    }
}

static void log_initial_page_tables(const guest_t *g, uint64_t ttbr0)
{
    uint64_t l0_off = ttbr0 - g->ipa_base;
    uint64_t *l0 = (uint64_t *) ((uint8_t *) g->host_base + l0_off);
    unsigned l0i = (unsigned) (g->ipa_base / (512ULL * 1024 * 1024 * 1024));
    log_debug("L0[%u]=0x%llx", l0i, (unsigned long long) l0[l0i]);

    uint64_t l1_ipa = l0[l0i] & 0xFFFFFFFFF000ULL;
    uint64_t *l1 =
        (uint64_t *) ((uint8_t *) g->host_base + (l1_ipa - g->ipa_base));
    unsigned l1i = (unsigned) ((g->ipa_base % (512ULL * 1024 * 1024 * 1024)) /
                               (1024ULL * 1024 * 1024));
    log_debug("L1[%u]=0x%llx", l1i, (unsigned long long) l1[l1i]);

    uint64_t l2_ipa = l1[l1i] & 0xFFFFFFFFF000ULL;
    uint64_t *l2 =
        (uint64_t *) ((uint8_t *) g->host_base + (l2_ipa - g->ipa_base));
    for (int i = 0; i < 16; i++) {
        if (l2[i])
            log_debug("L2[%d]=0x%llx", i, (unsigned long long) l2[i]);
    }
}

static bool load_interpreter(guest_t *g,
                             const char *sysroot,
                             guest_bootstrap_t *boot)
{
    if (boot->elf_info.interp_path[0] == '\0')
        return true;

    bool interp_host_temp = false;
    char interp_host_candidate[LINUX_PATH_MAX];
    elf_resolve_interp(sysroot, boot->elf_info.interp_path,
                       interp_host_candidate, sizeof(interp_host_candidate));
    if (strcmp(interp_host_candidate, boot->elf_info.interp_path) == 0) {
        path_translation_t tx;
        if (path_translate_at(LINUX_AT_FDCWD, boot->elf_info.interp_path,
                              PATH_TR_NONE, &tx) < 0) {
            log_error("failed to resolve interpreter: %s",
                      boot->elf_info.interp_path);
            return false;
        }
        if (tx.fuse_path) {
            int rc =
                fuse_materialize_path(tx.intercept_path, boot->interp_resolved,
                                      sizeof(boot->interp_resolved));
            if (rc < 0) {
                log_error("failed to materialize interpreter: %s",
                          boot->elf_info.interp_path);
                return false;
            }
            interp_host_temp = true;
        } else if (tx.is_dev_shm) {
            /* A loader in /dev/shm is never legitimate, and elf_load() below
             * opens it by path with no nofollow. Reject outright rather than
             * risk following a symlink leaf onto the host. (The guest is not
             * yet running, so no link can have been planted; a plain reject is
             * race-free, unlike the runtime execve paths.)
             */
            log_error("refusing /dev/shm interpreter: %s",
                      boot->elf_info.interp_path);
            return false;
        } else {
            str_copy_trunc(boot->interp_resolved, tx.host_path,
                           sizeof(boot->interp_resolved));
        }
    } else {
        str_copy_trunc(boot->interp_resolved, interp_host_candidate,
                       sizeof(boot->interp_resolved));
    }
    str_copy_trunc(
        boot->interp_display_path,
        interp_host_temp ? boot->elf_info.interp_path : boot->interp_resolved,
        sizeof(boot->interp_display_path));
    log_debug("loading interpreter: %s", boot->interp_resolved);

    /* One exit from here on. Every step below can fail, and each failure owes
     * the same unlink of a materialized temp; four copies of that is four
     * chances to forget one.
     */
    bool ok = false;

    if (elf_load(boot->interp_resolved, &boot->interp_info) < 0) {
        log_error("failed to load interpreter: %s", boot->interp_resolved);
        goto out;
    }

    if (!elf_interp_is_loadable(&boot->interp_info, boot->interp_resolved))
        goto out;

    boot->interp_base = g->interp_base;
    uint64_t infra_lo, infra_hi;
    guest_infra_window(g, &infra_lo, &infra_hi);
    if (elf_map_segments(&boot->interp_info, boot->interp_resolved,
                         g->host_base, g->guest_size,
                         (elf_window_t) {0, boot->interp_base}, infra_lo,
                         infra_hi) < 0) {
        log_error("failed to map interpreter segments");
        goto out;
    }
    ok = true;

    log_debug(
        "interpreter loaded at base=0x%llx, entry=0x%llx, %d segments",
        (unsigned long long) boot->interp_base,
        (unsigned long long) (boot->interp_info.entry + boot->interp_base),
        boot->interp_info.num_segments);

out:
    if (interp_host_temp)
        unlink(boot->interp_resolved);
    return ok;
}

static bool build_boot_regions(mem_region_t *regions,
                               int *nregions,
                               guest_t *g,
                               const guest_bootstrap_t *boot,
                               size_t shim_bin_len)
{
    /* The vDSO trampolines live in the same 2MiB block as the shim. They must
     * appear in the region set so finalize_block_perms validates and grants RX
     * to the vDSO page when splitting the block; otherwise vdso_build cannot
     * write into it through guest_ptr.
     */
    if (!append_boot_region(regions, nregions, g->shim_base,
                            g->shim_base + shim_bin_len, MEM_PERM_RX) ||

        /* shim_data is EL1-only: the guest must not directly read or write the
         * identity cache, attention flag, urandom bitmap, or ring, any of which
         * would let it spoof its own syscall results. The EL1 shim itself has
         * full RW. /proc/self/maps still lists [shim-data] (region tracking is
         * independent of EL0 access), but EL0 dereferences fault to the SIGSEGV
         * path.
         */
        !append_boot_region(regions, nregions, g->shim_data_base,
                            g->shim_data_base + BLOCK_2MIB,
                            MEM_PERM_RW_EL1_ONLY) ||
        !append_boot_region(regions, nregions, VDSO_BASE, VDSO_BASE + VDSO_SIZE,
                            MEM_PERM_RX)) {
        return false;
    }

    /* Rosetta guests never load the x86_64 ELF or its interpreter into guest
     * memory; rosetta itself reads the target via fd 3 once it is running.
     * Adding those segments to the page-table builder would emit ghost L2/L3
     * entries at the binary's x86_64 link address (typically 0x400000) pointing
     * into uninitialized primary-buffer GPAs. The rosetta image's own segments
     * are registered by rosetta_prepare's separate region append in the
     * bootstrap caller.
     */
    if (!g->is_rosetta) {
        if (!append_elf_segment_regions(regions, nregions, &boot->elf_info,
                                        boot->elf_load_base) ||
            !append_elf_segment_regions(regions, nregions, &boot->interp_info,
                                        boot->interp_base)) {
            return false;
        }
    }

    if (!append_boot_region(regions, nregions, g->brk_base, MMAP_RX_BASE,
                            MEM_PERM_RW) ||
        !append_boot_region(regions, nregions, g->stack_base, g->stack_top,
                            MEM_PERM_RW) ||
        !append_boot_region(regions, nregions, MMAP_RX_BASE,
                            MMAP_RX_INITIAL_END, MEM_PERM_RX) ||
        !append_boot_region(regions, nregions, MMAP_BASE, MMAP_INITIAL_END,
                            MEM_PERM_RW)) {
        return false;
    }

    g->mmap_rx_end = MMAP_RX_INITIAL_END;
    g->mmap_end = MMAP_INITIAL_END;
    return true;
}

int guest_bootstrap_prepare(guest_t *g,
                            const char *elf_host_path,
                            bool elf_host_path_temp,
                            const char *elf_guest_path,
                            const char *sysroot,
                            int guest_argc,
                            const char **guest_argv,
                            char **environ,
                            const unsigned char *shim_bin,
                            size_t shim_bin_len,
                            bool verbose,
                            bool *guest_initialized,
                            guest_bootstrap_t *boot)
{
    mem_region_t regions[MAX_BOOT_REGIONS];
    int nregions = 0;
    uint64_t native_vdso;
    uint64_t t0;

    memset(boot, 0, sizeof(*boot));
    *guest_initialized = false;

    t0 = startup_trace_now_ns();
    if (elf_load(elf_host_path, &boot->elf_info) < 0) {
        log_error("failed to load ELF: %s", elf_host_path);
        return -1;
    }
    startup_trace_step("elf_load", t0);

    bool want_rosetta = false;
    if (boot->elf_info.e_machine == EM_X86_64) {
        if (!proc_rosetta_enabled()) {
            log_error(
                "x86_64 ELF rejected by --no-rosetta "
                "(or ELFUSE_NO_ROSETTA=1): %s",
                elf_guest_path);
            return -1;
        }
        want_rosetta = true;
    } else if (boot->elf_info.e_machine != EM_AARCH64) {
        log_error("unsupported ELF machine type %u", boot->elf_info.e_machine);
        return -1;
    }

    log_debug(
        "ELF entry=0x%llx, %d segments, load range [0x%llx, 0x%llx), "
        "machine=%s",
        (unsigned long long) boot->elf_info.entry, boot->elf_info.num_segments,
        (unsigned long long) boot->elf_info.load_min,
        (unsigned long long) boot->elf_info.load_max,
        want_rosetta ? "x86_64-via-rosetta" : "aarch64");

    /* Rosetta is statically linked at 0x800000000000 (128 TiB), beyond the 36
     * and 40-bit IPA ranges. Request 48-bit IPA up-front so the page-table
     * builder can reach the rosetta segments.
     */
    uint32_t req_ipa = want_rosetta ? 48 : 0;
    t0 = startup_trace_now_ns();
    if (guest_init(g, 0, req_ipa) < 0) {
        log_error("failed to initialize guest");
        return -1;
    }

    startup_trace_step("guest_init", t0);
    *guest_initialized = true;
    g->is_rosetta = want_rosetta;
    proc_set_rosetta_active(want_rosetta);

    log_debug("IPA size: %u bits (%llu GiB primary)", g->ipa_bits,
              (unsigned long long) (g->guest_size / (1024ULL * 1024 * 1024)));

    rosetta_result_t rr;
    memset(&rr, 0, sizeof(rr));

    if (want_rosetta) {
        /* Rosetta path: no x86_64 ELF segments are loaded into guest memory
         * (rosetta itself does that lazily once it starts running). brk and
         * stack use the same defaults the aarch64 path falls back to when the
         * binary sits at low VAs; the x86_64 binary's load_max would be
         * meaningless here because nothing of it actually lives in primary
         * buffer GPA space.
         */
        boot->elf_load_base = 0;
        g->elf_load_min = ELF_DEFAULT_BASE;
        g->brk_base = BRK_BASE_DEFAULT;
        g->brk_current = g->brk_base;
        g->stack_top = STACK_TOP_DEFAULT;
        g->stack_base = g->stack_top - STACK_SIZE;
    } else {
        boot->elf_load_base =
            (boot->elf_info.e_type == ET_DYN) ? PIE_LOAD_BASE : 0;
        t0 = startup_trace_now_ns();
        uint64_t infra_lo, infra_hi;
        guest_infra_window(g, &infra_lo, &infra_hi);

        /* Forbidden from the reserve to the top of the slab: everything from
         * interp_base up is the interpreter's and the runtime's, so an ET_EXEC
         * linked above it must not be placed there.
         */
        if (elf_map_segments(&boot->elf_info, elf_host_path, g->host_base,
                             g->guest_size,
                             (elf_window_t) {0, boot->elf_load_base}, infra_lo,
                             g->guest_size) < 0) {
            log_error("failed to map ELF segments");
            return -1;
        }
        startup_trace_step("elf_map_segments", t0);

        /* Track the lowest loaded ELF address so the legacy fork IPC path
         * copies low-linked ET_EXECs (e.g. linked at 0x200000) in full.
         */
        g->elf_load_min = boot->elf_info.load_min + boot->elf_load_base;

        g->brk_base =
            PAGE_ALIGN_UP(boot->elf_info.load_max + boot->elf_load_base);
        if (g->brk_base < BRK_BASE_DEFAULT)
            g->brk_base = BRK_BASE_DEFAULT;
        g->brk_current = g->brk_base;

        g->stack_top = ALIGN_UP(g->brk_base, BLOCK_2MIB) + STACK_SIZE;
        if (g->stack_top < STACK_TOP_DEFAULT)
            g->stack_top = STACK_TOP_DEFAULT;
        g->stack_base = g->stack_top - STACK_SIZE;

        t0 = startup_trace_now_ns();
        if (!load_interpreter(g, sysroot, boot))
            return -1;
        startup_trace_step("load_interpreter", t0);
    }

    if (shim_bin_len > INFRA_SHIM_SLOT) {
        log_error("shim binary too large (%zu bytes, slot %llu)", shim_bin_len,
                  (unsigned long long) INFRA_SHIM_SLOT);
        return -1;
    }

    t0 = startup_trace_now_ns();
    memcpy((uint8_t *) g->host_base + g->shim_base, shim_bin, shim_bin_len);
    log_debug("shim loaded at offset 0x%llx (%zu bytes)",
              (unsigned long long) g->shim_base, shim_bin_len);

    if (!want_rosetta) {
        invalidate_exec_segments(&boot->elf_info, g->host_base,
                                 boot->elf_load_base);
        invalidate_exec_segments(&boot->interp_info, g->host_base,
                                 boot->interp_base);
    }
    sys_icache_invalidate((uint8_t *) g->host_base + g->shim_base,
                          shim_bin_len);
    startup_trace_step("shim_load_icache", t0);

    t0 = startup_trace_now_ns();
    if (!build_boot_regions(regions, &nregions, g, boot, shim_bin_len)) {
        log_error("too many memory regions (%d >= %d)", nregions,
                  MAX_BOOT_REGIONS);
        return -1;
    }
    startup_trace_step("build_boot_regions", t0);

    /* Rosetta path: append the rosetta image as a non-identity region so the
     * page-table builder maps VA 0x800000000000 -> primary buffer GPA.
     * rosetta_prepare also initialises the TTBR1 kbuf (page-table pages come
     * from the same pool that guest_build_page_tables is about to consume).
     */
    if (want_rosetta) {
        t0 = startup_trace_now_ns();
        if (rosetta_prepare(g, elf_host_path, regions, &nregions,
                            MAX_BOOT_REGIONS, verbose, &rr) < 0) {
            log_error("rosetta_prepare failed for %s", elf_guest_path);
            return -1;
        }
        startup_trace_step("rosetta_prepare", t0);
    }

    t0 = startup_trace_now_ns();
    boot->ttbr0 = guest_build_page_tables(g, regions, nregions);
    if (!boot->ttbr0) {
        log_error("failed to build page tables");
        return -1;
    }
    startup_trace_step("guest_build_page_tables", t0);

    /* No TLBI request here: the shim's _start does TLBI VMALLE1IS before
     * enabling the MMU (src/core/shim.S), and the per-vCPU accumulator is the
     * wrong place to stage a bring-up flush -- bootstrap may run on a thread
     * whose slot is later consumed by an unrelated syscall.
     */

    t0 = startup_trace_now_ns();
    if (want_rosetta) {
        /* /proc/self/maps for a rosetta guest reports the rosetta translator as
         * a single anonymous region covering [VA, VA+size). The original x86_64
         * binary is not loaded into guest memory; rosetta exposes it via the
         * guest fd rosetta_finalize pre-opens (published as AT_EXECFD).
         */
        register_elf_segment_regions(g, &rr.rosetta_info, 0,
                                     g->rosetta_guest_base - g->rosetta_va_base,
                                     ROSETTA_PATH);
    } else {
        char elf_realpath[LINUX_PATH_MAX];

        memset(elf_realpath, 0, sizeof(elf_realpath));
        if (elf_host_path_temp)
            str_copy_trunc(elf_realpath, elf_guest_path, sizeof(elf_realpath));
        else if (!realpath(elf_host_path, elf_realpath))
            str_copy_trunc(elf_realpath, elf_host_path, sizeof(elf_realpath));

        register_elf_segment_regions(g, &boot->elf_info, boot->elf_load_base,
                                     boot->elf_load_base, elf_realpath);
        register_elf_segment_regions(g, &boot->interp_info, boot->interp_base,
                                     boot->interp_base,
                                     boot->interp_display_path);
    }

    register_runtime_regions(g, shim_bin_len);
    mark_registered_backing_dirty(g);
    startup_trace_step("register_regions", t0);

    log_debug("TTBR0=0x%llx, IPA base=0x%llx", (unsigned long long) boot->ttbr0,
              (unsigned long long) g->ipa_base);
    if (verbose)
        log_initial_page_tables(g, boot->ttbr0);

    t0 = startup_trace_now_ns();
    syscall_init();
    proc_init();

    {
        char self_path[LINUX_PATH_MAX];
        uint32_t path_len = sizeof(self_path);

        if (_NSGetExecutablePath(self_path, &path_len) == 0)
            proc_set_elfuse_path(self_path);
    }

    proc_set_shim(shim_bin, (unsigned int) shim_bin_len);
    proc_set_elf_path(elf_guest_path);
    if (sysroot)
        proc_set_sysroot(sysroot);
    startup_trace_step("runtime_init", t0);

    /* rosetta_finalize pre-opens the x86_64 binary at the lowest free guest fd
     * >= 3 (published as AT_EXECFD), constructs the binfmt_misc argv
     * ([ROSETTA_PATH, binary, original_argv[1..]]), refreshes
     * /proc/self/cmdline, and installs the TTBR0 kbuf alias. The aarch64 path
     * uses the caller's argv directly. The remaining Rosetta runtime blocker is
     * high-VA mmap support for the translator's own slab and JIT allocations.
     */
    int rosetta_argc = 0;
    const char **rosetta_argv = NULL;
    int rosetta_execfd = -1;
    if (want_rosetta) {
        t0 = startup_trace_now_ns();
        if (rosetta_finalize(g, 0, elf_host_path, elf_host_path_temp,
                             elf_guest_path, guest_argc, guest_argv, &rr,
                             verbose, &rosetta_argc, &rosetta_argv, NULL,
                             &rosetta_execfd) < 0) {
            log_error("rosetta_finalize failed");
            return -1;
        }
        startup_trace_step("rosetta_finalize", t0);
    } else {
        proc_set_cmdline(guest_argc, guest_argv);
    }
    proc_set_environ((const char **) environ);

    t0 = startup_trace_now_ns();
    native_vdso = vdso_build(g);
    startup_trace_step("vdso_build", t0);
    linux_stack_auxv_t auxv;
    const elf_info_t *stack_elf =
        want_rosetta ? &rr.rosetta_info : &boot->elf_info;
    uint64_t stack_elf_load_base = want_rosetta ? 0 : boot->elf_load_base;
    uint64_t stack_interp_base = want_rosetta ? 0 : boot->interp_base;
    int stack_argc = want_rosetta ? rosetta_argc : guest_argc;
    const char **stack_argv = want_rosetta ? rosetta_argv : guest_argv;
    t0 = startup_trace_now_ns();
    boot->stack_pointer = build_linux_stack(
        g, g->stack_top, stack_argc, stack_argv, (const char **) environ,
        stack_elf, stack_elf_load_base, stack_interp_base, native_vdso,
        rosetta_execfd, elf_guest_path, &auxv);
    if (boot->stack_pointer == 0) {
        log_error("failed to build initial stack");
        free(rosetta_argv);
        return -1;
    }
    g->start_stack = boot->stack_pointer;
    startup_trace_step("build_linux_stack", t0);

    /* rosetta_argv was copied into the guest stack; the host allocation is no
     * longer needed. The strings themselves are constants (ROSETTA_PATH) or
     * owned by the caller (binary_path, guest_argv entries) so freeing just the
     * array is safe.
     */
    free(rosetta_argv);

    proc_set_auxv(auxv.words, auxv.nwords * sizeof(auxv.words[0]));
    if (want_rosetta) {
        boot->entry_point = rr.entry_point;
    } else {
        boot->entry_point = (boot->interp_base != 0)
                                ? (boot->interp_info.entry + boot->interp_base)
                                : (boot->elf_info.entry + boot->elf_load_base);
    }

    const char *entry_via = "";
    if (want_rosetta)
        entry_via = " (via rosetta)";
    else if (boot->interp_base)
        entry_via = " (via interpreter)";
    log_debug("SP=0x%llx, entry=0x%llx%s",
              (unsigned long long) boot->stack_pointer,
              (unsigned long long) boot->entry_point, entry_via);
    return 0;
}

int guest_bootstrap_create_vcpu(guest_t *g,
                                const guest_bootstrap_t *boot,
                                bool verbose,
                                hv_vcpu_t *out_vcpu,
                                hv_vcpu_exit_t **out_vexit)
{
    uint64_t sctlr;
    uint64_t sctlr_with_mmu;
    uint64_t t0;

    /* Rosetta needs TTBR1 walks enabled and TBI1=1 so the kbuf window at
     * KBUF_VA_BASE (bits-63-set) resolves and TaggedPointer extraction keeps
     * working. Aarch64 guests stay on the EPD1=1 variant which keeps the upper
     * VA range fault-clean.
     */
    uint64_t tcr_value = g->is_rosetta ? TCR_EL1_VALUE_KBUF : TCR_EL1_VALUE;
    uint64_t ttbr1_value = g->is_rosetta ? g->ttbr1 : 0;
    uint64_t shim_ipa = guest_ipa(g, g->shim_base);
    uint64_t entry_ipa = guest_ipa(g, boot->entry_point);
    uint64_t sp_ipa = guest_ipa(g, boot->stack_pointer);
    uint64_t el1_sp = guest_ipa(g, g->shim_data_base + BLOCK_2MIB);
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vexit;

    t0 = startup_trace_now_ns();
    HV_CHECK(hv_vcpu_create(&vcpu, &vexit, NULL));
    startup_trace_step("hv_vcpu_create", t0);
    g->vcpu = vcpu;
    g->vcpu_valid = true;
    g->exit = vexit;
    *out_vcpu = vcpu;
    *out_vexit = vexit;

    thread_register_main(vcpu, vexit, proc_get_pid(), el1_sp);

    t0 = startup_trace_now_ns();
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_VBAR_EL1, shim_ipa + 0x800));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, 0xFF00));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr_value));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, boot->ttbr0));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, ttbr1_value));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, 3ULL << 20));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, entry_ipa));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, 0x0));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, sp_ipa));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, el1_sp));

    /* Round-trip a sentinel through TPIDR_EL1 before installing the real value.
     * Validates only the hv_vcpu_{set,get}_sys_reg pre-run round trip, not
     * preservation across hv_vcpu_run -- the test-shim-identity microbench is
     * the end-to-end check for that.
     */
    if (shim_globals_self_test(vcpu) < 0)
        return -1;

    /* TPIDR_EL1 -> shim_globals base, CONTEXTIDR_EL1 -> tid (== pid for the
     * initial main thread). gettid fast path reads CONTEXTIDR_EL1 directly.
     */
    if (shim_globals_install_per_vcpu(vcpu, g, proc_get_pid()) < 0)
        return -1;

    /* Zero the shim-globals region and publish the initial identity so the very
     * first getpid / getuid / etc. SVC #0 hits the cache instead of returning
     * the all-zero seed. Future setuid/setgid paths refresh creds via
     * cred_publish_after; fork-child has its own publish on the inherited
     * identity.
     */
    shim_globals_init(g);
    shim_globals_publish_stats_gate(g);
    shim_globals_set_trace_enabled(g, verbose);
    shim_globals_publish_pid(g, proc_get_pid(), proc_get_ppid());
    shim_globals_publish_creds(g, proc_get_uid(), proc_get_euid(),
                               proc_get_gid(), proc_get_egid());
    proc_publish_pgsid_snapshot(g);

    /* Pre-fill the entropy ring so the first read(/dev/urandom) from the guest
     * is served by the shim fast path with no cold-start HVC for refill.
     */
    shim_globals_refill_urandom_ring(g);

    /* Register the singleton guest pointer so signal_queue and the itimer
     * setters can raise the attention flag without threading g through every
     * call site. signal_init clears this defensively; the first registration
     * must run after both proc_init and shim_globals_init.
     */
    signal_set_shim_globals_guest(g);

    /* Same singleton pattern but for the fd-table hooks that update the urandom
     * bitmap. Must run before any FD_URANDOM-typed slot is allocated; bootstrap
     * finishes before any guest syscall runs.
     */
    shim_globals_set_singleton(g);

    /* Publish the main vCPU's first arena only after shim_globals_init has
     * cleared every recycled control slot. Verbose tracing keeps all shim
     * syscall fast paths on HVC so the trace remains complete.
     */
    if (!verbose)
        mmap_fastpath_prepare_vcpu(g, current_thread);

    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTKCTL_EL1,
                                 CNTKCTL_EL1_EL0_TIMER_EN));

    HV_CHECK(hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, &sctlr));
    log_debug("SCTLR_EL1 default=0x%llx", (unsigned long long) sctlr);

    sctlr = SCTLR_RES1 | SCTLR_C | SCTLR_I | SCTLR_DZE | SCTLR_UCT | SCTLR_UCI;
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, sctlr));

    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_PC, shim_ipa));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5));
    vcpu_zero_gprs(vcpu);

    sctlr_with_mmu = SCTLR_RES1 | SCTLR_M | SCTLR_C | SCTLR_I | SCTLR_DZE |
                     SCTLR_UCT | SCTLR_UCI;
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_X0, sctlr_with_mmu));
    startup_trace_step("hv_vcpu_configure", t0);

    log_debug(
        "vCPU configured: PC=0x%llx SCTLR=0x%llx VBAR=0x%llx TTBR0=0x%llx "
        "TCR=0x%llx",
        (unsigned long long) shim_ipa, (unsigned long long) sctlr,
        (unsigned long long) (shim_ipa + 0x800),
        (unsigned long long) boot->ttbr0, (unsigned long long) tcr_value);
    log_debug("ELR_EL1=0x%llx SP_EL0=0x%llx SP_EL1=0x%llx",
              (unsigned long long) entry_ipa, (unsigned long long) sp_ipa,
              (unsigned long long) el1_sp);

    if (verbose)
        log_debug("main thread registered with SP_EL1=0x%llx",
                  (unsigned long long) el1_sp);

    /* guest_build_page_tables and the bootstrap-time guest_invalidate_ptes
     * calls (stack guard, null page, etc.) accumulate TLBI requests on this
     * (the main) thread's cpu_tlbi_req TLS slot. The shim's _start does TLBI
     * VMALLE1IS before enabling the MMU, so any TLB state was already dropped
     * before guest code runs. Clear the accumulator so the first guest syscall
     * does not redundantly broadcast on top of that.
     */
    tlbi_request_clear();

    return 0;
}

int guest_bootstrap_rosetta_post_reset(guest_t *g,
                                       const char *elf_host_path,
                                       bool elf_host_path_temp,
                                       const char *elf_guest_path,
                                       int guest_argc,
                                       const char **guest_argv,
                                       char **environ,
                                       size_t shim_bin_len,
                                       bool verbose,
                                       uint64_t *out_entry_point,
                                       uint64_t *out_stack_pointer,
                                       uint64_t *out_ttbr0)
{
    if (!g || !elf_host_path || !elf_guest_path || !out_entry_point ||
        !out_stack_pointer || !out_ttbr0)
        return -1;

    /* Re-anchor brk/stack to the Rosetta defaults. guest_reset already restored
     * mmap_next/mmap_end/mmap_rx_* to their initial values, but brk/stack were
     * tuned for the previous image, so reset them here. The x86_64 target
     * binary lives behind fd 3, not in guest memory, so brk_base does not move
     * with the target's load_max.
     */
    g->elf_load_min = ELF_DEFAULT_BASE;
    g->brk_base = BRK_BASE_DEFAULT;
    g->brk_current = g->brk_base;
    g->stack_top = STACK_TOP_DEFAULT;
    g->stack_base = g->stack_top - STACK_SIZE;

    mem_region_t regions[MAX_BOOT_REGIONS];
    int nregions = 0;
    rosetta_result_t rr;
    if (rosetta_prepare(g, elf_host_path, regions, &nregions, MAX_BOOT_REGIONS,
                        verbose, &rr) < 0) {
        log_error("rosetta_prepare failed during exec re-bootstrap");
        return -1;
    }

    /* build_boot_regions skips ELF segments when g->is_rosetta is set, so a
     * zero-initialized guest_bootstrap_t is enough to drive it here.
     */
    guest_bootstrap_t boot_stub;
    memset(&boot_stub, 0, sizeof(boot_stub));
    if (!build_boot_regions(regions, &nregions, g, &boot_stub, shim_bin_len)) {
        log_error("too many boot regions for rosetta exec re-bootstrap");
        return -1;
    }

    uint64_t ttbr0 = guest_build_page_tables(g, regions, nregions);
    if (!ttbr0) {
        log_error(
            "guest_build_page_tables failed in rosetta exec re-bootstrap");
        return -1;
    }
    g->ttbr0 = ttbr0;

    /* Re-publish /proc/self/maps style metadata. Mirrors the bootstrap path so
     * the post-exec view reports rosetta-as-anonymous-mapping plus the heap,
     * stack, stack-guard, shim, and shim-data.
     */
    register_elf_segment_regions(g, &rr.rosetta_info, 0,
                                 g->rosetta_guest_base - g->rosetta_va_base,
                                 ROSETTA_PATH);
    register_runtime_regions(g, shim_bin_len);
    mark_registered_backing_dirty(g);

    int rosetta_argc = 0;
    const char **rosetta_argv = NULL;
    int rosetta_execfd = -1;
    if (rosetta_finalize(g, 0, elf_host_path, elf_host_path_temp,
                         elf_guest_path, guest_argc, guest_argv, &rr, verbose,
                         &rosetta_argc, &rosetta_argv, NULL,
                         &rosetta_execfd) < 0) {
        log_error("rosetta_finalize failed during exec re-bootstrap");
        return -1;
    }

    proc_set_elf_path(elf_guest_path);
    proc_set_environ((const char **) environ);

    uint64_t native_vdso = vdso_build(g);
    linux_stack_auxv_t auxv;
    uint64_t sp =
        build_linux_stack(g, g->stack_top, rosetta_argc, rosetta_argv,
                          (const char **) environ, &rr.rosetta_info, 0, 0,
                          native_vdso, rosetta_execfd, elf_guest_path, &auxv);
    free(rosetta_argv);
    if (sp == 0) {
        log_error("build_linux_stack failed during exec re-bootstrap");
        return -1;
    }
    g->start_stack = sp;
    proc_set_auxv(auxv.words, auxv.nwords * sizeof(auxv.words[0]));

    *out_entry_point = rr.entry_point;
    *out_stack_pointer = sp;
    *out_ttbr0 = ttbr0;
    return 0;
}
