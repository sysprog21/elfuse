/* Guest memory management
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Identity-mapped guest memory: GVA == GPA == offset into host_base. The guest
 * address space size is determined by the VM's configured IPA width (capped at
 * 40-bit = 1TiB): 64GiB for native aarch64 on M2 (36-bit), 1TiB for M3+
 * (40-bit). Reserved via mmap(MAP_ANON); macOS demand-pages physical memory on
 * first touch, so only used pages consume RAM. The slab is mapped RWX to
 * Hypervisor.framework. The guest's own page tables (built here) enforce
 * per-region permissions using 2MiB block descriptors, which are mandatory for
 * transparent misaligned access. Page tables can be extended at runtime via
 * guest_extend_page_tables().
 *
 * PROT_NONE mappings in the primary address space (used by managed runtimes for
 * heap reservation) do NOT get page table entries; the translation fault is the
 * correct behavior. When mprotect changes an accessible region to PROT_NONE,
 * guest_invalidate_ptes() removes existing page table entries. Page tables are
 * created on demand when mprotect changes PROT_NONE to an accessible
 * permission.
 *
 * Page table format: AArch64 4KiB granule, up to 4-level:
 *   L0 entry covers 512GiB: multiple entries for >512GiB address spaces
 *   L1 entry covers 1GiB:   either block or table pointing to L2
 *   L2 entry covers 2MiB:   block descriptors with final permissions
 *   L3 entry covers 4KiB:   optional, created by guest_split_block() for mixed
 *                           permissions within a 2MiB block (W^X)
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "core/guest.h"
#include "core/startup-trace.h"
#include "debug/log.h"
#include "utils.h"
#include "runtime/futex.h"  /* futex_interrupt_request */
#include "runtime/thread.h" /* thread_destroy_all_vcpus */
#include "syscall/poll.h"   /* wakeup_pipe_signal */
#include "syscall/proc.h"   /* proc_request_exit_group */

/* Per-vCPU pending TLBI request. Zero-initialized in every host pthread by
 * virtue of TLS default-zeroing, which maps to TLBI_NONE.
 */
_Thread_local tlbi_request_t cpu_tlbi_req;

/* FEAT_TLBIRANGE host capability flag. Set once at bootstrap by
 * guest_probe_tlbi_range and treated as read-only thereafter. Apple Silicon M1+
 * implements ARMv8.5-A which mandates FEAT_TLBIRANGE; the probe stays
 * conservative and defaults to false until the flag is explicitly set so future
 * ports to non-Apple aarch64 hosts inherit the safe fallback.
 */
bool g_tlbi_range_supported = false;

static void guest_region_clear(guest_t *g);

/* Page table descriptor bits. */
#define PT_VALID (1ULL << 0)
#define PT_TABLE (1ULL << 1)     /* Table descriptor (L0/L1/L2) */
#define PT_BLOCK (1ULL << 0)     /* Block descriptor (L1/L2): valid bit only */
#define PT_AF (1ULL << 10)       /* Access Flag */
#define PT_SH_ISH (3ULL << 8)    /* Inner Shareable */
#define PT_NS (1ULL << 5)        /* Non-Secure */
#define PT_ATTR1 (1ULL << 2)     /* MAIR index 1: Normal WB cacheable */
#define PT_UXN (1ULL << 54)      /* Unprivileged Execute Never */
#define PT_PXN (1ULL << 53)      /* Privileged Execute Never */
#define PT_AP_RW_EL0 (1ULL << 6) /* AP[2:1]=01: RW at EL1, RW at EL0 */
#define PT_AP_RW_EL1 (0ULL << 6) /* AP[2:1]=00: RW at EL1, no access EL0 */
#define PT_AP_RO (3ULL << 6)     /* AP[2:1]=11: RO at EL1, RO at EL0 */

/* PAGE_SIZE / ALIGN_2MB_* live in utils.h; BLOCK_2MIB lives in core/guest.h. */
#define PAGE_SIZE GUEST_PAGE_SIZE
#define BLOCK_1GIB (1ULL * 1024 * 1024 * 1024)

/* Mask to extract the physical address from a 2MiB L2 block descriptor */
#define L2_BLOCK_ADDR_MASK 0xFFFFFFE00000ULL

/* Forward declaration (defined in the page table section below) */
static int desc_to_perms(uint64_t desc);

/* Page table pool allocator. */

/* Protects the page table pool bump allocator. Multiple threads may trigger
 * page table extension concurrently (via mmap/brk/mprotect).
 */
static pthread_mutex_t pt_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 2 */

/* Track whether the 80% warning has been emitted (avoid log spam) */
static bool pt_pool_warned = false;

static size_t guest_host_page_size_cached(void)
{
    static size_t cached;
    if (!cached) {
        long s = sysconf(_SC_PAGESIZE);
        cached = (s > 0) ? (size_t) s : GUEST_PAGE_SIZE;
    }
    return cached;
}

static void guest_region_clear_overlay(guest_region_t *r)
{
    r->overlay_active = false;
    r->overlay_start = 0;
    r->overlay_end = 0;
}

static void guest_region_clip_overlay(guest_region_t *r)
{
    if (!r->overlay_active || r->end <= r->start) {
        guest_region_clear_overlay(r);
        return;
    }

    size_t hps = guest_host_page_size_cached();
    uint64_t page_start = ALIGN_DOWN(r->start, hps);
    uint64_t page_end = ALIGN_UP(r->end, hps);
    uint64_t overlay_start =
        r->overlay_start > page_start ? r->overlay_start : page_start;
    uint64_t overlay_end =
        r->overlay_end < page_end ? r->overlay_end : page_end;

    if (overlay_end <= overlay_start) {
        guest_region_clear_overlay(r);
        return;
    }

    r->overlay_start = overlay_start;
    r->overlay_end = overlay_end;
}

/* Compute infra reserve placement from guest_size and store derived fields in
 * @g. Called from guest_init and guest_init_from_shm.
 *
 * Layout: a 16MiB region anchored at [interp_base - INFRA_RESERVE, interp_base)
 * sits in the dead zone between mmap_limit and interp_base. PT pool, shim, and
 * shim data fall at fixed offsets within the reserve (see guest.h).
 *
 * Returns 0 on success, -1 if the layout cannot be derived (interp_base too
 * small to fit the reserve). Today guest_init enforces a 64GiB minimum so the
 * underflow path is unreachable, but the explicit check guards future
 * configurations and any IPC restore that bypasses size selection.
 */
static int compute_infra_layout(guest_t *g)
{
    if (g->interp_base < INFRA_RESERVE) {
        log_error(
            "guest: interp_base 0x%llx smaller than INFRA_RESERVE (0x%llx); "
            "guest_size too small",
            (unsigned long long) g->interp_base,
            (unsigned long long) INFRA_RESERVE);
        return -1;
    }
    uint64_t infra_base = g->interp_base - INFRA_RESERVE;
    g->pt_pool_base = infra_base + INFRA_PT_POOL_OFF;
    g->pt_pool_end = infra_base + INFRA_PT_POOL_END_OFF;
    g->shim_base = infra_base + INFRA_SHIM_OFF;
    g->shim_data_base = infra_base + INFRA_SHIM_DATA_OFF;
    return 0;
}

/* Allocate a zeroed 4KiB page from the page table pool.
 * Returns GPA of the page, or 0 on pool exhaustion. Acquires pt_lock
 * internally. Caller typically holds mmap_lock.
 */
static uint64_t pt_alloc_page(guest_t *g)
{
    pthread_mutex_lock(&pt_lock);
    if (g->pt_pool_next + PAGE_SIZE > g->pt_pool_end) {
        log_error(
            "guest: page table pool exhausted "
            "(used %llu / %llu bytes)",
            (unsigned long long) (g->pt_pool_next - g->pt_pool_base),
            (unsigned long long) (g->pt_pool_end - g->pt_pool_base));
        pthread_mutex_unlock(&pt_lock);
        return 0;
    }
    uint64_t gpa = g->pt_pool_next;
    g->pt_pool_next += PAGE_SIZE;

    /* Warn at 80% pool usage so users can anticipate exhaustion */
    uint64_t used = gpa + PAGE_SIZE - g->pt_pool_base;
    uint64_t total = g->pt_pool_end - g->pt_pool_base;
    if (!pt_pool_warned && used > (total * 4 / 5)) {
        log_debug(
            "guest: page table pool at %llu%% "
            "(%llu / %llu bytes)",
            (unsigned long long) (used * 100 / total),
            (unsigned long long) used, (unsigned long long) total);
        pt_pool_warned = true;
    }

    /* Zero the page while still holding the lock so no other thread can observe
     * a partially-zeroed page table page.
     */
    memset((uint8_t *) g->host_base + gpa, 0, PAGE_SIZE);
    pthread_mutex_unlock(&pt_lock);
    return gpa;
}

/* Get host pointer to a page table entry array at a given GPA */
static uint64_t *pt_at(const guest_t *g, uint64_t gpa)
{
    return (uint64_t *) ((uint8_t *) g->host_base + gpa);
}

/* Public API */

/* FEAT_TLBIRANGE probe -- runs exactly once via pthread_once. ARMv8.4
 * introduced TLBI RVAE1IS for single-shot range invalidation; ARMv8.5+ makes it
 * mandatory. macOS does not surface a sysctl entry for FEAT_TLBIRANGE directly,
 * so use FEAT_LSE2 as a proxy -- both became mandatory in ARMv8.4 and Apple
 * ships them together across the entire M-series. A future non-Apple aarch64
 * host or an older ARM PE without FEAT_TLBIRANGE would otherwise trap the
 * shim's TLBI RVAE1IS, X9 to BAD_VEC; the proxy probe keeps the accumulator on
 * the per-page VAE1IS / VMALLE1IS path in that case.
 *
 * Width-tolerant read: macOS currently exposes the boolean as a 4-byte int, but
 * a future kernel could widen it to uint64_t. Read into a 64-bit slot and
 * accept any non-zero answer for any length sysctl actually returned.
 *
 * ELFUSE_DISABLE_TLBI_RANGE=1 forces the broadcast fallback so the VAE1IS-only
 * / VMALLE1IS path stays exercisable in CI on Apple Silicon -- otherwise the
 * fallback is unreachable on any host where the sysctl probe succeeds.
 *
 * pthread_once gates the probe so a re-bootstrap path (sys_execve, fork IPC
 * restore) cannot race a live vCPU reading the flag. The first guest_init wins
 * and the result is immutable for the process lifetime.
 */
static pthread_once_t tlbi_range_probe_once = PTHREAD_ONCE_INIT;

static void tlbi_range_probe_run(void)
{
    const char *disable_env = getenv("ELFUSE_DISABLE_TLBI_RANGE");
    if (disable_env && disable_env[0] && disable_env[0] != '0') {
        g_tlbi_range_supported = false;
        return;
    }
    uint64_t lse2_raw = 0;
    size_t lse2_len = sizeof(lse2_raw);
    g_tlbi_range_supported =
        (sysctlbyname("hw.optional.arm.FEAT_LSE2", &lse2_raw, &lse2_len, NULL,
                      0) == 0) &&
        lse2_raw != 0;
}

int guest_init(guest_t *g, uint64_t size, uint32_t ipa_bits)
{
    uint64_t t0;

    pthread_once(&tlbi_range_probe_once, tlbi_range_probe_run);

    memset(g, 0, sizeof(*g));
    g->shm_fd = -1;
    g->ipa_base = GUEST_IPA_BASE;
    g->elf_load_min = ELF_DEFAULT_BASE;
    g->brk_base = BRK_BASE_DEFAULT;
    g->brk_current = BRK_BASE_DEFAULT;
    g->mmap_next = MMAP_BASE;
    g->mmap_rx_next = MMAP_RX_BASE;

    /* Query the maximum IPA size supported by the hardware/kernel. macOS 15+ on
     * Apple Silicon reports 40 bits (1TiB). Older versions or fallback yields
     * 36 bits (64GiB).
     */
    uint32_t max_ipa = 0;
    hv_vm_config_get_max_ipa_size(&max_ipa);
    if (max_ipa < 36)
        max_ipa = 36;

    /* Determine VM IPA width: the Stage-2 width passed to
     * hv_vm_config_set_ipa_size. Distinct from the primary slab size below
     * because Rosetta needs 48-bit guest VAs (image at 128 TiB) even when HVF
     * rejects a 1 TiB Stage-2 mapping.
     *
     * ipa_bits = 0 : auto-detect (40-bit on macOS 15+, else 36-bit). ipa_bits >
     * 0 : use that exact value.
     */
    uint32_t vm_ipa;
    if (ipa_bits > 0)
        vm_ipa = ipa_bits;
    else if (max_ipa >= 40)
        vm_ipa = 40;
    else
        vm_ipa = 36;
    g->ipa_bits = vm_ipa;

    /* Primary slab size is decoupled from the VM IPA width. The slab is what
     * gets mmap'd and what hv_vm_map maps; some Apple Silicon hosts (including
     * M5 in field reports) reject a 1 TiB primary slab with HV_BAD_ARGUMENT
     * even when max_ipa >= 40, so a bisecting retry from 40-bit (1 TiB) down to
     * 36-bit (64 GiB) is necessary.
     */
    uint32_t initial_slab_bits = (max_ipa > 40) ? 40 : max_ipa;
    if (initial_slab_bits < 36)
        initial_slab_bits = 36;

    /* Create the HVF VM once at the requested IPA width. The slab retry loop
     * below remaps within this VM; only the slab side resizes.
     *
     * macOS may not release HVF VM resources immediately after hv_vm_destroy(),
     * so rapid sequential VM creation (e.g. running many test binaries) can hit
     * transient resource exhaustion. Retry with linear backoff (500ms
     * intervals, up to 30 attempts = 15 seconds max wait) to handle this
     * gracefully.
     */
    hv_return_t ret = HV_ERROR;
    t0 = startup_trace_now_ns();
    for (int attempt = 0; attempt < 30; attempt++) {
        hv_vm_config_t config = hv_vm_config_create();
        hv_vm_config_set_ipa_size(config, vm_ipa);
        ret = hv_vm_create(config);
        os_release(config);
        if (ret == HV_SUCCESS)
            break;
        usleep(500000); /* 500ms between attempts */
    }
    startup_trace_step("hv_vm_create", t0);
    if (ret != HV_SUCCESS) {
        log_error("guest: hv_vm_create failed: %d (ipa_bits=%u)", (int) ret,
                  vm_ipa);
        return -1;
    }

    /* Bisecting slab retry: try the largest slab first, halve on each failure
     * down to a known-safe 64 GiB floor. The shm_fd CoW upgrade is attempted on
     * every successful slab so file-backed memory is preserved at any size HVF
     * accepts.
     */
    static const uint32_t slab_attempt_bits[] = {40, 38, 36};
    bool mapped = false;
    size_t mapped_size = 0;
    for (size_t i = 0;
         i < sizeof(slab_attempt_bits) / sizeof(slab_attempt_bits[0]); i++) {
        uint32_t bits = slab_attempt_bits[i];
        if (bits > initial_slab_bits)
            continue;

        uint64_t try_size = 1ULL << bits;
        /* Respect a caller-supplied size cap (size > 0 means "no larger than
         * this"). Skip slab attempts that exceed the cap.
         */
        if (size > 0 && try_size > size)
            continue;

        /* Re-derive the layout for this slab size. */
        g->guest_size = try_size;
        g->interp_base = try_size - 0x100000000ULL;
        g->mmap_limit = try_size - 0x200000000ULL;
        g->overflow_ipa_next = try_size;
        if (compute_infra_layout(g) < 0)
            continue;
        g->pt_pool_next = g->pt_pool_base;

        /* Reserve primary address space via mmap(MAP_ANON). macOS demand-pages
         * this so an unused 1 TiB reservation costs no physical memory. Do NOT
         * memset because that would touch every page and defeat demand paging.
         */
        t0 = startup_trace_now_ns();
        g->host_base = mmap(NULL, try_size, PROT_READ | PROT_WRITE,
                            MAP_ANON | MAP_PRIVATE, -1, 0);
        startup_trace_step("primary_mmap", t0);
        if (g->host_base == MAP_FAILED) {
            perror("guest: mmap");
            g->host_base = NULL;
            continue;
        }

        /* Try the file-backed CoW upgrade. If any step fails, fall back
         * silently to MAP_ANON; fork will then use the IPC region-copy path
         * instead of SCM_RIGHTS fd passing.
         */
        char tmppath[] = "/tmp/elfuse-XXXXXX";
        t0 = startup_trace_now_ns();
        int sfd = mkstemp(tmppath);
        if (sfd >= 0) {
            unlink(tmppath); /* Unlink immediately; fd keeps file alive */
            if (ftruncate(sfd, (off_t) try_size) == 0) {
                void *p = mmap(g->host_base, try_size, PROT_READ | PROT_WRITE,
                               MAP_SHARED | MAP_FIXED, sfd, 0);
                if (p != MAP_FAILED) {
                    g->shm_fd = sfd;
                } else {
                    close(sfd);
                }
            } else {
                close(sfd);
            }
        }
        startup_trace_step("cow_shm_upgrade", t0);

        t0 = startup_trace_now_ns();
        ret = hv_vm_map(g->host_base, GUEST_IPA_BASE, try_size,
                        HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
        startup_trace_step("hv_vm_map", t0);
        if (ret == HV_SUCCESS) {
            mapped_size = try_size;
            mapped = true;
            log_info("guest: primary slab %u GiB (%u-bit) mapped",
                     (unsigned) (try_size >> 30), bits);
            break;
        }

        log_info("guest: hv_vm_map %u GiB failed (%d), trying smaller slab",
                 (unsigned) (try_size >> 30), (int) ret);
        if (g->shm_fd >= 0) {
            close(g->shm_fd);
            g->shm_fd = -1;
        }
        munmap(g->host_base, try_size);
        g->host_base = NULL;
    }

    if (!mapped) {
        log_error(
            "guest: hv_vm_map failed at every attempted slab size "
            "(start=%u-bit, floor=36-bit)",
            initial_slab_bits);
        hv_vm_destroy();
        return -1;
    }
    size = mapped_size;

    /* Seed HVF segment list with one entry covering the whole slab. sys_mmap
     * may later split this for MAP_SHARED file overlays.
     */
    g->segments[0] = (hvf_segment_t) {.ipa = GUEST_IPA_BASE, .len = size};
    g->n_segments = 1;

    return 0;
}

int guest_init_from_shm(guest_t *g,
                        int shm_fd,
                        uint64_t size,
                        uint32_t ipa_bits)
{
    uint64_t t0;

    memset(g, 0, sizeof(*g));
    g->shm_fd = -1; /* Child does not own the shm */
    g->ipa_base = GUEST_IPA_BASE;
    g->elf_load_min = ELF_DEFAULT_BASE;
    g->brk_base = BRK_BASE_DEFAULT;
    g->brk_current = BRK_BASE_DEFAULT;
    g->mmap_next = MMAP_BASE;
    g->mmap_rx_next = MMAP_RX_BASE;
    g->guest_size = size;
    g->ipa_bits = ipa_bits;

    /* Compute layout limits (same formula as guest_init) */
    g->interp_base = size - 0x100000000ULL;
    g->mmap_limit = size - 0x200000000ULL;
    g->overflow_ipa_next = size;
    if (compute_infra_layout(g) < 0) {
        /* Layout computation may reject a malformed header (impossible
         * guest_size / ipa_bits combination) before the mapping is set up;
         * close the inherited shm fd here so the caller's contract -- this
         * function takes ownership of shm_fd -- holds on every error path.
         */
        close(shm_fd);
        return -1;
    }
    g->pt_pool_next = g->pt_pool_base;

    /* Map the shm fd MAP_PRIVATE: copy-on-write semantics. Reads see the
     * parent's frozen snapshot; writes are private to this process. macOS CoW
     * is page-granular: only modified pages are duplicated.
     */
    t0 = startup_trace_now_ns();
    g->host_base =
        mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, shm_fd, 0);
    startup_trace_step("shm_mmap", t0);
    if (g->host_base == MAP_FAILED) {
        perror("guest: mmap shm");
        g->host_base = NULL;
        close(shm_fd);
        return -1;
    }

    /* Close the shm fd; the mapping keeps the pages alive */
    close(shm_fd);

    /* Create HVF VM with the same IPA width as the parent */
    hv_return_t ret = HV_ERROR;
    t0 = startup_trace_now_ns();
    for (int attempt = 0; attempt < 30; attempt++) {
        hv_vm_config_t config = hv_vm_config_create();
        hv_vm_config_set_ipa_size(config, ipa_bits);
        ret = hv_vm_create(config);
        os_release(config);
        if (ret == HV_SUCCESS)
            break;
        usleep(500000);
    }
    startup_trace_step("hv_vm_create_shm", t0);
    if (ret != HV_SUCCESS) {
        log_error("guest: hv_vm_create (shm) failed: %d", (int) ret);
        munmap(g->host_base, size);
        g->host_base = NULL;
        return -1;
    }

    t0 = startup_trace_now_ns();
    ret = hv_vm_map(g->host_base, GUEST_IPA_BASE, size,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    startup_trace_step("hv_vm_map_shm", t0);
    if (ret != HV_SUCCESS) {
        log_error("guest: hv_vm_map (shm) failed: %d", (int) ret);
        hv_vm_destroy();
        munmap(g->host_base, size);
        g->host_base = NULL;
        return -1;
    }

    /* Seed HVF segment list. The child re-establishes any per-region file
     * overlays the parent had after this call (handled by fork-state
     * deserialization).
     */
    g->segments[0] = (hvf_segment_t) {.ipa = GUEST_IPA_BASE, .len = size};
    g->n_segments = 1;

    log_debug(
        "guest: CoW fork: mapped %llu GiB from shm "
        "(ipa=%u bits)",
        (unsigned long long) (size / (1024ULL * 1024 * 1024)), ipa_bits);

    return 0;
}

/* Tear down all overflow segments. Each segment is owned by
 * guest_overflow_alloc, so the host buffer and its Stage-2 mapping are released
 * here. Resets noverflow and overflow_ipa_next to the supplied anchor
 * (guest_size for guest_reset, 0 for guest_destroy).
 */
static void release_overflow_segments(guest_t *g, uint64_t reset_anchor)
{
    for (int i = 0; i < g->noverflow; i++) {
        guest_overflow_t *o = &g->overflow[i];
        if (o->host_base && o->size) {
            hv_vm_unmap(o->ipa_start, o->size);
            munmap(o->host_base, o->size);
        }
        o->host_base = NULL;
        o->size = 0;
    }
    g->noverflow = 0;
    g->overflow_ipa_next = reset_anchor;
}

/* Tear down all extra (non-primary) IPA mappings recorded in g->mappings[].
 * Each owned host buffer is freed; unowned mappings (host VA supplied by the
 * caller of guest_add_mapping) only have their Stage-2 entry torn down. Resets
 * n_mappings to 0.
 */
static void release_extra_mappings(guest_t *g)
{
    for (int i = 0; i < g->n_mappings; i++) {
        guest_mapping_t *m = &g->mappings[i];
        if (m->host_va && m->size)
            hv_vm_unmap(m->gpa, m->size);
        if (m->owns_host && m->host_va)
            munmap(m->host_va, m->size);
        m->host_va = NULL;
        m->size = 0;
    }
    g->n_mappings = 0;
}

void guest_destroy(guest_t *g)
{
    /* Quiesce worker vCPUs before unmapping stage-2. thread_destroy_all_vcpus
     * only releases vCPU handles; it does not wait for the owning pthread to
     * leave hv_vcpu_run. A worker still inside the guest at unmap time takes a
     * stage-2 translation fault on its next instruction fetch and surfaces as
     * "unexpected exception EC=0x20" in the crash report. The foot terminal
     * reproduction tripped exactly that race. The exit_group syscall handler
     * already runs request, interrupt, and join before its own teardown; the
     * destroy path needs the same prefix because forkipc.c:vcpu_run_loop
     * returns straight into guest_destroy without going through the guest
     * exit_group handler. The request is guarded on the prior state so a
     * process that already chose its exit code keeps it intact.
     *
     * The wake signals cover workers blocked outside hv_vcpu_run: futex waiters
     * poll futex_interrupt_requested, and any thread parked in epoll or poll
     * wakes off the shared pipe. Without them, host-blocked workers miss the
     * hv_vcpus_exit kick (which only affects threads inside hv_vcpu_run) and
     * the 100ms join cap in thread_join_workers detaches them, leaving live
     * pthreads to crash on the imminent munmap.
     */
    if (!proc_exit_group_requested())
        proc_request_exit_group(0);
    futex_interrupt_request();
    wakeup_pipe_signal();
    thread_interrupt_all();
    thread_join_workers();
    /* Destroy all remaining worker vCPUs (thread table) before tearing down the
     * VM. This prevents hv_vm_destroy from racing with active vCPUs that may
     * still be running if thread join timed out during exit_group.
     */
    thread_destroy_all_vcpus();
    if (g->vcpu) {
        hv_vcpu_destroy(g->vcpu);
        g->vcpu = 0;
    }
    /* Unmap each HVF segment. hv_vm_destroy releases all stage-2 state
     * regardless, but unmapping explicitly keeps invariants clean for
     * downstream tools (Instruments, leak detectors).
     */
    for (int i = 0; i < g->n_segments; i++)
        hv_vm_unmap(g->segments[i].ipa, g->segments[i].len);
    g->n_segments = 0;

    /* Release extra IPA mappings (rosetta segments etc.). hv_vm_destroy would
     * release Stage-2 state on its own; the explicit unmap inside the helper
     * keeps Instruments / leak tools accurate.
     */
    release_extra_mappings(g);
    release_overflow_segments(g, 0);

    hv_vm_destroy();
    if (g->host_base) {
        munmap(g->host_base, g->guest_size);
        g->host_base = NULL;
    }
    for (int i = 0; i < g->nregions; i++) {
        if (g->regions[i].backing_fd >= 0) {
            close(g->regions[i].backing_fd);
            g->regions[i].backing_fd = -1;
        }
    }
    g->nregions = 0;
    g->npreannounced = 0;
    /* Close the shm fd if guest memory owns one (parent with shm backing) */
    if (g->shm_fd >= 0) {
        close(g->shm_fd);
        g->shm_fd = -1;
    }
}

/* Check whether a candidate IPA range [gpa, gpa+size) overlaps the primary
 * buffer or any existing extra mapping.
 *
 * Returns true on overlap.
 */
static bool guest_mapping_overlaps(const guest_t *g, uint64_t gpa, size_t size)
{
    if (size == 0)
        return true;
    uint64_t end = gpa + size;
    if (end < gpa)
        return true; /* arithmetic overflow */
    if (gpa < g->guest_size)
        return true; /* would collide with the primary buffer */
    for (int i = 0; i < g->n_mappings; i++) {
        const guest_mapping_t *m = &g->mappings[i];
        if (gpa < m->gpa + m->size && m->gpa < end)
            return true;
    }
    /* Overflow segments occupy IPA ranges stacked above guest_size on a
     * first-come basis. An explicit mapping added later must not silently land
     * on top of an already-allocated overflow segment; HVF would accept the
     * duplicate hv_vm_map but software bookkeeping (resolve order,
     * destroy/reset ownership) would become ambiguous.
     */
    for (int i = 0; i < g->noverflow; i++) {
        const guest_overflow_t *o = &g->overflow[i];
        if (gpa < o->ipa_start + o->size && o->ipa_start < end)
            return true;
    }
    return false;
}

int guest_add_mapping(guest_t *g,
                      uint64_t gpa,
                      size_t size,
                      uint32_t hv_perms,
                      void **host_va_inout)
{
    if (!g || !host_va_inout || size == 0)
        return -1;
    if ((gpa & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
        return -1;
    /* If the caller supplied a host VA, it must be page-aligned. NULL means
     * callee-allocate-and-own; non-NULL means caller-owned, mapped as-is into
     * Stage-2 without taking ownership.
     */
    if (*host_va_inout && ((uintptr_t) *host_va_inout & (PAGE_SIZE - 1)))
        return -1;
    if (g->n_mappings >= GUEST_MAX_MAPPINGS) {
        log_error("guest_add_mapping: GUEST_MAX_MAPPINGS exhausted");
        return -1;
    }
    if (guest_mapping_overlaps(g, gpa, size)) {
        log_error("guest_add_mapping: range [0x%llx,0x%llx) overlaps existing",
                  (unsigned long long) gpa, (unsigned long long) (gpa + size));
        return -1;
    }

    bool allocated = false;
    void *host_va = *host_va_inout;
    if (!host_va) {
        host_va = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
        if (host_va == MAP_FAILED) {
            log_error("guest_add_mapping: mmap %zu bytes failed: %s", size,
                      strerror(errno));
            return -1;
        }
        allocated = true;
    }

    hv_return_t ret = hv_vm_map(host_va, gpa, size, hv_perms);
    if (ret != HV_SUCCESS) {
        log_error(
            "guest_add_mapping: hv_vm_map gpa=0x%llx size=0x%zx "
            "perms=0x%x failed: %d",
            (unsigned long long) gpa, size, hv_perms, (int) ret);
        if (allocated)
            munmap(host_va, size);
        return -1;
    }

    guest_mapping_t *m = &g->mappings[g->n_mappings++];
    m->gpa = gpa;
    m->host_va = host_va;
    m->size = size;
    m->hv_perms = hv_perms;
    m->owns_host = allocated;

    *host_va_inout = host_va;
    return 0;
}

void guest_clear_rosetta_state(guest_t *g)
{
    if (!g)
        return;

    release_extra_mappings(g);

    g->is_rosetta = false;
    g->rosetta_guest_base = 0;
    g->rosetta_va_base = 0;
    g->rosetta_size = 0;
    g->rosetta_entry = 0;
    g->kbuf_gpa = 0;
    g->kbuf_base = NULL;
    g->ttbr1 = 0;
}

const guest_mapping_t *guest_find_mapping(const guest_t *g, uint64_t gpa)
{
    if (!g || gpa < g->guest_size)
        return NULL;
    for (int i = 0; i < g->n_mappings; i++) {
        const guest_mapping_t *m = &g->mappings[i];
        if (gpa >= m->gpa && gpa < m->gpa + m->size)
            return m;
    }
    return NULL;
}

const guest_overflow_t *guest_find_overflow(const guest_t *g, uint64_t gpa)
{
    if (!g || gpa < g->guest_size)
        return NULL;
    for (int i = 0; i < g->noverflow; i++) {
        const guest_overflow_t *o = &g->overflow[i];
        if (gpa >= o->ipa_start && gpa < o->ipa_start + o->size)
            return o;
    }
    return NULL;
}

bool guest_is_valid_range(const guest_t *g, uint64_t gpa, uint64_t len)
{
    if (!g)
        return false;
    if (len == 0)
        return true;
    uint64_t end = gpa + len;
    if (end < gpa) /* arithmetic overflow */
        return false;

    /* Primary buffer covers [0, guest_size). */
    if (end <= g->guest_size)
        return true;

    /* For an extra-region or overflow match the WHOLE range must live inside a
     * single region; host pointers cannot safely span discontiguous backing.
     * gpa must be the entry point of that lookup so a straddling range (primary
     * plus extra, or extra plus extra) is rejected.
     */
    if (gpa >= g->guest_size) {
        for (int i = 0; i < g->n_mappings; i++) {
            const guest_mapping_t *m = &g->mappings[i];
            if (gpa >= m->gpa && end <= m->gpa + m->size)
                return true;
        }
        for (int i = 0; i < g->noverflow; i++) {
            const guest_overflow_t *o = &g->overflow[i];
            if (gpa >= o->ipa_start && end <= o->ipa_start + o->size)
                return true;
        }
    }
    return false;
}

uint64_t guest_overflow_alloc(guest_t *g)
{
    if (!g)
        return UINT64_MAX;

    /* Reuse bump space in an existing segment first. */
    for (int i = 0; i < g->noverflow; i++) {
        guest_overflow_t *o = &g->overflow[i];
        if (o->next + BLOCK_2MIB <= o->size) {
            uint64_t ipa = o->ipa_start + o->next;
            o->next += BLOCK_2MIB;
            return ipa;
        }
    }

    if (g->noverflow >= GUEST_MAX_OVERFLOW) {
        log_error("guest_overflow_alloc: all %d segments exhausted",
                  GUEST_MAX_OVERFLOW);
        return UINT64_MAX;
    }

    /* overflow_ipa_next is anchored at guest_size by guest_init; ensure it also
     * stays clear of any explicitly-registered extra mapping so the new segment
     * does not collide with rosetta or kbuf placements.
     */
    uint64_t seg_ipa = g->overflow_ipa_next;
    if (seg_ipa < g->guest_size)
        seg_ipa = g->guest_size;
    uint64_t seg_size = GUEST_OVERFLOW_SIZE;
    uint64_t seg_end = seg_ipa + seg_size;
    if (seg_end < seg_ipa) {
        log_error("guest_overflow_alloc: IPA overflow at 0x%llx",
                  (unsigned long long) seg_ipa);
        return UINT64_MAX;
    }
    /* Skip past every extra mapping that overlaps the candidate placement. Each
     * skip moves seg_ipa forward, so the scan must restart to catch any mapping
     * the new position now overlaps. The loop is bounded by n_mappings -- each
     * iteration that skips advances past at least one mapping, so termination
     * is guaranteed.
     */
    bool moved;
    do {
        moved = false;
        for (int i = 0; i < g->n_mappings; i++) {
            const guest_mapping_t *m = &g->mappings[i];
            uint64_t m_end = m->gpa + m->size;
            if (seg_ipa < m_end && m->gpa < seg_end) {
                seg_ipa = (m_end > seg_ipa) ? m_end : seg_ipa;
                seg_end = seg_ipa + seg_size;
                if (seg_end < seg_ipa) {
                    log_error("guest_overflow_alloc: IPA overflow after skip");
                    return UINT64_MAX;
                }
                moved = true;
                break;
            }
        }
    } while (moved);

    void *host = mmap(NULL, seg_size, PROT_READ | PROT_WRITE,
                      MAP_ANON | MAP_PRIVATE, -1, 0);
    if (host == MAP_FAILED) {
        log_error("guest_overflow_alloc: mmap %llu MiB failed: %s",
                  (unsigned long long) (seg_size >> 20), strerror(errno));
        return UINT64_MAX;
    }
    hv_return_t ret =
        hv_vm_map(host, seg_ipa, seg_size,
                  HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    if (ret != HV_SUCCESS) {
        log_error("guest_overflow_alloc: hv_vm_map IPA 0x%llx failed: %d",
                  (unsigned long long) seg_ipa, (int) ret);
        munmap(host, seg_size);
        return UINT64_MAX;
    }

    int idx = g->noverflow++;
    g->overflow[idx].host_base = host;
    g->overflow[idx].ipa_start = seg_ipa;
    g->overflow[idx].size = seg_size;
    g->overflow[idx].next = BLOCK_2MIB; /* first 2 MiB block consumed */
    g->overflow_ipa_next = seg_end;
    return seg_ipa;
}

/* Write 128 x 2 MiB kbuf block descriptors into the supplied L2 page table
 * starting at slot 384 (the first slot covering KBUF_VA_BASE / KBUF_USER_VA).
 * Each descriptor maps the next 2 MiB of [kbuf_gpa, kbuf_gpa + KBUF_SIZE) with
 * RW + UXN + PXN: the kbuf must stay data-only under both the kernel TTBR1
 * mirror and the user-VA TTBR0 alias to preserve the aliasing-proof W^X
 * invariant.
 */
static void populate_kbuf_l2_blocks(uint64_t *l2, uint64_t kbuf_gpa)
{
    for (int i = 384; i < 512; i++) {
        uint64_t ipa = kbuf_gpa + (uint64_t) (i - 384) * BLOCK_2MIB;
        l2[i] = ipa | PT_AF | PT_SH_ISH | PT_ATTR1 | PT_AP_RW_EL0 | PT_UXN |
                PT_PXN | PT_BLOCK;
    }
}

int guest_init_kbuf(guest_t *g, uint64_t kbuf_gpa)
{
    if (!g)
        return -1;
    /* Scrub kbuf state up-front so partial failure leaves the guest in a
     * fully-zeroed state rather than a stale half-initialized one. The caller
     * must treat a -1 return as "kbuf is unconfigured" and must not read
     * g->ttbr1 / g->kbuf_base / g->kbuf_gpa.
     */
    g->ttbr1 = 0;
    g->kbuf_gpa = 0;
    g->kbuf_base = NULL;

    if (kbuf_gpa & (BLOCK_2MIB - 1)) {
        log_error("guest_init_kbuf: kbuf_gpa 0x%llx not 2 MiB-aligned",
                  (unsigned long long) kbuf_gpa);
        return -1;
    }
    if (kbuf_gpa + KBUF_SIZE > g->guest_size ||
        kbuf_gpa + KBUF_SIZE < kbuf_gpa) {
        log_error(
            "guest_init_kbuf: [0x%llx,+%llu MiB) exceeds primary buffer "
            "0x%llx",
            (unsigned long long) kbuf_gpa,
            (unsigned long long) (KBUF_SIZE >> 20),
            (unsigned long long) g->guest_size);
        return -1;
    }

    /* kbuf lives inside the primary buffer; the existing Stage-2 mapping at IPA
     * 0 already covers the GPA range, so no extra hv_vm_map is needed. macOS
     * demand-pages the host buffer, so untouched 256 MiB cost nothing. kbuf_gpa
     * and kbuf_base are published after the PT pool allocation succeeds below.
     */

    /* Build TTBR1 page-table tree: L0[511] -> L1 -> L1[511] -> L2. L2 entries
     * 384..511 cover [KBUF_VA_BASE, KBUF_VA_BASE+KBUF_SIZE) with 128 x 2 MiB
     * block descriptors. RW + UXN + PXN: kbuf is data-only, so no executable
     * alias can exist via TTBR1.
     */
    uint64_t l0_gpa = pt_alloc_page(g);
    uint64_t l1_gpa = pt_alloc_page(g);
    uint64_t l2_gpa = pt_alloc_page(g);
    if (!l0_gpa || !l1_gpa || !l2_gpa) {
        log_error("guest_init_kbuf: page-table allocation failed");
        /* Up-front scrub already cleared kbuf_base / kbuf_gpa / ttbr1. */
        return -1;
    }
    /* From this point the kbuf is real; publish the host pointer + GPA so
     * subsequent code can look them up. ttbr1 is published last, after the
     * L0/L1/L2 tree is fully populated below.
     */
    g->kbuf_gpa = kbuf_gpa;
    g->kbuf_base = (uint8_t *) g->host_base + kbuf_gpa;

    uint64_t *l0 = pt_at(g, l0_gpa);
    l0[511] = (g->ipa_base + l1_gpa) | PT_VALID | PT_TABLE;

    uint64_t *l1 = pt_at(g, l1_gpa);
    l1[511] = (g->ipa_base + l2_gpa) | PT_VALID | PT_TABLE;

    uint64_t *l2 = pt_at(g, l2_gpa);
    populate_kbuf_l2_blocks(l2, kbuf_gpa);

    g->ttbr1 = g->ipa_base + l0_gpa;
    return 0;
}

/* Forward declarations for helpers defined later in the file. */
static uint64_t make_block_desc(uint64_t gpa, int perms);

int guest_map_va_range(guest_t *g,
                       uint64_t va_start,
                       uint64_t va_end,
                       uint64_t gpa_start,
                       int perms)
{
    if (!g || va_end <= va_start)
        return -1;
    if ((va_start | va_end | gpa_start) & (BLOCK_2MIB - 1)) {
        log_error(
            "guest_map_va_range: arguments not 2 MiB aligned "
            "(va=[0x%llx,0x%llx) gpa=0x%llx)",
            (unsigned long long) va_start, (unsigned long long) va_end,
            (unsigned long long) gpa_start);
        return -1;
    }
    if (!g->ttbr0)
        return -1;

    uint64_t base = g->ipa_base;
    uint64_t *l0 = pt_at(g, g->ttbr0 - base);
    if (!l0)
        return -1;

    uint64_t cur_gpa = gpa_start;
    uint64_t changed_lo = UINT64_MAX, changed_hi = 0;
    bool bcast = tlbi_request_is_broadcast();
    if (perms & MEM_PERM_X)
        tlbi_request_mark_icache();
    for (uint64_t va = va_start; va < va_end;
         va += BLOCK_2MIB, cur_gpa += BLOCK_2MIB) {
        unsigned l0_idx = (unsigned) (va / (512ULL * BLOCK_1GIB));
        if (l0_idx >= 512) {
            log_error("guest_map_va_range: VA 0x%llx out of L0 range",
                      (unsigned long long) va);
            return -1;
        }
        if (!(l0[l0_idx] & PT_VALID)) {
            uint64_t l1_gpa = pt_alloc_page(g);
            if (!l1_gpa)
                return -1;
            l0[l0_idx] = (base + l1_gpa) | PT_VALID | PT_TABLE;
        }
        uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
        uint64_t *l1 = pt_at(g, l1_ipa - base);
        if (!l1)
            return -1;

        unsigned l1_idx =
            (unsigned) ((va % (512ULL * BLOCK_1GIB)) / BLOCK_1GIB);
        if (!(l1[l1_idx] & PT_VALID)) {
            uint64_t l2_gpa = pt_alloc_page(g);
            if (!l2_gpa)
                return -1;
            l1[l1_idx] = (base + l2_gpa) | PT_VALID | PT_TABLE;
        } else if (!(l1[l1_idx] & PT_TABLE)) {
            log_error(
                "guest_map_va_range: L1[%u] is a block, not a table; "
                "VA 0x%llx collides with an existing mapping",
                l1_idx, (unsigned long long) va);
            return -1;
        }
        uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
        uint64_t *l2 = pt_at(g, l2_ipa - base);
        if (!l2)
            return -1;

        unsigned l2_idx = (unsigned) ((va % BLOCK_1GIB) / BLOCK_2MIB);
        if (l2[l2_idx] & PT_VALID) {
            /* Block already mapped -- caller may want guest_update_perms /
             * guest_split_block instead. Skip silently to mirror upstream's
             * sys_mmap_high_va "reuse existing GPA" behavior.
             */
            continue;
        }
        l2[l2_idx] = make_block_desc(cur_gpa, perms);
        if (!bcast) {
            if (va < changed_lo)
                changed_lo = va;
            if (va + BLOCK_2MIB > changed_hi)
                changed_hi = va + BLOCK_2MIB;
        }
    }

    /* The new entries are visible to the host immediately; the shim flushes the
     * matching TLBs on syscall return via the per-vCPU accumulator. Skip the
     * request when every block was already mapped (no negative TLB entries can
     * apply since the prior install already invalidated them), or when the
     * accumulator already promised a broadcast.
     */
    if (!bcast && changed_hi > changed_lo)
        tlbi_request_range(changed_lo, changed_hi);
    guest_pt_gen_bump(g);
    return 0;
}

int guest_install_kbuf_user_alias(guest_t *g)
{
    if (!g || !g->kbuf_gpa || !g->ttbr0) {
        log_error(
            "guest_install_kbuf_user_alias: kbuf or ttbr0 not "
            "initialized");
        return -1;
    }

    /* Walk to the L0/L1/L2 slot for KBUF_USER_VA. The VA bits 47:0 are
     *   bits 47:39 = 511  (L0 idx)
     *   bits 38:30 = 511  (L1 idx)
     *   bits 29:21 = 384..511 (L2 idx, 128 entries covering 256 MiB)
     * Allocating L1/L2 pages from the PT pool if they are not present.
     */
    uint64_t base = g->ipa_base;
    uint64_t *l0 = pt_at(g, g->ttbr0 - base);
    if (!l0)
        return -1;

    if (!(l0[511] & PT_VALID)) {
        uint64_t l1_gpa = pt_alloc_page(g);
        if (!l1_gpa)
            return -1;
        l0[511] = (base + l1_gpa) | PT_VALID | PT_TABLE;
    }
    uint64_t l1_ipa = l0[511] & 0xFFFFFFFFF000ULL;
    uint64_t *l1 = pt_at(g, l1_ipa - base);
    if (!l1)
        return -1;

    if (!(l1[511] & PT_VALID)) {
        uint64_t l2_gpa = pt_alloc_page(g);
        if (!l2_gpa)
            return -1;
        l1[511] = (base + l2_gpa) | PT_VALID | PT_TABLE;
    } else if (!(l1[511] & PT_TABLE)) {
        log_error(
            "guest_install_kbuf_user_alias: L1[511] is a block, not a "
            "table; cannot install kbuf alias");
        return -1;
    }
    uint64_t l2_ipa = l1[511] & 0xFFFFFFFFF000ULL;
    uint64_t *l2 = pt_at(g, l2_ipa - base);
    if (!l2)
        return -1;

    /* Reject overlap before any descriptor is written so a collision leaves the
     * existing mapping intact.
     */
    for (int i = 384; i < 512; i++) {
        if (l2[i] & PT_VALID) {
            log_error(
                "guest_install_kbuf_user_alias: L2[%d] already populated "
                "(0x%llx); kbuf user-VA range collides with another "
                "mapping",
                i, (unsigned long long) l2[i]);
            return -1;
        }
    }
    populate_kbuf_l2_blocks(l2, g->kbuf_gpa);

    guest_pt_gen_bump(g);
    return 0;
}

typedef struct {
    uint64_t gpa, chunk;
} gva_translation_t;

/* Per-thread GVA TLB cache.
 *
 * Single-entry translation cache: avoids 3-4 pointer chases through the page
 * table on repeated accesses to the same 2MiB block (or 4KiB page if L3-split).
 * Validated by an atomic generation counter in guest_t that is bumped on every
 * page table modification.
 */
static _Thread_local struct {
    const guest_t *owner; /* Which guest_t this entry belongs to */
    uint64_t base_gva;    /* Block/page-aligned GVA */
    uint64_t base_gpa;    /* Corresponding GPA offset */
    uint64_t size;        /* 2MiB or 4KiB (0 = invalid) */
    int perms;            /* Cached permissions */
    uint64_t gen;         /* guest_t.pt_gen at population time */
} gva_tlb;

static void guest_tlb_flush(void)
{
    gva_tlb.size = 0;
}

static int gva_translate_perm(const guest_t *g,
                              uint64_t gva,
                              int required_perms,
                              gva_translation_t *out)
{
    /* Fast path: check per-thread TLB cache */
    uint64_t gen = atomic_load_explicit(&g->pt_gen, memory_order_acquire);
    if (gva_tlb.size && gva_tlb.owner == g && gva_tlb.gen == gen &&
        gva >= gva_tlb.base_gva && gva - gva_tlb.base_gva < gva_tlb.size &&
        (required_perms & gva_tlb.perms) == required_perms) {
        out->gpa = gva_tlb.base_gpa + (gva - gva_tlb.base_gva);
        out->chunk = (gva_tlb.base_gva + gva_tlb.size) - gva;
        return 0;
    }

    uint64_t base = g->ipa_base;

    const uint64_t *l0 = pt_at(g, g->ttbr0 - base);
    unsigned l0_idx = (unsigned) (gva / (512ULL * BLOCK_1GIB));
    if (l0_idx >= 512 || !(l0[l0_idx] & PT_VALID))
        return -1;

    uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
    if (l1_ipa < base || l1_ipa - base >= g->guest_size)
        return -1;
    const uint64_t *l1 = pt_at(g, l1_ipa - base);
    unsigned l1_idx = (unsigned) ((gva / BLOCK_1GIB) % 512);
    if (!(l1[l1_idx] & PT_VALID))
        return -1;

    uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
    if (l2_ipa < base || l2_ipa - base >= g->guest_size)
        return -1;
    const uint64_t *l2 = pt_at(g, l2_ipa - base);
    unsigned l2_idx = (unsigned) ((gva / BLOCK_2MIB) % 512);
    if (!(l2[l2_idx] & PT_VALID))
        return -1;

    if (l2[l2_idx] & PT_TABLE) {
        /* L3 page descriptor: 4KiB granularity. */
        uint64_t l3_ipa = l2[l2_idx] & 0xFFFFFFFFF000ULL;
        if (l3_ipa < base || l3_ipa - base >= g->guest_size)
            return -1;
        const uint64_t *l3 = pt_at(g, l3_ipa - base);
        unsigned l3_idx = (unsigned) ((gva / PAGE_SIZE) % 512);
        if (!(l3[l3_idx] & PT_VALID))
            return -1;

        int perms = desc_to_perms(l3[l3_idx]);
        /* EL1-only pages (shim_data) are inaccessible to guest EL0 in the page
         * tables; the host accessors that act on a guest-supplied GVA must
         * refuse them too, otherwise a guest could pass a shim_data GVA as a
         * syscall buffer and have the host write into the identity cache or
         * entropy ring on its behalf. The host's own publishers use direct
         * host_base+shim_data_base arithmetic and bypass this walker entirely.
         */
        if (perms & MEM_PERM_EL1_ONLY)
            return -1;
        if ((perms & required_perms) != required_perms)
            return -1;

        uint64_t page_ipa = l3[l3_idx] & 0xFFFFFFFFF000ULL;
        if (page_ipa < base)
            return -1;
        uint64_t gpa = (page_ipa - base) + (gva & (PAGE_SIZE - 1));
        /* Accept GPAs inside the primary buffer or covered by an extra IPA
         * mapping (rosetta segments, kbuf, etc.). Anything else is a dangling
         * page-table entry pointing at unmapped Stage-2 IPA.
         */
        if (gpa >= g->guest_size && !guest_find_mapping(g, gpa) &&
            !guest_find_overflow(g, gpa))
            return -1;

        out->gpa = gpa;
        out->chunk = PAGE_SIZE - (gva & (PAGE_SIZE - 1));

        /* Populate TLB cache for this 4KiB page */
        gva_tlb.owner = g;
        gva_tlb.base_gva = gva & ~(PAGE_SIZE - 1);
        gva_tlb.base_gpa = page_ipa - base;
        gva_tlb.size = PAGE_SIZE;
        gva_tlb.perms = perms;
        gva_tlb.gen = gen;
        return 0;
    }

    /* L2 block descriptor: 2MiB granularity. */
    int perms = desc_to_perms(l2[l2_idx]);
    /* See the L3 page-descriptor branch above: EL1-only blocks are inaccessible
     * to host-on-behalf-of-guest accesses for the same reason. shim_data is
     * mapped as a 2MiB EL1-only block at boot.
     */
    if (perms & MEM_PERM_EL1_ONLY)
        return -1;
    if ((perms & required_perms) != required_perms)
        return -1;

    uint64_t block_ipa = l2[l2_idx] & L2_BLOCK_ADDR_MASK;
    if (block_ipa < base)
        return -1;
    uint64_t gpa = (block_ipa - base) + (gva & (BLOCK_2MIB - 1));
    if (gpa >= g->guest_size && !guest_find_mapping(g, gpa) &&
        !guest_find_overflow(g, gpa))
        return -1;

    out->gpa = gpa;
    out->chunk = BLOCK_2MIB - (gva & (BLOCK_2MIB - 1));

    /* Populate TLB cache for this 2MiB block */
    gva_tlb.owner = g;
    gva_tlb.base_gva = gva & ~(BLOCK_2MIB - 1);
    gva_tlb.base_gpa = block_ipa - base;
    gva_tlb.size = BLOCK_2MIB;
    gva_tlb.perms = perms;
    gva_tlb.gen = gen;
    return 0;
}

static uint64_t gva_contiguous_avail(const guest_t *g,
                                     uint64_t gva,
                                     int required_perms,
                                     const gva_translation_t *first,
                                     uint64_t limit)
{
    uint64_t total = 0, next_gva = gva;
    uint64_t expect_gpa = first->gpa;
    gva_translation_t cur = *first;

    if (limit == 0)
        return 0;

    for (;;) {
        uint64_t chunk = cur.chunk;
        /* Clamp to the remaining bytes in whichever backing region cur.gpa
         * lives in: the primary buffer, or an extra IPA mapping. The original
         * primary-buffer clamp underflowed harmlessly for high GPAs, but the
         * explicit mapping lookup keeps the semantics correct.
         */
        uint64_t region_end;
        if (cur.gpa < g->guest_size) {
            region_end = g->guest_size;
        } else {
            const guest_mapping_t *m = guest_find_mapping(g, cur.gpa);
            if (m) {
                region_end = m->gpa + m->size;
            } else {
                const guest_overflow_t *o = guest_find_overflow(g, cur.gpa);
                if (!o)
                    break;
                region_end = o->ipa_start + o->size;
            }
        }
        if (chunk > region_end - cur.gpa)
            chunk = region_end - cur.gpa;
        if (chunk > limit - total)
            chunk = limit - total;

        total += chunk;
        if (total == limit)
            break;
        if (chunk < cur.chunk)
            break;
        if (next_gva > UINT64_MAX - chunk)
            break;
        next_gva += chunk;
        if (expect_gpa > UINT64_MAX - chunk)
            break;
        expect_gpa += chunk;

        if (gva_translate_perm(g, next_gva, required_perms, &cur) < 0)
            break;
        if (cur.gpa != expect_gpa)
            break;
    }

    return total;
}

/* Resolve a guest virtual address to a host pointer and available size.
 * Returns NULL if the address is not in any mapping.
 *
 * If avail is non-NULL, stores the number of physically contiguous bytes from
 * gva whose page-table entries are valid and satisfy required_perms
 * (MEM_PERM_R/W/X bitmask). The walk continues across adjacent L2/L3 entries
 * until a mapping, permission, or physical-contiguity break is found.
 */
static void *gva_resolve_perm(const guest_t *g,
                              uint64_t gva,
                              uint64_t *avail,
                              int required_perms,
                              uint64_t avail_limit)
{
    /* Always walk page tables to enforce permissions. The guest slab is
     * identity-mapped (GVA == GPA == offset), but L2 block descriptors carry
     * permission bits and L3 page tables have per-4KiB permissions after
     * guest_split_block. Skipping the walk would bypass W^X enforcement for all
     * normal guest addresses.
     */
    gva_translation_t first;
    if (gva_translate_perm(g, gva, required_perms, &first) < 0)
        return NULL;

    if (avail) {
        *avail =
            gva_contiguous_avail(g, gva, required_perms, &first, avail_limit);
    }
    if (first.gpa < g->guest_size)
        return (uint8_t *) g->host_base + first.gpa;

    /* GPA outside the primary buffer: consult the extra IPA mappings (rosetta
     * segments, kbuf) first, then the overflow segments (lazy 1 GiB bump
     * allocator for high-VA 2 MiB blocks). gva_contiguous_avail naturally stops
     * at GPA-discontinuity boundaries between regions, so a single region match
     * suffices for the host pointer translation.
     */
    const guest_mapping_t *m = guest_find_mapping(g, first.gpa);
    if (m) {
        if (avail) {
            uint64_t cap = (m->gpa + m->size) - first.gpa;
            if (*avail > cap)
                *avail = cap;
        }
        return (uint8_t *) m->host_va + (first.gpa - m->gpa);
    }
    const guest_overflow_t *o = guest_find_overflow(g, first.gpa);
    if (o) {
        if (avail) {
            uint64_t cap = (o->ipa_start + o->size) - first.gpa;
            if (*avail > cap)
                *avail = cap;
        }
        return (uint8_t *) o->host_base + (first.gpa - o->ipa_start);
    }
    return NULL;
}

void *guest_ptr(const guest_t *g, uint64_t gva)
{
    return gva_resolve_perm(g, gva, NULL, MEM_PERM_R, UINT64_MAX);
}

void *guest_ptr_w(const guest_t *g, uint64_t gva)
{
    return gva_resolve_perm(g, gva, NULL, MEM_PERM_W, UINT64_MAX);
}

void *guest_ptr_avail(const guest_t *g,
                      uint64_t gva,
                      uint64_t *avail,
                      int required_perms)
{
    return gva_resolve_perm(g, gva, avail, required_perms, UINT64_MAX);
}

void *guest_ptr_bound(const guest_t *g,
                      uint64_t gva,
                      uint64_t *avail,
                      int required_perms,
                      uint64_t len_limit)
{
    return gva_resolve_perm(g, gva, avail, required_perms, len_limit);
}

static inline int guest_copy(const guest_t *g,
                             uint64_t gva,
                             void *dst,
                             const void *src,
                             size_t len,
                             int required_perms)
{
    if (len == 0)
        return 0;
    if ((required_perms == MEM_PERM_R && !dst) ||
        (required_perms == MEM_PERM_W && !src))
        return -1;
    if (gva > UINT64_MAX - len)
        return -1;

    size_t copied = 0;
    while (copied < len) {
        uint64_t avail;
        void *ptr = gva_resolve_perm(g, gva + copied, &avail, required_perms,
                                     (uint64_t) (len - copied));
        if (!ptr)
            return -1;
        size_t chunk = len - copied;
        if (chunk > avail)
            chunk = avail;
        if (required_perms == MEM_PERM_R)
            memcpy((uint8_t *) dst + copied, ptr, chunk);
        else
            memcpy(ptr, (const uint8_t *) src + copied, chunk);
        copied += chunk;
    }
    return 0;
}

int guest_read(const guest_t *g, uint64_t gva, void *dst, size_t len)
{
    return guest_copy(g, gva, dst, NULL, len, MEM_PERM_R);
}

int guest_read_small(const guest_t *g, uint64_t gva, void *dst, size_t len)
{
    uint64_t avail = 0;
    void *src = guest_ptr_bound(g, gva, &avail, MEM_PERM_R, (uint64_t) len);
    if (src && avail >= len) {
        memcpy(dst, src, len);
        return 0;
    }

    return guest_read(g, gva, dst, len);
}

int guest_write(guest_t *g, uint64_t gva, const void *src, size_t len)
{
    return guest_copy(g, gva, NULL, src, len, MEM_PERM_W);
}

int guest_write_small(guest_t *g, uint64_t gva, const void *src, size_t len)
{
    uint64_t avail = 0;
    void *dst = guest_ptr_bound(g, gva, &avail, MEM_PERM_W, (uint64_t) len);
    if (dst && avail >= len) {
        memcpy(dst, src, len);
        return 0;
    }

    return guest_write(g, gva, src, len);
}

int guest_read_str(const guest_t *g, uint64_t gva, char *dst, size_t max)
{
    if (max == 0)
        return -1;
    size_t copied = 0, limit = max - 1;

    while (copied < limit) {
        if (gva > UINT64_MAX - copied)
            break;
        uint64_t avail;
        void *ptr = gva_resolve_perm(g, gva + copied, &avail, MEM_PERM_R,
                                     (uint64_t) (limit - copied));
        if (!ptr)
            break;

        size_t remain = limit - copied, chunk = avail < remain ? avail : remain;
        const char *src = (const char *) ptr;

        const void *nul = memchr(src, '\0', chunk);
        if (nul) {
            size_t slen = (const char *) nul - src;
            memcpy(dst + copied, src, slen + 1);
            return (int) (copied + slen);
        }
        memcpy(dst + copied, src, chunk);
        copied += chunk;
    }

    dst[copied] = '\0';
    return -1;
}

int guest_read_str_small(const guest_t *g, uint64_t gva, char *dst, size_t max)
{
    if (max == 0)
        return -1;

    size_t limit = max - 1;
    uint64_t avail = 0;
    const char *src =
        guest_ptr_bound(g, gva, &avail, MEM_PERM_R, (uint64_t) limit);
    if (src && avail >= limit) {
        const char *nul = memchr(src, '\0', limit);
        if (nul) {
            size_t slen = (size_t) (nul - src);
            memcpy(dst, src, slen + 1);
            return (int) slen;
        }
    }

    return guest_read_str(g, gva, dst, max);
}

/* guest_reset. */

void guest_reset(guest_t *g)
{
    /* Zero only actually-used memory regions. With a potentially 1TiB address
     * space, memset of the entire range would fault in all demand-paged memory
     * for no benefit. PROT_NONE regions (e.g., a managed runtime's heap
     * reservation) were never written to, so they're already in the MAP_ANON
     * zero-fill-on-demand state.
     */

    /* Zero tracked regions (ELF segments, heap, stack, mmap allocations). Skip
     * PROT_NONE regions because they were never touched.
     *
     * Scrub by backing GPA, not by VA: identity-mapped regions have gpa_base ==
     * start, but high-VA regions (rosetta) carry their VA in start/end and the
     * real primary-buffer offset in gpa_base. Filtering by end <= guest_size
     * alone would silently skip high-VA backing and leak bytes across a
     * rosetta-to-rosetta execve.
     */
    for (int i = 0; i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (r->prot == 0 /* PROT_NONE */ || r->end <= r->start)
            continue;
        uint64_t len = r->end - r->start;
        uint64_t gpa = r->gpa_base;
        if (gpa > g->guest_size || len > g->guest_size - gpa)
            continue; /* backing lies outside the primary slab */
        memset((uint8_t *) g->host_base + gpa, 0, len);
    }

    /* Zero page table pool (not tracked in region array) */
    if (g->pt_pool_next > g->pt_pool_base)
        memset((uint8_t *) g->host_base + g->pt_pool_base, 0,
               g->pt_pool_next - g->pt_pool_base);

    /* Zero shim code + data (not tracked in region array by guest_reset
     * callers; shim regions are added AFTER reset by the exec path)
     */
    memset((uint8_t *) g->host_base + g->shim_base, 0,
           g->shim_data_base + BLOCK_2MIB - g->shim_base);

    /* Release overflow segments. The page tables that referenced them are about
     * to be rebuilt by the exec path, so the GPA space is no longer needed. New
     * segments will be allocated lazily when the next binary exercises the
     * high-VA path. Rosetta placement (g->mappings[]) is intentionally NOT
     * touched: it survives execve so that re-execing another x86_64 binary
     * keeps the same rosetta image in place.
     */
    release_overflow_segments(g, g->guest_size);

    /* Reset allocation state */
    guest_pt_gen_bump(g);
    guest_tlb_flush();
    __atomic_store_n(&pt_pool_warned, false, __ATOMIC_RELAXED);
    g->pt_pool_next = g->pt_pool_base;
    g->brk_base = BRK_BASE_DEFAULT;
    g->brk_current = BRK_BASE_DEFAULT;
    g->mmap_next = MMAP_BASE;
    g->mmap_end = MMAP_INITIAL_END;
    g->mmap_rx_next = MMAP_RX_BASE;
    g->mmap_rx_end = MMAP_RX_INITIAL_END;
    g->mmap_rw_gap_hint = 0;
    g->mmap_rx_gap_hint = 0;
    g->ttbr0 = 0;
    tlbi_request_clear();
    g->elf_load_min = ELF_DEFAULT_BASE;

    /* Clear semantic region tracking (will be re-populated after exec) */
    guest_region_clear(g);
}

/* Used region enumeration. */

int guest_get_used_regions(const guest_t *g,
                           unsigned int shim_size,
                           used_region_t *out,
                           int max)
{
    int n = 0;

    /* Page table pool (high IPA, just below interp_base) */
    if (n < max && g->pt_pool_next > g->pt_pool_base) {
        out[n].offset = g->pt_pool_base;
        out[n].size = g->pt_pool_next - g->pt_pool_base;
        n++;
    }

    /* Shim code (high IPA) */
    if (n < max && shim_size > 0) {
        out[n].offset = g->shim_base;
        out[n].size = shim_size;
        n++;
    }

    /* Shim data/stack (full 2MiB block, high IPA) */
    if (n < max) {
        out[n].offset = g->shim_data_base;
        out[n].size = BLOCK_2MIB;
        n++;
    }

    /* Interpreter high block. The dynamic linker stores process-global state
     * such as __stack_chk_guard in its high mapping just above interp_base.
     * Fork children that take the region-copy path must inherit those bytes;
     * otherwise libc's post-fork canary check observes zeroed guard storage
     * and aborts before the child can exec.
     */
    if (n < max && g->interp_base > 0 &&
        g->interp_base <= g->guest_size - BLOCK_2MIB) {
        out[n].offset = g->interp_base;
        out[n].size = BLOCK_2MIB;
        n++;
    }

    /* ELF + brk region: from elf_load_min (set by ELF loader) to brk_current.
     * The lower bound is the actual ELF load address, not ELF_DEFAULT_BASE:
     * ET_EXECs linked below 0x400000 (e.g. at 0x200000) have segments below the
     * legacy default and would otherwise be silently dropped from the legacy
     * fork-IPC copy.
     */
    if (n < max && g->brk_current > g->elf_load_min) {
        out[n].offset = g->elf_load_min;
        out[n].size = g->brk_current - g->elf_load_min;
        n++;
    }

    /* Stack (dynamic position, stored in guest_t) */
    if (n < max) {
        out[n].offset = g->stack_base;
        out[n].size = g->stack_top - g->stack_base;
        n++;
    }

    /* mmap RW region (up to high-water mark). With the gap-finding allocator,
     * mmap_next is a high-water mark; freed regions within this range may
     * contain PROT_NONE pages (zero-fill, no cost to copy). This is
     * conservative but correct for fork state transfer.
     */
    if (n < max && g->mmap_next > MMAP_BASE) {
        out[n].offset = MMAP_BASE;
        out[n].size = g->mmap_next - MMAP_BASE;
        n++;
    }

    /* mmap RX region (code mappings from dynamic linker) */
    if (n < max && g->mmap_rx_next > MMAP_RX_BASE) {
        out[n].offset = MMAP_RX_BASE;
        out[n].size = g->mmap_rx_next - MMAP_RX_BASE;
        n++;
    }

    /* Rosetta image and TTBR1 kbuf live near the top of the primary buffer
     * (between the mmap RW high-water mark and the infra reserve), so the
     * MMAP_BASE..mmap_next range above misses them. Snapshot each as its own
     * block so the fork child inherits the translator image and the kernel-VA
     * scratchpad without rebuilding either.
     */
    if (g->is_rosetta) {
        if (n < max && g->rosetta_guest_base && g->rosetta_size) {
            out[n].offset = g->rosetta_guest_base;
            out[n].size = g->rosetta_size;
            n++;
        }
        if (n < max && g->kbuf_gpa) {
            out[n].offset = g->kbuf_gpa;
            out[n].size = KBUF_SIZE;
            n++;
        }
    }

    return n;
}

/* Semantic region tracking.
 *
 * Check whether two adjacent regions can be merged. They must be contiguous in
 * address space, have identical protection/flags/name, and have contiguous file
 * offsets (so the merged region still represents valid mapping). For anonymous
 * regions the offset is meaningless (always 0, but may become non-zero after
 * split/trim), so the contiguity check is skipped. Without this, adjacent
 * anonymous mmaps (common in megablock-style allocators) each create separate
 * entries that exhaust the region table.
 */
static bool regions_mergeable(const guest_region_t *a, const guest_region_t *b)
{
    if (a->end != b->start)
        return false;
    if (a->gpa_base + (a->end - a->start) != b->gpa_base)
        return false;
    if (a->prot != b->prot)
        return false;
    if (a->flags != b->flags)
        return false;
    if (a->backing_fd != b->backing_fd)
        return false;

    /* Do not merge noreserve with non-noreserve: the noreserve flag controls
     * lazy page fault behavior and merging would either lose the flag
     * (disabling lazy faults) or apply it to committed pages (causing spurious
     * re-zeroing on faults).
     */
    if (a->noreserve != b->noreserve)
        return false;
    if (a->overlay_active || b->overlay_active)
        return false;
    if (strcmp(a->name, b->name) != 0)
        return false;

    /* Anonymous regions have no file offset to preserve. The flags field
     * reliably distinguishes anonymous from file-backed because every
     * guest_region_add call site sets LINUX_MAP_ANONYMOUS explicitly.
     */
    if ((a->flags & LINUX_MAP_ANONYMOUS) && (b->flags & LINUX_MAP_ANONYMOUS))
        return true;
    return a->offset + (a->end - a->start) == b->offset;
}

/* First region whose start is >= start. regions[] is sorted by start. */
static int region_lower_bound_start(const guest_t *g, uint64_t start)
{
    int lo = 0;
    int hi = g->nregions;

    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (g->regions[mid].start < start)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* First region whose end is > addr. See guest.h for the contract; also used
 * inside this file to skip the untouched prefix for remove and set_prot.
 */
int guest_region_first_end_above(const guest_t *g, uint64_t addr)
{
    int lo = 0;
    int hi = g->nregions;

    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (g->regions[mid].end <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* Merge region at index i with its right neighbor (i+1) when their layouts
 * agree. No-op if i is the last region or layouts differ.
 */
static void try_merge_right(guest_t *g, int i)
{
    if (i + 1 >= g->nregions)
        return;
    if (!regions_mergeable(&g->regions[i], &g->regions[i + 1]))
        return;

    g->regions[i].end = g->regions[i + 1].end;
    memmove(&g->regions[i + 1], &g->regions[i + 2],
            (g->nregions - i - 2) * sizeof(guest_region_t));
    g->nregions--;
}

/* Merge region at index i with its left neighbor (i-1) when their layouts
 * agree. No-op if i is out of range or the layouts differ.
 */
static void try_merge_left(guest_t *g, int i)
{
    if (i <= 0 || i >= g->nregions)
        return;
    /* nregions is bounded by GUEST_MAX_REGIONS so i is in range. */
    /* cppcheck-suppress arrayIndexOutOfBoundsCond */
    if (!regions_mergeable(&g->regions[i - 1], &g->regions[i]))
        return;

    g->regions[i - 1].end = g->regions[i].end;
    memmove(&g->regions[i], &g->regions[i + 1],
            (g->nregions - i - 1) * sizeof(guest_region_t));
    g->nregions--;
}

int guest_region_add(guest_t *g,
                     uint64_t start,
                     uint64_t end,
                     int prot,
                     int flags,
                     uint64_t offset,
                     const char *name)
{
    return guest_region_add_ex(g, start, end, prot, flags, offset, name, -1);
}

int guest_region_add_ex(guest_t *g,
                        uint64_t start,
                        uint64_t end,
                        int prot,
                        int flags,
                        uint64_t offset,
                        const char *name,
                        int backing_fd)
{
    int owned_backing_fd = -1;
    if (backing_fd >= 0) {
        owned_backing_fd = dup(backing_fd);
        if (owned_backing_fd < 0)
            return -1;
    }

    return guest_region_add_ex_owned_gpa(g, start, end, start, prot, flags,
                                         offset, name, owned_backing_fd);
}

int guest_region_add_ex_gpa(guest_t *g,
                            uint64_t start,
                            uint64_t end,
                            uint64_t gpa_base,
                            int prot,
                            int flags,
                            uint64_t offset,
                            const char *name,
                            int backing_fd)
{
    int owned_backing_fd = -1;
    if (backing_fd >= 0) {
        owned_backing_fd = dup(backing_fd);
        if (owned_backing_fd < 0)
            return -1;
    }

    return guest_region_add_ex_owned_gpa(g, start, end, gpa_base, prot, flags,
                                         offset, name, owned_backing_fd);
}

int guest_region_add_ex_owned(guest_t *g,
                              uint64_t start,
                              uint64_t end,
                              int prot,
                              int flags,
                              uint64_t offset,
                              const char *name,
                              int owned_backing_fd)
{
    return guest_region_add_ex_owned_gpa(g, start, end, start, prot, flags,
                                         offset, name, owned_backing_fd);
}

int guest_region_add_ex_owned_gpa(guest_t *g,
                                  uint64_t start,
                                  uint64_t end,
                                  uint64_t gpa_base,
                                  int prot,
                                  int flags,
                                  uint64_t offset,
                                  const char *name,
                                  int owned_backing_fd)
{
    if (g->nregions >= GUEST_MAX_REGIONS) {
        log_error(
            "guest: region table full (%d/%d), "
            "cannot track [0x%llx-0x%llx) %s",
            g->nregions, GUEST_MAX_REGIONS, (unsigned long long) start,
            (unsigned long long) end, name ? name : "");
        if (owned_backing_fd >= 0)
            close(owned_backing_fd);
        return -1;
    }

    /* Find insertion point (keep sorted by start address). */
    int i = region_lower_bound_start(g, start);
    memmove(&g->regions[i + 1], &g->regions[i],
            (g->nregions - i) * sizeof(guest_region_t));

    guest_region_t *r = &g->regions[i];
    r->start = start;
    r->end = end;
    r->gpa_base = gpa_base;
    r->prot = prot;
    r->flags = flags;
    r->offset = offset;
    r->backing_fd = owned_backing_fd;
    r->shared = (flags & 0x01) != 0;      /* LINUX_MAP_SHARED = 0x01 */
    r->noreserve = (flags & 0x4000) != 0; /* LINUX_MAP_NORESERVE = 0x4000 */
    guest_region_clear_overlay(r);
    if (name) {
        str_copy_trunc(r->name, name, sizeof(r->name));
    } else {
        r->name[0] = '\0';
    }
    g->nregions++;

    /* Try to merge with adjacent regions to reduce table pressure. Merge right
     * first, then left (order matters: right merge does not change the index of
     * the left neighbor).
     */
    try_merge_right(g, i);
    try_merge_left(g, i);

    return 0;
}

int guest_preannounce(guest_t *g,
                      uint64_t start,
                      uint64_t end,
                      int prot,
                      int flags,
                      uint64_t offset,
                      const char *name)
{
    if (g->npreannounced >= GUEST_MAX_PREANNOUNCED)
        return -1;

    int i = g->npreannounced;
    while (i > 0 && g->preannounced[i - 1].start > start) {
        g->preannounced[i] = g->preannounced[i - 1];
        i--;
    }

    guest_region_t *r = &g->preannounced[i];
    memset(r, 0, sizeof(*r));
    r->start = start;
    r->end = end;
    r->gpa_base = start;
    r->prot = prot;
    r->flags = flags;
    r->offset = offset;
    r->backing_fd = -1;
    if (name)
        str_copy_trunc(r->name, name, sizeof(r->name));
    g->npreannounced++;
    return 0;
}

void guest_region_remove(guest_t *g, uint64_t start, uint64_t end)
{
    if (end <= start)
        return;

    /* In-place compaction: 'out' is the next output slot, 'in' is the next
     * input slot. Since the prefix [0, first) is untouched (it sorts strictly
     * before [start, end) by guest_region_first_end_above), both cursors begin
     * at 'first'. The non-overlap invariant guarantees out <= in throughout the
     * loop, so writes at g->regions[out] never clobber slots not yet read.
     */
    int first = guest_region_first_end_above(g, start);
    int out = first;
    int in = first;

    while (in < g->nregions) {
        guest_region_t *r = &g->regions[in];
        if (r->start >= end)
            break;

        bool keep_left = r->start < start;
        bool keep_right = r->end > end;

        /* Interior split: removal range lies strictly inside *r, producing two
         * output entries from one input slot. This is the only growth path;
         * handle it explicitly so the untouched suffix is shifted out of the
         * way before either half is written. After this branch no further input
         * regions can overlap [start, end), so the loop is done.
         */
        if (keep_left && keep_right) {
            if (g->nregions >= GUEST_MAX_REGIONS) {
                /* Table full: drop the tail [end, r->end) and fall through to
                 * the simple "trim end" treatment of *r. The tail stays mapped
                 * in page tables but is now untracked, so a later mprotect over
                 * that range would otherwise see vacuously uniform prot in the
                 * tracker and skip PTE work. Mark the tracker permanently stale
                 * to disarm the mprotect fast path for the lifetime of the
                 * process.
                 */
                log_error(
                    "guest: region table full, "
                    "munmap split drops tail [0x%llx-0x%llx)",
                    (unsigned long long) end, (unsigned long long) r->end);
                g->regions_tracker_stale = true;
                keep_right = false;
            } else {
                guest_region_t orig = *r;
                int suffix_count = g->nregions - in - 1;
                if (suffix_count > 0)
                    memmove(&g->regions[out + 2], &g->regions[in + 1],
                            suffix_count * sizeof(guest_region_t));

                guest_region_t left = orig;
                left.end = start;
                guest_region_clip_overlay(&left);
                g->regions[out] = left;

                guest_region_t right = orig;
                uint64_t trimmed = end - orig.start;
                right.offset += trimmed;
                right.gpa_base += trimmed;
                right.start = end;
                if (orig.backing_fd >= 0) {
                    right.backing_fd = dup(orig.backing_fd);
                    if (right.backing_fd < 0)
                        log_error(
                            "guest: dup() failed for region split "
                            "backing fd %d: %s",
                            orig.backing_fd, strerror(errno));
                }
                guest_region_clip_overlay(&right);
                g->regions[out + 1] = right;

                g->nregions = out + 2 + suffix_count;
                return;
            }
        }

        if (!keep_left && !keep_right) {
            if (r->backing_fd >= 0)
                close(r->backing_fd);
            in++;
            continue;
        }

        /* Trim-only paths: either keep_left xor keep_right is true. Build the
         * surviving half from the source slot, then publish it to g->regions
         * [out]. The original backing_fd transfers to whichever half survives;
         * no dup is needed because only one half remains.
         */
        guest_region_t survivor = *r;
        if (keep_left) {
            survivor.end = start;
        } else {
            uint64_t trimmed = end - r->start;
            survivor.offset += trimmed;
            survivor.gpa_base += trimmed;
            survivor.start = end;
        }
        guest_region_clip_overlay(&survivor);
        g->regions[out++] = survivor;
        in++;
    }

    /* Append the unread suffix (regions whose start >= end) after the compacted
     * overlap area, shifting only if compaction left a hole.
     */
    int tail = g->nregions - in;
    if (tail > 0 && out != in)
        memmove(&g->regions[out], &g->regions[in],
                tail * sizeof(guest_region_t));
    g->nregions = out + tail;
}

const guest_region_t *guest_region_find(const guest_t *g, uint64_t addr)
{
    /* Binary search in sorted array */
    int lo = 0, hi = g->nregions - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < g->regions[mid].start) {
            hi = mid - 1;
        } else if (addr >= g->regions[mid].end) {
            lo = mid + 1;
        } else {
            return &g->regions[mid];
        }
    }
    return NULL;
}

bool guest_region_range_prot_uniform(const guest_t *g,
                                     uint64_t start,
                                     uint64_t end,
                                     int prot)
{
    for (int i = guest_region_first_end_above(g, start); i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->prot != prot)
            return false;
    }
    return true;
}

bool guest_region_range_has_noreserve(const guest_t *g,
                                      uint64_t start,
                                      uint64_t end)
{
    for (int i = guest_region_first_end_above(g, start); i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->noreserve)
            return true;
    }
    return false;
}

void guest_region_set_prot(guest_t *g, uint64_t start, uint64_t end, int prot)
{
    /* Walk regions overlapping [start, end), split at boundaries, update prot.
     * Track the range of indices that were modified so the code can merge
     * afterward.
     */
    int first_modified = -1, last_modified = -1;

    /* The prefix skip ensures regions[i].end > start for i >= first; the
     * non-overlap invariant carries it through all later iterations.
     */
    for (int i = guest_region_first_end_above(g, start); i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;

        /* If region extends before start, split at start */
        if (r->start < start) {
            if (g->nregions >= GUEST_MAX_REGIONS) {
                /* The region keeps its old prot in the tracker, but PTEs for
                 * [start, r->end) have already been updated. Mark the tracker
                 * permanently stale so the mprotect fast path falls back to
                 * unconditional PTE work and cannot be fooled by a tracker that
                 * lags actual PTE state.
                 */
                log_error(
                    "guest: region table full, "
                    "mprotect split skipped at 0x%llx",
                    (unsigned long long) start);
                g->regions_tracker_stale = true;
                continue;
            }
            memmove(&g->regions[i + 1], &g->regions[i],
                    (g->nregions - i) * sizeof(guest_region_t));
            g->nregions++;
            /* Left half keeps original prot and backing_fd */
            g->regions[i].end = start;
            guest_region_clip_overlay(&g->regions[i]);
            /* Right half will be processed next iteration */
            g->regions[i + 1].offset += (start - g->regions[i + 1].start);
            g->regions[i + 1].gpa_base += (start - g->regions[i + 1].start);
            g->regions[i + 1].start = start;
            if (g->regions[i + 1].backing_fd >= 0) {
                g->regions[i + 1].backing_fd =
                    dup(g->regions[i + 1].backing_fd);
                if (g->regions[i + 1].backing_fd < 0)
                    log_error(
                        "guest: dup() failed for mprotect "
                        "split: %s",
                        strerror(errno));
            }
            guest_region_clip_overlay(&g->regions[i + 1]);
            i++; /* advance to the right half */
            r = &g->regions[i];
        }

        /* If region extends past end, split at end */
        if (r->end > end) {
            if (g->nregions >= GUEST_MAX_REGIONS) {
                /* Over-apply prot to the whole region: the tail [end, r->end)
                 * now claims new prot in the tracker even though PTE work did
                 * not cover it. Mark the tracker stale so the mprotect fast
                 * path stops trusting prot uniformity.
                 */
                log_error(
                    "guest: region table full, "
                    "mprotect split skipped at 0x%llx "
                    "(region [0x%llx-0x%llx) gets prot %d entirely)",
                    (unsigned long long) end, (unsigned long long) r->start,
                    (unsigned long long) r->end, prot);
                g->regions_tracker_stale = true;
                r->prot = prot;
                if (first_modified < 0)
                    first_modified = i;
                last_modified = i;
                continue;
            }
            memmove(&g->regions[i + 1], &g->regions[i],
                    (g->nregions - i) * sizeof(guest_region_t));
            g->nregions++;
            /* Left half: [r->start, end) with new prot */
            g->regions[i].end = end;
            g->regions[i].prot = prot;
            guest_region_clip_overlay(&g->regions[i]);
            /* Right half: [end, old_end) keeps original prot */
            g->regions[i + 1].offset += (end - g->regions[i + 1].start);
            g->regions[i + 1].gpa_base += (end - g->regions[i + 1].start);
            g->regions[i + 1].start = end;
            if (g->regions[i + 1].backing_fd >= 0) {
                g->regions[i + 1].backing_fd =
                    dup(g->regions[i + 1].backing_fd);
                if (g->regions[i + 1].backing_fd < 0)
                    log_error(
                        "guest: dup() failed for mprotect "
                        "end-split: %s",
                        strerror(errno));
            }
            guest_region_clip_overlay(&g->regions[i + 1]);
            if (first_modified < 0)
                first_modified = i;
            last_modified = i;
            break; /* done, right half is past the current range */
        }

        /* Region lies fully inside [start, end), so only prot changes. */
        r->prot = prot;
        if (first_modified < 0)
            first_modified = i;
        last_modified = i;
    }

    /* After updating prot, try to merge modified regions with neighbors. Work
     * right-to-left so index shifts do not invalidate earlier indices.
     */
    if (first_modified >= 0) {
        /* Merge last modified with its right neighbor */
        try_merge_right(g, last_modified);
        /* Merge adjacent modified regions (right to left) */
        for (int i = last_modified; i > first_modified; i--)
            try_merge_left(g, i);
        /* Merge first modified with its left neighbor */
        try_merge_left(g, first_modified);
    }
}

static void guest_region_clear(guest_t *g)
{
    for (int i = 0; i < g->nregions; i++) {
        if (g->regions[i].backing_fd >= 0) {
            close(g->regions[i].backing_fd);
            g->regions[i].backing_fd = -1;
        }
    }
    g->nregions = 0;
    g->npreannounced = 0;
}

/* Page table builder. */

/* Build block descriptor for a 2MiB block at the given GPA with perms. */
static uint64_t make_block_desc(uint64_t gpa, int perms)
{
    uint64_t desc = (gpa & L2_BLOCK_ADDR_MASK) /* PA bits */
                    | PT_AF | PT_SH_ISH | PT_NS |
                    PT_ATTR1    /* Normal WB cacheable */
                    | PT_BLOCK; /* Valid block */

    /* Execute permissions: XN bits disable execution */
    if (!(perms & MEM_PERM_X)) {
        desc |= PT_UXN | PT_PXN;
    }

    /* Write permissions via AP bits: AP[2:1]=00 -> RW for EL1 only (no EL0
     * access) AP[2:1]=01 -> RW for EL1 and EL0 AP[2:1]=11 -> RO for EL1 and EL0
     * MEM_PERM_EL1_ONLY drops EL0 access entirely; used for shim_data so the
     * guest cannot directly read or store to the cache, ring, bitmap, or
     * attention flag.
     */
    if (perms & MEM_PERM_EL1_ONLY) {
        desc |= PT_AP_RW_EL1;
        /* EL1-only data: never EL0-executable (already set above if MEM_PERM_X
         * is unset, but assert defensively).
         */
        desc |= PT_UXN | PT_PXN;
    } else if (perms & MEM_PERM_W) {
        desc |= PT_AP_RW_EL0;
    } else {
        desc |= PT_AP_RO;
    }

    return desc;
}

/* Convert mixed-permission and partially-covered 2MiB blocks into L3 4KiB
 * pages.
 *
 * The block-emit loop in guest_build_page_tables uses 2MiB block descriptors
 * and OR-merges permissions when multiple regions touch the same block. The
 * merge is correct only when every region in the block agrees on perms AND the
 * union of those regions covers the entire block; otherwise it leaves
 * over-permissive PTEs (e.g. .text RX + .data RW + heap RW in one 2MiB block
 * collapses to RWX) and grants access to gap pages that should fault.
 *
 * For each unique 2MiB block touched by the input regions, this pass either
 * keeps the block descriptor in place (single-perm full coverage) or splits it
 * into 512 L3 pages, invalidates the lot, and re-validates each region's pages
 * with the correct perms. Pages with no region coverage stay invalid, matching
 * Linux semantics for inter-segment gaps in small static binaries.
 */
static bool finalize_block_perms(guest_t *g, const mem_region_t *regions, int n)
{
    /* Walk every 2MiB block touched by any region. Blocks shared by multiple
     * regions are processed multiple times; the underlying split / invalidate /
     * re-validate sequence is idempotent (guest_split_block is a no-op once the
     * L2 entry is a table descriptor; guest_invalidate_ptes + per-region
     * guest_update_perms produce the same final L3 state on every pass), so
     * dedup is an optimization the heap-region scale (~127 blocks for the
     * default brk window) does not justify against a fixed-size visited set.
     *
     * Non-identity (va_base != 0) rosetta regions are skipped: the maintenance
     * helpers below (guest_split_block, guest_update_perms) navigate by GPA but
     * rosetta's L2 entries live at high-VA indices, so a GPA-keyed walk lands
     * in the wrong slot. Rosetta uses a single full-coverage RWX block
     * descriptor by design, so no L3 splitting is needed; if a later workload
     * requires per-segment perms inside the rosetta image, the maintenance
     * helpers must learn va_base first.
     */
    for (int r = 0; r < n; r++) {
        if (regions[r].va_base != 0)
            continue;
        uint64_t r_block_lo = ALIGN_2MIB_DOWN(regions[r].gpa_start);
        uint64_t r_block_hi = ALIGN_2MIB_UP(regions[r].gpa_end);

        for (uint64_t b = r_block_lo; b < r_block_hi; b += BLOCK_2MIB) {
            /* Walk all regions touching this block. Track perm uniformity and
             * collect them into idx[] sorted by start so coverage can be
             * checked with a single sweep.
             */
            int idx[GUEST_MAX_REGIONS];
            int nidx = 0;
            int first_perm = -1;
            bool same_perm = true;

            for (int s = 0; s < n; s++) {
                /* Non-identity regions are excluded from the coverage sweep for
                 * the same reason as the outer skip: their L2 entries live at a
                 * different VA-index than their GPA suggests, so mixing them
                 * into a GPA-keyed split would corrupt either tree.
                 */
                if (regions[s].va_base != 0)
                    continue;
                if (regions[s].gpa_end <= b ||
                    regions[s].gpa_start >= b + BLOCK_2MIB)
                    continue;
                if (first_perm < 0)
                    first_perm = regions[s].perms;
                else if (regions[s].perms != first_perm)
                    same_perm = false;

                int pos = nidx;
                while (pos > 0 &&
                       regions[idx[pos - 1]].gpa_start > regions[s].gpa_start) {
                    idx[pos] = idx[pos - 1];
                    pos--;
                }
                idx[pos] = s;
                nidx++;
            }

            /* Coverage sweep: regions are sorted by start, so the union covers
             * the block iff each region begins at or before the running
             * high-water mark.
             */
            uint64_t covered_until = b;
            bool full_coverage = true;
            for (int i = 0; i < nidx; i++) {
                uint64_t cs = regions[idx[i]].gpa_start;
                uint64_t ce = regions[idx[i]].gpa_end;
                if (cs > covered_until) {
                    full_coverage = false;
                    break;
                }
                if (ce > covered_until)
                    covered_until = ce;
            }
            if (covered_until < b + BLOCK_2MIB)
                full_coverage = false;

            /* Single perm covering the whole block: the existing 2MiB
             * descriptor is already correct.
             */
            if (same_perm && full_coverage)
                continue;

            /* Split into L3 pages, invalidate the lot, then rebuild the block
             * from per-page unions. This preserves the required permission
             * union when adjacent ELF segments share a 4KiB page after
             * page-granularity rounding.
             */
            if (guest_split_block(g, b) < 0)
                return false;
            if (guest_invalidate_ptes(g, b, b + BLOCK_2MIB) < 0)
                return false;

            int page_perms[BLOCK_2MIB / PAGE_SIZE] = {0};
            for (int i = 0; i < nidx; i++) {
                uint64_t s_start = regions[idx[i]].gpa_start;
                uint64_t s_end = regions[idx[i]].gpa_end;
                uint64_t apply_start = (s_start > b) ? s_start : b;
                uint64_t apply_end =
                    (s_end < b + BLOCK_2MIB) ? s_end : b + BLOCK_2MIB;
                /* Page-align to 4KiB so partially covered pages are recreated
                 * with the union of all overlapping segment permissions.
                 */
                apply_start = ALIGN_DOWN(apply_start, PAGE_SIZE);
                apply_end = PAGE_ALIGN_UP(apply_end);
                if (apply_end > b + BLOCK_2MIB)
                    apply_end = b + BLOCK_2MIB;

                for (uint64_t pa = apply_start; pa < apply_end;
                     pa += PAGE_SIZE) {
                    unsigned page_idx = (unsigned) ((pa - b) / PAGE_SIZE);
                    page_perms[page_idx] |= regions[idx[i]].perms;
                }
            }

            for (int i = 0; i < (int) ARRAY_SIZE(page_perms);) {
                int perms = page_perms[i];
                int run_start = i;

                while (i < (int) ARRAY_SIZE(page_perms) &&
                       page_perms[i] == perms)
                    i++;
                if (!perms)
                    continue;

                uint64_t run_gpa_start = b + (uint64_t) run_start * PAGE_SIZE;
                uint64_t run_gpa_end = b + (uint64_t) i * PAGE_SIZE;
                if (guest_update_perms(g, run_gpa_start, run_gpa_end, perms) <
                    0)
                    return false;
            }
        }
    }

    return true;
}

uint64_t guest_build_page_tables(guest_t *g, const mem_region_t *regions, int n)
{
    uint64_t base = g->ipa_base;

    /* Allocate L0 table */
    uint64_t l0_gpa = pt_alloc_page(g);
    if (!l0_gpa)
        return 0;

    uint64_t *l0 = pt_at(g, l0_gpa);

    /* For each region, determine which 2MiB blocks need mapping.
     * Identity-mapped: VA == GPA, so L0/L1/L2 indices and the block descriptor
     * output address are both derived from gpa_start + ipa_base.
     */
    for (int r = 0; r < n; r++) {
        uint64_t gpa_start = ALIGN_2MIB_DOWN(regions[r].gpa_start);
        uint64_t gpa_end = ALIGN_2MIB_UP(regions[r].gpa_end);
        int perms = regions[r].perms;
        /* Non-identity regions (rosetta segments) supply a va_base so the
         * page-table entry is indexed by VA, but the block descriptor still
         * carries the GPA where the data physically lives. va_offset is the
         * constant delta between VA and GPA inside the region; 0 for the
         * identity case which keeps the math identical to the original.
         */
        uint64_t va_offset = 0;
        if (regions[r].va_base)
            va_offset = regions[r].va_base - regions[r].gpa_start;

        for (uint64_t gpa = gpa_start; gpa < gpa_end; gpa += BLOCK_2MIB) {
            uint64_t output_ipa = base + gpa;
            uint64_t lookup_addr = output_ipa + va_offset;

            /* L0 index: which 512GiB slot this VA falls in */
            unsigned l0_idx = (unsigned) (lookup_addr / (512ULL * BLOCK_1GIB));
            if (l0_idx >= 512) {
                log_error("guest: VA 0x%llx out of L0 range",
                          (unsigned long long) lookup_addr);
                continue;
            }

            /* Allocate L1 table on first access to each L0 slot */
            if (!(l0[l0_idx] & PT_VALID)) {
                uint64_t l1_gpa = pt_alloc_page(g);
                if (!l1_gpa)
                    return 0;
                l0[l0_idx] = (base + l1_gpa) | PT_VALID | PT_TABLE;
            }
            uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
            uint64_t *l1 = pt_at(g, l1_ipa - base);

            /* L1 index within the 512GiB L0 entry (from VA) */
            unsigned l1_idx =
                (unsigned) ((lookup_addr % (512ULL * BLOCK_1GIB)) / BLOCK_1GIB);
            if (l1_idx >= 512) {
                log_error("guest: VA 0x%llx out of L1 range",
                          (unsigned long long) lookup_addr);
                continue;
            }

            /* Ensure L1 entry points to an L2 table */
            if (!(l1[l1_idx] & PT_VALID)) {
                uint64_t l2_gpa = pt_alloc_page(g);
                if (!l2_gpa)
                    return 0;
                l1[l1_idx] = (base + l2_gpa) | PT_VALID | PT_TABLE;
            }

            /* L2 table for this 1GiB region (stored in host at gpa offset) */
            uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
            uint64_t l2_gpa_off = l2_ipa - base;
            uint64_t *l2 = pt_at(g, l2_gpa_off);

            /* L2 index: which 2MiB block within the 1GiB region (from VA) */
            unsigned l2_idx =
                (unsigned) ((lookup_addr % BLOCK_1GIB) / BLOCK_2MIB);

            /* If block already mapped, merge permissions (most permissive). Use
             * a local variable for the merged perms. Do NOT modify the outer
             * perms variable, which would leak accumulated permissions to
             * subsequent 2MiB blocks in the same region.
             */
            int block_perms = perms;
            if (l2[l2_idx] & PT_BLOCK) {
                int old_perms = 0;
                if (!(l2[l2_idx] & PT_UXN))
                    old_perms |= MEM_PERM_X;
                if ((l2[l2_idx] & (3ULL << 6)) == PT_AP_RW_EL0)
                    old_perms |= MEM_PERM_W;
                old_perms |= MEM_PERM_R;
                block_perms |= old_perms;
            }

            /* Block descriptor: output IPA (where data physically lives). For
             * identity regions output_ipa == lookup_addr; for non-identity
             * (rosetta) the entry sits at the high VA but the descriptor points
             * to the primary-buffer GPA where the bytes actually are.
             */
            l2[l2_idx] = make_block_desc(output_ipa, block_perms);
        }
    }

    /* Store TTBR0 for later use by guest_extend_page_tables */
    uint64_t ttbr0 = base + l0_gpa;
    g->ttbr0 = ttbr0;

    /* Convert blocks shared by regions with mixed perms or partial coverage
     * into L3 4KiB pages so each segment's permissions are honored exactly.
     */
    if (!finalize_block_perms(g, regions, n))
        return 0;

    guest_pt_gen_bump(g);
    return ttbr0;
}

/* Extend page tables to cover [start, end) with 2MiB block descriptors. Walks
 * the existing L0->L1 structure (from g->ttbr0) and allocates new L2 tables as
 * needed. This is safe to call while the vCPU is paused (during HVC #5
 * handling). Records a TLBI request covering the new range so the shim flushes
 * the matching TLB entries before returning to EL0.
 */
int guest_extend_page_tables(guest_t *g,
                             uint64_t start,
                             uint64_t end,
                             int perms)
{
    /* Identity-only by construction: the L2 block descriptor's output IPA is
     * identical to the VA index, so the new mapping puts data at the same GPA
     * as the VA. That assumption breaks for non-identity rosetta ranges, where
     * data lives at a low GPA below interp_base while the VA sits at 128 TiB.
     * Such ranges already have entries installed by guest_map_va_range during
     * rosetta_prepare; an extension request at a non-identity VA would silently
     * fabricate a dangling block descriptor. Refuse cleanly so the misuse
     * surfaces in logs rather than in a post-mortem stage-2 fault.
     */
    if (start >= g->guest_size || end > g->guest_size) {
        log_error(
            "guest_extend_page_tables: [0x%llx,0x%llx) is outside the "
            "primary buffer; non-identity ranges must use "
            "guest_map_va_range",
            (unsigned long long) start, (unsigned long long) end);
        return -1;
    }
    /* Defensive: end is bounded by guest_size above, so the ALIGN_2MIB_UP below
     * cannot wrap on any reachable input. The explicit guard documents the
     * contract and matches the wrap guards in guest_invalidate_ptes /
     * guest_update_perms; keeps the three sites in sync if a future caller
     * lifts the guest_size cap.
     */
    if (end > UINT64_MAX - (BLOCK_2MIB - 1))
        return -1;

    uint64_t base = g->ipa_base;

    /* Navigate to L0 table */
    uint64_t l0_gpa_off = g->ttbr0 - base;
    uint64_t *l0 = pt_at(g, l0_gpa_off);

    /* Walk 2MiB blocks in [start, end). Track the smallest sub-range whose L2
     * entry actually transitioned from unmapped to mapped; blocks that were
     * already valid get no new descriptor and need no TLBI (false-positive
     * elimination mirrors guest_update_perms). Once the accumulator is already
     * TLBI_BROADCAST, the bookkeeping is wasted work.
     */
    if (perms & MEM_PERM_X)
        tlbi_request_mark_icache();
    uint64_t addr_start = ALIGN_2MIB_DOWN(start), addr_end = ALIGN_2MIB_UP(end);
    uint64_t changed_lo = UINT64_MAX, changed_hi = 0;
    bool bcast = tlbi_request_is_broadcast();

    for (uint64_t addr = addr_start; addr < addr_end; addr += BLOCK_2MIB) {
        uint64_t ipa = base + addr;

        /* L0 index: which 512GiB slot (>512GiB addresses need L0[1]+) */
        unsigned l0_idx = (unsigned) (ipa / (512ULL * BLOCK_1GIB));
        if (l0_idx >= 512) {
            log_error("guest: IPA 0x%llx out of L0 range in extend",
                      (unsigned long long) ipa);
            return -1;
        }

        /* Allocate L1 table on first access to each L0 slot */
        if (!(l0[l0_idx] & PT_VALID)) {
            uint64_t l1_gpa = pt_alloc_page(g);
            if (!l1_gpa)
                return -1;
            l0[l0_idx] = (base + l1_gpa) | PT_VALID | PT_TABLE;
        }

        uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
        uint64_t *l1 = pt_at(g, l1_ipa - base);

        unsigned l1_idx =
            (unsigned) ((ipa % (512ULL * BLOCK_1GIB)) / BLOCK_1GIB);
        if (l1_idx >= 512) {
            log_error("guest: IPA 0x%llx out of L1 range in extend",
                      (unsigned long long) ipa);
            return -1;
        }

        /* Ensure L1 entry points to an L2 table */
        if (!(l1[l1_idx] & PT_VALID)) {
            uint64_t l2_gpa = pt_alloc_page(g);
            if (!l2_gpa)
                return -1;
            l1[l1_idx] = (base + l2_gpa) | PT_VALID | PT_TABLE;
        }

        /* Navigate to L2 table */
        uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
        uint64_t *l2 = pt_at(g, l2_ipa - base);

        unsigned l2_idx = (unsigned) ((ipa % BLOCK_1GIB) / BLOCK_2MIB);

        /* Only map if not already mapped. A negative TLB entry from a prior
         * translation fault is possible only for VAs that were unmapped at the
         * time of the fault, so the TLBI is only needed for blocks actually
         * installed by this call.
         */
        /* At L2 a valid descriptor is either a 2 MiB block (bits[1:0] = 01) or
         * a table descriptor pointing to an L3 page table (bits[1:0] = 11).
         * Both indicate the slot is already mapped at some granule, so the
         * extend has nothing to install; skip without flushing. The previous "&
         * PT_BLOCK" test relied on PT_BLOCK == PT_VALID == bit 0 to cover both
         * cases by coincidence -- write it as an explicit PT_VALID test so the
         * intent survives a future descriptor-bit renumbering.
         */
        if (l2[l2_idx] & PT_VALID)
            continue;
        l2[l2_idx] = make_block_desc(ipa, perms);
        if (!bcast) {
            if (addr < changed_lo)
                changed_lo = addr;
            if (addr + BLOCK_2MIB > changed_hi)
                changed_hi = addr + BLOCK_2MIB;
        }
    }

    /* Large extends will exceed the selective cap and become broadcast. */
    if (!bcast && changed_hi > changed_lo)
        tlbi_request_range(base + changed_lo, base + changed_hi);
    guest_pt_gen_bump(g);
    return 0;
}

bool guest_va_block_mapped(const guest_t *g, uint64_t va)
{
    if (!g || !g->ttbr0 || (va & (BLOCK_2MIB - 1)))
        return false;

    uint64_t base = g->ipa_base;
    uint64_t *l0 = pt_at(g, g->ttbr0 - base);
    if (!l0)
        return false;

    unsigned l0_idx = (unsigned) (va / (512ULL * BLOCK_1GIB));
    if (l0_idx >= 512 || !(l0[l0_idx] & PT_VALID))
        return false;

    uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
    uint64_t *l1 = pt_at(g, l1_ipa - base);
    if (!l1)
        return false;

    unsigned l1_idx = (unsigned) ((va % (512ULL * BLOCK_1GIB)) / BLOCK_1GIB);
    if (!(l1[l1_idx] & PT_VALID) || !(l1[l1_idx] & PT_TABLE))
        return false;

    uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
    uint64_t *l2 = pt_at(g, l2_ipa - base);
    if (!l2)
        return false;

    unsigned l2_idx = (unsigned) ((va % BLOCK_1GIB) / BLOCK_2MIB);
    return (l2[l2_idx] & PT_VALID) != 0;
}

/* L3 page table splitting. */

/* L3 page descriptor: bits[1:0]=11 = valid page at level 3. This is distinct
 * from L2 block descriptors (bits[1:0]=01).
 */
#define PT_L3_PAGE (3ULL)

/* Build a 4KiB L3 page descriptor with the given permissions. Layout matches
 * block descriptors (AF, SH, NS, MAIR, AP, XN) except bits[1:0]=11 instead of
 * 01.
 */
static uint64_t make_page_desc(uint64_t pa, int perms)
{
    uint64_t desc = (pa & 0xFFFFFFFFF000ULL) /* PA bits [47:12] */
                    | PT_AF | PT_SH_ISH | PT_NS | PT_ATTR1 | PT_L3_PAGE;

    if (!(perms & MEM_PERM_X))
        desc |= PT_UXN | PT_PXN;

    if (perms & MEM_PERM_EL1_ONLY) {
        desc |= PT_AP_RW_EL1;
        desc |= PT_UXN | PT_PXN; /* EL1-only data never executes */
    } else if (perms & MEM_PERM_W) {
        desc |= PT_AP_RW_EL0;
    } else {
        desc |= PT_AP_RO;
    }

    return desc;
}

/* Extract MEM_PERM_* flags from a page table descriptor (block or page). The
 * AP[2:1] field encodes the EL1/EL0 access matrix; map 00 to MEM_PERM_RW |
 * MEM_PERM_EL1_ONLY so callers see the privileged-only shim_data slots
 * correctly instead of treating them as read-only.
 */
static int desc_to_perms(uint64_t desc)
{
    int perms = MEM_PERM_R;
    if (!(desc & PT_UXN))
        perms |= MEM_PERM_X;
    uint64_t ap = desc & (3ULL << 6);
    if (ap == PT_AP_RW_EL0) {
        perms |= MEM_PERM_W;
    } else if (ap == PT_AP_RW_EL1) {
        perms |= MEM_PERM_W | MEM_PERM_EL1_ONLY;
    }
    /* PT_AP_RO (11) stays MEM_PERM_R only. */
    return perms;
}

/* Locate the L2 descriptor that covers a 2 MiB block at the given guest virtual
 * address. The walk is VA-driven (L0/L1/L2 indices come from bits 47:21 of va),
 * so it locates the correct entry for non-identity rosetta regions too as long
 * as the caller passes the guest VA rather than the data's backing GPA. Callers
 * iterating regions[] by gpa_start MUST translate to the region's va_base when
 * va_base != 0 before invoking this helper, or skip the region entirely (see
 * finalize_block_perms for the prevailing pattern).
 *
 * Returns NULL if the VA falls outside the L0 range or no entry has been
 * installed along the L0 to L1 to L2 chain.
 */
static uint64_t *find_l2_entry(guest_t *g, uint64_t va)
{
    uint64_t base = g->ipa_base, ipa = base + va;

    uint64_t l0_gpa_off = g->ttbr0 - base;
    uint64_t *l0 = pt_at(g, l0_gpa_off);

    /* L0 index from the full VA (not just the IPA-offset slice); correct for
     * entries above the primary buffer (rosetta at 128 TiB, etc.).
     */
    unsigned l0_idx = (unsigned) (ipa / (512ULL * BLOCK_1GIB));
    if (l0_idx >= 512 || !(l0[l0_idx] & PT_VALID))
        return NULL;

    uint64_t l1_ipa = l0[l0_idx] & 0xFFFFFFFFF000ULL;
    uint64_t *l1 = pt_at(g, l1_ipa - base);

    unsigned l1_idx = (unsigned) ((ipa % (512ULL * BLOCK_1GIB)) / BLOCK_1GIB);
    if (l1_idx >= 512 || !(l1[l1_idx] & PT_VALID))
        return NULL;

    uint64_t l2_ipa = l1[l1_idx] & 0xFFFFFFFFF000ULL;
    uint64_t *l2 = pt_at(g, l2_ipa - base);

    unsigned l2_idx = (unsigned) ((ipa % BLOCK_1GIB) / BLOCK_2MIB);
    return &l2[l2_idx];
}

/* Split a 2MiB L2 block descriptor into 512 x 4KiB L3 page descriptors. The
 * caller provides the L2 entry via find_l2_entry. Extracts the output IPA from
 * the existing descriptor.
 *
 * No TLBI is issued by the split itself. The block-to-table transition
 * preserves the output address, permissions, and attributes of every page in
 * the 2 MiB range, so any cached translation from the old block descriptor
 * remains semantically correct. Per ARM ARM (FEAT_BBM Level 2), a CPU that
 * implements level-2 break-before-make support allows block <-> table changes
 * that preserve the resulting translation in all other respects without a BBM
 * sequence. Apple Silicon implements FEAT_BBM Level 2 across M1+; the
 * split-heavy stress paths in tests/ (test-stress mprotect cycling,
 * test-shim-urandom-toctou rapid flips, test-mprotect-mt R<->RW toggling, plus
 * dynamic-linker RELRO setup) run cleanly. A future PE without FEAT_BBM Level 2
 * would need either a real BBM sequence here (invalidate, TLBI, write table) or
 * an unconditional broadcast TLBI on every split; revisit if that ever surfaces
 * a TLB conflict abort.
 */
static int split_l2_block(guest_t *g, uint64_t *l2_entry)
{
    if (!l2_entry)
        return -1;

    /* Already a table descriptor (previously split); nothing to do */
    if ((*l2_entry & 3) == 3)
        return 0;

    /* Must be a valid block descriptor: bit[0]=1, bit[1]=0 */
    if (!(*l2_entry & PT_BLOCK))
        return -1;

    int old_perms = desc_to_perms(*l2_entry);

    uint64_t l3_gpa = pt_alloc_page(g);
    if (!l3_gpa)
        return -1;
    uint64_t *l3 = pt_at(g, l3_gpa);

    /* Fill 512 L3 entries with 4KiB page descriptors inheriting the block's
     * permissions. Extract the output IPA from bits [47:21] of the existing
     * descriptor (not from the caller's address).
     */
    uint64_t block_ipa = *l2_entry & L2_BLOCK_ADDR_MASK;
    for (int i = 0; i < 512; i++)
        l3[i] = make_page_desc(block_ipa + (uint64_t) i * PAGE_SIZE, old_perms);

    *l2_entry = (g->ipa_base + l3_gpa) | PT_VALID | PT_TABLE;
    return 0;
}

int guest_split_block(guest_t *g, uint64_t block_gpa)
{
    uint64_t block_start = ALIGN_2MIB_DOWN(block_gpa);
    uint64_t *l2_entry = find_l2_entry(g, block_start);
    int rc = split_l2_block(g, l2_entry);
    if (rc < 0)
        return rc;
    return 0;
}

int guest_invalidate_ptes(guest_t *g, uint64_t start, uint64_t end)
{
    uint64_t base = g->ipa_base;

    /* Page-align the range. The ALIGN_UP step on end could wrap to 0 for inputs
     * within PAGE_SIZE-1 of UINT64_MAX, silently turning the invalidation into
     * a no-op against a 0-length loop. Reject the pathological input rather
     * than allow a stale mapping to survive.
     */
    if (end > UINT64_MAX - (PAGE_SIZE - 1))
        return -1;
    start = start & ~(PAGE_SIZE - 1);
    end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (end <= start)
        return 0;

    for (uint64_t addr = start; addr < end;) {
        uint64_t *l2_entry = find_l2_entry(g, addr);
        if (!l2_entry) {
            /* No L2 entry (already unmapped); skip this 2MiB block */
            addr = ALIGN_2MIB_UP(addr + 1);
            continue;
        }

        uint64_t block_start = ALIGN_2MIB_DOWN(addr);
        uint64_t block_end = block_start + BLOCK_2MIB;

        /* Not mapped at all: skip */
        if (!(*l2_entry & 1)) {
            addr = block_end;
            continue;
        }

        /* Check if this is a 2MiB block or already an L3 table */
        if ((*l2_entry & 3) == 1) {
            /* 2MiB block descriptor */
            if (start <= block_start && end >= block_end) {
                /* Invalidating the entire 2MiB block: clear the L2 entry. The 2
                 * MiB range exceeds the selective cap and upgrades to
                 * broadcast.
                 */
                *l2_entry = 0;
                tlbi_request_range(base + block_start, base + block_end);
                addr = block_end;
                continue;
            }

            /* Partial invalidation within a 2MiB block: split first, then
             * invalidate individual L3 pages below.
             */
            if (guest_split_block(g, block_start) < 0)
                return -1;
        }

        /* L3 table: invalidate individual 4KiB page descriptors. Track the
         * smallest sub-range whose descriptor actually transitioned from mapped
         * to invalid; a page that was already 0 needs no TLBI (false-positive
         * elimination mirrors the guest_update_perms path). Skip the per-page
         * bookkeeping once a broadcast is already pending.
         */
        uint64_t l3_ipa = *l2_entry & 0xFFFFFFFFF000ULL;
        uint64_t *l3 = pt_at(g, l3_ipa - base);

        uint64_t page_start = (addr > block_start) ? addr : block_start;
        uint64_t page_end = (end < block_end) ? end : block_end;
        uint64_t changed_lo = UINT64_MAX, changed_hi = 0;
        bool bcast = tlbi_request_is_broadcast();

        for (uint64_t pa = page_start; pa < page_end; pa += PAGE_SIZE) {
            unsigned l3_idx =
                (unsigned) (((base + pa) % BLOCK_2MIB) / PAGE_SIZE);
            if (l3[l3_idx] != 0) {
                l3[l3_idx] = 0; /* Invalid descriptor */
                if (!bcast) {
                    if (pa < changed_lo)
                        changed_lo = pa;
                    if (pa + PAGE_SIZE > changed_hi)
                        changed_hi = pa + PAGE_SIZE;
                }
            }
        }

        if (!bcast && changed_hi > changed_lo)
            tlbi_request_range(base + changed_lo, base + changed_hi);
        addr = page_end;
    }

    guest_pt_gen_bump(g);
    return 0;
}

int guest_update_perms(guest_t *g, uint64_t start, uint64_t end, int perms)
{
    uint64_t base = g->ipa_base;

    /* Page-align the range. The ALIGN_UP on end could wrap to 0 for inputs
     * within PAGE_SIZE-1 of UINT64_MAX, silently degrading the call to a no-op
     * against a 0-length loop. Reject the pathological input rather than leave
     * stale perms in place.
     */
    if (end > UINT64_MAX - (PAGE_SIZE - 1))
        return -1;
    start = start & ~(PAGE_SIZE - 1);
    end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (end <= start)
        return 0;

    /* New perms include exec: the shim must IC IALLU on syscall return so a VA
     * that previously held NX content fetches the new instructions. The inverse
     * (removing exec) leaves no new code visible.
     */
    if (perms & MEM_PERM_X)
        tlbi_request_mark_icache();

    /* Aliasing-proof invariant: TTBR1 maps the kbuf RW + UXN + PXN. The same
     * physical pages will be dual-mapped at KBUF_USER_VA under TTBR0 by the
     * rosetta finalize path. An executable TTBR0 alias would defeat HVF's
     * per-mapping W^X enforcement and create a writable-and-executable race
     * against the kernel-VA mirror. Reject any attempt to grant MEM_PERM_X
     * inside the user-VA kbuf mirror window before page tables are touched.
     */
    if ((perms & MEM_PERM_X) && end > start &&
        guest_kbuf_user_va_overlap(start, end - start)) {
        log_error(
            "guest_update_perms: refusing executable kbuf alias "
            "[0x%llx, 0x%llx); violates W^X aliasing invariant",
            (unsigned long long) start, (unsigned long long) end);
        return -1;
    }

    for (uint64_t addr = start; addr < end;) {
        uint64_t *l2_entry = find_l2_entry(g, addr);
        if (!l2_entry) {
            /* Skip unmapped 2MiB blocks */
            addr = ALIGN_2MIB_UP(addr + 1);
            continue;
        }

        uint64_t block_start = ALIGN_2MIB_DOWN(addr);
        uint64_t block_end = block_start + BLOCK_2MIB;

        /* Not mapped at all: skip */
        if (!(*l2_entry & 1)) {
            addr = block_end;
            continue;
        }

        /* Check if this is a 2MiB block or already an L3 table */
        if ((*l2_entry & 3) == 1) {
            /* 2MiB block descriptor */
            int old_perms = desc_to_perms(*l2_entry);

            /* If the whole 2MiB block changes permissions, rewrite the block
             * descriptor without splitting. Extract the output IPA from the
             * existing descriptor, correct for both identity and non-identity
             * mapped regions.
             */
            if (start <= block_start && end >= block_end) {
                if (old_perms != perms) {
                    uint64_t ipa = *l2_entry & L2_BLOCK_ADDR_MASK;
                    *l2_entry = make_block_desc(ipa, perms);
                    tlbi_request_range(base + block_start, base + block_end);
                }
                addr = block_end;
                continue;
            }

            /* Partial update: split the 2MiB block into L3 pages first, then
             * fall through to update individual pages below.
             */
            if (old_perms != perms) {
                if (guest_split_block(g, block_start) < 0)
                    return -1;
            } else {
                /* Same permissions; no change needed */
                addr = block_end;
                continue;
            }
        }

        /* L3 table: update individual 4KiB page descriptors */
        uint64_t l3_ipa = *l2_entry & 0xFFFFFFFFF000ULL;
        uint64_t *l3 = pt_at(g, l3_ipa - base);

        /* Update pages within this 2MiB block that fall in [start, end). Track
         * the smallest sub-range that actually changed so the TLBI request only
         * covers descriptors whose value changed (false-positive elimination).
         * Once the accumulator has already promoted to TLBI_BROADCAST, the
         * bounding-box bookkeeping is wasted work -- the broadcast invalidates
         * everything regardless -- so the loop skips the compares in that mode
         * while still writing every changed descriptor.
         */
        uint64_t page_start = (addr > block_start) ? addr : block_start;
        uint64_t page_end = (end < block_end) ? end : block_end;
        uint64_t changed_lo = UINT64_MAX, changed_hi = 0;
        bool bcast = tlbi_request_is_broadcast();

        for (uint64_t pa = page_start; pa < page_end; pa += PAGE_SIZE) {
            unsigned l3_idx =
                (unsigned) (((base + pa) % BLOCK_2MIB) / PAGE_SIZE);
            /* Extract the existing output IPA from the L3 entry. For
             * non-identity mapped regions, pa is a VA not a GPA, so the builder
             * must use the IPA already stored in the descriptor (set by
             * guest_split_block).
             *
             * For invalidated entries (set to 0 by guest_invalidate_ptes), the
             * stored IPA is gone. Recover it from region metadata when the VA
             * range is non-identity mapped; otherwise fall back to the usual
             * identity IPA (base + pa).
             */
            uint64_t page_ipa;
            if (l3[l3_idx] & PT_VALID) {
                page_ipa = l3[l3_idx] & 0xFFFFFFFFF000ULL;
            } else {
                const guest_region_t *r = guest_region_find(g, pa);
                if (r) {
                    uint64_t page_gpa = r->gpa_base + (pa - r->start);
                    page_ipa = base + (page_gpa & ~(PAGE_SIZE - 1));
                } else {
                    page_ipa = base + (pa & ~(PAGE_SIZE - 1));
                }
            }
            uint64_t new_desc = make_page_desc(page_ipa, perms);
            if (l3[l3_idx] != new_desc) {
                l3[l3_idx] = new_desc;
                if (!bcast) {
                    if (pa < changed_lo)
                        changed_lo = pa;
                    if (pa + PAGE_SIZE > changed_hi)
                        changed_hi = pa + PAGE_SIZE;
                }
            }
        }

        if (!bcast && changed_hi > changed_lo)
            tlbi_request_range(base + changed_lo, base + changed_hi);
        addr = page_end;
    }

    guest_pt_gen_bump(g);
    return 0;
}

int guest_install_va_pages(guest_t *g,
                           uint64_t va,
                           uint64_t length,
                           uint64_t gpa,
                           int perms)
{
    if (!g || length == 0)
        return -1;
    if ((va | length | gpa) & (PAGE_SIZE - 1))
        return -1;
    /* Reject wrap on both the VA side and the GPA side. Without the gpa guard,
     * a caller could pass a near-UINT64_MAX gpa with a non-zero length and the
     * loop would wrap p back to a low GPA, silently installing descriptors
     * pointing at the wrong physical pages.
     */
    if (va > UINT64_MAX - length || gpa > UINT64_MAX - length)
        return -1;

    /* Aliasing-proof invariant: TTBR1 maps the kbuf RW + UXN + PXN, and the
     * same physical pages are mirrored at KBUF_USER_VA under TTBR0. An
     * executable alias inside the user-VA kbuf window would defeat HVF's
     * per-mapping W^X enforcement (the kernel-VA mirror is writable). Match the
     * equivalent check in guest_update_perms before touching pages.
     */
    if ((perms & MEM_PERM_X) && guest_kbuf_user_va_overlap(va, length)) {
        log_error(
            "guest_install_va_pages: refusing executable kbuf alias "
            "[0x%llx, 0x%llx); violates W^X aliasing invariant",
            (unsigned long long) va, (unsigned long long) (va + length));
        return -1;
    }

    uint64_t base = g->ipa_base;
    uint64_t end = va + length;
    uint64_t changed_lo = UINT64_MAX, changed_hi = 0;
    bool bcast = tlbi_request_is_broadcast();
    if (perms & MEM_PERM_X)
        tlbi_request_mark_icache();

    /* Walk one 4 KiB page at a time. find_l2_entry locates the L2 slot for each
     * VA; split_l2_block converts an L2 block descriptor into a table lazily so
     * individual L3 entries can be written. The L3 entry is then
     * unconditionally overwritten with the requested gpa + perms, so a prior
     * invalidation (or a fresh split inheriting the wrong block address) cannot
     * leave behind a stale or zero descriptor. Pages whose descriptor is
     * already identical are no-ops for TLBI purposes; skip them. Skip the
     * per-page bookkeeping once a broadcast is already pending.
     */
    for (uint64_t v = va, p = gpa; v < end; v += PAGE_SIZE, p += PAGE_SIZE) {
        uint64_t *l2_entry = find_l2_entry(g, v);
        if (!l2_entry)
            return -1;
        if (!(*l2_entry & PT_VALID))
            return -1;
        if ((*l2_entry & 3) == 1) {
            if (guest_split_block(g, ALIGN_2MIB_DOWN(v)) < 0)
                return -1;
        }
        uint64_t l3_ipa = *l2_entry & 0xFFFFFFFFF000ULL;
        uint64_t *l3 = pt_at(g, l3_ipa - base);
        if (!l3)
            return -1;
        unsigned l3_idx = (unsigned) (((base + v) % BLOCK_2MIB) / PAGE_SIZE);
        uint64_t new_desc = make_page_desc(base + p, perms);
        if (l3[l3_idx] != new_desc) {
            l3[l3_idx] = new_desc;
            if (!bcast) {
                if (v < changed_lo)
                    changed_lo = v;
                if (v + PAGE_SIZE > changed_hi)
                    changed_hi = v + PAGE_SIZE;
            }
        }
    }

    if (!bcast && changed_hi > changed_lo)
        tlbi_request_range(changed_lo, changed_hi);
    guest_pt_gen_bump(g);
    return 0;
}

/* Lazy page materialization for MAP_NORESERVE. */

int guest_materialize_lazy(guest_t *g, uint64_t fault_offset)
{
    /* Find the noreserve region containing this offset */
    const guest_region_t *region = NULL;
    for (int i = 0; i < g->nregions; i++) {
        if (g->regions[i].start <= fault_offset &&
            g->regions[i].end > fault_offset && g->regions[i].noreserve) {
            region = &g->regions[i];
            break;
        }
    }

    if (!region)
        return -1; /* Not a noreserve region */

    /* Materialize one 2MiB block containing the fault address. This is the
     * smallest granule that guest_extend_page_tables works with. For the common
     * case (sparse heap touch), materializing one block at a time is the right
     * trade-off: it avoids over-committing the large reservation while keeping
     * the fault rate manageable.
     */
    uint64_t block_start = fault_offset & ~(BLOCK_2MIB - 1);
    uint64_t block_end = block_start + BLOCK_2MIB;

    /* Clamp to guest size */
    if (block_end > g->guest_size)
        block_end = g->guest_size;

    uint64_t materialize_start =
        (block_start > region->start) ? block_start : region->start;
    uint64_t materialize_end =
        (block_end < region->end) ? block_end : region->end;
    bool partial_block = region->start > block_start || region->end < block_end;
    uint64_t *l2_entry = find_l2_entry(g, block_start);
    int had_mapping = l2_entry && (*l2_entry & PT_VALID);

    /* Convert prot flags to page table perms */
    int perms = 0;
    if (region->prot & LINUX_PROT_READ)
        perms |= MEM_PERM_R;
    if (region->prot & LINUX_PROT_WRITE)
        perms |= MEM_PERM_W;
    if (region->prot & LINUX_PROT_EXEC)
        perms |= MEM_PERM_X;
    if (perms == 0)
        perms = MEM_PERM_R; /* At minimum readable */

    /* Create page table entries. guest_extend_page_tables creates L2 block
     * descriptors but skips existing table descriptors (L2->L3 splits).
     * guest_update_perms handles the L3 case: if guest_invalidate_ptes
     * previously split the block and invalidated the L3 entries, update_perms
     * recreates them with correct perms.
     */
    if (guest_extend_page_tables(g, block_start, block_end, perms) < 0)
        return -1;

    if (partial_block) {
        if (guest_split_block(g, block_start) < 0)
            return -1;

        /* If this block had no page-table entry before the lazy fault,
         * guest_extend_page_tables() necessarily created a full 2MiB block.
         * Split it and remove pages outside this noreserve region so holes and
         * guards in the same 2MiB block remain faults. Existing split blocks
         * already encode neighboring mappings, so leave them intact.
         */
        if (!had_mapping) {
            if (block_start < materialize_start &&
                guest_invalidate_ptes(g, block_start, materialize_start) < 0)
                return -1;
            if (materialize_end < block_end &&
                guest_invalidate_ptes(g, materialize_end, block_end) < 0)
                return -1;
        }
    }

    guest_update_perms(g, materialize_start, materialize_end, perms);

    /* Zero the materialized memory. Only zero within the region boundaries to
     * avoid clobbering adjacent data.
     */
    if (materialize_end > materialize_start)
        memset((uint8_t *) g->host_base + materialize_start, 0,
               materialize_end - materialize_start);

    /* The page-table helpers above already requested the matching TLBI; no
     * additional flush is needed here.
     */
    return 0;
}
