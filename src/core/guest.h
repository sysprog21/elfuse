/*
 * Guest memory management
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provides identity-mapped guest physical memory (GVA == GPA == offset into
 * host buffer). Buffer size is determined by the VM's configured IPA width:
 *   - Native aarch64 on M2 (36-bit IPA): 64GiB
 *   - Native aarch64 on M3+ (40-bit IPA): 1TiB
 *
 * Reserved via mmap(MAP_ANON); macOS demand-pages physical memory on first
 * touch, so unused pages cost nothing. The slab is mapped RWX to
 * Hypervisor.framework; fine-grained permissions are enforced by the guest's
 * own page tables built from mem_region descriptors. Page tables can be
 * extended at runtime (e.g. when mmap/brk grows beyond initial mappings).
 */

#pragma once

#include <Hypervisor/Hypervisor.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* The guest slab and the shim_data block are plain byte-addressed mappings
 * whose layout the guest ABI fixes, so the words the host and the guest both
 * touch (page-table descriptors, the shim_data identity and urandom slots, the
 * vvar seqlock, a futex word) cannot be declared _Atomic. The host reaches them
 * by casting to _Atomic T *, which holds only while _Atomic T is laid out like
 * T and is lock-free: a lock-based atomic would take a host-side lock the
 * guest's LDAR/STLR in shim.S cannot see, and the two sides would order against
 * different things. Both properties are toolchain-dependent, so assert them
 * rather than assume them.
 */
_Static_assert(sizeof(_Atomic uint8_t) == sizeof(uint8_t) &&
                   _Alignof(_Atomic uint8_t) == _Alignof(uint8_t) &&
                   ATOMIC_CHAR_LOCK_FREE == 2,
               "8-bit atomics must match plain uint8_t and be lock-free");
_Static_assert(sizeof(_Atomic uint32_t) == sizeof(uint32_t) &&
                   _Alignof(_Atomic uint32_t) == _Alignof(uint32_t) &&
                   ATOMIC_INT_LOCK_FREE == 2,
               "32-bit atomics must match plain uint32_t and be lock-free");
_Static_assert(sizeof(_Atomic uint64_t) == sizeof(uint64_t) &&
                   _Alignof(_Atomic uint64_t) == _Alignof(uint64_t) &&
                   ATOMIC_LLONG_LOCK_FREE == 2,
               "64-bit atomics must match plain uint64_t and be lock-free");

/* Memory layout constants.
 *
 * Guest memory size is determined dynamically from the VM's IPA width (36-bit =
 * 64GiB on M2, 40-bit = 1TiB on M3+). See guest.c for the runtime probe that
 * selects the correct size.
 *
 * Infrastructure layout (page-table pool, shim code, shim data): a 16MiB
 * reserve placed just below g->interp_base, in the dead zone between
 * g->mmap_limit and g->interp_base. The exact base is computed at guest_init
 * time and stored in guest_t.pt_pool_base / pt_pool_end / shim_base /
 * shim_data_base. EL0 user binaries are therefore free to load at low addresses
 * (down to 64KiB) without colliding with the runtime.
 *
 * The reserve is demand-paged (MAP_ANON): unused page-table-pool pages cost no
 * host RAM, and the whole reserve consumes a negligible slice of the ~4 GiB
 * dead zone, so the pool is sized generously and gets every byte not spoken for
 * by the null guard, the shim code, and the shim data. Each split 2MiB block
 * draws one 4KiB L3 page from the pool and the bump allocator never reclaims
 * it, so a ~13.9MiB pool (3558 pages, ~7 GiB of split address space) hosts the
 * many V8 isolates a Node worker_threads pool / cluster spins up; a 960KiB pool
 * exhausted after only ~3 isolates and hard-aborted the guest. See
 * issue-pt-pool-exhaustion.md.
 *
 * The shim code slot is tight (40KiB, ~6x the ~7KiB shim blob) rather than a
 * round 1MiB so the freed space falls through to the pool; main.c
 * _Static_asserts the real shim blob fits, and bootstrap.c re-checks at load.
 *
 * Internal layout within the 16MiB reserve:
 *   +0x0000000 .. +0x0010000  unused (64KiB null guard)
 *   +0x0010000 .. +0x0DF6000  page-table pool (~13.9MiB, RW)
 *   +0x0DF6000 .. +0x0E00000  shim code slot (40KiB, RX). Sits in the same
 *                             2MiB L2 block as the PT pool tail, so that block
 *                             is split into 4KiB L3 pages (mixed RX/RW).
 *   +0x0E00000 .. +0x1000000  shim data + EL1 stack (full 2MiB L2 block, RW)
 *
 * Invariant: shim_data occupies the top 2MiB block of the reserve, so
 * INFRA_SHIM_DATA_OFF == INFRA_RESERVE - BLOCK_2MIB and shim_data_base +
 * BLOCK_2MIB == interp_base. The PT pool ends where the shim code slot begins
 * (INFRA_PT_POOL_END_OFF == INFRA_SHIM_OFF), and the slot is INFRA_SHIM_SLOT ==
 * INFRA_SHIM_DATA_OFF - INFRA_SHIM_OFF wide.
 */

/* Total size of the runtime infrastructure reserve. Shifted to [g->interp_base
 * - INFRA_RESERVE, g->interp_base) at guest_init.
 */
#define INFRA_RESERVE 0x01000000ULL         /* 16MiB */
#define INFRA_PT_POOL_OFF 0x00010000ULL     /* PT pool start */
#define INFRA_PT_POOL_END_OFF 0x00DF6000ULL /* pool end == shim base */
#define INFRA_SHIM_OFF 0x00DF6000ULL        /* shim code slot base */
#define INFRA_SHIM_DATA_OFF 0x00E00000ULL   /* shim data block base */
/* Shim slot width; main.c _Static_asserts the shim blob fits. */
#define INFRA_SHIM_SLOT (INFRA_SHIM_DATA_OFF - INFRA_SHIM_OFF)
#define ELF_DEFAULT_BASE 0x00400000ULL /* Typical ELF load base */
#define PIE_LOAD_BASE 0x00400000ULL    /* PIE (ET_DYN) executable base (4MiB) */
#define BRK_BASE_DEFAULT 0x01000000ULL /* Default brk start (16MiB) */

/* 8MiB stack (four 2MiB blocks); unused HVF backing pages consume no RAM. */
#define STACK_SIZE 0x00800000ULL

/* Used when brk_start is below 128MiB; otherwise placed above brk. */
#define STACK_TOP_DEFAULT 0x08000000ULL
#define STACK_GUARD_SIZE 0x00001000ULL /* 4KiB guard at stack bottom */

/* mmap RX region for PROT_EXEC; placed below 8GiB to leave the high mmap region
 * clear for runtimes that demand a specific minimum heap address.
 */
#define MMAP_RX_BASE 0x10000000ULL

/* Initial pre-mapped mmap RX end. Only covers the first 2MiB block; additional
 * pages are mapped lazily by guest_extend_page_tables() when sys_mmap needs
 * more PROT_EXEC space. Reduces startup time and memory pressure for small
 * binaries that never call mmap.
 */
#define MMAP_RX_INITIAL_END (MMAP_RX_BASE + 0x200000ULL) /* +2MiB */

/* mmap RW region starts at 8GiB to match real Linux address layouts. */
#define MMAP_BASE 0x200000000ULL

/* Initial pre-mapped mmap RW end. Only covers the first 2MiB block; additional
 * pages are mapped lazily by guest_extend_page_tables().
 */
#define MMAP_INITIAL_END (MMAP_BASE + 0x200000ULL) /* +2MiB */

/* mmap_limit and interp_base are computed dynamically from guest_size in main.c
 * and stored in guest_t.
 */
#define BLOCK_2MIB (2ULL * 1024 * 1024)

/* IPA base: guest memory is mapped at this IPA in the hypervisor. All guest
 * physical addresses = GUEST_IPA_BASE + offset. Must be 0 so that guest virtual
 * addresses match ELF link addresses (e.g. 0x400000). A non-zero IPA base would
 * require all ELF binaries to be linked at IPA_BASE+vaddr, which is
 * impractical.
 */
#define GUEST_IPA_BASE 0x0ULL

/* Kernel-VA window for x86_64-via-Rosetta guests.
 *
 * Rosetta issues MAP_FIXED at bits-63-set addresses (0xFFFFFFFFF0000000+) for
 * its internal kernel-VA allocations. With EPD1=1 (default TCR), TTBR1 walks
 * are disabled and such VAs fault. The kbuf window enables TTBR1, backs a 256
 * MiB region in the primary buffer at kbuf_gpa, and installs an L0[511]/
 * L1[511]/L2[384..511] page-table tree.
 *
 * KBUF_USER_VA is the bits-47:0 alias used by rosetta's TaggedPointer
 * extraction (which strips bits 63:48). Mapping the SAME physical kbuf pages at
 * both KBUF_VA_BASE under TTBR1 and KBUF_USER_VA under TTBR0 lets a single
 * physical region service both views.
 *
 * Aliasing-proof invariant: the kbuf is RW under both mappings; nothing
 * executable is ever installed inside [kbuf_gpa, kbuf_gpa + KBUF_SIZE). The
 * aliased VAs are leaf data only, so HVF's per-mapping W^X enforcement cannot
 * create a writable-and-executable race. Future kbuf writers must keep the
 * pages RW-only; an executable kbuf alias would violate the invariant.
 */
#define KBUF_VA_BASE \
    0xFFFFFFFFF0000000ULL       /* TTBR1 kernel-VA base (last 256 MiB) */
#define KBUF_SIZE 0x10000000ULL /* 256 MiB */
#define KBUF_USER_VA (KBUF_VA_BASE & 0x0000FFFFFFFFFFFFULL) /* TTBR0 mirror */

/* Page table attributes. Memory region permission flags */
#define MEM_PERM_R (1 << 0)
#define MEM_PERM_W (1 << 1)
#define MEM_PERM_X (1 << 2)

/* AP[2:1]=00: privileged-only (no EL0 read/write). Combine with MEM_PERM_R/W.
 * Used for shim_data so the guest cannot directly read or store to the identity
 * cache, urandom bitmap, ring, or attention flag. The EL1 shim still has full
 * RW. EL0 reads/writes fault to the EL0-fault path (SIGSEGV in the guest),
 * matching what Linux does for kernel-only pages exposed in /proc/self/maps .
 */
#define MEM_PERM_EL1_ONLY (1 << 3)
#define MEM_PERM_RX (MEM_PERM_R | MEM_PERM_X)
#define MEM_PERM_RW (MEM_PERM_R | MEM_PERM_W)
#define MEM_PERM_RW_EL1_ONLY (MEM_PERM_R | MEM_PERM_W | MEM_PERM_EL1_ONLY)

/* A contiguous region of guest memory to be mapped in page tables.
 *
 * Default mode (va_base == 0): identity-mapped, VA == GPA. Used by every boot
 * region (shim, vDSO, brk, stack) and every aarch64 ELF segment.
 *
 * Rosetta segments use va_base != 0 to install a non-identity mapping: the
 * rosetta ELF is statically linked at 0x800000000000 (128 TiB) but its bytes
 * live in the primary buffer at a low GPA. Page-table entries are indexed by
 * va_base + (offset within region) and emit a block descriptor whose output
 * address is gpa_start + (offset within region). This is the only place in
 * elfuse where guest VA diverges from guest GPA.
 */
typedef struct {
    uint64_t gpa_start; /* Output GPA / IPA (2MiB aligned) */
    uint64_t gpa_end;   /* Output GPA / IPA end (exclusive, 2MiB aligned) */
    uint64_t
        va_base; /* 0 for identity, else the guest VA the region appears at */
    int perms;   /* MEM_PERM_* flags */
} mem_region_t;

/* Semantic region tracking. */

/* Maximum number of tracked memory regions (heap/stack/mmap/ELF/etc.). Adjacent
 * anonymous regions with matching permissions are automatically coalesced (see
 * regions_mergeable in core/guest.c). Threaded runtimes create many thread
 * stacks with guard pages; with coalescing, typical workloads use ~50 regions.
 * 4096 provides ample headroom for edge cases (many interleaved guard pages,
 * file-backed mappings, etc.).
 */
#define GUEST_MAX_REGIONS 4096

/* Preannounced regions appear only in /proc/self/maps and are NOT consulted by
 * mmap / mprotect / munmap conflict checks. Used for runtimes such as Rosetta
 * that snapshot a code map from /proc/self/maps before they reserve or remap
 * their own address ranges via MAP_FIXED_NOREPLACE.
 */
#define GUEST_MAX_PREANNOUNCED 16

/* HVF stage-2 mapping segment. The slab is mapped to HVF in pieces so that
 * file-backed MAP_SHARED regions can have real host-VA overlays applied via
 * mmap MAP_FIXED|MAP_SHARED of a file fd. HVF requires hv_vm_unmap to target an
 * exactly-previously-mapped range; sub-range unmap of a larger map fails with
 * HV_BAD_ARGUMENT. To allow a 2 MiB-aligned middle range to be unmapped +
 * remapped (refreshing HVF stage-2 caching after a host mmap MAP_FIXED), the
 * slab is split into 2 MiB-aligned segments around each affected block. All
 * segments are 2 MiB-aligned and 2 MiB-sized at minimum.
 *
 * 256 segments is generous: each MAP_SHARED file mmap costs at most 2 new
 * segments (left/right of the carved block), and most workloads keep that count
 * well under 50.
 */
typedef struct {
    uint64_t ipa; /* 2 MiB-aligned IPA start */
    uint64_t len; /* 2 MiB-aligned length */
} hvf_segment_t;

#define GUEST_MAX_HVF_SEGMENTS 256

/* A semantic memory region tracked for munmap/mprotect and /proc/self/maps.
 * Distinct from mem_region_t which is used purely for page table construction.
 * Regions are kept sorted by start address in guest_t.regions[].
 */
typedef struct {
    uint64_t start;    /* GPA start for gap-finder (page-aligned) */
    uint64_t end;      /* GPA end (exclusive, page-aligned) */
    uint64_t gpa_base; /* Backing GPA corresponding to start. Equals start for
                        * identity-mapped regions; differs for high-VA guest
                        * mappings whose VA and GPA diverge.
                        */
    uint64_t vma_id;   /* Stable logical-VMA lineage. Tracker splits and
                        * mremap moves preserve it; compatible same-generation
                        * mappings may share it when the tracker coalesces
                        * them. Unlike inherited_at_fork, this ID remains
                        * meaningful across subsequent forks.
                        */
    int prot;          /* LINUX_PROT_* flags */
    int flags;         /* LINUX_MAP_* flags (for /proc/self/maps display) */
    uint64_t offset;   /* File offset (for /proc/self/maps display) */
    int backing_fd;    /* Duplicated host fd for file-backed mappings, or -1 */
    bool shared;       /* MAP_SHARED (writes should propagate) */
    bool noreserve;    /* Lazy region: PTEs and zeroing deferred until first
                        * touch. Set for MAP_NORESERVE and for all private
                        * anonymous mappings (sys_mmap folds the latter into
                        * the tracked MAP_NORESERVE bit; not guest visible).
                        */
    bool backing_ro;   /* MAP_SHARED region whose backing_fd was opened
                        * without write access, so its Linux max_prot is
                        * capped to PROT_READ. sys_mprotect must reject any
                        * later PROT_WRITE request against it with EACCES,
                        * matching a real kernel's VMA max_prot tracking.
                        */
    bool inherited_at_fork; /* Region existed at the most recent fork
                             * snapshot. Used by synthetic smaps to report
                             * only VMAs that can participate in that fork's
                             * CoW snapshot as Shared_Dirty.
                             */
    bool overlay_active; /* Region has a live host MAP_FIXED|MAP_SHARED overlay
                          * of backing_fd at host_base+start. The kernel's page
                          * cache keeps it coherent with the file and with peer
                          * overlays of the same file, so msync skips the
                          * snapshot-style pwrite-the-diff and refresh-from-file
                          * paths for these regions.
                          */
    uint64_t overlay_start; /* Host-page-aligned overlay start. May extend
                             * outside [start, end) when only part of a host
                             * page is guest-visible.
                             */
    uint64_t overlay_end;   /* Host-page-aligned overlay end (exclusive). */
    char name[64];          /* Label: "[heap]", "[stack]", ELF path, etc. */
} guest_region_t;

/* TLB invalidation request kinds. After every page-table modification, the shim
 * flushes the TLB on syscall return. The host accumulates the smallest
 * sufficient request across the syscall and emits it via the X8/X9/X10 register
 * channel. Kind values are an internal enum independent of the X8 wire codes;
 * the syscall epilogue does the mapping (src/syscall/syscall.c holds the
 * canonical table):
 *   TLBI_NONE      -> X8 = 0  (no TLB flush)
 *   TLBI_BROADCAST -> X8 = 1  (TLBI VMALLE1IS, broadest)
 *   TLBI_RANGE     -> X8 = 3, X9 = start VA, X10 = page count
 *                     (TLBI VAE1IS loop preserves unrelated TLB entries)
 *   TLBI_RANGE_LARGE -> X8 = 4, X9 = encoded range operand
 *                       (single TLBI RVAE1IS)
 * X8 = 2 is reserved for the execve drop-frame marker the shim handles
 * separately; it is never produced by the accumulator.
 */
typedef enum {
    TLBI_NONE = 0,
    TLBI_BROADCAST = 1,
    TLBI_RANGE = 2,
    TLBI_RANGE_LARGE = 3, /* FEAT_TLBIRANGE single-shot TLBI RVAE1IS for
                           * ranges that exceed TLBI_SELECTIVE_MAX_PAGES but
                           * stay within TLBI_RVAE_MAX_PAGES; encoded as
                           * X8 = 4 on the wire.
                           */
} tlbi_kind_t;

/* Cap selective per-page TLBI VAE1IS at this many 4 KiB pages. Beyond this, use
 * TLBI RVAE1IS if FEAT_TLBIRANGE is available, else fall back to
 * TLBI_BROADCAST: per-instruction issue cost outweighs the benefit once the
 * range is large. 16 pages == 64 KiB covers RELRO and other typical mprotect /
 * munmap targets.
 */
#define TLBI_SELECTIVE_MAX_PAGES 16

/* Cap single-shot TLBI RVAE1IS at this many 4 KiB pages. SCALE=0 covers up to
 * 64 pages, SCALE=1 up to 2048 pages, and SCALE=2 much larger ranges. 32768
 * pages (128 MiB) covers the lazy fault-around window with one instruction
 * while still fitting tlbi_request_t.pages in uint16_t.
 */
#define TLBI_RVAE_MAX_PAGES 32768

/* TLBI RVAE1IS operand bit-field constants. Per ARM ARM DDI 0487J.a D8.7.6 the
 * operand layout is:
 *   bits [36:0]   BaseADDR  (VA[48:12] for 4 KiB granule, DS=0)
 *   bits [38:37]  TTL       (0 = any level)
 *   bits [43:39]  NUM
 *   bits [45:44]  SCALE
 *   bits [47:46]  TG        (00 = RESERVED, 01 = 4 KiB, 10 = 16 KiB,
 *                            11 = 64 KiB)
 *   bits [63:48]  ASID
 * elfuse only ever issues 4 KiB-granule TLBIs (TCR_EL1.TG0 = 4 KiB), so TG is
 * hard-pinned to 01 and the corresponding bit is named here.
 */
#define RVAE_OPERAND_BADDR_MASK ((1ULL << 37) - 1)
#define RVAE_OPERAND_NUM_SHIFT 39
#define RVAE_OPERAND_SCALE_SHIFT 44
#define RVAE_OPERAND_TG_4KB (1ULL << 46)

/* Pure encoder: build the TLBI RVAE1IS Xt operand from a 4 KiB-aligned VA and a
 * page count in the supported SCALE=0..2 range. Lives in the header so the
 * emit path and host unit tests use the same expression. Each NUM step covers
 * 2^(5*SCALE+1) pages; the normalizer aligns and widens callers to that unit.
 * pages < 2 is clamped to 2 because SCALE=0 NUM=0 is the smallest encodable
 * range. Single-page callers normally use VAE1IS instead.
 */
static inline uint64_t tlbi_rvae_unit_pages(uint64_t pages)
{
    if (pages <= 64)
        return 2; /* SCALE=0 */
    if (pages <= 2048)
        return 64; /* SCALE=1 */
    return 2048;   /* SCALE=2 */
}

static inline uint64_t tlbi_rvae1is_operand(uint64_t start_va, uint16_t pages)
{
    if (pages < 2)
        pages = 2;
    uint64_t scale = pages <= 64 ? 0 : (pages <= 2048 ? 1 : 2);
    uint64_t unit_pages = 1ULL << (5 * scale + 1);
    uint64_t baddr = (start_va >> 12) & RVAE_OPERAND_BADDR_MASK;
    uint64_t num = ((pages + unit_pages - 1) / unit_pages) - 1;
    if (num > 31)
        num = 31;
    return baddr | (num << RVAE_OPERAND_NUM_SHIFT) |
           (scale << RVAE_OPERAND_SCALE_SHIFT) | RVAE_OPERAND_TG_4KB;
}

/* Runtime feature flag: TRUE when the host PE implements FEAT_TLBIRANGE
 * (ARMv8.4+, present on every Apple Silicon M1+). Probed once at bootstrap.
 * Read-only after startup so callers do not need an atomic load.
 */
extern bool g_tlbi_range_supported;

typedef struct {
    uint8_t kind;         /* tlbi_kind_t */
    uint8_t icache_flush; /* 1 = the change introduced executable content
                           *     visible to EL0, so the shim must IC IALLU
                           *     after the TLBI sequence. 0 = data-only
                           *     change, skip the I-cache invalidation. */
    uint16_t pages;       /* Page count for either range kind (1..MAX) */
    uint64_t start;       /* Page-aligned VA for either range kind */
} tlbi_request_t;

/* Layout contract: 16 bytes (1+1+2+4 padding+8). Documents the padding and pins
 * the TLS slot size so future field additions surface as a build break rather
 * than silently growing the per-vCPU footprint.
 */
_Static_assert(sizeof(tlbi_request_t) == 16,
               "tlbi_request_t must stay 16 bytes; update tlbi_request_clear "
               "and the syscall epilogue if the layout changes");

/* Multi-region IPA mapping.
 *
 * The primary buffer is identity-mapped at IPA 0 and covers the low IPA range
 * (typically 64 GiB on M1, 1 TiB on M3+). Anything that lives above that --
 * notably rosetta's statically-linked segments at 128 TiB -- needs its own
 * Stage-2 mapping installed via a separate hv_vm_map. Each such region is
 * recorded in guest_t.mappings[] so guest_ptr / gva_resolve can translate
 * page-table-walk results that land outside the primary buffer.
 *
 * macOS user-space cannot directly mmap at host VA 128 TiB, so the host VA is
 * unrelated to the guest IPA. The mapping records both.
 */
#define GUEST_MAX_MAPPINGS 8
typedef struct {
    uint64_t gpa;      /* IPA where the mapping is installed (Stage-2 base) */
    void *host_va;     /* Host virtual address backing the IPA range */
    size_t size;       /* Bytes covered (always page-aligned) */
    uint32_t hv_perms; /* HV_MEMORY_READ/WRITE/EXEC bitmask used at map time */
    bool owns_host;    /* True if host_va was allocated by guest_add_mapping */
} guest_mapping_t;

/* Overflow segment for incremental GPA expansion.
 *
 * The primary buffer's mmap pool is large by aarch64 standards (56 GiB on M1,
 * 1016 GiB on M3+) but rosetta JIT/PIE/slab traffic at 85 TB / 240 TB issues
 * many 2 MiB blocks that consume the pool quickly on hosts where Stage-2 caps
 * the primary buffer at 36-bit IPA. Overflow segments are 1 GiB host buffers
 * mapped at IPAs stacked just above guest_size; a bump allocator hands out 2
 * MiB blocks. New segments are created lazily so untouched overflow costs
 * nothing.
 */
#define GUEST_MAX_OVERFLOW 4
#define GUEST_OVERFLOW_SIZE                          \
    (1ULL * 1024 * 1024 * 1024) /* 1 GiB per segment \
                                 */
typedef struct {
    void *host_base;    /* Host buffer backing the IPA range */
    uint64_t ipa_start; /* Stage-2 IPA of this segment */
    uint64_t size;      /* Total bytes (always GUEST_OVERFLOW_SIZE today) */
    uint64_t next;      /* Bump offset; (next + BLOCK_2MIB) > size means full */
} guest_overflow_t;

/* One conservative "may contain nonzero bytes" bit per 2 MiB primary-slab
 * block. The largest supported slab is 1 TiB, so this costs 64 KiB per guest.
 * All access is serialized by mmap_lock.
 */
#define GUEST_DIRTY_BLOCKS_MAX ((1ULL << 40) / BLOCK_2MIB)
#define GUEST_DIRTY_WORDS (GUEST_DIRTY_BLOCKS_MAX / 64)

enum {
    GUEST_MATERIALIZE_CLEAN_SKIP = 0,
    GUEST_MATERIALIZE_DIRTY_MEMSET,
    GUEST_MATERIALIZE_ALREADY_VALID,
    GUEST_MATERIALIZE_WINDOW_BYTES,
    GUEST_MATERIALIZE_STATS_N,
};

/* Dirty-block zeroing claims. A claim makes its block's invalid PTE window
 * stable while the expensive host memset runs without mmap_lock. Waiters use
 * one guest-wide condition variable; the fixed table bounds host allocation
 * and is ample for the vCPU limit.
 */
#define GUEST_MATERIALIZE_CLAIMS 64
typedef struct {
    uint64_t start, end;
    bool active;
} guest_materialize_claim_t;

/* Guest state. */
typedef struct {
    void *host_base; /* Host pointer to allocated guest memory */
    int shm_fd; /* File fd backing host_base for CoW fork (-1 if MAP_ANON) */

    uint64_t guest_size; /* Total size (determined by IPA capacity) */
    uint64_t ipa_base;   /* IPA base for hv_vm_map (GUEST_IPA_BASE) */
    uint64_t mmap_limit; /* Max mmap address (computed from guest_size) */

    uint64_t interp_base; /* Dynamic linker load base (from guest_size) */

    /* Runtime-infrastructure reserve. Computed at guest_init time and placed at
     * [interp_base - INFRA_RESERVE, interp_base). All four values are derived
     * from the same base, so the inequalities
     *   pt_pool_base < pt_pool_end <= shim_base < shim_data_base
     * always hold, and shim_data_base + BLOCK_2MIB == interp_base.
     */
    uint64_t pt_pool_base;   /* Page-table pool start (high IPA) */
    uint64_t pt_pool_end;    /* Page-table pool end (exclusive) */
    uint64_t shim_base;      /* Shim code (2MiB block, RX) */
    uint64_t shim_data_base; /* Shim stack/data (2MiB block, RW) */

    uint64_t pt_pool_next; /* Next free page table page in pool */
    /* Lowest virtual address of the loaded ELF (executable image, not the
     * dynamic linker). Set by bootstrap and re-set by execve. Used by the
     * legacy fork IPC path to bound the ELF + brk copy chunk; it must cover
     * ET_EXECs linked below ELF_DEFAULT_BASE (e.g. 0x200000).
     */
    uint64_t elf_load_min;
    uint64_t brk_base;    /* Initial brk (set after ELF load) */
    uint64_t brk_current; /* Current brk position */
    uint64_t stack_base;  /* Bottom of stack region (dynamic, above brk) */
    uint64_t stack_top;   /* Top of stack (stack grows down from here) */
    uint64_t start_stack; /* Initial userspace SP for /proc/<pid>/stat */

    uint64_t mmap_next; /* RW mmap high-water mark for fork IPC snapshots */
    uint64_t mmap_end;  /* Current page-table-covered RW mmap limit */
    /* RX mmap high-water mark serialized through fork IPC. */
    uint64_t mmap_rx_next;
    uint64_t mmap_rx_end; /* Current page-table-covered RX mmap limit */
    /* Gap-finder allocator hints. First free GPA past the last successful mmap
     * in each region; munmap and mremap rewind the hint when a lower address is
     * freed. mprotect does not, since permission changes do not free address
     * space. Per-guest so multi-guest test harnesses (or any future second VM
     * in the same process) cannot cross-pollute each other's allocator state.
     */
    uint64_t mmap_rw_gap_hint, mmap_rx_gap_hint;

    uint64_t ttbr0; /* TTBR0 value (IPA of L0 page table) */
    uint64_t ttbr1; /* TTBR1 value (IPA of L0 kernel page table; 0 if unused) */
    hv_vcpu_t vcpu; /* vCPU handle */
    bool vcpu_valid; /* Handle value zero is valid; track ownership separately.
                      */
    hv_vcpu_exit_t *exit; /* vCPU exit info */
    uint32_t ipa_bits;    /* IPA bits requested from HVF */

    /* x86_64-via-Rosetta state. All zero for aarch64 guests. Populated when the
     * rosetta feature flag is on and an EM_X86_64 binary is loaded. Survives
     * guest_reset so execve of another x86_64 binary keeps the same placement
     * and kbuf wiring.
     *
     *   rosetta_guest_base : Stage-2 GPA where rosetta segments are installed
     *                        via guest_add_mapping (typically 128 TiB).
     *   rosetta_va_base    : Guest virtual base where rosetta is loaded
     *                        (matches its static link address, 0x800000000000).
     *   rosetta_size       : Total bytes covering all rosetta PT_LOAD segments.
     *   rosetta_entry      : Rosetta ELF entry point (high VA).
     *   kbuf_gpa           : Stage-2 GPA backing the kbuf window inside the
     *                        primary buffer (256 MiB, 2 MiB-aligned).
     *   kbuf_base          : Host pointer to the kbuf, == host_base+kbuf_gpa.
     *                        The guest VA for the kernel mirror is the fixed
     *                        constant KBUF_VA_BASE; the user-VA alias is the
     *                        derived constant KBUF_USER_VA.
     */
    bool is_rosetta;
    uint64_t rosetta_guest_base;
    uint64_t rosetta_va_base;
    uint64_t rosetta_size;
    uint64_t rosetta_entry;
    uint64_t kbuf_gpa;
    void *kbuf_base;

    /* Extra IPA mappings installed via hv_vm_map at a non-zero GPA. Consulted
     * by gva_resolve when the page-table walk yields a GPA outside the primary
     * buffer (gpa >= guest_size). Cleared on guest_init; preserved across
     * guest_reset because rosetta placement is stable across execve.
     */
    guest_mapping_t mappings[GUEST_MAX_MAPPINGS];
    int n_mappings;

    /* Overflow segments. noverflow grows from 0 lazily as guest_overflow_alloc
     * runs out of bump space. overflow_ipa_next tracks the next free IPA
     * stacked above guest_size; initialized in guest_init to g->guest_size.
     */
    guest_overflow_t overflow[GUEST_MAX_OVERFLOW];
    int noverflow;
    uint64_t overflow_ipa_next;

    /* Semantic region tracking for munmap/mprotect/proc-self-maps */
    guest_region_t regions[GUEST_MAX_REGIONS];
    int nregions;         /* Number of active regions */
    uint64_t next_vma_id; /* Last logical-VMA lineage ID allocated. */
    /* Sticky flag set when guest_region_set_prot could not honor a request
     * because the region table was full. After this point the tracker no longer
     * faithfully reflects PTE state, so the mprotect fast path must fall back
     * to unconditional PTE work. Propagated across fork IPC with the semantic
     * region snapshot so children inherit the same fast-path guard as the
     * parent.
     */
    bool regions_tracker_stale;
    guest_region_t preannounced[GUEST_MAX_PREANNOUNCED];
    int npreannounced; /* /proc/self/maps-only shadow regions */

    /* HVF stage-2 segment list: the union of segments[0..n_segments) covers the
     * live IPA range that is currently hv_vm_map'd to HVF. Sorted by ipa.
     * Initially one segment spans the whole slab. See guest.h header comment on
     * hvf_segment_t for the rationale.
     */
    hvf_segment_t segments[GUEST_MAX_HVF_SEGMENTS];
    int n_segments;

    /* Page table generation counter: incremented on every PT modification. Used
     * by the per-thread GVA TLB cache to detect stale entries. 64-bit to avoid
     * wrap-around stale hits over long-running sessions.
     */
    _Atomic uint64_t pt_gen;

    uint64_t dirty_blocks[GUEST_DIRTY_WORDS];
    uint64_t materialize_stats[GUEST_MATERIALIZE_STATS_N];
    guest_materialize_claim_t materialize_claims[GUEST_MATERIALIZE_CLAIMS];
    pthread_cond_t materialize_cond;

    /* Optional HVC 6 embedder extension hook.
     *
     * Native AArch64 guests reach this through HVC 6. When the build enables
     * ELFUSE_NR_EMBEDDER_HVC6, translated Rosetta guests may reach the same
     * handler through a private pseudo-syscall gated on g->is_rosetta.
     *
     * Handler implementations must treat call_nr and args as untrusted guest
     * input and allowlist supported call numbers.
     *
     * The handler may be invoked concurrently from multiple host threads once
     * the guest becomes multi-threaded, so implementations must be thread-safe.
     *
     * The hook is process-local and does not survive fork(). elfuse implements
     * fork via posix_spawn() of a fresh process, so the child must register its
     * own handler during bootstrap.
     */
    uint64_t (*hvc6_handler)(uint64_t call_nr,
                             const uint64_t args[8],
                             void *userdata);
    void *hvc6_userdata;
} guest_t;

/* Bump the page table generation counter (call after any PT modification). This
 * invalidates all per-thread GVA TLB caches.
 */
static inline void guest_pt_gen_bump(guest_t *g)
{
    atomic_fetch_add_explicit(&g->pt_gen, 1, memory_order_release);
}

/* TLB invalidation request helpers.
 *
 * Per-vCPU TLS slot. Each guest thread (= one host pthread + one HVF vCPU)
 * accumulates its own pending TLBI request as its syscall handlers mutate the
 * page tables. The syscall epilogue (src/syscall/syscall.c) reads its own
 * thread's slot, emits the X8/X9/X10 protocol, and clears it.
 *
 * Why per-vCPU and not a guest_t-global accumulator: a global slot lets one
 * vCPU's syscall epilogue drain (and clear) another vCPU's pending request
 * before that vCPU has eret'd back to EL0, allowing the second vCPU to use a
 * stale TLB until the broadcast TLBI from the first vCPU's shim catches up. A
 * per-vCPU slot makes each thread strictly responsible for issuing the TLBI for
 * its own changes before its own eret. Page-table changes are still global
 * (guest memory and page tables are shared), but TLBI VAE1IS and TLBI VMALLE1IS
 * in the inner-shareable domain broadcast to all PEs, so one vCPU's own TLBI is
 * sufficient to invalidate stale entries on its own PE before resuming guest
 * code.
 *
 * No locking is needed for the slot itself; only the owning thread reads or
 * writes it. Page-table updates remain serialized by mmap_lock.
 *
 * Cross-vCPU shootdown window: between vCPU A releasing mmap_lock at the end of
 * an mprotect/munmap and the shim on A issuing the TLBI, sibling vCPU B may
 * continue executing EL0 code that hits A's now-stale TLB entries. Real Linux
 * closes this with cross-CPU IPI synchronization in the kernel; user-space
 * emulation on Hypervisor.framework cannot inject a synchronous IPI into a
 * sibling vCPU thread, so the window remains. The guest is responsible for
 * serializing concurrent PT mutations against concurrent accesses (futex /
 * pthread_mutex), which is the same contract real Linux requires of
 * well-behaved multi-threaded code. A bounded-retry on stale-TLB data aborts is
 * a known hardening direction if a workload ever surfaces an actual reproducer.
 */
extern _Thread_local tlbi_request_t cpu_tlbi_req;

static inline void tlbi_request_clear(void)
{
    cpu_tlbi_req.kind = TLBI_NONE;
    cpu_tlbi_req.icache_flush = 0;
    cpu_tlbi_req.pages = 0;
    cpu_tlbi_req.start = 0;
}

static inline void tlbi_request_broadcast(void)
{
    cpu_tlbi_req.kind = TLBI_BROADCAST;
}

/* True if the accumulator is already at TLBI_BROADCAST. PT mutation helpers use
 * this to skip the per-page bounding-box bookkeeping (changed_lo / changed_hi
 * tracking and the final tlbi_request_range call) once a broadcast is already
 * promised; the inline tlbi_request_range itself short-circuits for the same
 * reason but the call-site loops still pay for the compares.
 */
static inline bool tlbi_request_is_broadcast(void)
{
    return cpu_tlbi_req.kind == TLBI_BROADCAST;
}

/* Mark that the current syscall's PT mutation introduced executable content
 * visible to EL0 (a new X mapping, or an mprotect that added MEM_PERM_X to a
 * previously-NX page). The shim consults this via X11 on syscall return to
 * decide whether IC IALLU is needed after the TLBI sequence. Data-only
 * page-table changes (mprotect RW<->R, munmap of data, etc.) leave this cleared
 * so the I-cache invalidation is skipped.
 */
static inline void tlbi_request_mark_icache(void)
{
    cpu_tlbi_req.icache_flush = 1;
}

/* Encode the pending TLBI request into the vCPU's X8/X9/X10/X11 registers for
 * the shim's post-HVC dispatch and clear the per-vCPU accumulator. Both the
 * syscall HVC #5 epilogue and the HVC #11 EL0-fault handler use this so the
 * same X8 wire codes (and X11 I-cache hint) drive every TLBI the host issues on
 * behalf of the guest. Keeping the helper inline lets the call sites compile to
 * the same switch in both files.
 */
static inline void tlbi_request_emit_to_vcpu(hv_vcpu_t vcpu)
{
    switch ((tlbi_kind_t) cpu_tlbi_req.kind) {
    case TLBI_BROADCAST:
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 1);
        hv_vcpu_set_reg(vcpu, HV_REG_X11, cpu_tlbi_req.icache_flush ? 1 : 0);
        break;
    case TLBI_RANGE:
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 3);
        hv_vcpu_set_reg(vcpu, HV_REG_X9, cpu_tlbi_req.start);
        hv_vcpu_set_reg(vcpu, HV_REG_X10, cpu_tlbi_req.pages);
        hv_vcpu_set_reg(vcpu, HV_REG_X11, cpu_tlbi_req.icache_flush ? 1 : 0);
        break;
    case TLBI_RANGE_LARGE: {
        /* Single-shot TLBI RVAE1IS for ranges above the selective cap. The
         * SCALE/NUM format and TG=01 assumption are documented at
         * tlbi_rvae1is_operand above. ASID stays 0 because the shim runs
         * single-ASID (TCR_EL1.A1=0, TTBR0 ASID=0; rosetta does not allocate a
         * separate ASID). If a future change introduces non-zero ASIDs, the
         * helper signature and the tlbi_request_t accumulator both need an ASID
         * field.
         */
        uint64_t operand =
            tlbi_rvae1is_operand(cpu_tlbi_req.start, cpu_tlbi_req.pages);
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 4);
        hv_vcpu_set_reg(vcpu, HV_REG_X9, operand);
        hv_vcpu_set_reg(vcpu, HV_REG_X11, cpu_tlbi_req.icache_flush ? 1 : 0);
        break;
    }
    case TLBI_NONE:
    default:
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 0);
        break;
    }
    tlbi_request_clear();
}

/* RVAE1IS requires BaseADDR alignment to its SCALE granule. Widen a requested
 * interval to that granule, repeating if widening crosses a SCALE threshold.
 * Over-invalidation is architecturally harmless and preserves unrelated TLB
 * entries far better than a VMALLE1IS broadcast.
 */
static inline bool tlbi_rvae_normalize(uint64_t *start, uint64_t *end)
{
    for (int pass = 0; pass < 3; pass++) {
        uint64_t pages = (*end - *start) >> 12;
        if (pages <= TLBI_SELECTIVE_MAX_PAGES)
            return true;
        uint64_t unit_pages = tlbi_rvae_unit_pages(pages);
        uint64_t unit_bytes = unit_pages << 12;
        uint64_t s = *start & ~(unit_bytes - 1);
        if (*end > UINT64_MAX - (unit_bytes - 1))
            return false;
        uint64_t e = (*end + unit_bytes - 1) & ~(unit_bytes - 1);
        *start = s;
        *end = e;
        if (((e - s) >> 12) <= unit_pages * 32)
            return ((e - s) >> 12) <= TLBI_RVAE_MAX_PAGES;
    }
    return false;
}

static inline void tlbi_request_range(uint64_t start, uint64_t end)
{
    if (cpu_tlbi_req.kind == TLBI_BROADCAST)
        return;
    if (end <= start)
        return;

    /* Page-align: TLBI VAE1IS operates on 4 KiB granules. ALIGN_UP can overflow
     * if end is within PAGE_SIZE-1 of UINT64_MAX; saturate to broadcast in that
     * pathological case rather than wrap to 0.
     */
    const uint64_t mask = 0xFFFULL;
    if (end > UINT64_MAX - mask) {
        tlbi_request_broadcast();
        return;
    }
    uint64_t s = start & ~mask;
    uint64_t e = (end + mask) & ~mask;
    uint64_t n = (e - s) >> 12;

    /* Two thresholds. (a) <= TLBI_SELECTIVE_MAX_PAGES uses the per-page VAE1IS
     * loop, which preserves the most TLB entries. (b) <= TLBI_RVAE_MAX_PAGES
     * uses a single TLBI RVAE1IS via FEAT_TLBIRANGE, which still preserves
     * unrelated TLB entries but costs only one instruction issue. Above
     * TLBI_RVAE_MAX_PAGES or when the feature is absent, broadcast (TLBI
     * VMALLE1IS).
     */
    uint64_t large_cap =
        g_tlbi_range_supported ? TLBI_RVAE_MAX_PAGES : TLBI_SELECTIVE_MAX_PAGES;
    if (g_tlbi_range_supported && n > TLBI_SELECTIVE_MAX_PAGES) {
        if (!tlbi_rvae_normalize(&s, &e)) {
            tlbi_request_broadcast();
            return;
        }
        n = (e - s) >> 12;
    }
    if (n > large_cap) {
        tlbi_request_broadcast();
        return;
    }
    if (cpu_tlbi_req.kind == TLBI_NONE) {
        cpu_tlbi_req.kind =
            (n > TLBI_SELECTIVE_MAX_PAGES) ? TLBI_RANGE_LARGE : TLBI_RANGE;
        cpu_tlbi_req.start = s;
        cpu_tlbi_req.pages = (uint16_t) n;
        return;
    }

    /* Coalesce by union. Disjoint ranges still produce a single bounding
     * interval; if it stays within the active cap, the range TLBI still wins
     * over a full flush by preserving unrelated TLB entries.
     */
    uint64_t es = cpu_tlbi_req.start;
    uint64_t pe = (uint64_t) cpu_tlbi_req.pages * 4096ULL;

    /* The accumulator only ever holds page counts <= large_cap (enforced by the
     * cap check above), so es + pe never overflows on real callers, but be
     * explicit.
     */
    if (es > UINT64_MAX - pe) {
        tlbi_request_broadcast();
        return;
    }
    uint64_t ee = es + pe;
    uint64_t us = s < es ? s : es;
    uint64_t ue = e > ee ? e : ee;
    uint64_t un = (ue - us) >> 12;
    if (g_tlbi_range_supported && un > TLBI_SELECTIVE_MAX_PAGES) {
        if (!tlbi_rvae_normalize(&us, &ue)) {
            tlbi_request_broadcast();
            return;
        }
        un = (ue - us) >> 12;
    }
    if (un > large_cap) {
        tlbi_request_broadcast();
        return;
    }
    cpu_tlbi_req.start = us;
    cpu_tlbi_req.pages = (uint16_t) un;

    /* Promote kind if the coalesced range now exceeds the per-page cap. The
     * inverse direction (LARGE -> RANGE) is impossible because un >= pe / 4096
     * after coalescing.
     */
    if (un > TLBI_SELECTIVE_MAX_PAGES)
        cpu_tlbi_req.kind = TLBI_RANGE_LARGE;
}

/* Convert a guest offset (0-based) to an IPA/VA (ipa_base + offset) */
static inline uint64_t guest_ipa(const guest_t *g, uint64_t offset)
{
    return g->ipa_base + offset;
}

/* True iff [start, end) overlaps the runtime infra reserve [interp_base -
 * INFRA_RESERVE, interp_base). Covers the full reserve including the 64 KiB
 * null-guard slot at the bottom (which has no PT entries but must not become
 * semantically reachable from guest mmap state). Used by sys_mmap (MAP_FIXED),
 * sys_munmap, and sys_mprotect to reject guest attempts to touch page tables,
 * shim code, or shim data through the syscall surface.
 */
static inline bool guest_range_hits_infra(const guest_t *g,
                                          uint64_t start,
                                          uint64_t end)
{
    uint64_t infra_lo = g->interp_base - INFRA_RESERVE;
    uint64_t infra_hi = g->interp_base;
    return start < infra_hi && end > infra_lo;
}

/* True iff a single address (PC, hint, etc.) falls inside the infra reserve.
 * Used by rt_sigreturn to reject forged frames that would redirect EL0 PC into
 * EL1 shim or page-table memory. Covers the full reserve, matching
 * guest_range_hits_infra.
 */
static inline bool guest_addr_in_infra(const guest_t *g, uint64_t addr)
{
    uint64_t infra_lo = g->interp_base - INFRA_RESERVE;
    uint64_t infra_hi = g->interp_base;
    return addr >= infra_lo && addr < infra_hi;
}

/* API */

/* Allocate guest memory, create VM, map to hypervisor. size: primary buffer
 * size (0 = auto-detect from IPA capacity). ipa_bits: IPA width for HVF VM (0 =
 * auto-detect).
 * Returns 0 on success, -1 on failure.
 */
int guest_init(guest_t *g, uint64_t size, uint32_t ipa_bits);

/* Initialize guest from a shared memory fd (CoW fork path). Creates the HVF VM
 * and maps the fd to the hypervisor. The child gets an instant CoW snapshot of
 * the parent's guest memory without copying.
 *
 * retain_shared selects the mapping: when true, shm_fd is an independent APFS
 * clone, so it is mapped MAP_SHARED and retained in g->shm_fd (guest_destroy
 * closes it) so the child can fclonefileat it for nested CoW fork. When false,
 * shm_fd may be the parent's live fd, so it is mapped MAP_PRIVATE and closed
 * after mapping. This function takes ownership of shm_fd on every path.
 * Returns 0 on success, -1 on failure.
 */
int guest_init_from_shm(guest_t *g,
                        int shm_fd,
                        uint64_t size,
                        uint32_t ipa_bits,
                        bool retain_shared);

/* Tear down VM and free guest memory. Must be terminal: the caller has to
 * proceed straight to process exit afterwards. If a worker vCPU is still live
 * past the join cap, HVF teardown cannot run safely, so guest_destroy leaks the
 * VM and slab for process exit to reclaim -- and macOS allows only one VM per
 * process, so a non-terminal caller would both leak and fail to bring up a
 * second VM. All current callers (main() cleanup, the fork-child run loop)
 * satisfy this. Remaining host-side cleanup (mounts, heap) is still safe to run
 * after a deferred teardown: it never touches HVF or guest memory.
 */
void guest_destroy(guest_t *g);

/* Install a Stage-2 mapping for a high IPA range that the primary buffer does
 * not cover (e.g. rosetta's segments at 128 TiB). Calls hv_vm_map with the
 * supplied permissions. If host_va_inout points to NULL, allocates an anon host
 * buffer of the requested size and records ownership so guest_destroy frees it.
 * Otherwise the caller-supplied host_va is mapped as-is and the mapping does
 * not own it. size and gpa must be page-aligned.
 *
 * The new region is appended to g->mappings[] for guest_ptr / gva_resolve
 * fall-through.
 *
 * Returns 0 on success, -1 if GUEST_MAX_MAPPINGS is exhausted, if the
 * allocation/mapping fails, or if the range collides with the primary buffer or
 * an existing extra mapping.
 *
 * Locking: callers MUST hold mmap_lock. gva_resolve_perm reads mappings[]
 * lock-free during page-table walks, so mutating n_mappings / mappings[] from
 * concurrent vCPUs without serialization would race.
 */
int guest_add_mapping(guest_t *g,
                      uint64_t gpa,
                      size_t size,
                      uint32_t hv_perms,
                      void **host_va_inout);

/* Tear down the Rosetta-specific guest personality: unmap the translator's
 * extra IPA mappings, clear the TTBR1/kbuf fields, and scrub the rosetta_*
 * metadata. Used when a Rosetta-launched process execve()s an aarch64 image.
 *
 * Locking: callers MUST hold mmap_lock. gva_resolve_perm reads mappings[]
 * lock-free during page-table walks.
 */
void guest_clear_rosetta_state(guest_t *g);

/* Linear scan of g->mappings[] for the entry covering gpa.
 *
 * Returns NULL if gpa is below g->guest_size (i.e. inside the primary buffer)
 * or not covered by any extra mapping.
 */
const guest_mapping_t *guest_find_mapping(const guest_t *g, uint64_t gpa);

/* Bump-allocate a 2 MiB block from the overflow segments. Lazily creates a new
 * 1 GiB segment (via mmap + hv_vm_map at g->overflow_ipa_next) when the
 * existing segments are exhausted.
 *
 * Returns the GPA of the allocated block, or UINT64_MAX if all
 * GUEST_MAX_OVERFLOW segments are full or a host/HVF allocation step failed.
 * Callers should treat UINT64_MAX as -ENOMEM.
 *
 * Locking: callers MUST hold mmap_lock. gva_resolve_perm reads overflow[]
 * lock-free during page-table walks.
 */
uint64_t guest_overflow_alloc(guest_t *g);

/* Locate the overflow segment covering gpa.
 *
 * Returns NULL if gpa is not within any overflow segment.
 */
const guest_overflow_t *guest_find_overflow(const guest_t *g, uint64_t gpa);

/* Returns true when [gpa, gpa+len) is fully contained within the primary
 * buffer, OR fully contained within a single extra mapping, OR fully contained
 * within a single overflow segment. The check rejects ranges that straddle
 * region boundaries -- host pointers cannot safely span discontiguous backing
 * regions. len == 0 returns true (zero-length ranges are well-formed by
 * convention; syscall handlers that disallow them check separately).
 *
 * Use this for syscalls that need to validate a guest IPA range without
 * coupling to the primary-buffer-only assumption: sys_mmap MAP_FIXED,
 * sys_munmap, sys_mremap, sys_mprotect, sys_msync, and any future caller that
 * handles rosetta high-VA traffic.
 */
bool guest_is_valid_range(const guest_t *g, uint64_t gpa, uint64_t len);

/* Initialize the TTBR1 kbuf window. kbuf_gpa must be 2 MiB-aligned and the
 * [kbuf_gpa, kbuf_gpa + KBUF_SIZE) range must lie within the primary buffer.
 * Allocates three page-table pages (L0/L1/L2) from the PT pool, populates
 * L0[511] -> L1, L1[511] -> L2, and L2[384..511] = 128 x 2 MiB block
 * descriptors with PT_AP_RW_EL0 | PT_UXN | PT_PXN (RW, non-executable).
 * Stores the resulting TTBR1 IPA in g->ttbr1 and sets g->kbuf_gpa /
 * g->kbuf_base. On any failure all three fields are scrubbed to 0/NULL so the
 * caller cannot read stale state.
 *
 * Returns 0 on success, -1 on alignment / bounds / PT-pool-exhaustion failure.
 *
 * Locking: callers MUST hold mmap_lock. The function mutates the PT pool and
 * the kbuf fields; gva translation reads ttbr1 lock-free.
 */
int guest_init_kbuf(guest_t *g, uint64_t kbuf_gpa);

/* Install the TTBR0 user-VA mirror of the kbuf window. Walks the existing TTBR0
 * tree (at g->ttbr0) to L0[511]/L1[511]/L2[384..511] and writes 128 x 2 MiB
 * block descriptors mapping [KBUF_USER_VA, KBUF_USER_VA + KBUF_SIZE) to
 * [g->kbuf_gpa, g->kbuf_gpa + KBUF_SIZE) with RW + UXN + PXN perms. Rosetta's
 * TaggedPointer extraction strips bits 63:48 so the same physical pages must be
 * reachable through both TTBR1 (kernel VA) and TTBR0 (the user-VA alias).
 *
 * Must be called after guest_build_page_tables (g->ttbr0 must point at a valid
 * L0 page) and after guest_init_kbuf (g->kbuf_gpa must be set).
 * Returns 0 on success, -1 on PT-pool exhaustion or invalid state.
 *
 * Locking: callers MUST hold mmap_lock.
 */
int guest_install_kbuf_user_alias(guest_t *g);

/* Install L2 block descriptors mapping [va_base, va_limit) to [gpa_start,
 * gpa_start + (va_limit-va_base)) under TTBR0. Both addresses and the size must
 * be 2 MiB-aligned. Walks the existing TTBR0 tree at g->ttbr0 and allocates
 * L1/L2 tables from the PT pool as needed.
 *
 * If an L2 slot is already populated, the function leaves it untouched and
 * continues with the next block; the caller is expected to use
 * guest_update_perms (or split + update_perms) if it needs to refine
 * permissions on an already-mapped 2 MiB block.
 *
 * Records a guest_pt_gen_bump and a TLBI request covering the new range so the
 * shim invalidates matching TLB entries on the way back to EL0.
 *
 * Returns 0 on success, -1 on alignment, PT-pool-exhaustion, or out-of-L0
 * failure. Used by sys_mmap for high-VA MAP_FIXED requests (rosetta's JIT slabs
 * at 240 TiB, code caches at 85 TiB) where the VA lives outside the primary
 * buffer but the GPA still does.
 *
 * Locking: callers MUST hold mmap_lock.
 */
int guest_map_va_range(guest_t *g,
                       uint64_t va_base,
                       uint64_t va_limit,
                       uint64_t gpa_start,
                       int perms);

/* Install (or overwrite) 4 KiB L3 page descriptors mapping [va, va+length) to
 * [gpa, gpa+length) with the requested perms. Unlike guest_update_perms, which
 * only edits existing descriptors and falls back to region metadata for invalid
 * entries, this helper always writes a fresh make_page_desc so a
 * previously-invalidated L3 slot is restored without consulting the region
 * table. Splits L2 block descriptors on the path lazily.
 *
 * All three arguments (va, length, gpa) must be PAGE_SIZE aligned. The L2 chain
 * (L0->L1->L2) must already be in place (caller's responsibility, typically via
 * a prior guest_map_va_range).
 *
 * Returns 0 on success, -1 on alignment, missing L2 chain, or PT-pool
 * exhaustion.
 *
 * Locking: callers MUST hold mmap_lock.
 */
int guest_install_va_pages(guest_t *g,
                           uint64_t va,
                           uint64_t length,
                           uint64_t gpa,
                           int perms);

/* Query whether a 2 MiB TTBR0 VA block already has any L2 entry, either a
 * block descriptor or an L3 table descriptor.
 */
bool guest_va_block_mapped(const guest_t *g, uint64_t va);

/* Returns true when the VA range [va, va+size) overlaps the user-VA kbuf alias
 * window [KBUF_USER_VA, KBUF_USER_VA+KBUF_SIZE). Callers that install TTBR0
 * mappings (the future rosetta_finalize, sys_mmap MAP_FIXED touching this
 * range, the page-table-build pass) must reject MEM_PERM_X when this helper
 * returns true: TTBR1 maps the same physical pages RW only, and an executable
 * TTBR0 alias would defeat HVF's per-mapping W^X enforcement.
 */
static inline bool guest_kbuf_user_va_overlap(uint64_t va, uint64_t size)
{
    if (size == 0)
        return false;
    uint64_t end = va + size;
    if (end < va) /* arithmetic overflow */
        end = UINT64_MAX;
    return va < (KBUF_USER_VA + KBUF_SIZE) && KBUF_USER_VA < end;
}

/* Get a host pointer for a guest virtual address (read access).
 * Returns NULL if gva is out of bounds or not readable.
 */
void *guest_ptr(const guest_t *g, uint64_t gva);

/* Like guest_ptr_avail but never triggers lazy fault-in. For callers that
 * already hold mmap_lock.
 */
void *guest_ptr_avail_nofault(const guest_t *g,
                              uint64_t gva,
                              uint64_t *avail,
                              int required_perms);

/* Materialize any lazy (deferred-PTE) blocks intersecting [gva, gva+len) so
 * later resolves under locks that rank after mmap_lock (futex buckets) do
 * not have to. Takes mmap_lock; call only from lock-free context. Returns 0
 * if anything was (or already is) materialized, -1 otherwise; callers that
 * merely pre-fault can ignore the result.
 */
int guest_lazy_faultin(const guest_t *g, uint64_t gva, uint64_t len);

/* Same as guest_lazy_faultin for callers that already hold mmap_lock (e.g.
 * SC_LOCKED syscall handlers about to guest_read/guest_write a lazy range:
 * the resolve-time hook would self-deadlock re-acquiring mmap_lock, so they
 * must materialize up front through this variant).
 */
int guest_lazy_faultin_locked(const guest_t *g, uint64_t gva, uint64_t len);

/* Smallest block-aligned va' in [va, end) whose 1GiB L1 slot is present in
 * the page tables, or end if none. Lets range walkers skip absent 1GiB /
 * 512GiB slots in O(1) instead of probing every 2MiB block. Locking: callers
 * MUST hold mmap_lock.
 */
uint64_t guest_va_next_present_block(const guest_t *g,
                                     uint64_t va,
                                     uint64_t end);

/* Get a host pointer for a guest virtual address (write access).
 * Returns NULL if gva is out of bounds or not writable.
 */
void *guest_ptr_w(const guest_t *g, uint64_t gva);

/* Get a host pointer for a guest virtual address, with available byte count.
 * *avail receives the number of contiguous bytes from gva whose page table
 * entries are valid and satisfy required_perms (MEM_PERM_R/W/X bitmask). The
 * function walks forward across adjacent L2 blocks and L3 pages until it hits
 * an invalid, permission-mismatched, or physically non-contiguous entry.
 * Returns NULL if the starting page is unmapped or lacks required_perms.
 */
void *guest_ptr_avail(const guest_t *g,
                      uint64_t gva,
                      uint64_t *avail,
                      int required_perms);

/* Get a host pointer for a guest range, capped to a caller-provided limit.
 * *avail receives the number of contiguous bytes available from gva, up to
 * len_limit.
 *
 * Returns NULL if the starting address is unmapped or lacks perms.
 */
void *guest_ptr_bound(const guest_t *g,
                      uint64_t gva,
                      uint64_t *avail,
                      int required_perms,
                      uint64_t len_limit);

/* Bounds-checked copy from guest memory to host buffer.
 * Returns 0 on success, -1 if out of bounds.
 */
int guest_read(const guest_t *g, uint64_t gva, void *dst, size_t len);

/* Optimized guest-to-host copy for small fixed-size inputs. Uses a direct guest
 * pointer when the full range is contiguous and readable, otherwise falls back
 * to guest_read() for boundary-crossing safety.
 */
int guest_read_small(const guest_t *g, uint64_t gva, void *dst, size_t len);

/* Bounds-checked copy from host buffer into guest memory.
 * Returns 0 on success, -1 if out of bounds.
 */
int guest_write(guest_t *g, uint64_t gva, const void *src, size_t len);

/* Bounds-checked copy from host buffer into guest memory, reporting how many
 * bytes landed.
 *
 * A caller whose return value is a byte count uses this instead of
 * guest_write(), which reports only whether the whole copy survived: a copy
 * that faults or leaves the mapping partway still places the bytes before that
 * point, and they are in guest memory whatever the caller reports. The count is
 * exact to the bound guest_host_copy_partial() documents.
 */
size_t guest_write_partial(guest_t *g,
                           uint64_t gva,
                           const void *src,
                           size_t len);

/* Same copy without lazy materialization. Callers that already hold mmap_lock
 * can use this after guest_lazy_faultin_locked(); an invalid destination then
 * fails instead of recursively trying to acquire mmap_lock.
 */
int guest_write_nofault(guest_t *g, uint64_t gva, const void *src, size_t len);

/* Optimized host-to-guest copy for small fixed-size outputs. Uses a direct
 * guest pointer when the full range is contiguous and writable, otherwise falls
 * back to guest_write() for boundary-crossing safety.
 */
int guest_write_small(guest_t *g, uint64_t gva, const void *src, size_t len);

/* Read a null-terminated string from guest memory. Copies up to max-1 bytes +
 * NUL into dst.
 *
 * Returns the string length, -1 if out of bounds or unterminated, or -2 when a
 * host SIGBUS hit a vanished MAP_SHARED page. The two failures differ only for
 * a caller deciding whether to retry: a -1 can be worth another attempt with a
 * bigger buffer, a -2 never is. Both are negative, so a caller testing < 0 need
 * not care.
 */
int guest_read_str(const guest_t *g, uint64_t gva, char *dst, size_t max);

/* Optimized guest string read for short, contiguous paths. Uses a direct guest
 * pointer when a full max-1-byte window is readable, otherwise falls back to
 * guest_read_str() for boundary-safe scanning.
 *
 * Returns the string length, -1 when the fast window did not apply and the
 * fallback also failed, or -2 when either took a host SIGBUS on a vanished
 * MAP_SHARED page. A caller holding a larger buffer can retry a -1 but never a
 * -2: the same address faults again. The fallback propagates its own -2, so a
 * path that straddles a page boundary is not retried either.
 */
int guest_read_str_small(const guest_t *g, uint64_t gva, char *dst, size_t max);

/* Copy between two resolved host pointers with host SIGBUS recovery armed.
 *
 * Returns the number of bytes that landed, which is len when nothing faulted
 * and less when a backing page vanished partway. Callers reporting a partial
 * transfer use this instead of guest_host_memcpy, which can only say whether
 * the whole copy survived.
 */
size_t guest_host_copy_partial(void *dst, const void *src, size_t len);

/* Build L0->L1->L2 page tables from an array of memory regions. Uses 2MiB block
 * descriptors.
 *
 * Returns the TTBR0 value (GPA of L0 table), or 0 on failure.
 */
uint64_t guest_build_page_tables(guest_t *g,
                                 const mem_region_t *regions,
                                 int n);

/* Extend page tables to cover a new address range [start, end) with 2MiB block
 * descriptors. Reuses the existing L0->L1 table structure and allocates new L2
 * tables as needed. Records a TLBI request covering the affected range (range
 * or broadcast).
 * Returns 0 on success, -1 on failure.
 */
int guest_extend_page_tables(guest_t *g,
                             uint64_t start,
                             uint64_t end,
                             int perms);

/* Split a 2MiB block descriptor into 512 x 4KiB L3 page descriptors. block_gpa
 * must be within a currently-mapped 2MiB block. The block's permissions are
 * inherited by all 512 page entries. If the block is already split (L2 entry is
 * a table descriptor), this is a no-op.
 *
 * No TLBI request is issued: the split alone preserves every VA->PA translation
 * in the block (each L3 page descriptor inherits the block's permissions).
 * Every caller follows the split with guest_invalidate_ptes or
 * guest_update_perms on the actually-changing range; that subsequent call
 * records the TLBI, and TLBI VAE1IS for any VA in the block also invalidates
 * the cached 2 MiB block entry covering that VA (ARM ARM B2.2.5.6), so a single
 * per-page TLBI suffices to retire the stale block translation as soon as any
 * affected page is accessed.
 *
 * Returns 0 on success, -1 on failure.
 */
int guest_split_block(guest_t *g, uint64_t block_gpa);

/* Invalidate page table entries for the range [start, end). Sets L2 block
 * descriptors and L3 page descriptors to 0 (invalid), causing translation
 * faults on access. Used when mprotect sets PROT_NONE; the correct behavior is
 * for the guest to fault. If a 2MiB block is only partially invalidated, the
 * block is split into L3 pages first (preserving the non-invalidated pages).
 * Records a TLBI request covering the invalidated range.
 * Returns 0 on success, -1 on failure.
 */
int guest_invalidate_ptes(guest_t *g, uint64_t start, uint64_t end);

/* Update page table permissions for the range [start, end). If a 2MiB block
 * needs mixed permissions (only part of it is being updated), the block is
 * automatically split into 4KiB L3 pages first. If the entire 2MiB block is
 * being updated, the block descriptor is modified in place without splitting.
 * perms is a MEM_PERM_R/W/X combination. Records a TLBI request only for pages
 * whose descriptor actually changed.
 * Returns 0 on success, -1 on failure.
 */
int guest_update_perms(guest_t *g, uint64_t start, uint64_t end, int perms);

/* Reset guest memory for execve. Zeros ELF, brk, stack, mmap regions and resets
 * page table pool, brk, and mmap allocation state. Preserves the host_base
 * mapping and VM/vCPU handles.
 */
void guest_reset(guest_t *g);

/* A used memory region for fork state transfer */
typedef struct {
    uint64_t offset; /* Offset from host_base (0-based) */
    uint64_t size;   /* Size in bytes */
} used_region_t;

/* Enumerate used memory regions for fork state transfer. Writes up to max
 * entries into out[].
 *
 * Returns the count written. shim_size is the shim binary size (needed to
 * determine shim region).
 */
int guest_get_used_regions(const guest_t *g,
                           unsigned int shim_size,
                           used_region_t *out,
                           int max);

/* Semantic region tracking API. */

/* Add a region to the sorted tracking array. Overlapping regions are NOT
 * merged; each call adds a distinct entry.
 *
 * Returns 0 on success, -1 if the region table is full or backing fd
 * duplication fails.
 */
int guest_region_add(guest_t *g,
                     uint64_t start,
                     uint64_t end,
                     int prot,
                     int flags,
                     uint64_t offset,
                     const char *name);
int guest_region_add_ex(guest_t *g,
                        uint64_t start,
                        uint64_t end,
                        int prot,
                        int flags,
                        uint64_t offset,
                        const char *name,
                        int backing_fd);
int guest_region_add_ex_gpa(guest_t *g,
                            uint64_t start,
                            uint64_t end,
                            uint64_t gpa_base,
                            int prot,
                            int flags,
                            uint64_t offset,
                            const char *name,
                            int backing_fd);

/* Like guest_region_add_ex, but consumes owned_backing_fd on success or
 * failure. inherited_at_fork identifies bytes copied from the latest fork
 * snapshot. vma_id preserves logical-VMA provenance across tracker splits and
 * mremap moves; pass 0 for a new VMA.
 */
int guest_region_add_ex_owned(guest_t *g,
                              uint64_t start,
                              uint64_t end,
                              int prot,
                              int flags,
                              uint64_t offset,
                              const char *name,
                              int owned_backing_fd,
                              bool inherited_at_fork,
                              uint64_t vma_id);
int guest_region_add_ex_owned_gpa(guest_t *g,
                                  uint64_t start,
                                  uint64_t end,
                                  uint64_t gpa_base,
                                  int prot,
                                  int flags,
                                  uint64_t offset,
                                  const char *name,
                                  int owned_backing_fd,
                                  bool inherited_at_fork,
                                  uint64_t vma_id);

/* Re-seed the logical-VMA allocator from a restored region snapshot. Fork IPC
 * restores regions by value, so next_vma_id must be advanced past every
 * serialized lineage before child-private mappings are added.
 */
void guest_reseed_next_vma_id(guest_t *g);

/* Add a preannounced region that appears in /proc/self/maps only. These entries
 * are kept separate from regions[] so they do not cause -EEXIST on guest
 * MAP_FIXED_NOREPLACE reservations.
 *
 * No producer wires this up today. The storage, fork-IPC, and /proc/self/maps
 * consumer are kept as scaffolding for runtimes that consult /proc/self/maps
 * before reserving VA ranges. Preannouncing the x86_64 image during Rosetta
 * bring-up was tried and rejected: it perturbed Rosetta's internal allocation
 * tracker. The hook stays until a workload needs an advertise-only entry.
 */
int guest_preannounce(guest_t *g,
                      uint64_t start,
                      uint64_t end,
                      int prot,
                      int flags,
                      uint64_t offset,
                      const char *name);

/* Reserve any backing fd needed by an interior split in [start, end). The
 * reservation must be consumed by guest_region_remove_reserved().
 * Returns 0 on success, -1 when the backing fd cannot be duplicated.
 */
int guest_region_remove_prepare(guest_t *g,
                                uint64_t start,
                                uint64_t end,
                                int *reserved_backing_fd);

/* Remove all region coverage in [start, end). Regions fully contained are
 * deleted; partially overlapping regions are trimmed or split. Any required
 * backing fd is reserved before the first metadata mutation.
 */
int guest_region_remove(guest_t *g, uint64_t start, uint64_t end);

/* Commit a removal using a backing fd reserved by
 * guest_region_remove_prepare(). Ownership of reserved_backing_fd is consumed
 * even when this call does not need an interior split.
 */
int guest_region_remove_reserved(guest_t *g,
                                 uint64_t start,
                                 uint64_t end,
                                 int reserved_backing_fd);

/* Find the region containing addr.
 *
 * Returns a pointer to the region (inside the guest_t regions array) or NULL if
 * addr is not in any tracked region.
 */
const guest_region_t *guest_region_find(const guest_t *g, uint64_t addr);

/* Update protection bits for all region coverage in [start, end). Splits
 * regions at boundaries as needed.
 */
void guest_region_set_prot(guest_t *g, uint64_t start, uint64_t end, int prot);

/* Index of the first region whose end is strictly above addr. Earlier regions
 * sort entirely below addr (regions[] is start-sorted and non-overlapping, so
 * ends are monotonic). Callers use this to skip the untouched prefix in O(log
 * n) before a linear walk over the overlap.
 */
int guest_region_first_end_above(const guest_t *g, uint64_t addr);

/* True if every tracked region overlapping [start, end) already has prot.
 * Returns true vacuously when no region overlaps the range, since callers use
 * this to decide whether page-table maintenance can be skipped and an untracked
 * sub-range has no PTEs of its own to update.
 */
bool guest_region_range_prot_uniform(const guest_t *g,
                                     uint64_t start,
                                     uint64_t end,
                                     int prot);

/* True if any tracked region overlapping [start, end) is MAP_NORESERVE. Callers
 * must run page-table maintenance for such ranges even when prot already
 * matches, because lazy materialization may have produced PTEs that need
 * re-permissioning.
 */
bool guest_region_range_has_noreserve(const guest_t *g,
                                      uint64_t start,
                                      uint64_t end);

/* True if any tracked region overlapping [start, end) is MAP_SHARED with a
 * backing_fd that lost write access (backing_ro), i.e. its Linux max_prot is
 * capped to PROT_READ. sys_mprotect uses this to reject PROT_WRITE upgrades
 * with EACCES.
 */
bool guest_region_range_has_ro_shared_backing(const guest_t *g,
                                              uint64_t start,
                                              uint64_t end);

/* Try to materialize a lazy (deferred-PTE: private anonymous or
 * MAP_NORESERVE) page at the given offset. Called from the data/instruction
 * abort handler when the faulting address falls within a lazy region, and
 * from the host-access fault-in path when a syscall targets a lazy range the
 * guest has not touched yet. Creates page table entries for one 2MiB block
 * containing the fault address. A slab block known to be clean skips zeroing;
 * a possibly-dirty block zeros invalid pages before publishing them. A block
 * that is already valid returns success without re-zeroing
 * (concurrent-fault idempotence).
 * Returns 0 on success (caller should TLBI and retry), -1 if the offset is
 * not in a lazy region or the region is PROT_NONE.
 * Locking: callers MUST hold mmap_lock.
 */
int guest_materialize_lazy(guest_t *g, uint64_t fault_offset);

/* Guest-fault variant with per-vCPU sequential fault-around. */
int guest_materialize_lazy_fault(guest_t *g, uint64_t fault_offset);

/* Dirty-map and in-flight-claim helpers. Callers hold mmap_lock. */
bool guest_block_may_be_dirty(const guest_t *g, uint64_t block_start);
void guest_dirty_mark_range(guest_t *g, uint64_t start, uint64_t end);
void guest_dirty_clear_zeroed_range(guest_t *g, uint64_t start, uint64_t end);
void guest_materialize_wait_range_locked(guest_t *g,
                                         uint64_t start,
                                         uint64_t end);
void guest_materialize_wait_all_locked(guest_t *g);

/* Whether the 4KiB page containing va has a valid stage-1 descriptor.
 * Locking: callers MUST hold mmap_lock.
 */
bool guest_va_pte_valid(guest_t *g, uint64_t va);
