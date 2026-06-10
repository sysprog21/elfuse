/* Guest memory syscalls
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest memory syscalls: brk, mmap, munmap, mprotect, mremap, madvise, msync
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

#include "debug/log.h"
#include "utils.h"

#include "runtime/thread.h"
#include "syscall/abi.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/mem.h"

/* Protects mmap/brk bump allocators and page table extension. Multiple threads
 * may call mmap/brk concurrently; without this lock they could get overlapping
 * allocations or corrupt page table structures.
 */
pthread_mutex_t mmap_lock = PTHREAD_MUTEX_INITIALIZER; /* Lock order: 1 */

/* Host kernel page size (16 KiB on Apple Silicon, typically 4 KiB on Intel
 * macOS). MAP_FIXED requires addr/length/offset multiples of this, so an
 * overlay onto a guest 4 KiB-aligned IPA is only applicable when the IPA
 * happens to land on a host page boundary; otherwise sys_mmap falls back to the
 * pread snapshot path.
 */
static size_t host_page_size_cached(void)
{
    static size_t cached;
    if (!cached) {
        long s = sysconf(_SC_PAGESIZE);
        cached = (s > 0) ? (size_t) s : 4096;
    }
    return cached;
}

/* Gap-finding allocator for mmap.
 *
 * find_free_gap_inner() scans guest_t.regions[] (sorted) for the first free gap
 * of length bytes within [min_addr, max_addr). Replaces a bump allocator so
 * munmap'd ranges become reusable (critical for runtimes that reserve, trim,
 * and re-reserve in the same address window).
 *
 * Per-guest hints (mmap_rw_gap_hint / mmap_rx_gap_hint in guest_t) amortize the
 * O(n) scan to O(1) for sequential allocations: after each success the hint is
 * set to the end of the allocation. munmap/mremap rewinds the hint when a lower
 * address is freed. Stored in guest_t so multiple guest instances in one
 * process (test harnesses, future multi-VM use) cannot cross-pollute each
 * other's allocator state. Reset to 0 by guest_init, guest_init_from_shm (via
 * memset), and guest_reset.
 */

typedef struct {
    uint64_t start, end;
} remove_range_t;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t gpa_base;
    int prot;
    int flags;
    uint64_t offset;
    int backing_fd;
    bool overlay_active;
    uint64_t overlay_start;
    uint64_t overlay_end;
    char name[sizeof(((guest_region_t *) 0)->name)];
} region_snapshot_t;

static int capture_region_snapshots(guest_t *g,
                                    uint64_t start,
                                    uint64_t end,
                                    region_snapshot_t *snaps,
                                    int max_snaps);
static void close_region_snapshots(region_snapshot_t *snaps, int n);
static int restore_snapshot_overlays_in_place(guest_t *g,
                                              const region_snapshot_t *snaps,
                                              int n);
static int restore_snapshot_page_tables(guest_t *g,
                                        uint64_t start,
                                        uint64_t end,
                                        const region_snapshot_t *snaps,
                                        int n);
static int restore_region_snapshots(guest_t *g,
                                    region_snapshot_t *snaps,
                                    int n);

static int region_count_after_removes(const guest_t *g,
                                      const remove_range_t *ranges,
                                      int nranges)
{
    int count = 0;

    for (int i = 0; i < g->nregions; i++) {
        remove_range_t segments[3] = {{g->regions[i].start, g->regions[i].end}};
        int nsegments = 1;

        for (int r = 0; r < nranges; r++) {
            remove_range_t next[3] = {0};
            int next_nsegments = 0;

            for (int s = 0; s < nsegments; s++) {
                uint64_t start = segments[s].start, end = segments[s].end;

                if (end <= ranges[r].start || start >= ranges[r].end) {
                    next[next_nsegments++] = segments[s];
                    continue;
                }
                if (start < ranges[r].start)
                    next[next_nsegments++] =
                        (remove_range_t) {start, ranges[r].start};
                if (end > ranges[r].end)
                    next[next_nsegments++] =
                        (remove_range_t) {ranges[r].end, end};
            }

            memcpy(segments, next, sizeof(next));
            nsegments = next_nsegments;
        }

        count += nsegments;
    }

    return count;
}

static int region_has_capacity_after_removes(const guest_t *g,
                                             const remove_range_t *ranges,
                                             int nranges,
                                             int added_regions)
{
    return region_count_after_removes(g, ranges, nranges) + added_regions <=
           GUEST_MAX_REGIONS;
}

static int dup_region_backing_fd(const guest_region_t *region)
{
    if (!region || region->backing_fd < 0)
        return -1;

    return dup(region->backing_fd);
}

static bool region_has_live_overlay(const guest_region_t *r)
{
    return r->overlay_active && r->overlay_end > r->overlay_start;
}

static void region_clear_overlay(guest_region_t *r)
{
    r->overlay_active = false;
    r->overlay_start = 0;
    r->overlay_end = 0;
}

static void region_clip_overlay(guest_region_t *r);

static void clear_overlay_metadata_range(guest_t *g,
                                         uint64_t start,
                                         uint64_t end)
{
    for (int i = 0; i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (!region_has_live_overlay(r))
            continue;
        if (r->overlay_start != start || r->overlay_end != end)
            continue;
        region_clear_overlay(r);
    }
}

static void mark_overlay_metadata_range(guest_t *g,
                                        uint64_t start,
                                        uint64_t end,
                                        uint64_t overlay_start,
                                        uint64_t overlay_end)
{
    for (int i = 0; i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= start)
            continue;
        r->overlay_active = true;
        r->overlay_start = overlay_start;
        r->overlay_end = overlay_end;
        region_clip_overlay(r);
    }
}

static void region_clip_overlay(guest_region_t *r)
{
    if (!region_has_live_overlay(r) || r->end <= r->start) {
        region_clear_overlay(r);
        return;
    }

    size_t hps = host_page_size_cached();
    uint64_t page_start = ALIGN_DOWN(r->start, hps);
    uint64_t page_end = ALIGN_UP(r->end, hps);

    if (r->overlay_start < page_start)
        r->overlay_start = page_start;
    if (r->overlay_end > page_end)
        r->overlay_end = page_end;
    if (r->overlay_end <= r->overlay_start)
        region_clear_overlay(r);
}

static void split_regions_at_boundary(guest_t *g, uint64_t boundary)
{
    if (boundary == 0)
        return;

    for (int i = 0; i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (boundary <= r->start)
            break;
        if (boundary >= r->end)
            continue;
        if (g->nregions >= GUEST_MAX_REGIONS) {
            log_error(
                "guest: region table full, cleanup split skipped at "
                "0x%llx",
                (unsigned long long) boundary);
            return;
        }

        memmove(&g->regions[i + 1], &g->regions[i],
                (g->nregions - i) * sizeof(guest_region_t));
        g->nregions++;

        g->regions[i].end = boundary;
        g->regions[i + 1].offset += (boundary - g->regions[i + 1].start);
        g->regions[i + 1].gpa_base += (boundary - g->regions[i + 1].start);
        g->regions[i + 1].start = boundary;
        if (g->regions[i + 1].backing_fd >= 0) {
            g->regions[i + 1].backing_fd = dup(g->regions[i + 1].backing_fd);
            if (g->regions[i + 1].backing_fd < 0)
                log_error("guest: dup() failed for cleanup split: %s",
                          strerror(errno));
        }
        region_clip_overlay(&g->regions[i]);
        region_clip_overlay(&g->regions[i + 1]);
        return;
    }
}

static uint64_t find_free_gap_inner(const guest_t *g,
                                    uint64_t length,
                                    uint64_t min_addr,
                                    uint64_t max_addr,
                                    uint64_t align)
{
    /* Round the search start up to the next host-page boundary so an unaligned
     * addr hint cannot return a result that lands inside a host page already
     * covered by a preceding region's overlay tail (the overlay extends to
     * ALIGN_UP(r->end, hps)). Apple Silicon enforces 16 KiB host pages;
     * aligning to the guest 4 KiB page is not enough. Advance past each walked
     * region to the same boundary for the same reason.
     */
    uint64_t gap_start = ALIGN_UP(min_addr, align);

    /* Skip the prefix of regions entirely below gap_start in O(log n). After a
     * successful allocation the gap hint advances near or past the existing
     * region tail, so the linear walk would otherwise re-scan that whole prefix
     * on every mmap, addr-hint probe, or hint-miss full scan.
     */
    for (int i = guest_region_first_end_above(g, gap_start); i < g->nregions;
         i++) {
        /* A region can still slip below gap_start after the ALIGN_UP advance
         * below skips past a smaller adjacent region; keep the cheap guard.
         */
        if (g->regions[i].end <= gap_start)
            continue;

        /* The search is bounded to [min_addr, max_addr). Once the sorted region
         * stream reaches max_addr, later regions cannot affect any candidate
         * gap inside the window.
         */
        if (g->regions[i].start >= max_addr)
            break;

        /* If this region starts far enough after gap_start, the allocator found
         * a gap. Must also verify the gap is within max_addr; regions[] may
         * contain entries beyond max_addr that could push gap_start past the
         * valid range.
         */
        if (gap_start <= max_addr && length <= max_addr - gap_start &&
            g->regions[i].start >= gap_start + length)
            return gap_start;

        /* Region overlaps; advance past it and round to the next host page */
        gap_start = ALIGN_UP(g->regions[i].end, align);
    }

    /* Check trailing space after all regions */
    if (gap_start <= max_addr && length <= max_addr - gap_start)
        return gap_start;
    return UINT64_MAX; /* No suitable gap found */
}

/* Find a free gap, probing the cached post-allocation hint before a full scan.
 * The hint tracks the first address after the last successful mapping in each
 * region, which avoids rescanning the same prefix on sequential mmap activity.
 * A miss falls back to the region base so holes reopened by munmap are still
 * reusable.
 */
static uint64_t find_free_gap(guest_t *g,
                              uint64_t length,
                              uint64_t min_addr,
                              uint64_t max_addr,
                              uint64_t align)
{
    /* RX and RW mappings advance independently, so keep separate hints. */
    uint64_t *hint =
        (min_addr < MMAP_BASE) ? &g->mmap_rx_gap_hint : &g->mmap_rw_gap_hint;

    /* Try cached hint first (only if within the valid range) */
    if (*hint >= min_addr && *hint < max_addr) {
        uint64_t result =
            find_free_gap_inner(g, length, *hint, max_addr, align);
        if (result != UINT64_MAX) {
            *hint = ALIGN_UP(result + length, align);
            return result;
        }
    }

    /* Full scan from base */
    uint64_t result = find_free_gap_inner(g, length, min_addr, max_addr, align);
    if (result != UINT64_MAX)
        *hint = ALIGN_UP(result + length, align);
    return result;
}

/* Convert Linux PROT_* flags to guest page table permission bits. MEM_PERM_R is
 * always set. PROT_NONE callers should skip this.
 */
static int prot_to_perms(int prot)
{
    int perms = MEM_PERM_R;
    if (prot & LINUX_PROT_WRITE)
        perms |= MEM_PERM_W;
    if (prot & LINUX_PROT_EXEC)
        perms |= MEM_PERM_X;
    return perms;
}

static void *host_ptr_for_gpa(const guest_t *g, uint64_t gpa)
{
    if (gpa < g->guest_size)
        return (uint8_t *) g->host_base + gpa;

    const guest_mapping_t *m = guest_find_mapping(g, gpa);
    if (m)
        return (uint8_t *) m->host_va + (gpa - m->gpa);

    const guest_overflow_t *o = guest_find_overflow(g, gpa);
    if (o)
        return (uint8_t *) o->host_base + (gpa - o->ipa_start);

    return NULL;
}

static bool region_range_overlaps(const guest_t *g,
                                  uint64_t start,
                                  uint64_t end)
{
    int lo = 0, hi = g->nregions - 1, first = g->nregions;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (g->regions[mid].end > start) {
            first = mid;
            hi = mid - 1;
        } else {
            lo = mid + 1;
        }
    }

    return first < g->nregions && g->regions[first].start < end;
}

static bool high_va_replaceable_region(const guest_region_t *r)
{
    return r && !region_has_live_overlay(r) &&
           (r->flags & LINUX_MAP_SHARED) == 0;
}

static bool high_va_replaceable_gpa_base(guest_t *g,
                                         uint64_t start,
                                         uint64_t end,
                                         uint64_t *out_gpa_base,
                                         int *out_flags,
                                         uint64_t *out_offset)
{
    int idx = -1;
    for (int i = 0; i < g->nregions; i++) {
        if (g->regions[i].end <= start)
            continue;
        if (g->regions[i].start > start)
            return false;
        idx = i;
        break;
    }
    if (idx < 0)
        return false;

    uint64_t cursor = start;
    uint64_t gpa_cursor = 0;
    bool first = true;

    for (int i = idx; i < g->nregions && cursor < end; i++) {
        const guest_region_t *r = &g->regions[i];
        uint64_t seg_start = (r->start < cursor) ? cursor : r->start;
        uint64_t seg_end = (r->end > end) ? end : r->end;
        if (seg_start != cursor || seg_end <= seg_start ||
            !high_va_replaceable_region(r))
            return false;

        if (first) {
            uint64_t intra_region = cursor - r->start;
            gpa_cursor = r->gpa_base + intra_region;
            if (out_flags)
                *out_flags = r->flags;
            if (out_offset)
                *out_offset = r->offset + intra_region;
            first = false;
        } else if (r->gpa_base != gpa_cursor) {
            return false;
        }

        cursor = seg_end;
        gpa_cursor += seg_end - seg_start;
    }

    if (cursor != end || first)
        return false;

    if (out_gpa_base)
        *out_gpa_base = gpa_cursor - (end - start);
    return true;
}

static int64_t sys_mmap_high_va(guest_t *g,
                                uint64_t addr,
                                uint64_t length,
                                int prot,
                                int flags,
                                guest_fd_t fd,
                                uint64_t offset,
                                bool replace_existing,
                                bool is_noreplace)
{
    int64_t ret = -LINUX_ENOMEM;

    if (!g->is_rosetta)
        return -LINUX_ENOMEM;

    bool is_anon = (flags & LINUX_MAP_ANONYMOUS) != 0;
    bool is_shared = (flags & LINUX_MAP_SHARED) != 0;
    host_fd_ref_t backing_ref = {.fd = -1, .owned = false};
    int host_backing_fd = -1;
    int track_backing_fd = -1;
    bool close_host_backing_fd = false;
    /* High-water mark of VA installed by the mapping loop; reachable from the
     * fail label so the rollback knows what to invalidate. Must be initialized
     * before any goto fail that runs before the loop.
     */
    uint64_t va_installed_end = 0;

    /* If a fresh block has been block-mapped (live RW/RX over the full 2 MiB)
     * but has not yet had its L3 split-inherited entries zeroed, the rollback
     * must clear the full block, not just [addr, addr+length). Tracks at most
     * one in-flight fresh block at a time; UINT64_MAX means no in-flight fresh
     * block needs full-scope rollback.
     */
    uint64_t inflight_fresh_block_va = UINT64_MAX;
    uint64_t replaced_gpa_base = 0;
    int replaced_flags = 0;
    uint64_t replaced_offset = 0;
    bool replaced_region_removed = false;
    region_snapshot_t *replaced_snaps = NULL;
    int replaced_nsnaps = 0;
    bool replaced_ptes_modified = false;
    uint8_t *map_host = NULL;
    /* When the high-VA replacement reuses an existing host backing,
     * populate_existing is about to clobber map_host with memset / pread before
     * guest_install_va_pages and guest_region_add_ex_owned_gpa commit. Snapshot
     * the original bytes so the fail path can restore them; without this, a
     * late-step failure leaves the guest's old mapping pointing at corrupted
     * memory.
     */
    uint8_t *replaced_bytes_snap = NULL;
    bool replaced_bytes_dirty = false;

    /* Sibling vCPUs may otherwise observe transient zeroes, partial file
     * contents, or rollback bytes while populate_existing rewrites map_host in
     * place. The overlay paths already use the same pattern; mmap_lock only
     * serializes memory syscalls, not vCPU execution. Track whether the
     * siblings_quiesced bracket is open so the success-return and the fail-path
     * both resume.
     */
    bool siblings_quiesced = false;

    if (!is_anon && is_shared)
        return -LINUX_ENODEV;

    /* Reject wrap before reusing addr + length anywhere below. The caller
     * page-rounds length, but addr is guest-supplied and a huge length against
     * a high VA can still overflow. Also reject the case where addr + length is
     * too close to UINT64_MAX for ALIGN_UP to round up the 2 MiB boundary
     * without wrapping to 0 (which would make va_end smaller than va_start and
     * underflow backing_span).
     */
    if (length == 0 || addr > UINT64_MAX - length)
        return -LINUX_ENOMEM;
    if ((addr + length) > UINT64_MAX - (BLOCK_2MIB - 1))
        return -LINUX_ENOMEM;

    if (guest_kbuf_user_va_overlap(addr, length))
        return -LINUX_ENOMEM;

    /* Set when this call enters the replace-an-existing-mapping branch
     * (region_range_overlaps + replaceable + snapshots captured). Used
     * everywhere the function needs to decide between the fresh-allocation path
     * and the reuse-the-existing-backing path. The earlier proxy
     * (replaced_gpa_base != 0) mis-classified replacements targeting a region
     * backed at GPA 0 (a valid guest physical address) as fresh allocations,
     * which silently bypassed the byte snapshot, region remove, and rollback
     * restore work.
     */
    bool replacing_existing = false;

    /* Cap the byte-snapshot allocation that populate_existing needs for
     * rollback. The mapping itself can still be arbitrarily large in the
     * fresh-allocation path; only the replace-an-existing branch needs the
     * host-side malloc, so the cap only applies to replacement. 256 MiB is
     * comfortably above realistic Rosetta dynamic-linker reservations and far
     * below the multi-GiB malloc bombs a hostile guest could otherwise force.
     * Reject early with -ENOMEM so the caller falls back to a smaller MAP_FIXED
     * footprint rather than triggering the host OOM killer.
     */
    enum { HIGH_VA_SNAPSHOT_MAX = (size_t) 256 << 20 };

    if (region_range_overlaps(g, addr, addr + length) &&
        length > HIGH_VA_SNAPSHOT_MAX)
        return -LINUX_ENOMEM;

    if (region_range_overlaps(g, addr, addr + length)) {
        if (is_noreplace)
            return -LINUX_EEXIST;
        if (!replace_existing)
            return -LINUX_ENOMEM;
        if (!high_va_replaceable_gpa_base(g, addr, addr + length,
                                          &replaced_gpa_base, &replaced_flags,
                                          &replaced_offset))
            return -LINUX_ENOMEM;
        if (!region_has_capacity_after_removes(
                g, &(remove_range_t) {addr, addr + length}, 1, 1))
            return -LINUX_ENOMEM;
        replaced_snaps = malloc(GUEST_MAX_REGIONS * sizeof(*replaced_snaps));
        if (!replaced_snaps)
            return -LINUX_ENOMEM;
        replaced_nsnaps = capture_region_snapshots(
            g, addr, addr + length, replaced_snaps, GUEST_MAX_REGIONS);
        if (replaced_nsnaps < 0) {
            free(replaced_snaps);
            return replaced_nsnaps;
        }
        replacing_existing = true;
    }

    uint64_t va_start = ALIGN_DOWN(addr, BLOCK_2MIB);
    uint64_t va_end = ALIGN_UP(addr + length, BLOCK_2MIB);
    uint64_t backing_span = va_end - va_start;
    uint64_t backing_gpa_start = 0;
    uint64_t backing_limit = 0;

    if (replacing_existing) {
        backing_gpa_start = replaced_gpa_base - (addr - va_start);
    } else {
        backing_gpa_start =
            ALIGN_UP((g->mmap_end > g->mmap_next) ? g->mmap_end : g->mmap_next,
                     BLOCK_2MIB);
        backing_limit =
            g->kbuf_gpa ? g->kbuf_gpa : (g->interp_base - INFRA_RESERVE);
        if (backing_gpa_start >= backing_limit ||
            backing_span > backing_limit - backing_gpa_start)
            return -LINUX_ENOMEM;
    }

    if (!is_anon) {
        if (fuse_fd_refuse_mmap(fd)) {
            char materialized_path[PATH_MAX];
            int rc = fuse_materialize_fd(fd, materialized_path,
                                         sizeof(materialized_path));
            if (rc < 0)
                return rc;
            host_backing_fd = open(materialized_path, O_RDONLY | O_CLOEXEC);
            int saved_errno = errno;
            unlink(materialized_path);
            if (host_backing_fd < 0) {
                errno = saved_errno;
                return linux_errno();
            }
            close_host_backing_fd = true;
        } else {
            if (host_fd_ref_open(fd, &backing_ref) < 0)
                return -LINUX_EBADF;
            host_backing_fd = backing_ref.fd;
        }
        track_backing_fd = dup(host_backing_fd);
        if (track_backing_fd < 0) {
            ret = -LINUX_ENOMEM;
            goto fail;
        }
        if (prot != LINUX_PROT_NONE) {
            char probe;
            ssize_t nr;
            do {
                nr = pread(host_backing_fd, &probe, sizeof(probe),
                           (off_t) offset);
            } while (nr < 0 && errno == EINTR);
            if (nr < 0) {
                ret = linux_errno();
                goto fail;
            }
        }
    }

    int map_perms =
        (prot == LINUX_PROT_NONE) ? MEM_PERM_RW : prot_to_perms(prot);

    if (replacing_existing) {
        map_host = host_ptr_for_gpa(g, backing_gpa_start + (addr - va_start));
        if (!map_host)
            goto fail;
        goto populate_existing;
    }

    /* Mapping loop installs PT state in block-sized steps. Any L1/L2 tables
     * newly allocated during this call are left in place on rollback: they are
     * zero descriptors after invalidation and harmless until reused by a later
     * mmap.
     */
    va_installed_end = va_start;

    for (uint64_t va = va_start; va < va_end; va += BLOCK_2MIB) {
        uint64_t gpa = backing_gpa_start + (va - va_start);

        void *host = host_ptr_for_gpa(g, gpa);
        if (!host)
            goto fail;
        memset(host, 0, BLOCK_2MIB);

        /* Detect freshness BEFORE guest_map_va_range so the decision is not
         * confused by a prior high-VA mmap into the same 2 MiB block. A fresh
         * block needs its split-inherited L3 entries zeroed so gap pages do not
         * silently inherit block-level perms; a pre-existing block must be left
         * alone so earlier mappings into the same block survive.
         */
        bool fresh_block = !guest_va_block_mapped(g, va);

        if (guest_map_va_range(g, va, va + BLOCK_2MIB, gpa, map_perms) < 0)
            goto fail;
        va_installed_end = va + BLOCK_2MIB;

        /* Fresh blocks are live with full-2 MiB block-level perms from here
         * until guest_invalidate_ptes zeros the split-inherited L3 entries. If
         * split or invalidate fails in between, the rollback must scrub the
         * entire block; record it for the fail path.
         */
        if (fresh_block)
            inflight_fresh_block_va = va;

        /* Always split so guest_install_va_pages can write 4 KiB L3 PTEs for
         * the actual mapped range; pre-existing tables make split a no-op.
         */
        if (guest_split_block(g, va) < 0)
            goto fail;

        if (fresh_block) {
            if (guest_invalidate_ptes(g, va, va + BLOCK_2MIB) < 0)
                goto fail;
            /* L3 entries are zeroed; the block is no longer live at 2 MiB scope
             * and the narrow rollback is sufficient.
             */
            inflight_fresh_block_va = UINT64_MAX;
        }
    }

    map_host = host_ptr_for_gpa(g, backing_gpa_start + (addr - va_start));
    if (!map_host)
        goto fail;

populate_existing:
    /* Snapshot the existing host backing before the destructive write so a
     * later guest_install_va_pages / guest_region_add failure can restore the
     * guest's original mapping bytes from the fail path instead of leaving it
     * pointing at zeroed-or-partially-written memory. The fresh-allocation path
     * lands here too, but its map_host sits on a brand-new GPA range that no
     * guest mapping currently observes, so the snapshot is only needed when
     * replacing_existing.
     */
    if (replacing_existing && (is_anon || prot != LINUX_PROT_NONE)) {
        replaced_bytes_snap = malloc(length);
        if (!replaced_bytes_snap) {
            ret = -LINUX_ENOMEM;
            goto fail;
        }
        /* Quiesce siblings before the snapshot read so the memcpy cannot see
         * torn writes from another vCPU running guest code on the existing
         * mapping, and so the destructive memset / pread below stays invisible
         * to concurrent readers until the region tables commit (or the fail
         * path restores the bytes).
         */
        thread_quiesce_siblings();
        siblings_quiesced = true;
        memcpy(replaced_bytes_snap, map_host, length);
    }

    if (is_anon) {
        memset(map_host, 0, length);
        replaced_bytes_dirty = replacing_existing;
    } else if (prot != LINUX_PROT_NONE) {
        memset(map_host, 0, length);
        replaced_bytes_dirty = replacing_existing;
        uint8_t *dst = map_host;
        size_t remaining = length;
        off_t file_off = (off_t) offset;
        while (remaining > 0) {
            ssize_t nr = pread(host_backing_fd, dst, remaining, file_off);
            if (nr < 0) {
                if (errno == EINTR)
                    continue;
                /* Real host I/O failure (not EINTR); previously the loop broke
                 * without setting ret and the syscall returned a "successful"
                 * partially-zero mapping.
                 */
                ret = linux_errno();
                goto fail;
            }
            if (nr == 0)
                break;
            dst += nr;
            remaining -= (size_t) nr;
            file_off += nr;
        }
    }

    /* Install L3 PTEs for the actual mapped range. Fresh blocks were fully
     * invalidated in the loop above so their gap pages do not inherit
     * block-level perms; pre-existing blocks are left untouched so prior
     * high-VA mmaps into the same 2 MiB block survive.
     *
     * PROT_NONE still needs an explicit invalidate for the requested pages:
     * when the range lands inside a reused 2 MiB block, leaving the inherited
     * L3 descriptors intact would make the new guard range spuriously
     * accessible.
     */
    if (prot == LINUX_PROT_NONE) {
        replaced_ptes_modified = replacing_existing;
        if (guest_invalidate_ptes(g, addr, addr + length) < 0)
            goto fail;
    } else {
        uint64_t gpa_for_addr = backing_gpa_start + (addr - va_start);
        replaced_ptes_modified = replacing_existing;
        if (guest_install_va_pages(g, addr, length, gpa_for_addr,
                                   prot_to_perms(prot)) < 0)
            goto fail;
    }

    uint64_t backing_gpa_end = backing_gpa_start + backing_span;
    if (!replacing_existing) {
        if (backing_gpa_end > g->mmap_next)
            g->mmap_next = backing_gpa_end;
        if (backing_gpa_end > g->mmap_end)
            g->mmap_end = backing_gpa_end;
    }

    uint64_t gpa_base = backing_gpa_start + (addr - va_start);
    if (!region_has_capacity_after_removes(
            g,
            replacing_existing ? &(remove_range_t) {addr, addr + length} : NULL,
            replacing_existing ? 1 : 0, 1))
        goto fail;
    if (replacing_existing) {
        guest_region_remove(g, addr, addr + length);
        replaced_region_removed = true;
    }
    if (guest_region_add_ex_owned_gpa(g, addr, addr + length, gpa_base, prot,
                                      flags, offset, NULL,
                                      track_backing_fd) < 0)
        goto fail;
    /* Ownership of track_backing_fd is now held by the new region. The fail
     * handler below skips closing when track_backing_fd < 0, so subsequent
     * steps must not goto fail or the region's backing fd would be
     * double-closed.
     */
    if (close_host_backing_fd && host_backing_fd >= 0)
        close(host_backing_fd);
    host_fd_ref_close(&backing_ref);
    if (replaced_snaps) {
        close_region_snapshots(replaced_snaps, replaced_nsnaps);
        free(replaced_snaps);
    }
    if (replaced_bytes_snap) {
        free(replaced_bytes_snap);
        replaced_bytes_snap = NULL;
    }
    if (siblings_quiesced)
        thread_resume_siblings();

    return (int64_t) addr;

fail:
    /* If populate_existing already overwrote the original mapping's bytes, the
     * snapshot has the pre-replacement contents; copy them back before any
     * later cleanup so the guest's old mapping comes out of rollback pointing
     * at the same data it had before this call. The snapshot is freed
     * unconditionally below.
     */
    if (replaced_bytes_dirty && replaced_bytes_snap && map_host)
        memcpy(map_host, replaced_bytes_snap, length);

    /* Roll back PT state installed by this call. The success path preserves
     * pre-existing 2 MiB blocks (so prior high-VA mmaps in the same block
     * survive); the rollback must respect that same invariant. Two cases:
     *
     *   1. An in-flight fresh block: block-mapped at full-2 MiB perms but not
     *      yet invalidated. Zero the entire 2 MiB so no stray RW/RX mapping
     *      survives across the failure.
     *   2. The requested subrange [addr, addr+length): pre-existing
     *      blocks and completed fresh blocks were only ever written
     *      inside this range by guest_install_va_pages, so a narrow
     *      invalidate is the right scope. Completed fresh blocks had all
     *      L3 entries cleared in the loop, so any leftover split-
     *      inherited descriptors outside [addr, addr+length) are dormant
     *      and harmless until overwritten by a future mmap into the same
     *      VA range. Region tracking itself was never updated on this
     *      path (guest_region_add_ex_owned_gpa is the final commit), so
     *      region metadata is consistent without further cleanup.
     */
    if (inflight_fresh_block_va != UINT64_MAX) {
        if (guest_invalidate_ptes(g, inflight_fresh_block_va,
                                  inflight_fresh_block_va + BLOCK_2MIB) < 0) {
            log_error(
                "sys_mmap_high_va: rollback invalidate failed for "
                "fresh block [0x%llx, 0x%llx)",
                (unsigned long long) inflight_fresh_block_va,
                (unsigned long long) (inflight_fresh_block_va + BLOCK_2MIB));
        }
    }
    if (va_installed_end > va_start) {
        if (guest_invalidate_ptes(g, addr, addr + length) < 0) {
            log_error(
                "sys_mmap_high_va: rollback invalidate failed for "
                "VA [0x%llx, 0x%llx)",
                (unsigned long long) addr,
                (unsigned long long) (addr + length));
        }
    }
    if (track_backing_fd >= 0)
        close(track_backing_fd);
    /* Restore region/PTE snapshots when this call mutated regions[] or the page
     * tables; otherwise just drop the snapshot allocation. Whichever path runs,
     * the common cleanup below frees snapshots and fds and resumes siblings, so
     * a restore failure only needs to override the returned errno -- it must
     * not skip cleanup. (Earlier code used replaced_gpa_base != 0 as the proxy
     * for "replacing existing", which mis-classified replacements over a
     * GPA-0-backed region; replacing_existing is now set explicitly when
     * snapshots are captured.)
     */
    if (replaced_snaps && replacing_existing && replaced_region_removed) {
        int restore_err =
            restore_region_snapshots(g, replaced_snaps, replaced_nsnaps);
        if (restore_err == 0 && replaced_ptes_modified)
            restore_err = restore_snapshot_page_tables(
                g, addr, addr + length, replaced_snaps, replaced_nsnaps);
        if (restore_err < 0)
            ret = restore_err;
    } else if (replaced_snaps && replacing_existing && replaced_ptes_modified) {
        int restore_err = restore_snapshot_page_tables(
            g, addr, addr + length, replaced_snaps, replaced_nsnaps);
        if (restore_err < 0)
            ret = restore_err;
        else
            (void) restore_snapshot_overlays_in_place(g, replaced_snaps,
                                                      replaced_nsnaps);
    }
    if (replaced_snaps) {
        close_region_snapshots(replaced_snaps, replaced_nsnaps);
        free(replaced_snaps);
    }
    if (replaced_bytes_snap)
        free(replaced_bytes_snap);
    if (close_host_backing_fd && host_backing_fd >= 0)
        close(host_backing_fd);
    host_fd_ref_close(&backing_ref);
    /* Close the siblings_quiesced bracket as the very last step, so the byte
     * restore + region/PTE restore + fd cleanup all complete before any sibling
     * vCPU resumes guest execution.
     */
    if (siblings_quiesced)
        thread_resume_siblings();
    return ret;
}

static int mremap_extend_range(guest_t *g,
                               uint64_t off,
                               uint64_t size,
                               int prot)
{
    if (prot == LINUX_PROT_NONE) {
        guest_invalidate_ptes(g, off, off + size);
        return 0;
    }

    int page_perms = prot_to_perms(prot);
    uint64_t ext_start = ALIGN_DOWN(off, BLOCK_2MIB);
    uint64_t ext_end = ALIGN_UP(off + size, BLOCK_2MIB);
    if (ext_end > g->guest_size)
        ext_end = g->guest_size;
    if (guest_extend_page_tables(g, ext_start, ext_end, page_perms) < 0)
        return -1;
    guest_update_perms(g, off, off + size, page_perms);
    return 0;
}

static int hvf_apply_file_overlay(guest_t *g,
                                  uint64_t ipa,
                                  uint64_t len,
                                  int fd,
                                  off_t file_off);
static int hvf_apply_file_overlay_quiesced(guest_t *g,
                                           uint64_t ipa,
                                           uint64_t len,
                                           int fd,
                                           off_t file_off);
static int hvf_remove_file_overlay(guest_t *g, uint64_t ipa, uint64_t len);

static int read_file_range_to_guest(guest_t *g,
                                    uint64_t guest_off,
                                    int fd,
                                    uint64_t file_off,
                                    uint64_t len)
{
    uint8_t *dst = (uint8_t *) g->host_base + guest_off;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t nr = pread(fd, dst, remaining, (off_t) file_off);
        if (nr < 0) {
            if (errno == EINTR)
                continue;
            return linux_errno();
        }
        if (nr == 0)
            break;
        dst += nr;
        remaining -= (size_t) nr;
        file_off += (uint64_t) nr;
    }

    return 0;
}

static int restore_file_overlay_range(guest_t *g,
                                      uint64_t start,
                                      uint64_t end,
                                      uint64_t overlay_start,
                                      uint64_t overlay_end,
                                      int fd,
                                      uint64_t file_off)
{
    int err = hvf_apply_file_overlay(
        g, overlay_start, overlay_end - overlay_start, fd, (off_t) file_off);
    if (err < 0)
        return err;
    mark_overlay_metadata_range(g, start, end, overlay_start, overlay_end);
    return 0;
}

typedef struct {
    uint64_t overlay_start;
    uint64_t overlay_len;
    int snap_base;
    int nsnaps;
} fork_overlay_snapshot_t;

struct mmap_fork_anon_shared_txn {
    int nsnaps;
    region_snapshot_t snaps[GUEST_MAX_REGIONS];
    int noverlays;
    fork_overlay_snapshot_t overlays[GUEST_MAX_REGIONS];
};

static void close_region_snapshots(region_snapshot_t *snaps, int n)
{
    for (int i = 0; i < n; i++) {
        if (snaps[i].backing_fd >= 0) {
            close(snaps[i].backing_fd);
            snaps[i].backing_fd = -1;
        }
    }
}

/* Close any open dup'd backing fds in *snaps_ptr, free the heap buffer, and
 * zero out the caller's pointer/count so a follow-on call is a no-op. Used for
 * buffers allocated via malloc by sys_mmap and sys_mremap; the stack-allocated
 * callers in capture_region_snapshots itself keep using close_region_snapshots
 * directly.
 */
static void dispose_region_snapshots(region_snapshot_t **snaps_ptr, int *n_ptr)
{
    if (snaps_ptr && *snaps_ptr) {
        close_region_snapshots(*snaps_ptr, n_ptr ? *n_ptr : 0);
        free(*snaps_ptr);
        *snaps_ptr = NULL;
    }
    if (n_ptr)
        *n_ptr = 0;
}

static int capture_region_snapshots(guest_t *g,
                                    uint64_t start,
                                    uint64_t end,
                                    region_snapshot_t *snaps,
                                    int max_snaps)
{
    split_regions_at_boundary(g, start);
    split_regions_at_boundary(g, end);

    int n = 0;
    for (int i = 0; i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= start)
            continue;
        if (n >= max_snaps) {
            close_region_snapshots(snaps, n);
            return -LINUX_ENOMEM;
        }

        region_snapshot_t *snap = &snaps[n++];
        snap->start = r->start;
        snap->end = r->end;
        snap->gpa_base = r->gpa_base;
        snap->prot = r->prot;
        snap->flags = r->flags;
        snap->offset = r->offset;
        snap->backing_fd = -1;
        if (r->backing_fd >= 0) {
            snap->backing_fd = dup(r->backing_fd);
            if (snap->backing_fd < 0) {
                close_region_snapshots(snaps, n);
                return -LINUX_ENOMEM;
            }
        }
        snap->overlay_active = r->overlay_active;
        snap->overlay_start = r->overlay_start;
        snap->overlay_end = r->overlay_end;
        str_copy_trunc(snap->name, r->name, sizeof(snap->name));
    }

    return n;
}

static int restore_snapshot_overlays_in_place(guest_t *g,
                                              const region_snapshot_t *snaps,
                                              int n)
{
    for (int i = 0; i < n; i++) {
        const region_snapshot_t *snap = &snaps[i];
        if (!snap->overlay_active || snap->backing_fd < 0)
            continue;

        bool first = true;
        uint64_t snap_file_off =
            snap->offset + (snap->overlay_start - snap->start);
        for (int j = 0; j < i; j++) {
            const region_snapshot_t *prev = &snaps[j];
            if (!prev->overlay_active || prev->backing_fd < 0)
                continue;
            uint64_t prev_file_off =
                prev->offset + (prev->overlay_start - prev->start);
            if (prev->overlay_start == snap->overlay_start &&
                prev->overlay_end == snap->overlay_end &&
                prev_file_off == snap_file_off) {
                first = false;
                break;
            }
        }

        if (first) {
            int err = restore_file_overlay_range(
                g, snap->start, snap->end, snap->overlay_start,
                snap->overlay_end, snap->backing_fd, snap_file_off);
            if (err < 0)
                return err;
            continue;
        }

        mark_overlay_metadata_range(g, snap->start, snap->end,
                                    snap->overlay_start, snap->overlay_end);
    }

    return 0;
}

static bool snapshot_has_materialized_ptes(const region_snapshot_t *snap)
{
    return snap->prot != LINUX_PROT_NONE &&
           (snap->flags & LINUX_MAP_NORESERVE) == 0;
}

static int restore_snapshot_page_tables(guest_t *g,
                                        uint64_t start,
                                        uint64_t end,
                                        const region_snapshot_t *snaps,
                                        int n)
{
    if (guest_invalidate_ptes(g, start, end) < 0)
        return -LINUX_ENOMEM;

    for (int i = 0; i < n; i++) {
        const region_snapshot_t *snap = &snaps[i];
        if (!snapshot_has_materialized_ptes(snap))
            continue;

        int page_perms = prot_to_perms(snap->prot);
        uint64_t ext_start = ALIGN_DOWN(snap->start, BLOCK_2MIB);
        uint64_t ext_end = ALIGN_UP(snap->end, BLOCK_2MIB);
        if (ext_end > g->guest_size)
            ext_end = g->guest_size;

        if (guest_extend_page_tables(g, ext_start, ext_end, page_perms) < 0)
            return -LINUX_ENOMEM;
        guest_update_perms(g, snap->start, snap->end, page_perms);
    }

    /* guest_extend_page_tables() repopulates whole 2 MiB blocks, so clear holes
     * and deferred mappings again after all snapshot ranges are back.
     */
    uint64_t cursor = start;
    for (int i = 0; i < n; i++) {
        const region_snapshot_t *snap = &snaps[i];
        if (cursor < snap->start &&
            guest_invalidate_ptes(g, cursor, snap->start) < 0)
            return -LINUX_ENOMEM;
        if (!snapshot_has_materialized_ptes(snap) &&
            guest_invalidate_ptes(g, snap->start, snap->end) < 0)
            return -LINUX_ENOMEM;
        cursor = snap->end;
    }
    if (cursor < end && guest_invalidate_ptes(g, cursor, end) < 0)
        return -LINUX_ENOMEM;

    return 0;
}

static int restore_region_snapshots(guest_t *g, region_snapshot_t *snaps, int n)
{
    for (int i = 0; i < n; i++) {
        region_snapshot_t *snap = &snaps[i];
        if (guest_region_add_ex_owned_gpa(
                g, snap->start, snap->end, snap->gpa_base, snap->prot,
                snap->flags, snap->offset, snap->name[0] ? snap->name : NULL,
                snap->backing_fd) < 0) {
            snap->backing_fd = -1;
            close_region_snapshots(snaps, n);
            return -LINUX_ENOMEM;
        }
        snap->backing_fd = -1;
    }

    for (int i = 0; i < n; i++) {
        const region_snapshot_t *snap = &snaps[i];
        if (!snap->overlay_active)
            continue;

        bool first = true;
        uint64_t snap_file_off =
            snap->offset + (snap->overlay_start - snap->start);
        for (int j = 0; j < i; j++) {
            const region_snapshot_t *prev = &snaps[j];
            if (!prev->overlay_active)
                continue;
            uint64_t prev_file_off =
                prev->offset + (prev->overlay_start - prev->start);
            if (prev->overlay_start == snap->overlay_start &&
                prev->overlay_end == snap->overlay_end &&
                prev_file_off == snap_file_off) {
                first = false;
                break;
            }
        }

        if (first) {
            const guest_region_t *r = guest_region_find(g, snap->start);
            if (!r || r->backing_fd < 0)
                return -LINUX_EFAULT;
            int err = restore_file_overlay_range(
                g, snap->start, snap->end, snap->overlay_start,
                snap->overlay_end, r->backing_fd, snap_file_off);
            if (err < 0)
                return err;
            continue;
        }

        mark_overlay_metadata_range(g, snap->start, snap->end,
                                    snap->overlay_start, snap->overlay_end);
    }

    return 0;
}

static int rollback_fresh_mmap_allocation(guest_t *g,
                                          uint64_t start,
                                          uint64_t length,
                                          bool overlay_installed,
                                          uint64_t overlay_ipa,
                                          uint64_t overlay_len,
                                          uint64_t saved_mmap_next,
                                          uint64_t saved_mmap_end,
                                          uint64_t saved_mmap_rx_next,
                                          uint64_t saved_mmap_rx_end,
                                          uint64_t saved_rw_gap_hint,
                                          uint64_t saved_rx_gap_hint)
{
    if (overlay_installed)
        hvf_remove_file_overlay(g, overlay_ipa, overlay_len);
    if (guest_invalidate_ptes(g, start, start + length) < 0)
        return -LINUX_ENOMEM;
    g->mmap_next = saved_mmap_next;
    g->mmap_end = saved_mmap_end;
    g->mmap_rx_next = saved_mmap_rx_next;
    g->mmap_rx_end = saved_mmap_rx_end;
    g->mmap_rw_gap_hint = saved_rw_gap_hint;
    g->mmap_rx_gap_hint = saved_rx_gap_hint;
    return 0;
}

/* HVF stage-2 segment management.
 *
 * The slab is mapped to HVF in 2 MiB-aligned segments tracked by g->segments[].
 * Initially the slab is one segment (set up by guest_init). MAP_SHARED
 * file-backed mmap may need to overlay a sub-range of the slab with a real host
 * mmap MAP_FIXED|MAP_SHARED of the file fd. HVF caches the host VA->PA mapping
 * at hv_vm_map time and a plain MAP_FIXED overlay does not refresh it (see
 * comment in src/runtime/forkipc.c for the empirical evidence). To force HVF to
 * re-walk the host page tables after the overlay, the affected segment is
 * hv_vm_unmap'd, the file is mmap'd MAP_FIXED|MAP_SHARED into its host VA, and
 * the segment is hv_vm_map'd again.
 *
 * HVF rejects sub-range hv_vm_unmap of a larger map (HV_BAD_ARGUMENT).
 * Therefore, before applying the first overlay inside a large segment, the
 * segment is split into 2 MiB-aligned pieces around the affected range so each
 * piece is independently unmappable.
 */

/* HVF flags applied to slab segments. The slab is mapped RWX so guest stage-1
 * page tables retain full control over per-page permissions (W^X is enforced by
 * the guest's L2/L3 entries, not stage-2). File overlay segments use the same
 * RWX flags so PROT_EXEC mmaps still work; the host file mmap is created
 * PROT_READ|PROT_WRITE so HVF never asks the host kernel for execute permission
 * on the file pages.
 */
#define HVF_SEGMENT_FLAGS (HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)

/* Find the index of the segment containing ipa, or -1 if none. */
static int hvf_segment_find(const guest_t *g, uint64_t ipa)
{
    int lo = 0, hi = g->n_segments - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        const hvf_segment_t *s = &g->segments[mid];
        if (ipa >= s->ipa && ipa < s->ipa + s->len)
            return mid;
        if (ipa < s->ipa)
            hi = mid - 1;
        else
            lo = mid + 1;
    }
    return -1;
}

/* Restore the slab backing for [ipa, ipa+len) in the host VA. Used to undo a
 * previous file overlay. Maps shm_fd MAP_SHARED if the slab is shm-backed (so
 * subsequent fork CoW snapshots see consistent content), otherwise
 * MAP_ANON|MAP_PRIVATE. The IPA is unmapped from the guest's perspective by the
 * caller (page tables invalidated, region removed), so the content of the
 * restored backing is not directly observable to the guest until a subsequent
 * mmap targets the same IPA.
 *
 * The caller must ensure no HVF segment currently covers [ipa, ipa+len).
 * Returns 0 on success, -errno on failure.
 */
static int hvf_restore_slab_backing(guest_t *g, uint64_t ipa, uint64_t len)
{
    void *target = (uint8_t *) g->host_base + ipa;
    void *p;
    if (g->shm_fd >= 0) {
        p = mmap(target, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                 g->shm_fd, (off_t) ipa);
    } else {
        p = mmap(target, len, PROT_READ | PROT_WRITE,
                 MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    }
    if (p == MAP_FAILED)
        return -linux_errno();
    return 0;
}

/* Split the segment that exactly contains [aligned_start, aligned_end) so that
 * the middle range becomes its own segment. The caller MUST have quiesced
 * sibling vCPUs before calling so HVF's brief unmap window does not race with
 * concurrent guest accesses through stage-2.
 *
 * Up to two new segments may be inserted on either side. If the segment already
 * exactly matches the requested bounds, this is a no-op.
 *
 * Both bounds must be 2 MiB-aligned.
 *
 * Returns 0 on success, -errno on failure.
 */
static int hvf_segment_split(guest_t *g,
                             uint64_t aligned_start,
                             uint64_t aligned_end)
{
    int idx = hvf_segment_find(g, aligned_start);
    if (idx < 0)
        return -LINUX_EFAULT;
    hvf_segment_t orig = g->segments[idx];
    if (aligned_end > orig.ipa + orig.len)
        return -LINUX_EFAULT;
    if (aligned_start == orig.ipa && aligned_end == orig.ipa + orig.len)
        return 0;

    hvf_segment_t pieces[3];
    int n_pieces = 0;
    if (aligned_start > orig.ipa)
        pieces[n_pieces++] =
            (hvf_segment_t) {.ipa = orig.ipa, .len = aligned_start - orig.ipa};
    pieces[n_pieces++] = (hvf_segment_t) {.ipa = aligned_start,
                                          .len = aligned_end - aligned_start};
    if (aligned_end < orig.ipa + orig.len)
        pieces[n_pieces++] = (hvf_segment_t) {
            .ipa = aligned_end, .len = orig.ipa + orig.len - aligned_end};

    if (g->n_segments + n_pieces - 1 > GUEST_MAX_HVF_SEGMENTS)
        return -LINUX_ENOMEM;

    if (hv_vm_unmap(orig.ipa, orig.len) != HV_SUCCESS)
        return -LINUX_EIO;

    for (int i = 0; i < n_pieces; i++) {
        void *host_va = (uint8_t *) g->host_base + pieces[i].ipa;
        if (hv_vm_map(host_va, pieces[i].ipa, pieces[i].len,
                      HVF_SEGMENT_FLAGS) != HV_SUCCESS) {
            /* Best-effort recovery: tear down whatever pieces we already mapped
             * (HVF would reject hv_vm_map(orig) as overlapping if we left them
             * in place) and re-map the original segment. Sibling vCPUs are
             * quiesced so they cannot observe the gap. If the final remap also
             * fails the IPA range stays without stage-2 entries and the guest
             * will fault on access; log the unrecoverable state so post-mortem
             * points at the right culprit instead of the unrelated downstream
             * fault.
             */
            for (int j = 0; j < i; j++)
                hv_vm_unmap(pieces[j].ipa, pieces[j].len);
            hv_return_t r = hv_vm_map((uint8_t *) g->host_base + orig.ipa,
                                      orig.ipa, orig.len, HVF_SEGMENT_FLAGS);
            if (r != HV_SUCCESS)
                log_error(
                    "hvf_segment_split: recovery hv_vm_map(0x%llx, 0x%llx) "
                    "failed with 0x%x; IPA range left without stage-2 "
                    "entries",
                    (unsigned long long) orig.ipa,
                    (unsigned long long) orig.len, (int) r);
            return -LINUX_EIO;
        }
    }

    /* Replace orig with pieces in the segment array */
    int tail = g->n_segments - idx - 1;
    memmove(&g->segments[idx + n_pieces], &g->segments[idx + 1],
            (size_t) tail * sizeof(hvf_segment_t));
    for (int i = 0; i < n_pieces; i++)
        g->segments[idx + i] = pieces[i];
    g->n_segments += n_pieces - 1;
    return 0;
}

static int hvf_segment_split_range_boundaries(guest_t *g,
                                              uint64_t aligned_start,
                                              uint64_t aligned_end)
{
    int idx;

    idx = hvf_segment_find(g, aligned_start);
    if (idx < 0)
        return -LINUX_EFAULT;
    if (g->segments[idx].ipa < aligned_start) {
        int err = hvf_segment_split(
            g, aligned_start, g->segments[idx].ipa + g->segments[idx].len);
        if (err < 0)
            return err;
    }

    idx = hvf_segment_find(g, aligned_end - 1);
    if (idx < 0)
        return -LINUX_EFAULT;
    if (aligned_end < g->segments[idx].ipa + g->segments[idx].len) {
        int err = hvf_segment_split(g, g->segments[idx].ipa, aligned_end);
        if (err < 0)
            return err;
    }
    return 0;
}

static int hvf_segment_collect_range(guest_t *g,
                                     uint64_t aligned_start,
                                     uint64_t aligned_end,
                                     hvf_segment_t *segments,
                                     int max_segments)
{
    uint64_t cursor = aligned_start;
    int n = 0;

    while (cursor < aligned_end) {
        int idx = hvf_segment_find(g, cursor);
        if (idx < 0 || g->segments[idx].ipa != cursor)
            return -LINUX_EFAULT;
        if (n >= max_segments)
            return -LINUX_ENOMEM;
        segments[n++] = g->segments[idx];
        cursor += g->segments[idx].len;
    }
    return cursor == aligned_end ? n : -LINUX_EFAULT;
}

static void hvf_remap_segments_best_effort(guest_t *g,
                                           const hvf_segment_t *segments,
                                           int nsegments)
{
    for (int i = 0; i < nsegments; i++) {
        hv_return_t r =
            hv_vm_map((uint8_t *) g->host_base + segments[i].ipa,
                      segments[i].ipa, segments[i].len, HVF_SEGMENT_FLAGS);
        if (r != HV_SUCCESS)
            log_error(
                "hvf: recovery hv_vm_map(0x%llx, 0x%llx) failed with 0x%x",
                (unsigned long long) segments[i].ipa,
                (unsigned long long) segments[i].len, (int) r);
    }
}

/* Apply a real MAP_SHARED file overlay at [ipa, ipa+len) backed by [fd,
 * file_off). The IPA range may be sub-2 MiB; the containing 2 MiB segment is
 * split out first if it is not already isolated. Caller holds mmap_lock and has
 * already quiesced sibling vCPUs (or has none). The fork pre-snapshot path
 * quiesces siblings before calling this so the overlay install does not trigger
 * a nested quiesce.
 */
static int hvf_apply_file_overlay_quiesced(guest_t *g,
                                           uint64_t ipa,
                                           uint64_t len,
                                           int fd,
                                           off_t file_off)
{
    uint64_t aligned_start = ALIGN_2MIB_DOWN(ipa);
    uint64_t aligned_end = ALIGN_2MIB_UP(ipa + len);
    hvf_segment_t segments[GUEST_MAX_HVF_SEGMENTS];
    int nsegments;

    int err = hvf_segment_split_range_boundaries(g, aligned_start, aligned_end);
    if (err < 0)
        return err;
    nsegments = hvf_segment_collect_range(g, aligned_start, aligned_end,
                                          segments, GUEST_MAX_HVF_SEGMENTS);
    if (nsegments < 0)
        return nsegments;

    int unmapped = 0;
    for (int i = 0; i < nsegments; i++) {
        if (hv_vm_unmap(segments[i].ipa, segments[i].len) != HV_SUCCESS) {
            hvf_remap_segments_best_effort(g, segments, unmapped);
            return -LINUX_EIO;
        }
        unmapped++;
    }

    void *target = (uint8_t *) g->host_base + ipa;
    void *p = mmap(target, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                   fd, file_off);
    if (p == MAP_FAILED) {
        int saved = linux_errno();
        /* The overlay failed; restore the segment to slab backing so the host
         * VA range stays consistent. The host VA was untouched by the failed
         * mmap, so nothing else to undo.
         */
        hvf_remap_segments_best_effort(g, segments, nsegments);
        return saved < 0 ? saved : -saved;
    }

    for (int i = 0; i < nsegments; i++) {
        if (hv_vm_map((uint8_t *) g->host_base + segments[i].ipa,
                      segments[i].ipa, segments[i].len,
                      HVF_SEGMENT_FLAGS) == HV_SUCCESS)
            continue;
        /* Restore slab backing so the host VA stops referencing the caller's
         * file fd (which they expect to take back), then re-issue hv_vm_map so
         * the IPA range is not left without stage-2 entries. Without the second
         * hv_vm_map, sibling vCPUs would page-fault on this IPA after
         * thread_resume_siblings with no chance of recovery short of process
         * exit.
         */
        hvf_restore_slab_backing(g, ipa, len);
        hvf_remap_segments_best_effort(g, segments, nsegments);
        return -LINUX_EIO;
    }

    return 0;
}

/* True when the backing fd allows writes through. The overlay path replaces the
 * slab's RW host VA with MAP_SHARED|MAP_FIXED of this fd, and Apple HVF refuses
 * hv_vm_map of any permission onto a host VA whose write capability does not
 * cover the requested stage-2 perms. A read-only fd lands there with the kernel
 * rejecting either PROT_WRITE on the host mmap or, after a PROT_READ downgrade,
 * the post-overlay hv_vm_map with HV_DENIED. Centralises that decision: both
 * the overlay entry (hvf_apply_file_overlay) and the sys_mmap fast-path skip
 * share this gate so read-only backers are routed straight to the snapshot
 * pread path.
 *
 * Returns true on the optimistic path when fcntl itself fails: the subsequent
 * mmap / hv_vm_map will surface the real error rather than this helper
 * synthesising one.
 */
static bool overlay_fd_writable(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0)
        return true;
    return (fl & O_ACCMODE) != O_RDONLY;
}

/* Apply a real MAP_SHARED file overlay at [ipa, ipa+len) backed by [fd,
 * file_off). The IPA range may be sub-2 MiB; the containing 2 MiB segment is
 * split out first if it is not already isolated. Caller holds mmap_lock and has
 * not quiesced siblings yet. The function quiesces siblings around the
 * unmap+remap window so concurrent vCPUs cannot fault on the
 * temporarily-unmapped IPA range.
 */
static int hvf_apply_file_overlay(guest_t *g,
                                  uint64_t ipa,
                                  uint64_t len,
                                  int fd,
                                  off_t file_off)
{
    if (!overlay_fd_writable(fd))
        return -LINUX_EACCES;
    thread_quiesce_siblings();
    int err = hvf_apply_file_overlay_quiesced(g, ipa, len, fd, file_off);
    thread_resume_siblings();
    return err;
}

static int hvf_remove_file_overlay_quiesced(guest_t *g,
                                            uint64_t ipa,
                                            uint64_t len)
{
    uint64_t aligned_start = ALIGN_2MIB_DOWN(ipa);
    uint64_t aligned_end = ALIGN_2MIB_UP(ipa + len);
    hvf_segment_t segments[GUEST_MAX_HVF_SEGMENTS];
    int nsegments;

    int err = hvf_segment_split_range_boundaries(g, aligned_start, aligned_end);
    if (err < 0)
        return err;
    nsegments = hvf_segment_collect_range(g, aligned_start, aligned_end,
                                          segments, GUEST_MAX_HVF_SEGMENTS);
    if (nsegments < 0)
        return nsegments;

    int unmapped = 0;
    for (int i = 0; i < nsegments; i++) {
        if (hv_vm_unmap(segments[i].ipa, segments[i].len) != HV_SUCCESS) {
            hvf_remap_segments_best_effort(g, segments, unmapped);
            return -LINUX_EIO;
        }
        unmapped++;
    }

    err = hvf_restore_slab_backing(g, ipa, len);
    if (err < 0) {
        /* Best-effort: re-establish the segment with whatever the host VA
         * currently has (still the file overlay) so the guest can see something
         * rather than nothing.
         */
        hvf_remap_segments_best_effort(g, segments, nsegments);
        return err;
    }

    for (int i = 0; i < nsegments; i++) {
        if (hv_vm_map((uint8_t *) g->host_base + segments[i].ipa,
                      segments[i].ipa, segments[i].len,
                      HVF_SEGMENT_FLAGS) != HV_SUCCESS)
            return -LINUX_EIO;
    }

    return 0;
}

/* Undo a file overlay at [ipa, ipa+len) by restoring the slab backing and
 * refreshing the containing HVF segment. Caller holds mmap_lock. Sibling vCPUs
 * are quiesced around the brief unmap window.
 */
static int hvf_remove_file_overlay(guest_t *g, uint64_t ipa, uint64_t len)
{
    thread_quiesce_siblings();
    int err = hvf_remove_file_overlay_quiesced(g, ipa, len);
    thread_resume_siblings();
    return err;
}

/* Walk semantic regions in [start, end) and undo any active MAP_SHARED file
 * overlays on the underlying host VA. Used before sys_mmap MAP_FIXED replaces a
 * previously-overlaid range with a new mapping (anonymous or different file):
 * without restoring the slab backing first, stale file pages would leak into
 * the new mapping.
 *
 * Returns 0 on success, -errno on failure; region overlay metadata is cleared
 * only for ranges where the underlying host-VA overlay was successfully torn
 * down so a partial failure does not leave the runtime believing an overlay is
 * gone while the file mmap is still live (which would cause a later memset to
 * write into the file). Caller holds mmap_lock.
 */
static int cleanup_overlays_in_range(guest_t *g, uint64_t start, uint64_t end)
{
    size_t hps = host_page_size_cached();
    uint64_t host_start = ALIGN_DOWN(start, hps);
    uint64_t host_end = ALIGN_UP(end, hps);

    split_regions_at_boundary(g, host_start);
    split_regions_at_boundary(g, host_end);

    /* Snapshot affected ranges first; the host-side mmap calls below do not
     * touch the region array, but a future caller invariant is to allow this
     * loop to mutate metadata only after the unmap-and-restore dance succeeds.
     * The bounded buffer keeps the function stack-only.
     */
    struct {
        uint64_t off, len;
    } overlays[GUEST_MAX_REGIONS];
    int n = 0;
    for (int i = 0; i < g->nregions && n < GUEST_MAX_REGIONS; i++) {
        guest_region_t *r = &g->regions[i];
        if (r->start >= host_end)
            break;
        if (r->end <= host_start)
            continue;
        if (!region_has_live_overlay(r))
            continue;
        uint64_t s =
            r->overlay_start > host_start ? r->overlay_start : host_start;
        uint64_t e = r->overlay_end < host_end ? r->overlay_end : host_end;
        if (e <= s)
            continue;
        bool seen = false;
        for (int j = 0; j < n; j++) {
            if (overlays[j].off == s && overlays[j].len == e - s) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            overlays[n].off = s;
            overlays[n].len = e - s;
            n++;
        }
    }
    int err = 0;
    for (int i = 0; i < n; i++) {
        int rc = hvf_remove_file_overlay(g, overlays[i].off, overlays[i].len);
        if (rc < 0) {
            /* Stop on first failure; leave overlay_active set on regions we
             * could not tear down so subsequent operations still see a live
             * overlay there and route through the overlay-aware paths.
             */
            if (!err)
                err = rc;
            break;
        }
        clear_overlay_metadata_range(g, overlays[i].off,
                                     overlays[i].off + overlays[i].len);
    }
    return err;
}

/* Memory syscalls (tightly coupled to guest.h). */

int64_t sys_brk(guest_t *g, uint64_t addr)
{
    /* brk addresses as seen by the guest are IPA-based */
    uint64_t ipa_brk = guest_ipa(g, g->brk_current);
    uint64_t ipa_base = guest_ipa(g, g->brk_base);
    uint64_t old_brk = g->brk_current;

    if (addr == 0) {
        return (int64_t) ipa_brk;
    }

    if (addr < ipa_base) {
        return (int64_t) ipa_brk;
    }

    /* Convert IPA back to offset for internal tracking */
    uint64_t new_off = addr - g->ipa_base;
    if (new_off >= g->guest_size) {
        return (int64_t) ipa_brk;
    }

    /* Materialize any newly exposed heap pages. This must handle both:
     * 1. growth into brand-new 2 MiB blocks, and
     * 2. growth within an already-split block where finalize_block_perms()
     *    intentionally left non-covered pages invalid until brk exposes them.
     */
    if (new_off > old_brk) {
        uint64_t grow_start = ALIGN_DOWN(old_brk, GUEST_PAGE_SIZE);
        uint64_t grow_end = PAGE_ALIGN_UP(new_off);

        if (guest_extend_page_tables(g, grow_start, grow_end, MEM_PERM_RW) < 0)
            return (int64_t) ipa_brk;
        if (guest_update_perms(g, grow_start, grow_end, MEM_PERM_RW) < 0)
            return (int64_t) ipa_brk;
    }

    /* Zero new pages if growing */
    if (new_off > g->brk_current) {
        memset((uint8_t *) g->host_base + g->brk_current, 0,
               new_off - g->brk_current);
    }

    g->brk_current = new_off;

    /* Update "[heap]" region tracking atomically. Find-and-update-in-place
     * avoids the remove+add gap where a concurrent /proc/self/maps reader could
     * see no heap region.
     */
    if (new_off > g->brk_base) {
        bool found = false;
        for (int i = 0; i < g->nregions; i++) {
            if (g->regions[i].start == g->brk_base &&
                !strcmp(g->regions[i].name, "[heap]")) {
                g->regions[i].end = new_off;
                found = true;
                break;
            }
        }
        if (!found) {
            guest_region_add(
                g, g->brk_base, new_off, LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0, "[heap]");
        }
    } else {
        /* brk shrank back to base; remove heap region */
        guest_region_remove(g, g->brk_base,
                            old_brk > g->brk_base ? old_brk : g->brk_base + 1);
    }

    return (int64_t) guest_ipa(g, g->brk_current);
}

int64_t sys_mmap(guest_t *g,
                 uint64_t addr,
                 uint64_t length,
                 int prot,
                 int flags,
                 int fd,
                 int64_t offset)
{
    bool is_anon = (flags & LINUX_MAP_ANONYMOUS) != 0;
    bool needs_exec = (prot & LINUX_PROT_EXEC) != 0;
    bool is_prot_none = (prot == LINUX_PROT_NONE);
    bool is_noreserve = is_anon && (flags & LINUX_MAP_NORESERVE) != 0;
    host_fd_ref_t backing_ref = {.fd = -1, .owned = 0};
    int host_backing_fd = -1, track_backing_fd = -1;
    /* Tracks whether hvf_apply_file_overlay has installed a host
     * MAP_FIXED|MAP_SHARED mapping that the failure paths must undo if later
     * steps (page tables, region tracking) fall over. Without this, a
     * partial-success rollback leaves the file mmap'd at host_base+ipa with no
     * region tracking, and the next operation in that range would memset zeros
     * directly into the user's file.
     */
    bool overlay_installed = false;
    uint64_t overlay_ipa = 0;
    uint64_t overlay_len = 0;
    uint64_t saved_mmap_next = g->mmap_next;
    uint64_t saved_mmap_end = g->mmap_end;
    uint64_t saved_mmap_rx_next = g->mmap_rx_next;
    uint64_t saved_mmap_rx_end = g->mmap_rx_end;
    uint64_t saved_rw_gap_hint = g->mmap_rw_gap_hint;
    uint64_t saved_rx_gap_hint = g->mmap_rx_gap_hint;
    /* Heap-allocated to avoid blowing the ~512 KiB default stack on macOS
     * worker threads: GUEST_MAX_REGIONS * sizeof(region_snapshot_t) is on the
     * order of half a megabyte. Allocated lazily inside the FIXED path that
     * actually consumes it; non-FIXED mmaps never touch this pointer. Always
     * free()'d (free(NULL) is a no-op) before return.
     */
    region_snapshot_t *replaced_snaps = NULL;
    int replaced_nsnaps = 0;
    bool replaced_regions_removed = false;
    int track_flags =
        ((flags & LINUX_MAP_SHARED) ? LINUX_MAP_SHARED : LINUX_MAP_PRIVATE);
    if (is_anon)
        track_flags |= LINUX_MAP_ANONYMOUS;

    /* Preserve MAP_NORESERVE in region metadata before merge checks run. */
    if (is_noreserve)
        track_flags |= LINUX_MAP_NORESERVE;

    /* The memory syscall layer handles all mmap variants. For file-backed
     * MAP_SHARED, it falls back to MAP_PRIVATE semantics (copy-on-write). All
     * threads share the same guest_t address space (CLONE_VM semantics), so
     * MAP_SHARED and MAP_PRIVATE are equivalent within the guest.
     */

    /* Linux rejects zero-length mmap */
    if (length == 0)
        return -LINUX_EINVAL;

    /* Linux requires page-aligned offset for file-backed mmap */
    if (!is_anon && (offset & 4095))
        return -LINUX_EINVAL;

    if (!is_anon && fuse_fd_refuse_mmap(fd)) {
        bool allow_materialized_fuse_mmap =
            g->is_rosetta &&
            ((flags & LINUX_MAP_FIXED) ||
             (flags & LINUX_MAP_FIXED_NOREPLACE)) &&
            addr >= g->guest_size && !(flags & LINUX_MAP_SHARED);
        if (!allow_materialized_fuse_mmap)
            return -LINUX_ENODEV;
    }

    bool is_fixed =
        (flags & LINUX_MAP_FIXED) || (flags & LINUX_MAP_FIXED_NOREPLACE);
    if (is_fixed && (addr & 4095))
        return -LINUX_EINVAL;

    /* MAP_FIXED_NOREPLACE: like MAP_FIXED but fail with -EEXIST if the range
     * overlaps any existing mapping.
     */
    bool is_noreplace = (flags & LINUX_MAP_FIXED_NOREPLACE) != 0;

    size_t hps = host_page_size_cached();
    uint64_t align = hps;
    if (!is_fixed && !is_anon && fd >= 0 && (flags & LINUX_MAP_SHARED)) {
        align = BLOCK_2MIB;
    }

    /* Round length up to align size (overflow-safe) */
    if (length > UINT64_MAX - (align - 1))
        return -LINUX_ENOMEM;
    length = ALIGN_UP(length, align);
    if (length == 0)
        return -LINUX_ENOMEM;

    uint64_t result_off; /* Result as offset (0-based) */
    if (is_fixed) {
        /* Addresses above TASK_SIZE (bit 63 set or beyond user VA range) are
         * rejected, matching real Linux kernel behavior.
         */
        if (addr > 0x0000FFFFFFFFFFFFULL)
            return -LINUX_ENOMEM;

        if (addr >= g->guest_size)
            return sys_mmap_high_va(g, addr, length, prot, flags, fd, offset,
                                    true, is_noreplace);

        /* High-VA MAP_FIXED (rosetta's JIT slabs at 240 TiB, code caches at 85
         * TiB, etc.) is not safe to expose yet. The previous draft could
         * install TTBR0 aliases for addresses above the primary guest buffer,
         * but munmap/mprotect/fork bookkeeping still track regions by low GPA
         * and mmap_next only. Returning success here therefore created mappings
         * that later teardown paths could not manage and let overflow-backed
         * aliases corrupt the fork snapshot high-water mark. Fail closed until
         * the region metadata and teardown paths are made VA-aware end-to-end.
         */
        /* MAP_FIXED: addr is IPA-based, convert to offset */
        uint64_t off = addr - g->ipa_base;
        /* Use subtraction-based check to avoid off+length overflow. Stays
         * primary-buffer-only for the low-VA path because the body below issues
         * raw host_base+off arithmetic (memset, pread, etc.). The high-VA path
         * above is the alternate route for rosetta.
         */
        if (off > g->guest_size || length > g->guest_size - off)
            return -LINUX_ENOMEM;

        /* Reject MAP_FIXED targeting VM infrastructure: page table pool, shim
         * code, and shim data/stack regions. A guest must not be able to
         * overwrite EL1 exception vectors or page tables. The reserve sits at
         * high IPA (just below g->interp_base) so the range check uses the
         * runtime fields rather than compile-time low-memory constants.
         */
        uint64_t fix_end = off + length;
        if (guest_range_hits_infra(g, off, fix_end))
            return -LINUX_EINVAL;

        result_off = off;

        /* MAP_FIXED_NOREPLACE: reject if any existing region overlaps. Use
         * binary search (regions are sorted by start address) to find the first
         * region that could overlap [result_off, result_off+length).
         */
        if (is_noreplace) {
            int lo = 0, hi = g->nregions - 1, first = g->nregions;
            while (lo <= hi) {
                int mid = (lo + hi) / 2;
                if (g->regions[mid].end > result_off) {
                    first = mid;
                    hi = mid - 1;
                } else {
                    lo = mid + 1;
                }
            }
            if (first < g->nregions &&
                g->regions[first].start < result_off + length)
                return -LINUX_EEXIST;
        }

        if (!is_anon) {
            if (host_fd_ref_open(fd, &backing_ref) < 0)
                return -LINUX_EBADF;
            host_backing_fd = backing_ref.fd;
        }

        remove_range_t replaced = {result_off, result_off + length};
        if (!region_has_capacity_after_removes(g, &replaced, 1, 1)) {
            host_fd_ref_close(&backing_ref);
            return -LINUX_ENOMEM;
        }
        replaced_snaps = malloc(GUEST_MAX_REGIONS * sizeof(*replaced_snaps));
        if (!replaced_snaps) {
            host_fd_ref_close(&backing_ref);
            return -LINUX_ENOMEM;
        }
        replaced_nsnaps =
            capture_region_snapshots(g, result_off, result_off + length,
                                     replaced_snaps, GUEST_MAX_REGIONS);
        if (replaced_nsnaps < 0) {
            free(replaced_snaps);
            host_fd_ref_close(&backing_ref);
            return replaced_nsnaps;
        }
        if (!is_anon) {
            track_backing_fd = dup(host_backing_fd);
            if (track_backing_fd < 0) {
                dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            if (!is_prot_none) {
                char probe;
                ssize_t nr;
                do {
                    nr = pread(host_backing_fd, &probe, sizeof(probe), offset);
                } while (nr < 0 && errno == EINTR);
                if (nr < 0) {
                    close(track_backing_fd);
                    dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                    host_fd_ref_close(&backing_ref);
                    return linux_errno();
                }
            }
        }

        if (!is_prot_none) {
            /* Ensure page table entries exist for the fixed range. PROT_NONE
             * reservations skip page table creation, so when MAP_FIXED commits
             * pages within a PROT_NONE region (e.g., a runtime carves an RW
             * slab out of its previously reserved PROT_NONE heap), the memory
             * syscall layer must create L2 block descriptors first.
             * guest_extend_page_tables is idempotent for already-mapped blocks.
             */
            int page_perms = prot_to_perms(prot);

            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->guest_size)
                ext_end = g->guest_size;

            /* Restore slab backing under any pre-existing MAP_SHARED file
             * overlay in the replaced range. Without this, stale file pages
             * leak into the new mapping. Must run before guest_region_remove
             * because the cleanup walker reads the live region metadata.
             */
            int cleanup_err =
                cleanup_overlays_in_range(g, result_off, result_off + length);
            if (cleanup_err < 0) {
                (void) restore_snapshot_overlays_in_place(g, replaced_snaps,
                                                          replaced_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                host_fd_ref_close(&backing_ref);
                return cleanup_err;
            }

            if (guest_extend_page_tables(g, ext_start, ext_end, page_perms) <
                0) {
                (void) restore_snapshot_overlays_in_place(g, replaced_snaps,
                                                          replaced_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }

            /* Remove old metadata only after fallible page-table preparation
             * succeeds.
             */
            guest_region_remove(g, result_off, result_off + length);
            replaced_regions_removed = true;

            /* Fine-tune permissions for the exact range. Handles L3 splitting
             * when MAP_FIXED overlays different permissions onto an existing
             * 2MiB block (e.g., .data RW over .text RX).
             */
            guest_update_perms(g, result_off, result_off + length, page_perms);

            /* For MAP_ANONYMOUS: zero the region (host memory may contain stale
             * data from earlier mappings). For MAP_SHARED + regular file:
             * install a real host mmap MAP_FIXED|MAP_SHARED overlay so the
             * guest sees live host writes and its own writes hit the file
             * directly. For MAP_PRIVATE file-backed: read file contents into
             * guest memory; private writes stay in the slab. Short reads leave
             * the remainder zeroed (memset first).
             */
            if (is_anon) {
                memset((uint8_t *) g->host_base + result_off, 0, length);
            } else if (fd >= 0 && (flags & LINUX_MAP_SHARED) &&
                       (result_off % host_page_size_cached() == 0) &&
                       ((uint64_t) offset % host_page_size_cached() == 0)) {
                uint64_t fixed_overlay_len =
                    ALIGN_UP(length, host_page_size_cached());
                int oerr =
                    hvf_apply_file_overlay(g, result_off, fixed_overlay_len,
                                           host_backing_fd, (off_t) offset);
                if (oerr < 0) {
                    int restore_err = restore_region_snapshots(
                        g, replaced_snaps, replaced_nsnaps);
                    if (restore_err == 0)
                        restore_err = restore_snapshot_page_tables(
                            g, result_off, result_off + length, replaced_snaps,
                            replaced_nsnaps);
                    if (track_backing_fd >= 0)
                        close(track_backing_fd);
                    if (restore_err < 0) {
                        dispose_region_snapshots(&replaced_snaps,
                                                 &replaced_nsnaps);
                        host_fd_ref_close(&backing_ref);
                        return restore_err;
                    }
                    dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                    host_fd_ref_close(&backing_ref);
                    return oerr;
                }
                overlay_installed = true;
                overlay_ipa = result_off;
                overlay_len = fixed_overlay_len;
            } else if (fd >= 0) {
                memset((uint8_t *) g->host_base + result_off, 0, length);
                uint8_t *dst = (uint8_t *) g->host_base + result_off;
                size_t remaining = length;
                off_t file_off = offset;
                bool read_io_err = false;
                int saved_errno = 0;
                while (remaining > 0) {
                    ssize_t nr =
                        pread(host_backing_fd, dst, remaining, file_off);
                    if (nr < 0) {
                        if (errno == EINTR)
                            continue;
                        /* Real host I/O error (not EINTR). EOF zero- fill stays
                         * an accepted outcome (nr == 0 below); an I/O failure
                         * returning a "successful" partially-zero mapping is
                         * not. Restore the prior region/PTE state and surface
                         * the errno to the caller.
                         */
                        read_io_err = true;
                        saved_errno = errno;
                        break;
                    }
                    if (nr == 0)
                        break; /* EOF; remaining bytes stay zeroed */
                    dst += nr;
                    remaining -= (size_t) nr;
                    file_off += nr;
                }
                if (read_io_err) {
                    int restore_err = restore_region_snapshots(
                        g, replaced_snaps, replaced_nsnaps);
                    if (restore_err == 0)
                        restore_err = restore_snapshot_page_tables(
                            g, result_off, result_off + length, replaced_snaps,
                            replaced_nsnaps);
                    if (track_backing_fd >= 0)
                        close(track_backing_fd);
                    if (restore_err < 0) {
                        dispose_region_snapshots(&replaced_snaps,
                                                 &replaced_nsnaps);
                        host_fd_ref_close(&backing_ref);
                        return restore_err;
                    }
                    dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                    host_fd_ref_close(&backing_ref);
                    errno = saved_errno;
                    return linux_errno();
                }
            }
        } else {
            /* Restore slab backing under any pre-existing MAP_SHARED file
             * overlay before dropping the region tracking.
             */
            int cleanup_err =
                cleanup_overlays_in_range(g, result_off, result_off + length);
            if (cleanup_err < 0) {
                (void) restore_snapshot_overlays_in_place(g, replaced_snaps,
                                                          replaced_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
                host_fd_ref_close(&backing_ref);
                return cleanup_err;
            }

            /* Remove any existing region coverage in the fixed range. */
            guest_region_remove(g, result_off, result_off + length);
            replaced_regions_removed = true;

            /* PROT_NONE with MAP_FIXED: invalidate existing page table entries
             * so the region becomes truly inaccessible. Without this, stale
             * PTEs from initial page table setup (e.g., ELF segment
             * pre-mapping) remain valid, making pages accessible when they
             * should fault on access. A real Linux kernel's mmap(MAP_FIXED,
             * PROT_NONE) removes existing VMAs and their page table entries,
             * making the range fault on access.
             */
            guest_invalidate_ptes(g, result_off, result_off + length);
        }
    }

    /* Non-fixed mmap: allocate from the gap-finding allocator and snapshot file
     * backing once the final guest range is known.
     */
    if (!is_fixed) {
        if (g->is_rosetta && addr >= g->guest_size &&
            addr <= 0x0000FFFFFFFFFFFFULL) {
            int64_t high_hint = sys_mmap_high_va(g, addr, length, prot, flags,
                                                 fd, offset, false, false);
            if (high_hint >= 0)
                return high_hint;
        }
        if (needs_exec && !(prot & LINUX_PROT_WRITE)) {
            /* PROT_EXEC without PROT_WRITE: allocate from the RX mmap region.
             * Apple HVF enforces W^X on 2MiB block page table entries, so
             * executable mappings must be in separate 2MiB blocks from writable
             * ones. The RX region at MMAP_RX_BASE is pre-mapped with execute
             * permission.
             */
            result_off =
                find_free_gap(g, length, MMAP_RX_BASE, g->mmap_limit, align);
            if (result_off == UINT64_MAX) {
                log_debug(
                    "mmap: RX address space exhausted "
                    "(len=0x%llx, limit=0x%llx, %u-bit IPA / %llu GiB)",
                    (unsigned long long) length,
                    (unsigned long long) g->mmap_limit, g->ipa_bits,
                    (unsigned long long) (g->guest_size >> 30));
                return -LINUX_ENOMEM;
            }
            /* High-water mark for fork IPC state transfer */
            uint64_t rx_hwm = result_off + length;
            if (rx_hwm > g->mmap_rx_next)
                g->mmap_rx_next = rx_hwm;
        } else {
            /* RW (or PROT_NONE, or PROT_READ): allocate from main mmap region.
             * Honor the address hint if provided and within bounds. Some
             * managed-runtime allocators need the heap at a specific high
             * address range (e.g., ~264GiB for a megablock-style map) and
             * spin-retry if they get a low address instead. On real Linux, mmap
             * tries the hint first and falls back to any suitable address.
             */
            result_off = UINT64_MAX;
            if (addr != 0) {
                uint64_t hint_off = addr - g->ipa_base;
                if (hint_off >= ELF_DEFAULT_BASE && hint_off <= g->mmap_limit &&
                    length <= g->mmap_limit - hint_off) {
                    /* Real Linux treats non-fixed mmap(addr!=0) as a strong
                     * hint, including low canonical addresses such as the
                     * traditional x86-64 ET_EXEC base at 0x400000. box64 uses
                     * this pattern when reserving address space for static
                     * ET_EXEC binaries; forcing every hint below MMAP_BASE into
                     * the high RW arena breaks that expectation and the guest
                     * later still dereferences the low address.
                     *
                     * Probe the hinted range first. Keep low-hint searches
                     * below MMAP_BASE so an unresolved low hint does not
                     * silently spill into the high arena on this fast path.
                     */
                    uint64_t hint_max =
                        (hint_off < MMAP_BASE) ? MMAP_BASE : g->mmap_limit;
                    result_off = find_free_gap_inner(g, length, hint_off,
                                                     hint_max, align);
                }
            }
            if (result_off == UINT64_MAX)
                result_off =
                    find_free_gap(g, length, MMAP_BASE, g->mmap_limit, align);
            if (result_off == UINT64_MAX) {
                log_debug(
                    "mmap: RW address space exhausted "
                    "(len=0x%llx, limit=0x%llx, %u-bit IPA / %llu GiB)",
                    (unsigned long long) length,
                    (unsigned long long) g->mmap_limit, g->ipa_bits,
                    (unsigned long long) (g->guest_size >> 30));
                return -LINUX_ENOMEM;
            }
            /* High-water mark for fork IPC state transfer */
            uint64_t rw_hwm = result_off + length;
            if (rw_hwm > g->mmap_next)
                g->mmap_next = rw_hwm;
        }
        if (!is_anon) {
            if (host_fd_ref_open(fd, &backing_ref) < 0)
                return -LINUX_EBADF;
            host_backing_fd = backing_ref.fd;
        }
        if (!region_has_capacity_after_removes(g, NULL, 0, 1)) {
            host_fd_ref_close(&backing_ref);
            return -LINUX_ENOMEM;
        }
        if (!is_anon) {
            track_backing_fd = dup(host_backing_fd);
            if (track_backing_fd < 0) {
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
        }
    }

    /* PROT_NONE mappings do not need new page table entries, but mmap must
     * invalidate any stale PTEs from previous allocations at this address.
     * Without this, a freed-then-reallocated-as-PROT_NONE range retains the old
     * RW page table entries, letting the guest read/write what should be
     * inaccessible memory.
     */
    if (is_prot_none && !is_fixed) {
        guest_invalidate_ptes(g, result_off, result_off + length);
    }

    if (!is_prot_none && !is_fixed && !is_noreserve) {
        /* Extend page tables for this specific allocation range only.
         * guest_extend_page_tables skips already-mapped blocks, so calling it
         * on pre-mapped regions is a no-op. This avoids creating entries for
         * PROT_NONE gaps between allocations.
         */
        if (needs_exec && !(prot & LINUX_PROT_WRITE)) {
            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->mmap_limit)
                ext_end = g->mmap_limit;
            if (guest_extend_page_tables(g, ext_start, ext_end, MEM_PERM_RX) <
                0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            /* Re-validate any previously-invalidated L3 entries (see the RW
             * path comment below for the full explanation).
             */
            guest_update_perms(g, result_off, result_off + length, MEM_PERM_RX);
            if (ext_end > g->mmap_rx_end)
                g->mmap_rx_end = ext_end;
        } else {
            uint64_t ext_start = ALIGN_DOWN(result_off, BLOCK_2MIB);
            uint64_t ext_end = ALIGN_UP(result_off + length, BLOCK_2MIB);
            if (ext_end > g->mmap_limit)
                ext_end = g->mmap_limit;
            /* Preserve execute permission for RWX requests. Stage-2 (hv_vm_map)
             * is RWX for the whole buffer; stage-1 PTEs set AP=RW_EL0 with
             * UXN/PXN=0 for combined W+X. HVF allows this in stage-1 even
             * though normal W^X enforcement disallows it per HV_MEMORY flags.
             */
            int ext_perms = MEM_PERM_RW;
            if (prot & LINUX_PROT_EXEC)
                ext_perms |= MEM_PERM_X;
            if (guest_extend_page_tables(g, ext_start, ext_end, ext_perms) <
                0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                return -LINUX_ENOMEM;
            }
            /* Update permissions on the allocated range. This handles two
             * cases:
             * 1. RWX: pre-existing RW blocks need execute permission added
             * 2. L3 split entries: if an L2 block was previously split into
             *    L3 page entries (e.g., via mprotect(PROT_NONE) on a sub-block
             *    range), guest_extend_page_tables skips the L2 entry (it sees
             *    a valid table descriptor). The L3 entries may be invalidated,
             *    so the memory syscall layer must re-create them with the
             *    correct permissions.
             */
            guest_update_perms(g, result_off, result_off + length, ext_perms);
            if (ext_end > g->mmap_end)
                g->mmap_end = ext_end;
        }

        /* Zero the mapped region */
        memset((uint8_t *) g->host_base + result_off, 0, length);
    }

    /* MAP_NORESERVE: invalidate any stale PTEs (like PROT_NONE path) but track
     * the region for lazy materialization on first fault. Page table entries
     * will be created by guest_materialize_lazy() when the guest first touches
     * a page in this range.
     */
    if (is_noreserve && !is_fixed) {
        guest_invalidate_ptes(g, result_off, result_off + length);
    }

    /* For file-backed mmap, populate the region with file contents. MAP_SHARED
     * installs a real host mmap MAP_FIXED|MAP_SHARED overlay so guest reads
     * observe concurrent host writes and guest writes hit the file directly.
     * MAP_PRIVATE pread-snapshots into private guest pages so writes stay
     * local. Skip for PROT_NONE: the region has no page table entries yet; data
     * is faulted in when mprotect makes the pages accessible.
     */
    if (!is_anon && fd >= 0 && !is_prot_none) {
        size_t hps = host_page_size_cached();
        /* mmap rounds length up to the host page size internally; only addr and
         * offset alignment matter for MAP_FIXED on macOS Apple Silicon (16 KiB
         * host pages). The "extra" trailing bytes inside the host page are
         * never reachable by the guest because the gap-finder advances the hint
         * to the next host-page boundary after each allocation.
        /* mmap rounds length up to the host page size internally; only
         * addr and offset alignment matter for MAP_FIXED on macOS Apple
         * Silicon (16 KiB host pages). The "extra" trailing bytes inside
         * the host page are never reachable by the guest because the
         * gap-finder advances the hint to the next host-page boundary
         * after each allocation.
         */
        /* overlay_fd_writable rejects read-only backing fds inside
         * hvf_apply_file_overlay; mirror the check here so a read-only mmap
         * takes the snapshot pread path directly, skipping the thread_quiesce /
         * segment_split cycle the overlay would otherwise perform before
         * returning EACCES.
         */
        bool overlay_aligned = (flags & LINUX_MAP_SHARED) &&
                               overlay_fd_writable(host_backing_fd) &&
                               (result_off % hps == 0) &&
                               ((uint64_t) offset % hps == 0);
        if (overlay_aligned) {
            uint64_t nf_overlay_len = ALIGN_UP(length, hps);
            int oerr = hvf_apply_file_overlay(g, result_off, nf_overlay_len,
                                              host_backing_fd, (off_t) offset);
            if (oerr < 0) {
                int rollback_err = rollback_fresh_mmap_allocation(
                    g, result_off, length, false, 0, 0, saved_mmap_next,
                    saved_mmap_end, saved_mmap_rx_next, saved_mmap_rx_end,
                    saved_rw_gap_hint, saved_rx_gap_hint);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                if (rollback_err < 0)
                    return rollback_err;
                return oerr;
            }
            overlay_installed = true;
            overlay_ipa = result_off;
            overlay_len = nf_overlay_len;
        } else {
            uint8_t *dst = (uint8_t *) g->host_base + result_off;
            size_t remaining = length;
            off_t file_off = offset;
            bool read_err = false;
            int saved_errno = 0;
            while (remaining > 0) {
                ssize_t nr = pread(host_backing_fd, dst, remaining, file_off);
                if (nr < 0) {
                    if (errno == EINTR)
                        continue;
                    read_err = true;
                    saved_errno = errno;
                    break;
                }
                if (nr == 0)
                    break; /* EOF; remaining pages stay zeroed */
                dst += nr;
                remaining -= (size_t) nr;
                file_off += nr;
            }
            if (read_err) {
                /* Any host I/O error (total OR partial) is fatal. The previous
                 * "remaining == length" gate silently kept partial-read
                 * mappings with a zeroed tail when an I/O error fired
                 * mid-stream, which made truncated file contents visible to the
                 * guest as a successful mmap.
                 */
                int rollback_err = rollback_fresh_mmap_allocation(
                    g, result_off, length, false, 0, 0, saved_mmap_next,
                    saved_mmap_end, saved_mmap_rx_next, saved_mmap_rx_end,
                    saved_rw_gap_hint, saved_rx_gap_hint);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                host_fd_ref_close(&backing_ref);
                if (rollback_err < 0)
                    return rollback_err;
                errno = saved_errno;
                return linux_errno();
            }
        }
    }

    /* Record the new region. guest_region_add_ex derives shared from the
     * LINUX_MAP_SHARED bit in track_flags for msync write-back.
     */
    if (guest_region_add_ex_owned(g, result_off, result_off + length, prot,
                                  track_flags, is_anon ? 0 : (uint64_t) offset,
                                  NULL, track_backing_fd) < 0) {
        /* Region table was full: undo any host overlay we just installed so the
         * file is not left mmap'd at host_base+ipa with no tracking. Without
         * this, a later operation in that range would memset zeros directly
         * into the user's file via the leaked overlay.
         */
        int rollback_err = 0;
        if (replaced_regions_removed) {
            if (overlay_installed)
                hvf_remove_file_overlay(g, overlay_ipa, overlay_len);
            rollback_err =
                restore_region_snapshots(g, replaced_snaps, replaced_nsnaps);
            if (rollback_err == 0)
                rollback_err = restore_snapshot_page_tables(
                    g, result_off, result_off + length, replaced_snaps,
                    replaced_nsnaps);
        } else {
            rollback_err = rollback_fresh_mmap_allocation(
                g, result_off, length, overlay_installed, overlay_ipa,
                overlay_len, saved_mmap_next, saved_mmap_end,
                saved_mmap_rx_next, saved_mmap_rx_end, saved_rw_gap_hint,
                saved_rx_gap_hint);
        }
        dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);
        host_fd_ref_close(&backing_ref);
        if (rollback_err < 0)
            return rollback_err;
        return -LINUX_ENOMEM;
    }

    /* Mark the region as overlay-backed when sys_mmap installed a real
     * MAP_FIXED|MAP_SHARED overlay on the host VA. Used by msync to skip the
     * snapshot-style pwrite/refresh paths for regions that the kernel already
     * keeps coherent with the file's page cache.
     */
    if (!is_anon && fd >= 0 && !is_prot_none && (flags & LINUX_MAP_SHARED)) {
        if ((result_off % hps == 0) && ((uint64_t) offset % hps == 0)) {
            for (int i = 0; i < g->nregions; i++) {
                if (g->regions[i].start == result_off &&
                    g->regions[i].end == result_off + length) {
                    g->regions[i].overlay_active = true;
                    g->regions[i].overlay_start = result_off;
                    g->regions[i].overlay_end =
                        result_off + ALIGN_UP(length, hps);
                    break;
                }
            }
        }
    }

    host_fd_ref_close(&backing_ref);
    dispose_region_snapshots(&replaced_snaps, &replaced_nsnaps);

    /* Return IPA-based address to guest */
    return (int64_t) guest_ipa(g, result_off);
}

/* sys_mremap. */

int64_t sys_mremap(guest_t *g,
                   uint64_t old_addr,
                   uint64_t old_size,
                   uint64_t new_size,
                   int flags,
                   uint64_t new_addr)
{
    /* Validate alignment */
    if (old_addr & 4095)
        return -LINUX_EINVAL;

    /* Round sizes to page boundary */
    if (old_size > UINT64_MAX - 4095 || new_size > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    old_size = PAGE_ALIGN_UP(old_size);
    new_size = PAGE_ALIGN_UP(new_size);
    if (new_size == 0)
        return -LINUX_EINVAL;
    /* Linux allows old_size==0 only for certain vma types (e.g., shared
     * anonymous with MREMAP_MAYMOVE). mremap does not support these; reject.
     */
    if (old_size == 0)
        return -LINUX_EINVAL;

    /* Reject MREMAP_DONTUNMAP (not implemented) */
    if (flags & LINUX_MREMAP_DONTUNMAP)
        return -LINUX_EINVAL;

    /* MREMAP_FIXED requires MREMAP_MAYMOVE */
    if ((flags & LINUX_MREMAP_FIXED) && !(flags & LINUX_MREMAP_MAYMOVE))
        return -LINUX_EINVAL;

    /* Reject unknown flags */
    if (flags &
        ~(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP))
        return -LINUX_EINVAL;

    /* Overflow check on old range. mremap's body shrinks, copies, and zeroes
     * via raw host_base+off arithmetic, so the check stays primary-only here
     * until the data-movement paths are made region-aware.
     */
    uint64_t old_off = old_addr - g->ipa_base;
    if (old_off > g->guest_size)
        return -LINUX_EFAULT;
    if (old_size > 0 && old_size > g->guest_size - old_off)
        return -LINUX_EFAULT;

    /* Reject mremap whose source range touches VM infrastructure (page tables,
     * shim code, shim data). Without this guard a guest can move the shim_data
     * block out from under the EL1 stack or the shim- globals identity cache,
     * since the move path issues raw memmove, memset, region removal and PTE
     * invalidation. Matches the parallel guards in sys_mmap MAP_FIXED,
     * sys_munmap and sys_mprotect.
     */
    if (guest_range_hits_infra(g, old_off, old_off + old_size))
        return -LINUX_EINVAL;

    /* Verify the whole source range is covered by one tracked VMA. mremap()
     * must not copy holes or unrelated adjacent mappings.
     */
    const guest_region_t *src_reg = guest_region_find(g, old_off);
    if (!src_reg || src_reg->end - old_off < old_size)
        return -LINUX_EFAULT;

    /* Same size: nothing to do */
    if (old_size == new_size && !(flags & LINUX_MREMAP_FIXED))
        return (int64_t) old_addr;

    /* Shrinking mremap keeps the base address and releases only the tail. */
    if (new_size < old_size && !(flags & LINUX_MREMAP_FIXED)) {
        uint64_t tail_off = old_off + new_size, tail_end = old_off + old_size;
        /* Restore slab backing under any tail overlay before zeroing so the
         * memset does not write zeros into a file.
         */
        int cleanup_err = cleanup_overlays_in_range(g, tail_off, tail_end);
        if (cleanup_err < 0)
            return cleanup_err;
        /* Zero the trimmed region */
        memset((uint8_t *) g->host_base + tail_off, 0, tail_end - tail_off);
        guest_region_remove(g, tail_off, tail_end);
        guest_invalidate_ptes(g, tail_off, tail_end);
        if (tail_off < g->mmap_rw_gap_hint)
            g->mmap_rw_gap_hint = tail_off;
        if (tail_off < g->mmap_rx_gap_hint)
            g->mmap_rx_gap_hint = tail_off;
        return (int64_t) old_addr;
    }

    /* MREMAP_FIXED: move to a specific new address */
    if (flags & LINUX_MREMAP_FIXED) {
        if (new_addr & 4095)
            return -LINUX_EINVAL;
        uint64_t new_off = new_addr - g->ipa_base;
        /* MREMAP_FIXED dest stays primary-only for the same reason as the
         * source check above.
         */
        if (new_off > g->guest_size || new_size > g->guest_size - new_off)
            return -LINUX_ENOMEM;

        /* Same infrastructure protection as the source range: the move tail
         * removes any existing dest region and rewrites PTEs, which would
         * corrupt page tables / shim text / shim data if the dest lands inside
         * infra.
         */
        if (guest_range_hits_infra(g, new_off, new_off + new_size))
            return -LINUX_EINVAL;

        /* Linux rejects MREMAP_FIXED when old and new ranges overlap */
        uint64_t old_end = old_off + old_size, new_end = new_off + new_size;
        if (old_off < new_end && new_off < old_end)
            return -LINUX_EINVAL;

        remove_range_t removed[] = {
            {old_off, old_end},
            {new_off, new_end},
        };
        if (!region_has_capacity_after_removes(g, removed, 2, 1))
            return -LINUX_ENOMEM;

        /* Capture old region metadata BEFORE modifying any regions. If mremap
         * removed destination first, an overlapping source would lose its
         * metadata. The overlap check above prevents this case, but capturing
         * first is still the safe ordering.
         */
        const guest_region_t *old_reg = guest_region_find(g, old_off);
        int prot =
            old_reg ? old_reg->prot : (LINUX_PROT_READ | LINUX_PROT_WRITE);
        int track_flags = old_reg ? old_reg->flags
                                  : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
        uint64_t track_offset = old_reg ? old_reg->offset : 0;
        int track_backing_fd = dup_region_backing_fd(old_reg);
        if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
            return -LINUX_ENOMEM;
        bool source_overlay = old_reg && region_has_live_overlay(old_reg);
        uint64_t source_file_off =
            old_reg ? old_reg->offset + (old_off - old_reg->start) : 0;
        char track_name[sizeof(old_reg->name)] = {0};
        /* Heap-allocated to avoid blowing the ~512 KiB default macOS thread
         * stack: each region_snapshot_t array is GUEST_MAX_REGIONS *
         * sizeof(region_snapshot_t), so two of them on the stack would be close
         * to a megabyte. Freed via dispose_region_snapshots on every exit path
         * below.
         */
        region_snapshot_t *source_snaps = NULL;
        region_snapshot_t *dest_snaps = NULL;
        int source_nsnaps = 0, dest_nsnaps = 0;
        if (old_reg)
            str_copy_trunc(track_name, old_reg->name, sizeof(track_name));

        source_snaps = malloc(GUEST_MAX_REGIONS * sizeof(*source_snaps));
        dest_snaps = malloc(GUEST_MAX_REGIONS * sizeof(*dest_snaps));
        if (!source_snaps || !dest_snaps) {
            free(source_snaps);
            free(dest_snaps);
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        source_nsnaps = capture_region_snapshots(
            g, old_off, old_off + old_size, source_snaps, GUEST_MAX_REGIONS);
        if (source_nsnaps < 0) {
            free(source_snaps);
            free(dest_snaps);
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return source_nsnaps;
        }
        dest_nsnaps = capture_region_snapshots(g, new_off, new_off + new_size,
                                               dest_snaps, GUEST_MAX_REGIONS);
        if (dest_nsnaps < 0) {
            dispose_region_snapshots(&source_snaps, &source_nsnaps);
            free(dest_snaps);
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return dest_nsnaps;
        }

        if (source_overlay) {
            int cleanup_err =
                cleanup_overlays_in_range(g, old_off, old_off + old_size);
            if (cleanup_err < 0) {
                (void) restore_snapshot_overlays_in_place(g, source_snaps,
                                                          source_nsnaps);
                dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
                dispose_region_snapshots(&source_snaps, &source_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                return cleanup_err;
            }
        }

        int cleanup_err =
            cleanup_overlays_in_range(g, new_off, new_off + new_size);
        if (cleanup_err < 0) {
            int restore_err = restore_snapshot_overlays_in_place(
                g, source_snaps, source_nsnaps);
            if (restore_err < 0) {
                dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
                dispose_region_snapshots(&source_snaps, &source_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                return restore_err;
            }
            (void) restore_snapshot_overlays_in_place(g, dest_snaps,
                                                      dest_nsnaps);
            dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
            dispose_region_snapshots(&source_snaps, &source_nsnaps);
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return cleanup_err;
        }

        if (mremap_extend_range(g, new_off, new_size, prot) < 0) {
            int restore_err = restore_snapshot_overlays_in_place(
                g, source_snaps, source_nsnaps);
            if (restore_err < 0) {
                dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
                dispose_region_snapshots(&source_snaps, &source_nsnaps);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                return restore_err;
            }
            (void) restore_snapshot_overlays_in_place(g, dest_snaps,
                                                      dest_nsnaps);
            dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
            dispose_region_snapshots(&source_snaps, &source_nsnaps);
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        /* Remove existing mappings at the destination after all fallible
         * preparation is complete.
         */
        guest_region_remove(g, new_off, new_off + new_size);

        /* Copy data (use memmove for potential overlap). If the source has a
         * live overlay, the read side of the memmove pulls live file content;
         * the destination receives a private snapshot at mremap time (no
         * overlay reapplied), and msync's emulated pwrite-the-diff path keeps
         * subsequent writes consistent.
         */
        uint64_t copy_len = old_size < new_size ? old_size : new_size;
        if (prot == LINUX_PROT_NONE) {
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
        } else if (source_overlay) {
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
            int copy_err = read_file_range_to_guest(
                g, new_off, track_backing_fd, source_file_off, copy_len);
            if (copy_err < 0) {
                int restore_err = restore_snapshot_overlays_in_place(
                    g, source_snaps, source_nsnaps);
                if (restore_err < 0)
                    copy_err = restore_err;
                restore_err =
                    restore_region_snapshots(g, dest_snaps, dest_nsnaps);
                /* Re-establish the destination's page-table state to match the
                 * regions we just restored. mremap_extend_range above had
                 * filled in PTEs for the new mremap target; without this
                 * rollback those PTEs would outlive the regions and the guest
                 * would see live mappings where its own metadata (after the
                 * restore) says nothing is mapped.
                 */
                int pt_err = restore_snapshot_page_tables(
                    g, new_off, new_off + new_size, dest_snaps, dest_nsnaps);
                if (pt_err < 0 && restore_err >= 0)
                    restore_err = pt_err;
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                dispose_region_snapshots(&source_snaps, &source_nsnaps);
                dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
                if (restore_err < 0)
                    return restore_err;
                return copy_err;
            }
        } else {
            memmove((uint8_t *) g->host_base + new_off,
                    (uint8_t *) g->host_base + old_off, copy_len);
        }
        /* Zero any extension beyond old data */
        if (new_size > old_size)
            memset((uint8_t *) g->host_base + new_off + old_size, 0,
                   new_size - old_size);

        /* Remove old mapping */
        if (old_size > 0) {
            memset((uint8_t *) g->host_base + old_off, 0, old_size);
            guest_region_remove(g, old_off, old_off + old_size);
            guest_invalidate_ptes(g, old_off, old_off + old_size);
            if (old_off < g->mmap_rw_gap_hint)
                g->mmap_rw_gap_hint = old_off;
            if (old_off < g->mmap_rx_gap_hint)
                g->mmap_rx_gap_hint = old_off;
        }

        if (guest_region_add_ex_owned(
                g, new_off, new_off + new_size, prot, track_flags, track_offset,
                track_name[0] ? track_name : NULL, track_backing_fd) < 0) {
            (void) restore_region_snapshots(g, dest_snaps, dest_nsnaps);
            dispose_region_snapshots(&source_snaps, &source_nsnaps);
            dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
            return -LINUX_ENOMEM;
        }
        dispose_region_snapshots(&source_snaps, &source_nsnaps);
        dispose_region_snapshots(&dest_snaps, &dest_nsnaps);
        return (int64_t) guest_ipa(g, new_off);
    }

    /* Grow in place: try to extend without moving */
    if (new_size > old_size) {
        uint64_t grow_off = old_off + old_size, grow_len = new_size - old_size;

        /* Reject growing into infrastructure (page tables, shim text, shim
         * data). The source-range infra guard above only covers [old_off,
         * old_off+old_size); the grown tail can still spill into infra without
         * it.
         */
        if (guest_range_hits_infra(g, grow_off, grow_off + grow_len))
            return -LINUX_EINVAL;

        /* Check if the space after the old region is free (overflow-safe) */
        if (grow_off <= g->guest_size && grow_len <= g->guest_size - grow_off) {
            bool can_grow = true;
            for (int i = 0; i < g->nregions; i++) {
                if (g->regions[i].start >= grow_off + grow_len)
                    break;
                if (g->regions[i].end > grow_off &&
                    g->regions[i].start < grow_off + grow_len) {
                    /* Skip the region being extended */
                    if (g->regions[i].start == old_off)
                        continue;
                    can_grow = false;
                    break;
                }
            }

            if (can_grow) {
                remove_range_t removed = {old_off, old_off + old_size};
                if (!region_has_capacity_after_removes(g, &removed, 1, 1))
                    return -LINUX_ENOMEM;

                /* Extend in place */
                const guest_region_t *old_reg = guest_region_find(g, old_off);
                int prot = old_reg ? old_reg->prot
                                   : (LINUX_PROT_READ | LINUX_PROT_WRITE);
                int track_flags =
                    old_reg ? old_reg->flags
                            : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
                uint64_t track_offset = old_reg ? old_reg->offset : 0;
                int track_backing_fd = dup_region_backing_fd(old_reg);
                bool old_overlay = old_reg && region_has_live_overlay(old_reg);
                uint64_t old_overlay_start =
                    old_overlay ? old_reg->overlay_start : 0;
                uint64_t old_overlay_end =
                    old_overlay ? old_reg->overlay_end : 0;
                if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
                    return -LINUX_ENOMEM;
                char track_name[sizeof(old_reg->name)] = {0};
                if (old_reg)
                    str_copy_trunc(track_name, old_reg->name,
                                   sizeof(track_name));

                if (mremap_extend_range(g, grow_off, grow_len, prot) < 0) {
                    if (track_backing_fd >= 0)
                        close(track_backing_fd);
                    return -LINUX_ENOMEM;
                }

                memset((uint8_t *) g->host_base + grow_off, 0, grow_len);

                /* Update region tracking: remove old, add extended */
                guest_region_remove(g, old_off, old_off + old_size);
                if (guest_region_add_ex_owned(g, old_off, old_off + new_size,
                                              prot, track_flags, track_offset,
                                              track_name[0] ? track_name : NULL,
                                              track_backing_fd) < 0)
                    return -LINUX_ENOMEM;
                if (old_overlay)
                    mark_overlay_metadata_range(g, old_off, old_off + old_size,
                                                old_overlay_start,
                                                old_overlay_end);

                /* Update high-water marks */
                uint64_t hwm = old_off + new_size;
                if (old_off >= MMAP_RX_BASE && old_off < MMAP_BASE) {
                    if (hwm > g->mmap_rx_next)
                        g->mmap_rx_next = hwm;
                } else if (old_off >= MMAP_BASE) {
                    if (hwm > g->mmap_next)
                        g->mmap_next = hwm;
                }

                return (int64_t) old_addr;
            }
        }

        /* Growth in place failed; MREMAP_MAYMOVE is required */
        if (!(flags & LINUX_MREMAP_MAYMOVE))
            return -LINUX_ENOMEM;

        /* Allocate a new region and move */
        const guest_region_t *old_reg = guest_region_find(g, old_off);
        int prot =
            old_reg ? old_reg->prot : (LINUX_PROT_READ | LINUX_PROT_WRITE);
        int track_flags = old_reg ? old_reg->flags
                                  : (LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS);
        uint64_t track_offset = old_reg ? old_reg->offset : 0;
        int track_backing_fd = dup_region_backing_fd(old_reg);
        if (old_reg && old_reg->backing_fd >= 0 && track_backing_fd < 0)
            return -LINUX_ENOMEM;
        bool source_overlay = old_reg && region_has_live_overlay(old_reg);
        uint64_t source_overlay_start =
            source_overlay ? old_reg->overlay_start : 0;
        uint64_t source_overlay_end = source_overlay ? old_reg->overlay_end : 0;
        uint64_t source_file_off =
            old_reg ? old_reg->offset + (old_off - old_reg->start) : 0;
        uint64_t source_overlay_file_off =
            source_overlay
                ? old_reg->offset + (source_overlay_start - old_reg->start)
                : 0;
        char track_name[sizeof(old_reg->name)] = {0};
        if (old_reg)
            str_copy_trunc(track_name, old_reg->name, sizeof(track_name));
        int needs_exec = (prot & LINUX_PROT_EXEC) != 0;

        uint64_t new_off;
        if (needs_exec && !(prot & LINUX_PROT_WRITE))
            new_off = find_free_gap(g, new_size, MMAP_RX_BASE, g->mmap_limit,
                                    host_page_size_cached());
        else
            new_off = find_free_gap(g, new_size, MMAP_BASE, g->mmap_limit,
                                    host_page_size_cached());

        if (new_off == UINT64_MAX) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        remove_range_t removed = {old_off, old_off + old_size};
        if (!region_has_capacity_after_removes(g, &removed, 1, 1)) {
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        if (source_overlay) {
            int cleanup_err =
                cleanup_overlays_in_range(g, old_off, old_off + old_size);
            if (cleanup_err < 0) {
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                return cleanup_err;
            }
        }

        if (mremap_extend_range(g, new_off, new_size, prot) < 0) {
            if (source_overlay) {
                int restore_err = restore_file_overlay_range(
                    g, old_off, old_off + old_size, source_overlay_start,
                    source_overlay_end, track_backing_fd,
                    source_overlay_file_off);
                if (restore_err < 0) {
                    if (track_backing_fd >= 0)
                        close(track_backing_fd);
                    return restore_err;
                }
            }
            if (track_backing_fd >= 0)
                close(track_backing_fd);
            return -LINUX_ENOMEM;
        }

        /* Copy old data, zero extension. The new range was just allocated from
         * a free gap so it has no overlays to clean up; the source may have an
         * overlay, which is read transparently by the memcpy before its
         * underlying slab is restored below.
         */
        if (prot == LINUX_PROT_NONE) {
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
        } else if (source_overlay) {
            memset((uint8_t *) g->host_base + new_off, 0, new_size);
            int copy_err = read_file_range_to_guest(
                g, new_off, track_backing_fd, source_file_off, old_size);
            if (copy_err < 0) {
                /* Roll back both sides: re-apply the source overlay so the
                 * caller's MAP_SHARED is not silently demoted to a slab
                 * snapshot, and tear down the destination PTEs we just
                 * allocated via mremap_extend_range so the guest does not see
                 * phantom zero pages where the failed mremap landed.
                 */
                (void) restore_file_overlay_range(
                    g, old_off, old_off + old_size, source_overlay_start,
                    source_overlay_end, track_backing_fd,
                    source_overlay_file_off);
                guest_invalidate_ptes(g, new_off, new_off + new_size);
                if (track_backing_fd >= 0)
                    close(track_backing_fd);
                return copy_err;
            }
        } else {
            memcpy((uint8_t *) g->host_base + new_off,
                   (uint8_t *) g->host_base + old_off, old_size);
        }
        memset((uint8_t *) g->host_base + new_off + old_size, 0,
               new_size - old_size);

        /* Remove old mapping. Any live source overlay was already torn down
         * before the destination range was touched.
         */
        memset((uint8_t *) g->host_base + old_off, 0, old_size);
        guest_region_remove(g, old_off, old_off + old_size);
        guest_invalidate_ptes(g, old_off, old_off + old_size);
        if (old_off < g->mmap_rw_gap_hint)
            g->mmap_rw_gap_hint = old_off;
        if (old_off < g->mmap_rx_gap_hint)
            g->mmap_rx_gap_hint = old_off;

        /* Track new region */
        if (guest_region_add_ex_owned(
                g, new_off, new_off + new_size, prot, track_flags, track_offset,
                track_name[0] ? track_name : NULL, track_backing_fd) < 0)
            return -LINUX_ENOMEM;

        /* Update high-water marks */
        uint64_t hwm = new_off + new_size;
        if (new_off >= MMAP_RX_BASE && new_off < MMAP_BASE) {
            if (hwm > g->mmap_rx_next)
                g->mmap_rx_next = hwm;
        } else if (new_off >= MMAP_BASE) {
            if (hwm > g->mmap_next)
                g->mmap_next = hwm;
        }

        return (int64_t) guest_ipa(g, new_off);
    }

    /* Should not reach here */
    return -LINUX_EINVAL;
}

/* sys_madvise. */

/* Returns true if [off, off+length) is fully covered by mapped regions. Mirrors
 * Linux madvise_walk_vmas, which returns -ENOMEM whenever it would step over an
 * unmapped sub-range. Caller holds mmap_lock.
 */
static bool madvise_range_mapped(const guest_t *g,
                                 uint64_t off,
                                 uint64_t length)
{
    uint64_t end = off + length;
    uint64_t covered = off;
    for (int i = 0; i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= covered)
            continue;
        if (r->start > covered)
            return false;
        covered = r->end;
    }
    return covered >= end;
}

int64_t sys_madvise(guest_t *g, uint64_t addr, uint64_t length, int advice)
{
    if (addr & 4095)
        return -LINUX_EINVAL;

    if (length > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return 0;

    /* Range must lie within the guest IPA window. Linux returns -ENOMEM (not
     * -EINVAL) for addresses outside the process address space; see madvise(2):
     * "Addresses in the specified range are not currently mapped, or are
     * outside the address space of the process." Stays primary-only because
     * MADV_DONTNEED zeroes via raw host_base+off and the slab restore path
     * likewise assumes primary backing. The region-aware variant will consume
     * guest_is_valid_range once the body is updated.
     */
    uint64_t off = addr - g->ipa_base;
    if (off > g->guest_size || length > g->guest_size - off)
        return -LINUX_ENOMEM;

    /* Defensive guard against destructive advice on infrastructure ranges (page
     * tables, shim text, shim data). MADV_DONTNEED would zero shim data via raw
     * host_base+off arithmetic; MADV_FREE on a future flag change could do the
     * same. Today the destructive advice paths happen to skip non-anonymous
     * regions, but a future regression should not silently reopen the hole.
     */
    if (guest_range_hits_infra(g, off, off + length))
        return -LINUX_EINVAL;

    switch (advice) {
    case LINUX_MADV_DONTNEED: {
        /* MADV_DONTNEED: zero anon pages so next access sees zero-fill, restore
         * file-backed pages from the current backing file contents. Linux
         * returns -ENOMEM if any part of the range is unmapped.
         *
         * Writable MAP_SHARED file-backed regions are preserved so elfuse does
         * not overwrite unsynced in-memory writes with backing-file contents.
         * Read-only MAP_SHARED mappings can be invalidated safely and should
         * refault from the current file image.
         *
         * PROT_NONE anonymous regions still get zeroed so the guest's next
         * mprotect-and-read sees zero-fill (Linux semantics: pages are
         * detached, faulted in lazily as zero on re-grant).
         */
        if (!madvise_range_mapped(g, off, length))
            return -LINUX_ENOMEM;

        uint64_t end = off + length;
        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *r = &g->regions[i];
            if (r->start >= end)
                break;
            if (r->end <= off)
                continue;
            if (!(r->flags & LINUX_MAP_ANONYMOUS) && r->backing_fd < 0)
                continue;
            if (r->shared && r->backing_fd >= 0 && (r->prot & LINUX_PROT_WRITE))
                continue;
            /* Overlay-backed regions already serve their content from the
             * file's page cache. The "zero + pread" reset would write zeros
             * straight into the file because the host VA is the file. Skip the
             * reset; the next guest read already sees the current file image,
             * which is what MADV_DONTNEED promises.
             */
            if (r->overlay_active)
                continue;

            uint64_t zstart = (r->start > off) ? r->start : off;
            uint64_t zend = (r->end < end) ? r->end : end;
            memset((uint8_t *) g->host_base + zstart, 0, zend - zstart);
            if (!(r->flags & LINUX_MAP_ANONYMOUS)) {
                /* EOF leaves the tail zero per mmap rules; the helper already
                 * returns 0 in that case after stopping the read loop.
                 */
                int err = read_file_range_to_guest(
                    g, zstart, r->backing_fd, r->offset + (zstart - r->start),
                    zend - zstart);
                if (err < 0)
                    return err;
            }
        }
        return 0;
    }

    case LINUX_MADV_FREE: {
        /* MADV_FREE: only valid for private anonymous mappings. Linux returns
         * -EINVAL for any non-anonymous vma (vma_is_anonymous check), even if
         * the region is tracked without a live backing fd. Subsequent reads may
         * legally return either old data or zero, so a no-op satisfies the spec
         * for the anon case.
         */
        if (!madvise_range_mapped(g, off, length))
            return -LINUX_ENOMEM;

        uint64_t end = off + length;
        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *r = &g->regions[i];
            if (r->start >= end)
                break;
            if (r->end <= off)
                continue;
            if (!(r->flags & LINUX_MAP_ANONYMOUS) ||
                (r->flags & LINUX_MAP_SHARED))
                return -LINUX_EINVAL;
        }
        return 0;
    }

    case LINUX_MADV_NORMAL:
    case LINUX_MADV_RANDOM:
    case LINUX_MADV_SEQUENTIAL:
    case LINUX_MADV_WILLNEED:
    case LINUX_MADV_HUGEPAGE:
    case LINUX_MADV_NOHUGEPAGE:
    case LINUX_MADV_COLD:
    case LINUX_MADV_PAGEOUT:
        /* Advisory hints: accept silently. Linux walks vmas and returns -ENOMEM
         * for any unmapped sub-range; mirror that for fidelity. No host swap
         * means PAGEOUT/COLD do not actually evict -- keeping data in place is
         * a stricter guarantee than Linux's.
         */
        if (!madvise_range_mapped(g, off, length))
            return -LINUX_ENOMEM;
        return 0;

    default:
        return -LINUX_EINVAL;
    }
}

/* Anonymous mmap wrapper for other modules. */
int64_t sys_mmap_anon(guest_t *g, uint64_t addr, uint64_t length, int prot)
{
    return sys_mmap(g, addr, length, prot,
                    LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
}

static int compare_range_pair(const void *a, const void *b)
{
    const uint64_t *ra = a;
    const uint64_t *rb = b;

    if (ra[0] < rb[0])
        return -1;
    if (ra[0] > rb[0])
        return 1;
    return 0;
}

static int munmap_guest_range(guest_t *g, uint64_t unmap_off, uint64_t end)
{
    /* Reject munmap targeting VM infrastructure regions. */
    if (guest_range_hits_infra(g, unmap_off, end))
        return -LINUX_EINVAL;

    /* Restore slab backing under any active MAP_SHARED file overlay before
     * zeroing the host VA. Without this, the memset below would write zeros
     * directly into the file.
     */
    int cleanup_err = cleanup_overlays_in_range(g, unmap_off, end);
    if (cleanup_err < 0)
        return cleanup_err;

    /* Invalidate PTEs first. This may need to split a 2MiB block which can fail
     * if the page table pool is exhausted. Failing before region removal keeps
     * metadata consistent.
     */
    if (guest_invalidate_ptes(g, unmap_off, end) < 0)
        return -LINUX_ENOMEM;
    for (int i = 0; i < g->nregions; i++) {
        guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= unmap_off)
            continue;
        if (r->prot == LINUX_PROT_NONE)
            continue;
        uint64_t zstart = (r->start > unmap_off) ? r->start : unmap_off;
        uint64_t zend = (r->end < end) ? r->end : end;
        memset((uint8_t *) g->host_base + zstart, 0, zend - zstart);
    }
    guest_region_remove(g, unmap_off, end);
    if (unmap_off < g->mmap_rw_gap_hint)
        g->mmap_rw_gap_hint = unmap_off;
    if (unmap_off < g->mmap_rx_gap_hint)
        g->mmap_rx_gap_hint = unmap_off;

    return 0;
}

void mem_cleanup_deferred_stack_unmaps(guest_t *g, thread_entry_t *t)
{
    uint64_t starts[MAX_DEFERRED_STACK_UNMAPS];
    uint64_t ends[MAX_DEFERRED_STACK_UNMAPS];
    int nranges;

    if (!g || !t)
        return;

    nranges = thread_prepare_deferred_stack_unmaps_for_cleanup(
        t, starts, ends, (int) ARRAY_SIZE(starts));
    if (nranges <= 0)
        return;

    pthread_mutex_lock(&mmap_lock);
    for (int i = 0; i < nranges; i++) {
        int rc = munmap_guest_range(g, starts[i], ends[i]);
        if (rc < 0) {
            log_error(
                "deferred stack munmap for tid=%lld leaked: "
                "[0x%llx-0x%llx) rc=%d (region tracking inconsistent)",
                (long long) t->guest_tid, (unsigned long long) starts[i],
                (unsigned long long) ends[i], rc);
            continue;
        }
        thread_drop_deferred_stack_unmap(t, starts[i], ends[i]);
    }
    pthread_mutex_unlock(&mmap_lock);
}

/* sys_munmap. */

int64_t sys_munmap(guest_t *g, uint64_t addr, uint64_t length)
{
    if ((addr & 4095) || length == 0)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return -LINUX_EINVAL;
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;

    if (addr <= 0x0000FFFFFFFFFFFFULL) {
        if (addr >= g->guest_size) {
            if (region_range_overlaps(g, addr, addr + length)) {
                if (guest_invalidate_ptes(g, addr, addr + length) < 0)
                    return -LINUX_ENOMEM;
                guest_region_remove(g, addr, addr + length);
            }
            return 0;
        }
        uint64_t unmap_off = addr - g->ipa_base;
        if (unmap_off <= g->guest_size && length <= g->guest_size - unmap_off) {
            uint64_t end = unmap_off + length;
            thread_deferred_stack_unmap_txn_t txns[MAX_THREADS];
            uint64_t ranges[MAX_THREADS][2];
            int nranges = thread_collect_and_defer_stack_ranges(
                unmap_off, end, txns, (int) ARRAY_SIZE(txns));
            if (nranges < 0)
                return -LINUX_ENOMEM;

            for (int i = 0; i < nranges; i++) {
                ranges[i][0] = txns[i].start;
                ranges[i][1] = txns[i].end;
            }
            if (nranges > 1)
                qsort(ranges, (size_t) nranges, sizeof(ranges[0]),
                      compare_range_pair);

            uint64_t cursor = unmap_off;
            for (int i = 0; i < nranges && cursor < end; i++) {
                uint64_t keep_start = ranges[i][0];
                uint64_t keep_end = ranges[i][1];

                if (keep_start > cursor) {
                    int rc = munmap_guest_range(
                        g, cursor, keep_start < end ? keep_start : end);
                    if (rc < 0) {
                        thread_rollback_deferred_stack_ranges(txns, nranges);
                        return rc;
                    }
                }
                if (keep_end > cursor)
                    cursor = keep_end;
            }
            if (cursor < end) {
                int rc = munmap_guest_range(g, cursor, end);
                if (rc < 0) {
                    thread_rollback_deferred_stack_ranges(txns, nranges);
                    return rc;
                }
            }
            thread_finish_deferred_stack_ranges(txns, nranges);
        }
    }
    return 0;
}

/* sys_mprotect. */

static bool mprotect_same_prot_fast_path_safe(int prot)
{
    /* Non-fixed main-arena mmap initially installs RW PTEs for PROT_READ
     * mappings, relying on mprotect to tighten them later. Do not trust the
     * region tracker alone for read-only same-prot requests.
     */
    return prot == LINUX_PROT_NONE || (prot & LINUX_PROT_WRITE) ||
           (prot & LINUX_PROT_EXEC);
}

int64_t sys_mprotect(guest_t *g, uint64_t addr, uint64_t length, int prot)
{
    if (addr & 4095)
        return -LINUX_EINVAL;
    if (length == 0)
        return 0;
    length = PAGE_ALIGN_UP(length);
    if (length == 0)
        return -LINUX_EINVAL;
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;

    if (addr <= 0x0000FFFFFFFFFFFFULL) {
        if (addr >= g->guest_size) {
            uint64_t mprot_end = addr + length;
            if (guest_kbuf_user_va_overlap(addr, length) &&
                (prot & LINUX_PROT_EXEC))
                return -LINUX_EINVAL;

            /* Fast path: if the tracker already records this prot for every
             * overlapping region and none are MAP_NORESERVE, page tables are
             * already in sync and no PTE work is required. The tracker update
             * is also a no-op, so skip it. Read-only same-prot requests still
             * need PTE work because some mmap paths install RW PTEs while
             * recording PROT_READ in the tracker. Disabled once
             * regions_tracker_stale is set: prior set_prot calls hit
             * GUEST_MAX_REGIONS and left the tracker out of sync with PTEs.
             */
            if (mprotect_same_prot_fast_path_safe(prot) &&
                !g->regions_tracker_stale &&
                guest_region_range_prot_uniform(g, addr, mprot_end, prot) &&
                !guest_region_range_has_noreserve(g, addr, mprot_end))
                return 0;

            /* Do PTE work BEFORE updating the tracker. If page-table
             * maintenance fails, regions[] still reflects the old prot, so a
             * retry will see the mismatch and re-attempt the update instead of
             * short-circuiting on stale tracker state.
             */
            if (prot != LINUX_PROT_NONE) {
                if (guest_update_perms(g, addr, mprot_end,
                                       prot_to_perms(prot)) < 0)
                    return -LINUX_ENOMEM;
            } else {
                if (guest_invalidate_ptes(g, addr, mprot_end) < 0)
                    return -LINUX_ENOMEM;
            }
            guest_region_set_prot(g, addr, mprot_end, prot);
            return 0;
        }
        uint64_t mprot_off = addr - g->ipa_base;
        if (mprot_off <= g->guest_size && length <= g->guest_size - mprot_off) {
            uint64_t mprot_end = mprot_off + length;

            /* Reject mprotect targeting VM infrastructure (page tables, shim).
             * Matches the guard in sys_munmap.
             */
            if (guest_range_hits_infra(g, mprot_off, mprot_end))
                return -LINUX_EINVAL;

            /* Same fast path / ordering / staleness gate as above. */
            if (mprotect_same_prot_fast_path_safe(prot) &&
                !g->regions_tracker_stale &&
                guest_region_range_prot_uniform(g, mprot_off, mprot_end,
                                                prot) &&
                !guest_region_range_has_noreserve(g, mprot_off, mprot_end))
                return 0;

            if (prot != LINUX_PROT_NONE) {
                int page_perms = prot_to_perms(prot);
                if (guest_extend_page_tables(g, mprot_off, mprot_end,
                                             page_perms) < 0)
                    return -LINUX_ENOMEM;
                if (guest_update_perms(g, mprot_off, mprot_end, page_perms) < 0)
                    return -LINUX_ENOMEM;
            } else {
                if (guest_invalidate_ptes(g, mprot_off, mprot_end) < 0)
                    return -LINUX_ENOMEM;
            }
            guest_region_set_prot(g, mprot_off, mprot_end, prot);
        }
    }
    return 0;
}

/* msync helpers. */

static int same_backing_file(int fd_a, int fd_b)
{
    if (fd_a < 0 || fd_b < 0)
        return 0;
    struct stat st_a, st_b;
    if (fstat(fd_a, &st_a) < 0 || fstat(fd_b, &st_b) < 0)
        return 0;
    return st_a.st_dev == st_b.st_dev && st_a.st_ino == st_b.st_ino;
}

static int64_t pwrite_all_at(int fd,
                             const uint8_t *src,
                             uint64_t len,
                             uint64_t file_off)
{
    while (len > 0) {
        size_t chunk =
            len > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX : (size_t) len;
        ssize_t nw;
        do {
            nw = pwrite(fd, src, chunk, (off_t) file_off);
        } while (nw < 0 && errno == EINTR);
        if (nw < 0)
            return linux_errno();
        if (nw == 0)
            return -LINUX_EIO;
        src += nw;
        file_off += (uint64_t) nw;
        len -= (uint64_t) nw;
    }

    return 0;
}

static int64_t sync_shared_aliases_range(guest_t *g,
                                         int backing_fd,
                                         uint64_t file_start,
                                         uint64_t file_end)
{
    uint8_t original[4096];

    for (uint64_t chunk_start = file_start; chunk_start < file_end;) {
        uint64_t chunk_end = ALIGN_DOWN(chunk_start + sizeof(original), 4096);
        if (chunk_end <= chunk_start || chunk_end > file_end)
            chunk_end = file_end;
        size_t chunk_len = (size_t) (chunk_end - chunk_start);

        memset(original, 0, chunk_len);
        ssize_t nr;
        do {
            nr = pread(backing_fd, original, chunk_len, (off_t) chunk_start);
        } while (nr < 0 && errno == EINTR);
        if (nr < 0)
            return linux_errno();

        for (int i = 0; i < g->nregions; i++) {
            const guest_region_t *src = &g->regions[i];
            if (!src->shared || src->backing_fd < 0)
                continue;
            if (!(src->prot & LINUX_PROT_WRITE))
                continue;
            if (!same_backing_file(backing_fd, src->backing_fd))
                continue;

            uint64_t region_file_start = src->offset;
            uint64_t region_file_end = src->offset + (src->end - src->start);
            uint64_t wfile_start = chunk_start > region_file_start
                                       ? chunk_start
                                       : region_file_start;
            uint64_t wfile_end =
                chunk_end < region_file_end ? chunk_end : region_file_end;
            if (wfile_start >= wfile_end)
                continue;

            const uint8_t *guest = (const uint8_t *) g->host_base + src->start +
                                   (wfile_start - src->offset);
            size_t offset = (size_t) (wfile_start - chunk_start);
            size_t len = (size_t) (wfile_end - wfile_start);

            for (size_t pos = 0; pos < len;) {
                while (pos < len && guest[pos] == original[offset + pos])
                    pos++;
                size_t run_start = pos;
                while (pos < len && guest[pos] != original[offset + pos])
                    pos++;
                if (pos > run_start) {
                    int64_t err =
                        pwrite_all_at(src->backing_fd, guest + run_start,
                                      pos - run_start, wfile_start + run_start);
                    if (err < 0)
                        return err;
                }
            }
        }

        chunk_start = chunk_end;
    }

    return 0;
}

static int64_t refresh_shared_region_range(guest_t *g,
                                           guest_region_t *r,
                                           uint64_t file_start,
                                           uint64_t file_end)
{
    uint64_t region_file_start = r->offset;
    uint64_t region_file_end = r->offset + (r->end - r->start);
    uint64_t rfile_start =
        file_start > region_file_start ? file_start : region_file_start;
    uint64_t rfile_end =
        file_end < region_file_end ? file_end : region_file_end;
    if (rfile_start >= rfile_end)
        return 0;

    uint64_t guest_off = r->start + (rfile_start - r->offset);
    uint64_t len = rfile_end - rfile_start, file_off = rfile_start;
    uint8_t *buf = (uint8_t *) g->host_base + guest_off;

    while (len > 0) {
        size_t chunk =
            len > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX : (size_t) len;
        ssize_t nr;
        do {
            nr = pread(r->backing_fd, buf, chunk, (off_t) file_off);
        } while (nr < 0 && errno == EINTR);
        if (nr < 0)
            return linux_errno();
        if (nr == 0)
            break;
        buf += nr;
        file_off += (uint64_t) nr;
        len -= (uint64_t) nr;
    }

    return 0;
}

/* sys_msync. */

int64_t sys_msync(guest_t *g, uint64_t addr, uint64_t length, int flags)
{
    if (addr & 4095)
        return -LINUX_EINVAL;
    if (flags & ~(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC))
        return -LINUX_EINVAL;
    if ((flags & LINUX_MS_ASYNC) && (flags & LINUX_MS_SYNC))
        return -LINUX_EINVAL;
    if (length == 0)
        return 0;
    if (length > UINT64_MAX - 4095)
        return -LINUX_EINVAL;
    length = PAGE_ALIGN_UP(length);
    if (addr > UINT64_MAX - length)
        return -LINUX_EINVAL;
    if (addr < g->ipa_base)
        return -LINUX_ENOMEM;

    uint64_t off = addr - g->ipa_base;
    /* sys_msync stays primary-only here for the same reason as madvise: msync
     * iterates regions and reaches into host_base+off to read pages back from
     * the file overlay. Widening to extra-region ranges needs a region-aware
     * iterator landing alongside the data-movement refactor.
     */
    if (off > g->guest_size || length > g->guest_size - off)
        return -LINUX_ENOMEM;
    uint64_t end = off + length;

    uint64_t cursor = off;
    while (cursor < end) {
        const guest_region_t *r = guest_region_find(g, cursor);
        if (!r || r->start > cursor)
            return -LINUX_ENOMEM;
        cursor = r->end < end ? r->end : end;
    }

    for (int i = 0; i < g->nregions; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->start >= end)
            break;
        if (r->end <= off)
            continue;
        if (!r->shared || r->backing_fd < 0)
            continue;

        uint64_t sync_start = r->start > off ? r->start : off;
        uint64_t sync_end = r->end < end ? r->end : end;
        uint64_t file_start = r->offset + (sync_start - r->start);
        uint64_t file_end = file_start + (sync_end - sync_start);

        /* Real overlay regions are kept coherent with the file by the kernel's
         * page cache. The snapshot-style pwrite-the-diff would compare the live
         * file against itself and may trip on macOS's page-cache write path;
         * the refresh-from-file pass would do the same self-write. Both are
         * no-ops for overlays, so MS_SYNC collapses to a plain fsync.
         */
        if (!r->overlay_active) {
            int64_t err = sync_shared_aliases_range(g, r->backing_fd,
                                                    file_start, file_end);
            if (err < 0)
                return err;
        }

        if (flags & LINUX_MS_SYNC) {
            if (fsync(r->backing_fd) < 0)
                return linux_errno();
        }

        for (int j = 0; j < g->nregions; j++) {
            guest_region_t *dst = &g->regions[j];
            if (!dst->shared || dst->backing_fd < 0)
                continue;
            /* Skip self and overlay-backed peers: the page cache already keeps
             * them coherent with the file. Only legacy snapshot regions (e.g.,
             * a region created by mremap that lost its overlay) need refresh.
             */
            if (dst == r || dst->overlay_active)
                continue;
            if (!same_backing_file(r->backing_fd, dst->backing_fd))
                continue;

            int64_t refresh_err =
                refresh_shared_region_range(g, dst, file_start, file_end);
            if (refresh_err < 0)
                return refresh_err;
        }
    }

    return 0;
}

/* See mem.h. Walk regions, convert each MAP_SHARED|MAP_ANONYMOUS region without
 * backing fd into a memfd-backed overlay so fork can hand the fd to the child
 * for live coherence. Caller has quiesced sibling vCPUs.
 */
static void mmap_fork_dispose_anon_shared_txn(
    mmap_fork_anon_shared_txn_t **txn_ptr)
{
    if (!txn_ptr || !*txn_ptr)
        return;

    mmap_fork_anon_shared_txn_t *txn = *txn_ptr;
    close_region_snapshots(txn->snaps, txn->nsnaps);
    free(txn);
    *txn_ptr = NULL;
}

int mmap_fork_prepare_anon_shared(guest_t *g,
                                  mmap_fork_anon_shared_txn_t **txn_out)
{
    /* Callers must provide a non-NULL txn_out: the transaction handle is the
     * only way to commit or abort the partial state mutated below. Reject up
     * front so the body can assume *txn_out is writable on every exit path.
     */
    if (!txn_out)
        return -LINUX_EINVAL;
    *txn_out = NULL;

    mmap_fork_anon_shared_txn_t *txn = calloc(1, sizeof(*txn));
    if (!txn)
        return -LINUX_ENOMEM;

    pthread_mutex_lock(&mmap_lock);

    size_t hps = host_page_size_cached();

    /* Snapshot candidate ranges first; conversion mutates the region table via
     * hvf_segment_split / mark_overlay_metadata_range and would invalidate the
     * walk indices.
     */
    struct {
        uint64_t start;
        uint64_t end;
    } cands[GUEST_MAX_REGIONS];
    int n_cands = 0;
    for (int i = 0; i < g->nregions && n_cands < GUEST_MAX_REGIONS; i++) {
        const guest_region_t *r = &g->regions[i];
        if (r->backing_fd >= 0)
            continue;
        if (!r->shared)
            continue;
        if (!(r->flags & LINUX_MAP_ANONYMOUS))
            continue;
        if ((r->start % hps) != 0)
            continue; /* misaligned start: snapshot fallback */
        /* If the region is shorter than a host page, the host
         * MAP_FIXED|MAP_SHARED mmap rounds up to ALIGN_UP(len, hps) and may
         * alias the next region's host page. Codex flagged this tail-aliasing
         * hazard. Skip when any subsequent region's tail crosses r->end into
         * the same host page. The leading region is always the one we convert,
         * so backing_fd is naturally -1 for it; sibling regions in the
         * host-page tail will each be inspected on their own iteration.
         */
        uint64_t aligned_end = ALIGN_UP(r->end, hps);
        if (aligned_end > r->end) {
            bool tail_clear = true;
            for (int j = i + 1; j < g->nregions; j++) {
                if (g->regions[j].start >= aligned_end)
                    break;
                if (g->regions[j].end > r->end) {
                    tail_clear = false;
                    break;
                }
            }
            if (!tail_clear)
                continue;
        }
        cands[n_cands].start = r->start;
        cands[n_cands].end = r->end;
        n_cands++;
    }

    for (int i = 0; i < n_cands; i++) {
        uint64_t start = cands[i].start;
        uint64_t end = cands[i].end;
        if (end <= start)
            continue;
        uint64_t len = end - start;
        uint64_t aligned_len = ALIGN_UP(len, hps);

        char tmpl[] = "/tmp/elfuse-anonsh-XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd < 0) {
            log_warn("fork-prep: mkstemp for anon-shared region: %s",
                     strerror(errno));
            continue;
        }
        unlink(tmpl);
        if (ftruncate(fd, (off_t) aligned_len) < 0) {
            log_warn("fork-prep: ftruncate(%llu) failed: %s",
                     (unsigned long long) aligned_len, strerror(errno));
            close(fd);
            continue;
        }

        /* Seed the temp file with the parent's current bytes so the child sees
         * pre-fork content through the kernel page cache after re-installation.
         */
        const uint8_t *src = (const uint8_t *) g->host_base + start;
        uint64_t remain = len;
        off_t off = 0;
        bool seed_ok = true;
        while (remain > 0) {
            size_t chunk = remain > (uint64_t) SSIZE_MAX ? (size_t) SSIZE_MAX
                                                         : (size_t) remain;
            ssize_t nw = pwrite(fd, src, chunk, off);
            if (nw < 0) {
                if (errno == EINTR)
                    continue;
                seed_ok = false;
                break;
            }
            if (nw == 0) {
                seed_ok = false;
                break;
            }
            src += nw;
            off += nw;
            remain -= (uint64_t) nw;
        }
        if (!seed_ok) {
            log_warn("fork-prep: seed pwrite failed for anon-shared");
            close(fd);
            continue;
        }

        /* Pre-stage the per-region backing_fd dups before installing the
         * overlay. A post-install dup failure would otherwise leave the parent
         * live on the temp file but with regions stuck at backing_fd=-1, which
         * the SCM_RIGHTS sender silently skips. Reserving fds up front and
         * aborting on failure preserves the snapshot fallback when the host
         * runs out of fds.
         */
        int region_idxs[GUEST_MAX_REGIONS];
        int dup_fds[GUEST_MAX_REGIONS];
        int n_regions = 0;
        for (int j = 0; j < g->nregions; j++) {
            const guest_region_t *r = &g->regions[j];
            if (r->start >= end)
                break;
            if (r->end <= start)
                continue;
            if (r->backing_fd >= 0)
                continue;
            region_idxs[n_regions++] = j;
        }
        bool dup_ok = true;
        int dups_done = 0;
        for (int k = 0; k < n_regions; k++) {
            int dup_fd = dup(fd);
            if (dup_fd < 0) {
                log_warn("fork-prep: dup failed: %s", strerror(errno));
                dup_ok = false;
                break;
            }
            dup_fds[dups_done++] = dup_fd;
        }
        if (!dup_ok) {
            for (int k = 0; k < dups_done; k++)
                close(dup_fds[k]);
            close(fd);
            continue;
        }

        if (txn->noverlays >= GUEST_MAX_REGIONS ||
            txn->nsnaps >= GUEST_MAX_REGIONS) {
            for (int k = 0; k < n_regions; k++)
                close(dup_fds[k]);
            close(fd);
            pthread_mutex_unlock(&mmap_lock);
            *txn_out = txn;
            return -LINUX_ENOMEM;
        }

        int snap_base = txn->nsnaps;
        int nsnaps =
            capture_region_snapshots(g, start, end, &txn->snaps[txn->nsnaps],
                                     GUEST_MAX_REGIONS - txn->nsnaps);
        if (nsnaps < 0) {
            for (int k = 0; k < n_regions; k++)
                close(dup_fds[k]);
            close(fd);
            pthread_mutex_unlock(&mmap_lock);
            *txn_out = txn;
            return nsnaps;
        }

        int err = hvf_apply_file_overlay_quiesced(g, start, aligned_len, fd, 0);
        if (err < 0) {
            log_warn("fork-prep: overlay install [0x%llx, 0x%llx) failed: %d",
                     (unsigned long long) start,
                     (unsigned long long) (start + aligned_len), err);
            close_region_snapshots(&txn->snaps[snap_base], nsnaps);
            for (int k = 0; k < n_regions; k++)
                close(dup_fds[k]);
            close(fd);
            continue;
        }

        txn->nsnaps += nsnaps;
        txn->overlays[txn->noverlays++] = (fork_overlay_snapshot_t) {
            .overlay_start = start,
            .overlay_len = aligned_len,
            .snap_base = snap_base,
            .nsnaps = nsnaps,
        };

        /* Mark every region in [start, end) with overlay span [start,
         * start+aligned_len). The candidate filter guarantees the host-page
         * tail is empty of other tracked regions, so the extended overlay span
         * never aliases a neighbor's backing. Assign the pre-staged dups in
         * lockstep with the iteration order used to size n_regions above.
         */
        mark_overlay_metadata_range(g, start, end, start, start + aligned_len);
        for (int k = 0; k < n_regions; k++) {
            guest_region_t *r = &g->regions[region_idxs[k]];
            r->backing_fd = dup_fds[k];
            r->offset = r->start - start;
        }
        close(fd);
    }

    pthread_mutex_unlock(&mmap_lock);
    *txn_out = txn;
    return 0;
}

void mmap_fork_commit_anon_shared(mmap_fork_anon_shared_txn_t **txn_ptr)
{
    mmap_fork_dispose_anon_shared_txn(txn_ptr);
}

int mmap_fork_abort_anon_shared(guest_t *g,
                                mmap_fork_anon_shared_txn_t **txn_ptr)
{
    if (!txn_ptr || !*txn_ptr)
        return 0;

    mmap_fork_anon_shared_txn_t *txn = *txn_ptr;
    int rc = 0;

    pthread_mutex_lock(&mmap_lock);

    for (int i = txn->noverlays - 1; i >= 0; i--) {
        const fork_overlay_snapshot_t *ovl = &txn->overlays[i];

        /* Validate every captured region snapshot for this overlay BEFORE
         * tearing down the host MAP_SHARED|MAP_FIXED mapping. Removing the
         * overlay first and then discovering the region shape has drifted
         * (e.g., a sibling vCPU that returned from a long host syscall after
         * the quiesce timeout ran mmap or munmap during the prepare/abort
         * window) leaves the host VA restored to slab while the region metadata
         * still claims the temp-file overlay -- a silent desync. By verifying
         * first the function leaves the overlay live and surfaces -EFAULT so
         * the caller can decide what to do (still better than a partial
         * teardown).
         */
        bool drifted = false;
        for (int j = 0; j < ovl->nsnaps; j++) {
            const region_snapshot_t *snap = &txn->snaps[ovl->snap_base + j];
            const guest_region_t *found = guest_region_find(g, snap->start);
            if (!found || found->start != snap->start ||
                found->end != snap->end) {
                drifted = true;
                break;
            }
        }
        if (drifted) {
            if (rc == 0)
                rc = -LINUX_EFAULT;
            continue;
        }

        int err = hvf_remove_file_overlay_quiesced(g, ovl->overlay_start,
                                                   ovl->overlay_len);
        if (err < 0) {
            if (rc == 0)
                rc = err;
            continue;
        }

        for (int j = 0; j < ovl->nsnaps; j++) {
            region_snapshot_t *snap = &txn->snaps[ovl->snap_base + j];
            const guest_region_t *found = guest_region_find(g, snap->start);
            guest_region_t *r = (guest_region_t *) found;
            /* Validation above ensured r exists with matching bounds. Re-check
             * defensively in case hvf_remove_file_overlay_quiesced itself
             * mutated the region table on its failure paths.
             */
            if (!r || r->start != snap->start || r->end != snap->end) {
                if (rc == 0)
                    rc = -LINUX_EFAULT;
                continue;
            }
            if (r->backing_fd >= 0) {
                close(r->backing_fd);
                r->backing_fd = -1;
            }
            r->prot = snap->prot;
            r->flags = snap->flags;
            r->offset = snap->offset;
            r->backing_fd = snap->backing_fd;
            snap->backing_fd = -1;
            r->overlay_active = snap->overlay_active;
            r->overlay_start = snap->overlay_start;
            r->overlay_end = snap->overlay_end;
            str_copy_trunc(r->name, snap->name, sizeof(r->name));
        }
    }

    pthread_mutex_unlock(&mmap_lock);
    mmap_fork_dispose_anon_shared_txn(txn_ptr);
    return rc;
}

/* See mem.h. Re-install host MAP_SHARED|MAP_FIXED overlays on the child after
 * IPC restore using parent-side overlay metadata captured before the recv path
 * cleared the inherited overlay flags.
 */
int mmap_fork_restore_overlays(guest_t *g,
                               const bool *parent_active,
                               const uint64_t *parent_ovl_start,
                               const uint64_t *parent_ovl_end)
{
    pthread_mutex_lock(&mmap_lock);
    int rc = 0;

    for (int i = 0; i < g->nregions; i++) {
        if (!parent_active[i])
            continue;
        guest_region_t *r = &g->regions[i];
        if (r->backing_fd < 0)
            continue;
        if (r->overlay_active)
            continue; /* already re-installed via a sibling region */

        uint64_t ovl_s = parent_ovl_start[i];
        uint64_t ovl_e = parent_ovl_end[i];
        if (ovl_e <= ovl_s)
            continue;

        /* file_off corresponding to ovl_s. The standard install path keeps
         * ovl_s == r->start (host-page-aligned guest start), so file_off ==
         * r->offset. Handle the defensive clip-extends-low case by shifting
         * r->offset down by the missing bytes; if that would underflow, skip
         * the region (cannot honestly recreate).
         */
        uint64_t file_off;
        if (ovl_s >= r->start) {
            uint64_t delta = ovl_s - r->start;
            if (r->offset > UINT64_MAX - delta) {
                log_warn(
                    "fork-child: file_off overflow for region [0x%llx, "
                    "0x%llx)",
                    (unsigned long long) r->start, (unsigned long long) r->end);
                continue;
            }
            file_off = r->offset + delta;
        } else {
            uint64_t delta = r->start - ovl_s;
            if (delta > r->offset) {
                log_warn(
                    "fork-child: file_off underflow for region [0x%llx, "
                    "0x%llx)",
                    (unsigned long long) r->start, (unsigned long long) r->end);
                continue;
            }
            file_off = r->offset - delta;
        }

        int err = hvf_apply_file_overlay(g, ovl_s, ovl_e - ovl_s, r->backing_fd,
                                         (off_t) file_off);
        if (err < 0) {
            /* -LINUX_EACCES is the writable-fd gate in hvf_apply_file_overlay
             * rejecting a read-only backing fd (foot's fontconfig caches,
             * shared library file-backed regions, etc.). The fallback to
             * snapshot semantics is correct for those: the child reads the
             * pre-fork bytes and never writes back, which is what the parent
             * already did. Log at debug level so the success path stays quiet.
             * Any other failure is unexpected and stays at warn.
             */
            if (err == -LINUX_EACCES)
                log_debug(
                    "fork-child: read-only backing fd, skipping overlay "
                    "[0x%llx, 0x%llx) (snapshot semantics)",
                    (unsigned long long) ovl_s, (unsigned long long) ovl_e);
            else
                log_warn(
                    "fork-child: overlay re-install [0x%llx, 0x%llx) failed: "
                    "%d",
                    (unsigned long long) ovl_s, (unsigned long long) ovl_e,
                    err);
            rc = err;
            continue;
        }

        /* Mark each region that the parent had attached to this same overlay
         * span. Calling mark_overlay_metadata_range with the region's own
         * [start, end) bounds marks only that region (the region table is
         * sorted and non-overlapping). The outer loop later sees
         * overlay_active=true for sibling regions and skips the redundant
         * install.
         */
        for (int j = 0; j < g->nregions; j++) {
            if (!parent_active[j])
                continue;
            if (parent_ovl_start[j] != ovl_s || parent_ovl_end[j] != ovl_e)
                continue;
            mark_overlay_metadata_range(g, g->regions[j].start,
                                        g->regions[j].end, ovl_s, ovl_e);
        }
    }

    pthread_mutex_unlock(&mmap_lock);
    return rc;
}
