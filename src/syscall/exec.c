/*
 * execve syscall handler
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements execve: reads path/argv/envp from guest memory, closes CLOEXEC
 * fds, resets the guest VM, reloads the shim and new ELF, rebuilds page tables,
 * and restarts at the new entry point.
 */

#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <libkern/OSCacheControl.h>

#include "debug/log.h"
#include "hvutil.h"
#include "utils.h"

#include "core/bootstrap.h"
#include "core/elf.h"
#include "core/rosetta.h"
#include "core/shim-globals.h"
#include "core/stack.h"
#include "core/vdso.h"

#include "runtime/forkipc.h"
#include "runtime/futex.h"
#include "runtime/thread.h"

#include "syscall/linux-wire.h"
#include "syscall/chown-overlay.h"
#include "syscall/exec.h"
#include "syscall/wakeup-pipe.h" /* wakeup_pipe_signal */
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/mem.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/signal.h"


/* Force HVF to commit the sysreg/GPR writes that sys_execve performs after a
 * guest_reset before vcpu_run resumes. HVF defers writes until the next
 * register-touch on the owning thread, and a stale read here is harmless. Use
 * the HV_CHECK-wrapped accessors so a real HVF error (HV_BUSY, HV_ERROR) past
 * the point of no return aborts cleanly with a diagnostic instead of silently
 * resuming with undefined register state.
 */
static void exec_sync_vcpu_regs(hv_vcpu_t vcpu)
{
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR0_EL1);
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_TCR_EL1);
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_TTBR1_EL1);
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_ELR_EL1);
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_SP_EL0);
    (void) vcpu_get_sysreg(vcpu, HV_SYS_REG_SPSR_EL1);
    (void) vcpu_get_reg(vcpu, HV_REG_PC);
}

/* Re-enter the replacement image through the shim's _start cold-boot protocol
 * instead of resuming the interrupted svc_handler frame.
 *
 * guest_reset recycles the PT pool in place, so after the rebuild the vCPU's
 * hardware TLB can still hold walk-cache entries that point into recycled
 * page-table pages. Resuming a translated fetch through that state is unsound:
 * the walk can read a rewritten page and either fault (transient EL1
 * instruction abort at the shim, observed as BAD_EXCEPTION vec=0x200) or
 * silently translate to the wrong IPA. The TLBI VMALLE1IS in exec_drop_frame
 * came too late -- fetching the instructions leading up to it already required
 * translation.
 *
 * The only architecturally safe sequence is the one cold boot already uses:
 * enter _start with SCTLR.M=0 (instruction fetches use flat IPA addressing and
 * cannot be misdirected), let it TLBI + IC with the MMU off, then enable the
 * MMU via HVC #4 and ERET to ELR_EL1. This mirrors the staging in
 * guest_bootstrap_create_vcpu; the caller must have set TTBR0/TCR/TTBR1/
 * ELR_EL1/SP_EL0/SPSR_EL1/TPIDR_EL0 for the new image beforehand.
 */
static void exec_stage_mmu_off_reentry(hv_vcpu_t vcpu, guest_t *g)
{
    uint64_t shim_ipa = guest_ipa(g, g->shim_base);
    uint64_t el1_sp = guest_ipa(g, g->shim_data_base + BLOCK_2MIB);
    uint64_t sctlr =
        SCTLR_RES1 | SCTLR_C | SCTLR_I | SCTLR_DZE | SCTLR_UCT | SCTLR_UCI;

    /* The old syscall frame on the EL1 stack is dead; _start never pops it, so
     * reset SP_EL1 to the stack top as cold boot does. HV_CHECK on every write
     * for parity with guest_bootstrap_create_vcpu: past the point of no return
     * a silent HVF failure would resume the vCPU on half-staged register state,
     * so abort instead.
     */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL1, el1_sp));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, sctlr));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_PC, shim_ipa));
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_CPSR, 0x3c5));
    vcpu_zero_gprs(vcpu);
    HV_CHECK(hv_vcpu_set_reg(vcpu, HV_REG_X0, sctlr | SCTLR_M));
}

static void exec_republish_shim_globals_or_die(hv_vcpu_t vcpu,
                                               guest_t *g,
                                               bool verbose)
{
    /* guest_reset zeros shim_data. Reinitialize the host-owned fast-path state
     * before returning to either native aarch64 code or the Rosetta runtime,
     * otherwise identity and urandom fast paths observe all-zero cache state
     * after exec.
     */
    shim_globals_init(g);
    shim_globals_publish_stats_gate(g);
    shim_globals_set_trace_enabled(g, verbose);

    /* TPIDR_EL1 carries the shim_globals base. Past PNR, failure leaves the
     * replacement image unable to use the EL1 shim safely, so abort in the same
     * shape as other post-reset fatal errors.
     */
    if (shim_globals_install_tpidr(vcpu, g) < 0) {
        log_fatal(
            "execve failed after point of no return: "
            "shim_globals_install_tpidr");
        exit(128);
    }

    shim_globals_publish_pid(g, proc_get_pid(), proc_get_ppid());
    shim_globals_publish_creds(g, proc_get_uid(), proc_get_euid(),
                               proc_get_gid(), proc_get_egid());
    proc_publish_pgsid_snapshot(g);
    shim_globals_rebuild_urandom_bitmap();
    shim_globals_refill_urandom_ring(g);
    shim_globals_recompute_attention(g);

    /* The ptrace lane is not part of the recompute above, which owns only the
     * signal lane, so shim_globals_init's memset is otherwise the last word on
     * it. Restate it from the live thread table instead of inheriting a zero.
     *
     * No test covers this and none can today, which is worth saying plainly
     * rather than leaving as an apparent gap: after a successful execve no
     * tracer is left to observe the lane. thread_exec_de_thread has removed
     * every CLONE_THREAD sibling, and an execve with a live CLONE_VM child is
     * refused with ENOSYS well before this point, so the scan can only answer
     * false and the memset already wrote that. What this buys is that the
     * post-exec value is stated where the other lanes are stated, instead of
     * being a consequence of a memset elsewhere continuing to be correct. It
     * starts carrying weight the moment a tracer can outlive an exec.
     */
    pthread_mutex_t *tlock = thread_get_lock();
    pthread_mutex_lock(tlock);
    shim_globals_ptrace_attention(g, thread_ptrace_interrupt_pending_locked());
    pthread_mutex_unlock(tlock);
}

/* Release the buffers and temporary host-side files that sys_execve allocates
 * before crossing the point of no return. Used by both the Rosetta and the
 * aarch64 success paths.
 */
static void exec_cleanup_inputs(char **argv,
                                char **envp,
                                char *argv_buf,
                                char *envp_buf,
                                const char *path_host_buf,
                                bool path_host_temp,
                                const char *interp_host_buf,
                                bool interp_host_temp)
{
    if (path_host_temp)
        unlink(path_host_buf);
    if (interp_host_temp)
        unlink(interp_host_buf);
    free(argv);
    free(envp);
    free(argv_buf);
    free(envp_buf);
}

/* Open an execve image (binary or interpreter). For a shm redirect, force
 * O_NOFOLLOW so a symlink leaf cannot point the exec at a host file; a real
 * binary in /dev/shm still opens. See dev_shm_resolve_path().
 */
static int exec_open_image(const char *host_path, bool shm_nofollow)
{
    int oflags = O_RDONLY | O_CLOEXEC;
    if (shm_nofollow)
        oflags |= O_NOFOLLOW;
    return open(host_path, oflags);
}

static int exec_resolve_guest_host_path(const char *guest_path,
                                        char *host_path,
                                        size_t host_path_sz,
                                        bool *host_path_temp,
                                        bool *shm_nofollow)
{
    path_translation_t tx;
    if (!guest_path || !host_path || host_path_sz == 0 || !host_path_temp ||
        !shm_nofollow) {
        errno = EINVAL;
        return -1;
    }

    *host_path_temp = false;
    *shm_nofollow = false;
    if (path_translate_at(LINUX_AT_FDCWD, guest_path, PATH_TR_NONE, &tx) < 0)
        return -1;
    if (tx.fuse_path) {
        int rc =
            fuse_materialize_path(tx.intercept_path, host_path, host_path_sz);
        if (rc < 0) {
            errno = -rc;
            return -1;
        }
        *host_path_temp = true;
        return 0;
    }

    size_t len = str_copy_trunc(host_path, tx.host_path, host_path_sz);
    if (len >= host_path_sz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    *shm_nofollow = tx.is_dev_shm;
    return 0;
}

/* A translated interpreter path is usable when it is a FUSE temp copy, or when
 * translation rewrote the spelling AND the rewritten file actually exists. The
 * existence probe is what separates a real sysroot hit from an escaped prefix
 * whose loader suffix is absent: without it a differs-but-missing path would be
 * accepted and the /lib/<basename> fallback skipped, so a store-style
 * interpreter (e.g. a /nix/.../ld-musl.so.1 that ships the loader under /lib)
 * would fail to launch.
 *
 * A shm redirect is probed without following the leaf, because that is the rule
 * exec_open_image then opens under. access(2) follows, so a symlink in the shm
 * backing directory would answer "usable" for a path the O_NOFOLLOW open
 * refuses with ELOOP, and the fallback that would have found the loader is
 * skipped. Elsewhere following is right: an interpreter is routinely a symlink,
 * as /lib/ld-musl-aarch64.so.1 is on musl images.
 */
static bool exec_translated_usable(const char *host,
                                   const char *guest,
                                   bool temp,
                                   bool shm_nofollow)
{
    if (temp)
        return true;
    if (!strcmp(host, guest))
        return false;
    if (shm_nofollow) {
        struct stat st;
        return lstat(host, &st) == 0 && !S_ISLNK(st.st_mode);
    }
    return access(host, F_OK) == 0;
}

/* Resolve PT_INTERP through the same translation as every other guest path, so
 * a sysroot interpreter is found with its stored spelling, containment, and
 * FUSE materialization applied. The bootstrap loader differs: it probes
 * elf_resolve_interp's literal spellings first and falls through to
 * path_translate_at only when they miss; see load_interpreter in
 * src/core/bootstrap.c.
 */
static int exec_resolve_interp_host_path(const char *interp_guest_path,
                                         char *interp_host_path,
                                         size_t interp_host_path_sz,
                                         bool *interp_host_temp,
                                         bool *shm_nofollow)
{
    *shm_nofollow = false;
    if (exec_resolve_guest_host_path(interp_guest_path, interp_host_path,
                                     interp_host_path_sz, interp_host_temp,
                                     shm_nofollow) < 0)
        return -1;
    if (exec_translated_usable(interp_host_path, interp_guest_path,
                               *interp_host_temp, *shm_nofollow))
        return 0;

    /* Literal fallback: before accepting it, try the image's /lib for the
     * loader's basename. Store-style interpreter paths such as
     * /nix/.../lib/ld-musl-aarch64.so.1 ship the loader under /lib.
     */
    const char *base = strrchr(interp_guest_path, '/');
    base = base ? base + 1 : interp_guest_path;
    char lib_guest[LINUX_PATH_MAX];
    int n = snprintf(lib_guest, sizeof(lib_guest), "/lib/%s", base);
    if (n > 0 && (size_t) n < sizeof(lib_guest)) {
        char lib_host[LINUX_PATH_MAX];
        bool lib_temp = false;
        bool lib_shm = false;
        if (exec_resolve_guest_host_path(lib_guest, lib_host, sizeof(lib_host),
                                         &lib_temp, &lib_shm) == 0 &&
            exec_translated_usable(lib_host, lib_guest, lib_temp, lib_shm)) {
            size_t len =
                str_copy_trunc(interp_host_path, lib_host, interp_host_path_sz);
            if (len >= interp_host_path_sz) {
                errno = ENAMETOOLONG;
                return -1;
            }
            *interp_host_temp = lib_temp;
            *shm_nofollow = lib_shm;
        }
    }
    return 0;
}

/* Read a NULL-terminated pointer array from guest memory. Each pointer in the
 * array is a 64-bit GVA pointing to a string.
 * Returns the count of entries (excluding the NULL terminator), or a negative
 * error code: -1: EFAULT (guest read error) -2: E2BIG (exceeded limits) -3:
 * ENOMEM (host out of memory)
 *
 * *out_argv will be set to a heap-allocated array of pointers, which must be
 * freed by caller. *out_buf will be set to a heap-allocated buffer containing
 * all the strings, which must be freed by caller.
 */
static int read_string_array(guest_t *g,
                             uint64_t array_gva,
                             char ***out_argv,
                             char **out_buf,
                             size_t *out_buf_size,
                             char *temp_str,
                             size_t *running_bytes)
{
    int count = 0;
    while (true) {
        uint64_t ptr;
        if (guest_read_small(g, array_gva + (uint64_t) count * 8, &ptr,
                             sizeof(ptr)) < 0)
            return -1;
        if (ptr == 0)
            break;
        count++;
        if (count > ELFUSE_MAX_ARG_STRINGS)
            return -2;
    }

    char **argv = malloc(sizeof(char *) * (count + 1));
    if (!argv)
        return -3;

    size_t buf_size = 4096;
    char *buf = malloc(buf_size);
    if (!buf) {
        free(argv);
        return -3;
    }

    size_t buf_off = 0;
    for (int i = 0; i < count; i++) {
        uint64_t ptr;
        if (guest_read_small(g, array_gva + (uint64_t) i * 8, &ptr,
                             sizeof(ptr)) < 0) {
            free(argv);
            free(buf);
            return -1;
        }

        int rc = guest_read_str(g, ptr, temp_str, LINUX_MAX_ARG_STRLEN);
        if (rc < 0) {
            size_t temp_len = strlen(temp_str);
            free(argv);
            free(buf);
            return (temp_len >= LINUX_MAX_ARG_STRLEN - 1) ? -2 : -1;
        }

        size_t len = (size_t) rc;

        if (*running_bytes + len + 1 > ELFUSE_MAX_ARG_BYTES) {
            free(argv);
            free(buf);
            return -2;
        }

        if (buf_off + len + 1 > buf_size) {
            size_t new_size = (buf_off + len + 1 + 4095) & ~4095ULL;
            char *new_buf = realloc(buf, new_size);
            if (!new_buf) {
                free(argv);
                free(buf);
                return -3;
            }
            if (new_buf != buf) {
                ptrdiff_t diff = new_buf - buf;
                for (int j = 0; j < i; j++)
                    argv[j] += diff;
                buf = new_buf;
            }
            buf_size = new_size;
        }

        memcpy(buf + buf_off, temp_str, len + 1);
        argv[i] = buf + buf_off;
        buf_off += len + 1;
        *running_bytes += len + 1;
    }

    argv[count] = NULL;
    *out_argv = argv;
    *out_buf = buf;
    *out_buf_size = buf_size;
    return count;
}

/* True when st -- the fstat of the image execve actually opened -- is the file
 * ELFUSE_FAKEROOT_EXEC names.
 *
 * Matching on (st_dev, st_ino) rather than on the pathname is what makes the
 * hatch safe to hand a guest-supplied string. A name compare would decide on
 * one path and execute another: the guest spelling and the host spelling of a
 * sysroot file differ, translation collapses symlinks and ".." on the way to
 * the file, and a writable parent directory lets the guest swap the leaf
 * between the compare and the open. Identity answers "is this that file" about
 * the descriptor already open, so every spelling that reaches the marked
 * executable elevates and nothing else does.
 *
 * Resolved per call rather than cached at startup so that replacing the marked
 * executable takes effect, and because --sysroot is not established yet when
 * the environment is parsed. Fails closed on anything unresolvable, including a
 * fuse-materialized image, whose private temp copy has an identity of its own.
 */
static bool exec_matches_fakeroot_target(const struct stat *st)
{
    const char *marked = proc_fakeroot_exec_path();
    if (!marked || !st)
        return false;

    path_translation_t tx;
    if (path_translate_at(LINUX_AT_FDCWD, marked, PATH_TR_NONE, &tx) < 0)
        return false;
    if (tx.fuse_path)
        return false;

    struct stat marked_st;
    if (stat(tx.host_path, &marked_st) != 0)
        return false;
    return marked_st.st_dev == st->st_dev && marked_st.st_ino == st->st_ino;
}

/* Is ID something the guest can actually mean?
 *
 * A sysroot is an ordinary directory tree owned by whoever unpacked it, and
 * elfuse maps no host IDs into the guest, so most files report the invoking
 * macOS user (e.g. 501) -- an ID that exists nowhere in the guest's own
 * /etc/passwd. Honouring setuid on such a file would leave the process at an
 * effective ID that is neither root nor its own, failing both `euid == 0`
 * privilege checks and ownership comparisons against guest IDs, and the granted
 * ID would follow whoever happens to own the tree rather than anything the
 * guest chose.
 *
 * Accept only root and the caller's own ID, and only when both views of
 * ownership agree on it.
 *
 * physical is what the host reports; seen is what the guest's own stat reports,
 * after the virtual chown overlay. Elevating needs both because each view alone
 * fails in a different direction. Reading the set-id owner through the overlay
 * would make root self-service, since the overlay takes any unprivileged
 * guest's chown -- chown its own file to 0, set the bit, exec. Reading it only
 * from the host would let a file the guest's own stat says belongs to someone
 * else still elevate, because a physically root-owned file keeps elevating
 * after the guest chowns it away.
 *
 * Requiring agreement grants nothing new: root still means a file the host
 * really owns as root, and a guest chown can only ever withdraw an elevation,
 * never create one. The caller's own ID makes the bit a no-op, as on Linux.
 * Anything else leaves the ID untouched and the program simply runs
 * unprivileged -- the outcome Linux gives for a setuid binary on a nosuid
 * mount, and never an exec failure.
 */
static bool exec_id_may_elevate(uint32_t physical,
                                uint32_t seen,
                                uint32_t self_id)
{
    if (physical != seen)
        return false;
    return physical == 0 || physical == self_id;
}

static int check_exec_permission(const struct stat *st)
{
    uint32_t uid = proc_get_euid();
    uint32_t gid = proc_get_egid();

    /* Root can execute if any execute bit is set */
    if (uid == 0) {
        if (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
            return 0;
        return -LINUX_EACCES;
    }

    if (uid == (uint32_t) st->st_uid) {
        if (st->st_mode & S_IXUSR)
            return 0;
        return -LINUX_EACCES;
    }

    bool in_group = (gid == (uint32_t) st->st_gid);
    if (!in_group) {
        gid_t groups[64];
        int ngroups = getgroups(64, groups);
        if (ngroups > 0) {
            for (int i = 0; i < ngroups; i++) {
                if (groups[i] == (gid_t) st->st_gid) {
                    in_group = true;
                    break;
                }
            }
        }
    }

    if (in_group) {
        if (st->st_mode & S_IXGRP)
            return 0;
        return -LINUX_EACCES;
    }

    if (st->st_mode & S_IXOTH)
        return 0;

    return -LINUX_EACCES;
}

/* Close the fds marked CLOEXEC, removing them from the shared table under
 * fd_lock and cleaning up type-specific host resources after the unlock.
 * Cleanup acquires sfd_lock or inotify_lock, which must NOT be held under
 * fd_lock (lock ordering: fd_lock(3) < sfd_lock(5a) < inotify_lock(7)).
 *
 * Two passes: count first, then heap-allocate. That avoids placing a ~236 KiB
 * VLA on the stack (FD_TABLE_SIZE * sizeof(fd_entry_t+int)).
 *
 * This reads nothing from the exec in progress, which is what lets it sit
 * outside sys_execve rather than inline in its post-PNR half.
 */
static void exec_close_cloexec_fds(void)
{
    int cloexec_count = 0;
    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].type != FD_CLOSED &&
            (fd_table[i].linux_flags & LINUX_O_CLOEXEC))
            cloexec_count++;
    }

    struct cloexec_entry {
        int fd;
        fd_entry_t snap;
    };
    struct cloexec_entry *cloexec_list = NULL;
    if (cloexec_count > 0) {
        cloexec_list =
            malloc((size_t) cloexec_count * sizeof(struct cloexec_entry));
        if (!cloexec_list) {
            /* OOM during exec: fall back to fixed-size batches so cleanup still
             * runs outside fd_lock.
             *
             * Each batch rescans from slot 0 rather than carrying a cursor
             * across the unlocked window, and the loop ends on the first pass
             * that finds nothing. That is deliberate: the window drops fd_lock,
             * so a cursor that only moves forward would never re-examine a slot
             * it had already passed. Every pass marks what it takes closed, so
             * the candidate set shrinks and the loop terminates. The repeated
             * scanning is bounded by the table size times the batch count and
             * only happens once malloc has already failed, which is a trade
             * this path can afford.
             */
            struct cloexec_entry batch[32];
            for (;;) {
                int batch_count = 0;
                for (int scan = 0; scan < FD_TABLE_SIZE &&
                                   batch_count < (int) (ARRAY_SIZE(batch));
                     scan++) {
                    if (fd_table[scan].type == FD_CLOSED ||
                        !(fd_table[scan].linux_flags & LINUX_O_CLOEXEC))
                        continue;
                    batch[batch_count].fd = scan;
                    batch[batch_count].snap = fd_table[scan];
                    batch_count++;
                    fd_mark_closed_unlocked(scan);
                }
                if (batch_count == 0)
                    break;
                pthread_mutex_unlock(&fd_lock);
                for (int j = 0; j < batch_count; j++)
                    fd_cleanup_entry(batch[j].fd, &batch[j].snap);
                pthread_mutex_lock(&fd_lock);
            }
            cloexec_count = 0;
        } else {
            int n = 0;
            for (int i = 0; i < FD_TABLE_SIZE; i++) {
                if (fd_table[i].type != FD_CLOSED &&
                    (fd_table[i].linux_flags & LINUX_O_CLOEXEC)) {
                    cloexec_list[n].fd = i;
                    cloexec_list[n].snap = fd_table[i];
                    n++;
                    fd_mark_closed_unlocked(i);
                }
            }
        }
    }
    pthread_mutex_unlock(&fd_lock);

    /* fd_cleanup_entry may close host fds, DIR*, epoll/kqueue state, or inotify
     * state, so keep it outside fd_lock.
     */
    for (int j = 0; j < cloexec_count; j++)
        fd_cleanup_entry(cloexec_list[j].fd, &cloexec_list[j].snap);
    free(cloexec_list);
}

/* What the PT_INTERP probe produces. The values move together: the caller's
 * failure path closes the fd, and the post-PNR mapping needs the parsed headers
 * plus both spellings of the path, so they are one thing rather than five
 * locals threaded down the length of sys_execve.
 */
typedef struct {
    elf_info_t info;
    char resolved[LINUX_PATH_MAX];
    char display_path[LINUX_PATH_MAX];
    int fd;

    /* resolved holds a materialized temporary that the caller must unlink. The
     * flag lives beside the buffer it describes because
     * exec_resolve_guest_host_path clears it on entry and then sets it for
     * whichever buffer it filled: a flag belonging to some other buffer would
     * be silently retargeted, losing one temp and unlinking the wrong path.
     */
    bool resolved_temp;
} exec_interp_t;

/* Resolve, open, and parse the PT_INTERP interpreter (headers only) before exec
 * crosses the point of no return, so a bad interpreter is a recoverable ENOEXEC
 * instead of a fatal exit. elf_map_segments_fd runs later, post-PNR.
 *
 * x86_64 targets do not pre-load their PT_INTERP: Rosetta is statically linked
 * and loads the target binary, and any guest-side dynamic linker, itself via fd
 * 3.
 *
 * On failure the fd, if any, is left in interp for the caller's fail label to
 * close, as is interp->resolved_temp when a temporary was materialized.
 */
static int64_t exec_preload_interp(const guest_t *g,
                                   const elf_info_t *elf_info,
                                   bool target_is_rosetta,
                                   exec_interp_t *interp)
{
    if (target_is_rosetta || elf_info->interp_path[0] == '\0')
        return 0;

    bool shm = false;

    if (exec_resolve_interp_host_path(elf_info->interp_path, interp->resolved,
                                      sizeof(interp->resolved),
                                      &interp->resolved_temp, &shm) < 0) {
        log_error("execve: failed to resolve interpreter: %s",
                  elf_info->interp_path);
        return -LINUX_ENOEXEC;
    }
    str_copy_trunc(
        interp->display_path,
        interp->resolved_temp ? elf_info->interp_path : interp->resolved,
        sizeof(interp->display_path));

    log_debug("execve: pre-validating interpreter: %s", interp->resolved);

    interp->fd = exec_open_image(interp->resolved, shm);
    if (interp->fd < 0) {
        log_error("execve: failed to open interpreter: %s", interp->resolved);
        return linux_errno();
    }

    struct stat interp_st;
    if (fstat(interp->fd, &interp_st) < 0) {
        return linux_errno();
    }
    chown_overlay_apply(&interp_st);

    int64_t err = check_exec_permission(&interp_st);
    if (err < 0) {
        return err;
    }

    if (elf_load_fd(interp->fd, interp->resolved, &interp->info) < 0) {
        log_error("execve: failed to load interpreter: %s", interp->resolved);
        return -LINUX_ENOEXEC;
    }

    if (!elf_interp_is_loadable(&interp->info, interp->resolved))
        return -LINUX_ENOEXEC;

    /* Settle the interpreter's placement here, the same way the executable's is
     * settled above. Without this the only thing that rejects a badly placed
     * interpreter is elf_map_segments_fd, which runs after the point of no
     * return where the sole remaining option is exit(128). A guest able to
     * write its own sysroot could kill elfuse on demand by patching a PT_LOAD
     * in ld-musl; Linux returns ENOEXEC and the caller survives.
     */
    uint64_t infra_lo, infra_hi;
    guest_infra_window(g, &infra_lo, &infra_hi);
    if (!elf_check_placement(&interp->info, interp->resolved, g->guest_size,
                             (elf_window_t) {0, g->interp_base}, infra_lo,
                             infra_hi))
        return -LINUX_ENOEXEC;
    return 0;
}


/* execve handoff to the thread group leader.
 *
 * One slot, because two threads racing to replace the same image have no
 * meaningful joint outcome: the second waits for the first, and if the first
 * succeeded the second never wakes as a running thread (de_thread reaps it).
 * Linux serializes the same window on cred_guard_mutex.
 *
 *             ┌───────┐
 *             │ EMPTY │
 *             └───────┘
 *                 │
 *           ┌─────▾─────┐
 *           │ PUBLISHED │
 *           └───────────┘
 *                 │
 *             ┌───▾───┐
 *             │ TAKEN │
 *             └───────┘
 *       ┌────────┘ └────┐
 *       │               │
 *   ┌───▾──┐   ┌────────▾────────┐
 *   │ DONE │   │ leader frees it │
 *   └──────┘   └─────────────────┘
 *       └──────────┐
 *                  │
 *       ┌──────────▾─────────┐
 *       │ requester frees it │
 *       └────────────────────┘
 *
 * The leader runs the whole of sys_execve on its own vCPU. A successful exec
 * never reaches DONE, because the requester is reaped by de_thread and has no
 * one to report to, so the leader clears the slot itself. A failure before the
 * point of no return posts its result in DONE, and the requester clears the
 * slot once it has read it.
 *
 * One edge back to EMPTY is not drawn above: the requester copies host_path
 * into the slot after publishing, so a name that does not fit withdraws its own
 * request and answers ENAMETOOLONG without a leader ever seeing it. The leader
 * tolerates that flap because it re-checks the state under the lock.
 */
typedef enum {
    HANDOFF_EMPTY = 0,
    HANDOFF_PUBLISHED,
    HANDOFF_TAKEN,
    HANDOFF_DONE,
} exec_handoff_state_t;

static struct {
    exec_handoff_state_t state;
    int64_t result;
    uint64_t path_gva, argv_gva, envp_gva;

    /* Copied, not borrowed: on success the requester is reaped by de_thread and
     * its pthread stack is freed while the leader is still inside sys_execve.
     */
    char host_path[LINUX_PATH_MAX]; /* empty when the caller passed none */
    uint64_t blocked_mask; /* requester's signal mask, adopted by the leader */
} exec_handoff;

static pthread_mutex_t exec_handoff_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exec_handoff_cond = PTHREAD_COND_INITIALIZER;

/* The state is the truth; the flag thread_stop_requested polls is its lock-free
 * mirror, since that predicate runs in blocking waits where taking this mutex
 * would be wrong. Move them together so they cannot drift. Caller holds the
 * lock.
 */
static void exec_handoff_set_state(exec_handoff_state_t st)
{
    exec_handoff.state = st;
    thread_set_leader_work_pending(st == HANDOFF_PUBLISHED);
}

void exec_handoff_wake_waiters(void)
{
    pthread_mutex_lock(&exec_handoff_lock);
    pthread_cond_broadcast(&exec_handoff_cond);
    pthread_mutex_unlock(&exec_handoff_lock);
}

/* Block until the slot reaches want.
 *
 * Returns false when thread_stop_requested broke the wait instead, which for
 * the requester means the exec it asked for already succeeded and de_thread is
 * reaping it. Caller holds the lock; the bounded quantum is a safety net under
 * the wake in thread_wake_leader_for_work.
 */
static bool exec_handoff_wait_for(exec_handoff_state_t want)
{
    while (exec_handoff.state != want && !thread_stop_requested()) {
        struct timespec ts;
        timespec_deadline_in_ms(&ts, 100);
        pthread_cond_timedwait(&exec_handoff_cond, &exec_handoff_lock, &ts);

        /* Re-poke while the request is still unclaimed. The leader is woken
         * once at publish, and a kick that lands between two hv_vcpu_run calls
         * is lost; without this the requester waits forever and the leader runs
         * on none the wiser. The wake set broadcasts this same condvar, so the
         * lock has to come off around it.
         */
        if (exec_handoff.state == HANDOFF_PUBLISHED) {
            pthread_mutex_unlock(&exec_handoff_lock);
            thread_wake_leader_for_work();
            pthread_mutex_lock(&exec_handoff_lock);
        }
    }
    return exec_handoff.state == want;
}

/* Requester side: publish the request, wake the leader, and block until it
 * reports back or this thread is torn down.
 *
 * Returns the errno the guest should see, or SYSCALL_EXEC_HAPPENED if the exec
 * succeeded (in which case this thread is already being reaped and the value
 * only has to keep the dispatcher from writing X0).
 */
static int64_t exec_handoff_to_leader(uint64_t path_gva,
                                      uint64_t argv_gva,
                                      uint64_t envp_gva,
                                      const char *host_path)
{
    pthread_mutex_lock(&exec_handoff_lock);

    /* Wait for the slot. A concurrent handoff either fails (freeing the slot)
     * or succeeds, in which case thread_stop_requested breaks this wait.
     */
    if (!exec_handoff_wait_for(HANDOFF_EMPTY)) {
        pthread_mutex_unlock(&exec_handoff_lock);
        return -LINUX_EINTR;
    }

    exec_handoff_set_state(HANDOFF_PUBLISHED);
    exec_handoff.path_gva = path_gva;
    exec_handoff.argv_gva = argv_gva;
    exec_handoff.envp_gva = envp_gva;

    /* An empty string is the "no host_path" marker, so the flag the buffer
     * would otherwise need stays derivable from the buffer itself.
     */
    exec_handoff.host_path[0] = '\0';
    if (host_path && str_copy_trunc(exec_handoff.host_path, host_path,
                                    sizeof(exec_handoff.host_path)) >=
                         sizeof(exec_handoff.host_path)) {
        exec_handoff_set_state(HANDOFF_EMPTY);
        pthread_cond_broadcast(&exec_handoff_cond);
        pthread_mutex_unlock(&exec_handoff_lock);
        return -LINUX_ENAMETOOLONG;
    }
    exec_handoff.blocked_mask =
        current_thread ? thread_blocked_load(current_thread) : 0;
    pthread_mutex_unlock(&exec_handoff_lock);

    /* The leader may be parked in a blocking syscall. thread_stop_requested is
     * true for it while a request is pending, so its wait returns EINTR and its
     * run loop reaches the service point.
     */
    thread_wake_leader_for_work();

    pthread_mutex_lock(&exec_handoff_lock);
    bool reported = exec_handoff_wait_for(HANDOFF_DONE);

    int64_t result;
    if (!reported) {
        /* Torn down: the exec succeeded and de_thread is reaping this thread.
         * Leave the slot to the leader, which clears it.
         */
        result = -LINUX_EINTR;
    } else {
        result = exec_handoff.result;
        exec_handoff_set_state(HANDOFF_EMPTY);
        pthread_cond_broadcast(&exec_handoff_cond);
    }
    pthread_mutex_unlock(&exec_handoff_lock);

    return result;
}


/* Drop any handoff state on behalf of the image being replaced. A requester
 * blocked in the slot is reaped by de_thread and never returns to read it, so
 * the new image must not inherit an occupied slot.
 */
static void exec_handoff_reset(void)
{
    pthread_mutex_lock(&exec_handoff_lock);
    exec_handoff_set_state(HANDOFF_EMPTY);
    pthread_cond_broadcast(&exec_handoff_cond);
    pthread_mutex_unlock(&exec_handoff_lock);
}

int64_t exec_run_handoff(hv_vcpu_t vcpu, guest_t *g, bool verbose)
{
    uint64_t path_gva, argv_gva, envp_gva;
    char host_path_buf[LINUX_PATH_MAX];
    const char *host_path = NULL;
    uint64_t saved_mask = 0;

    pthread_mutex_lock(&exec_handoff_lock);
    if (exec_handoff.state != HANDOFF_PUBLISHED) {
        pthread_mutex_unlock(&exec_handoff_lock);
        return 0;
    }
    exec_handoff_set_state(HANDOFF_TAKEN);
    path_gva = exec_handoff.path_gva;
    argv_gva = exec_handoff.argv_gva;
    envp_gva = exec_handoff.envp_gva;
    if (exec_handoff.host_path[0]) {
        str_copy_trunc(host_path_buf, exec_handoff.host_path,
                       sizeof(host_path_buf));
        host_path = host_path_buf;
    }

    /* Moving out of PUBLISHED also clears the pending mirror, which is what
     * stops thread_stop_requested from returning EINTR to the very thread now
     * servicing the request: sys_execve can itself block on a FUSE-backed
     * binary.
     */

    /* Linux keeps the exec'ing thread's signal mask across execve, and that
     * thread is the one the new image inherits from. The leader runs the
     * syscall in its place, so it adopts the mask too.
     */
    uint64_t adopt_mask = exec_handoff.blocked_mask;
    pthread_mutex_unlock(&exec_handoff_lock);

    /* Adopt the requester's mask, which is what the new image inherits on
     * Linux. Through the signal module rather than by storing to the field:
     * writers hold sig_lock (order 4) apart from the two clone sites, which
     * write a child's mask before its pthread exists, and
     * thread_signal_deliverable reads it lock-free against all of them.
     */
    saved_mask = signal_save_blocked();
    signal_set_blocked(adopt_mask);

    int64_t rc =
        sys_execve(vcpu, g, path_gva, argv_gva, envp_gva, verbose, host_path);

    pthread_mutex_lock(&exec_handoff_lock);
    if (rc == SYSCALL_EXEC_HAPPENED) {
        /* Drop any SVC restart this leader had armed before it picked the
         * handoff up. The image it belonged to is gone, and leaving it armed
         * lets the new image's first syscall match the recorded ELR by
         * coincidence (most plausibly on a self-re-exec at the same load base)
         * and read as a restart, which is what makes sys_connect swallow a
         * genuine EISCONN. The cancel sees the mismatch and only clears the
         * record.
         */
        syscall_restart_cancel(vcpu);

        /* The requester is being reaped by de_thread and will never read this.
         * Free the slot so the new image can execve again.
         */
        exec_handoff_set_state(HANDOFF_EMPTY);
    } else {
        /* The exec failed before its point of no return, so this thread goes
         * back to being itself: the requester's mask belonged to the image that
         * never got loaded.
         */
        signal_restore_blocked(saved_mask);
        exec_handoff.result = rc;
        exec_handoff_set_state(HANDOFF_DONE);
    }
    pthread_cond_broadcast(&exec_handoff_cond);
    pthread_mutex_unlock(&exec_handoff_lock);

    return rc == SYSCALL_EXEC_HAPPENED ? SYSCALL_EXEC_HAPPENED : 0;
}

/* Where segment i of a loaded image lands in the guest, given the base the
 * image was mapped at. The page-table region list and the /proc/self/maps list
 * are both derived from these, which is the only reason the two agree; each
 * used to recompute the arithmetic itself, twice over for the executable and
 * the interpreter.
 */
static inline uint64_t exec_seg_start(const elf_info_t *info,
                                      int i,
                                      uint64_t base)
{
    return info->segments[i].gpa + base;
}

static inline uint64_t exec_seg_end(const elf_info_t *info,
                                    int i,
                                    uint64_t base)
{
    return info->segments[i].gpa + info->segments[i].memsz + base;
}

/* What the post-PNR rebuild needs from the pre-PNR resolution, gathered in one
 * place because two phases already take the whole set and the phases still
 * inlined in sys_execve take most of it. Every member is settled before
 * guest_reset and read-only afterwards.
 */
typedef struct {
    unsigned int shim_size;
    const elf_info_t *elf_info;
    uint64_t elf_load_base;
    const exec_interp_t *interp;
    uint64_t interp_base;
    const char *path; /* Guest-visible name, for /proc/self/maps */
} exec_image_t;

/* Describe the replacement image's address space and install its page tables.
 *
 * Runs past the point of no return, so every failure here is fatal rather than
 * an errno: the old image is already gone and there is nothing to return to.
 * That is also why the bounds check before each append is a goto to one fatal
 * exit instead of an error path.
 *
 * Also publishes the two mmap watermarks (g->mmap_rx_end, g->mmap_end) that the
 * fresh regions establish.
 *
 * Returns the new TTBR0.
 */
static uint64_t exec_install_address_space(guest_t *g, const exec_image_t *img)
{
    const unsigned int shim_size = img->shim_size;
    const elf_info_t *elf_info = img->elf_info;
    const uint64_t elf_load_base = img->elf_load_base;
    const exec_interp_t *interp = img->interp;
    const uint64_t interp_base = img->interp_base;

    /* Worst case: 7 fixed regions (shim, shim-data, vDSO, brk, stack, mmap RX,
     * mmap RW) plus up to ELF_MAX_SEGMENTS for both the executable and the
     * interpreter. Sized comfortably to keep the bounds-check loops simple
     * after the point of no return.
     */
#define MAX_REGIONS (8 + 2 * ELF_MAX_SEGMENTS)
    mem_region_t regions[MAX_REGIONS];
    int nregions = 0;

    /* Fixed regions (shim, shim-data, vDSO, brk, stack, mmap RX, mmap RW): 7
     * entries. Bounds-check before each to prevent array overflow. After the
     * point of no return, overflow is fatal (exit).
     */

    /* Keep the shim executable-only; HVF faults on merged RWX mappings. */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = g->shim_base,
                                          .gpa_end = g->shim_base + shim_size,
                                          .perms = MEM_PERM_RX};

    /* EL1 exception handlers use this block for stack and scratch state.
     * EL1-only so EL0 cannot read or store directly to the identity cache,
     * urandom ring, or attention word that the shim fast paths consult. Matches
     * bootstrap.c; if this regresses to plain RW, execve quietly defeats the
     * protection on every new image.
     */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] =
        (mem_region_t) {.gpa_start = g->shim_data_base,
                        .gpa_end = g->shim_data_base + BLOCK_2MIB,
                        .perms = MEM_PERM_RW_EL1_ONLY};

    /* The vDSO sits in the same 2MiB block as the shim. The page-table builder
     * splits the block into 4KiB L3 pages when its regions don't fully cover
     * it, so the vDSO must appear here to keep the trampoline page valid and RX
     * after rebuild.
     */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = VDSO_BASE,
                                          .gpa_end = VDSO_BASE + VDSO_SIZE,
                                          .perms = MEM_PERM_RX};

    /* Translate ELF p_flags into guest page permissions, for the executable and
     * then the interpreter shifted by its own base. Silent drops would leave a
     * loaded segment unmapped, so treat overflow as fatal (this is already past
     * the point of no return).
     */
    const elf_info_t *lists[] = {elf_info, &interp->info};
    const uint64_t bases[] = {elf_load_base, interp_base};
    for (size_t l = 0; l < ARRAY_SIZE(lists); l++) {
        for (int i = 0; i < lists[l]->num_segments; i++) {
            if (nregions >= MAX_REGIONS)
                goto too_many_regions;
            regions[nregions++] = (mem_region_t) {
                .gpa_start = exec_seg_start(lists[l], i, bases[l]),
                .gpa_end = exec_seg_end(lists[l], i, bases[l]),
                .perms = elf_pf_to_prot(lists[l]->segments[i].flags)};
        }
    }

    /* brk region (RW). Pre-mapped up to MMAP_RX_BASE. */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = g->brk_base,
                                          .gpa_end = MMAP_RX_BASE,
                                          .perms = MEM_PERM_RW};

    /* The dynamic stack bounds were recomputed above from the new brk. */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = g->stack_base,
                                          .gpa_end = g->stack_top,
                                          .perms = MEM_PERM_RW};

    /* PROT_EXEC mmap allocations start in a separate RX area to preserve W^X
     * with 2MiB page-table blocks.
     */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = MMAP_RX_BASE,
                                          .gpa_end = MMAP_RX_INITIAL_END,
                                          .perms = MEM_PERM_RX};
    g->mmap_rx_end = MMAP_RX_INITIAL_END;

    /* Non-executable mmap allocations start high to match Linux address-space
     * layout and avoid low executable/heap regions.
     */
    if (nregions >= MAX_REGIONS)
        goto too_many_regions;
    regions[nregions++] = (mem_region_t) {.gpa_start = MMAP_BASE,
                                          .gpa_end = MMAP_INITIAL_END,
                                          .perms = MEM_PERM_RW};
    g->mmap_end = MMAP_INITIAL_END;

    uint64_t ttbr0 = guest_build_page_tables(g, regions, nregions);
    if (!ttbr0) {
        log_fatal(
            "execve failed after point of no return: "
            "failed to build page tables");
        exit(128);
    }
    return ttbr0;

too_many_regions:
    log_fatal(
        "execve failed after point of no return: "
        "too many memory regions (max %d)",
        MAX_REGIONS);
    exit(128);
}

/* Republish the guest's /proc/self/maps view for the replacement image.
 *
 * Runs alongside exec_install_address_space and describes the same address
 * space, one layer up: that call installs the hardware mapping, this one names
 * it for the guest. The two lists must agree, so a region added to one belongs
 * in the other.
 *
 * Also punches the two holes that carry no mapping at all: the stack guard page
 * and the NULL page, whose PTEs are invalidated rather than described.
 */
static void exec_publish_maps(guest_t *g, const exec_image_t *img)
{
    const unsigned int shim_size = img->shim_size;
    const elf_info_t *elf_info = img->elf_info;
    const uint64_t elf_load_base = img->elf_load_base;
    const exec_interp_t *interp = img->interp;
    const uint64_t interp_base = img->interp_base;
    const char *path = img->path;

    /* Rebuild /proc/self/maps metadata in parallel with the new page tables. */
    guest_region_add(g, g->shim_base, g->shim_base + shim_size,
                     LINUX_PROT_READ | LINUX_PROT_EXEC, LINUX_MAP_PRIVATE, 0,
                     "[shim]");

    /* Report PROT_NONE for [shim-data] to match the EL1-only mapping (see
     * matching bootstrap.c registration). EL0 dereferences fault, so user
     * tooling reading /proc/self/maps should see the same access state.
     */
    guest_region_add(g, g->shim_data_base, g->shim_data_base + BLOCK_2MIB,
                     LINUX_PROT_NONE, LINUX_MAP_PRIVATE, 0, "[shim-data]");

    /* Same two lists, same order, same spans as exec_install_address_space.
     * interp->display_path was resolved before guest_reset, so naming the
     * interpreter here needs no filesystem lookup past the point of no return.
     */
    const elf_info_t *lists[] = {elf_info, &interp->info};
    const uint64_t bases[] = {elf_load_base, interp_base};
    const char *names[] = {path, interp->display_path};
    for (size_t l = 0; l < ARRAY_SIZE(lists); l++) {
        for (int i = 0; i < lists[l]->num_segments; i++) {
            guest_region_add(g, exec_seg_start(lists[l], i, bases[l]),
                             exec_seg_end(lists[l], i, bases[l]),
                             elf_pf_to_prot(lists[l]->segments[i].flags),
                             LINUX_MAP_PRIVATE, lists[l]->segments[i].offset,
                             names[l]);
        }
    }

    /* Leave the lowest stack page unmapped so downward overflow faults before
     * corrupting adjacent mappings.
     */
    guest_invalidate_ptes(g, g->stack_base, g->stack_base + STACK_GUARD_SIZE);
    guest_region_add(g, g->stack_base, g->stack_base + STACK_GUARD_SIZE,
                     LINUX_PROT_NONE, LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                     0, "[stack-guard]");
    guest_region_add(g, g->stack_base + STACK_GUARD_SIZE, g->stack_top,
                     LINUX_PROT_READ | LINUX_PROT_WRITE,
                     LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, 0, "[stack]");

    /* Preserve Linux-style NULL dereference faults after exec. */
    guest_invalidate_ptes(g, 0, 0x1000);
}

/* The EL0 address space an image is entered on. The three travel together
 * because a TTBR without its TCR is not a translation regime.
 */
typedef struct {
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t tcr;
} exec_addr_space_t;

/* Program EL0 for the image just loaded, then re-enter through the shim.
 *
 * Every register the new program starts on is written here rather than restored
 * from the syscall frame the shim saved on entry. No X8=2 drop-frame marker
 * appears because there is no frame to drop: the MMU-off _start re-entry never
 * pops one, and sys_execve returns SYSCALL_EXEC_HAPPENED so the dispatch
 * epilogue does not run. The marker belongs to the paths that ERET out of the
 * saved frame, which is signal delivery and rt_sigreturn.
 *
 * The caller has passed the point of no return, so a failed write is fatal
 * rather than an errno: resuming on half-staged translation or return state is
 * worse than stopping. exec_stage_mmu_off_reentry below already reasons that
 * way, and these writes are the same commitment.
 */
static void exec_enter_new_image(hv_vcpu_t vcpu,
                                 guest_t *g,
                                 uint64_t entry_point,
                                 uint64_t sp,
                                 const exec_addr_space_t *as)
{
    uint64_t entry_ipa = guest_ipa(g, entry_point), sp_ipa = guest_ipa(g, sp);

    /* Switch EL0 translation to the rebuilt page tables. */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, as->ttbr0));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, as->tcr));
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, as->ttbr1));

    /* The shim will ERET to this address after syscall dispatch returns. */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, entry_ipa));

    /* SP_EL0 points at the freshly built Linux initial stack. */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, sp_ipa));

    /* SPSR_EL1: EL0t, AArch64 */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, 0x0));

    /* Reset TPIDR_EL0 (thread-local storage base). The previous program's TLS
     * pointer must not leak into the new program because glibc's ld-linux uses
     * TLS very early (GL() macro accesses static TLS), and a stale TPIDR_EL0
     * causes it to read garbage for its internal state (link_map l_relocated
     * flags, scope lists, etc.), breaking relocation.
     */
    HV_CHECK(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, 0));

    /* Drop all register contents from the old image and re-enter through the
     * shim's MMU-off _start protocol (TLBI before any translated fetch).
     */
    exec_stage_mmu_off_reentry(vcpu, g);
    tlbi_request_clear();

    exec_sync_vcpu_regs(vcpu);
}

/* Over the function-size limit on purpose.
 *
 * The point of no return runs through the middle of it. Before PNR every exit
 * restores the old image; after it there is no exit but the fatal one. A split
 * would put that boundary at a call edge, where it is invisible.
 */
/* NOLINTNEXTLINE(readability-function-size) */
int64_t sys_execve(hv_vcpu_t vcpu,
                   guest_t *g,
                   uint64_t path_gva,
                   uint64_t argv_gva,
                   uint64_t envp_gva,
                   bool verbose,
                   const char *host_path)
{
    /* Not the leader: hand the whole syscall to it. See exec_handoff_to_leader
     * for why the leader has to be the one that survives.
     */
    if (!thread_current_is_leader())
        return exec_handoff_to_leader(path_gva, argv_gva, envp_gva, host_path);

    /* Linux gives the exec'ing task a new mm and leaves a CLONE_VM child on the
     * old one. elfuse has a single guest slab, so guest_reset would zero the
     * memory that child is executing. Refuse while one is live, for the same
     * reason and with the same recoverable errno as above.
     */
    if (thread_count_active_vm_clones() > 0) {
        log_error(
            "execve with %d live CLONE_VM child(ren) is not supported; "
            "they share the guest memory guest_reset would zero",
            thread_count_active_vm_clones());
        return -LINUX_ENOSYS;
    }

    /* Copy guest execve inputs before any state-reset point of no return. A
     * provided host_path (from execveat resolution) is used directly for the
     * exec open, but the guest-visible identity in path must carry the guest
     * spelling: strip the sysroot and decode escaped components so
     * /proc/self/exe never reports the private host namespace.
     */
    char path[LINUX_PATH_MAX];
    if (host_path) {
        if (path_host_to_guest(host_path, path, sizeof(path)) < 0)
            return -LINUX_ENAMETOOLONG;
    } else if (guest_read_str(g, path_gva, path, sizeof(path)) < 0) {
        return -LINUX_EFAULT;
    }

    log_debug("execve(\"%s\")", path);

    char path_host_buf[LINUX_PATH_MAX];
    const char *path_host = host_path ? host_path : path;
    bool path_host_temp = false;

    /* Whether path_host is a shm redirect leaf (drives O_NOFOLLOW on the exec
     * open). Re-evaluated whenever path_host is repointed to an interpreter.
     */
    bool path_host_shm = false;
    char interp_host_buf[LINUX_PATH_MAX];
    bool interp_host_temp = false;

    int64_t err = 0;
    char **argv = NULL;
    char **envp = NULL;
    char *argv_buf = NULL;
    char *envp_buf = NULL;
    size_t argv_buf_size = 0;
    size_t envp_buf_size = 0;
    size_t running_bytes = 0;
    int exec_fd = -1;
    exec_interp_t interp;
    memset(&interp, 0, sizeof(interp));
    interp.fd = -1;


    char *temp_str = malloc(LINUX_MAX_ARG_STRLEN);
    if (!temp_str) {
        err = -LINUX_ENOMEM;
        goto fail;
    }

    int argc = read_string_array(g, argv_gva, &argv, &argv_buf, &argv_buf_size,
                                 temp_str, &running_bytes);
    if (argc < 0) {
        err = (argc == -2) ? -LINUX_E2BIG
                           : ((argc == -3) ? -LINUX_ENOMEM : -LINUX_EFAULT);
        goto fail;
    }

    int envc = 0;
    if (envp_gva != 0) {
        envc = read_string_array(g, envp_gva, &envp, &envp_buf, &envp_buf_size,
                                 temp_str, &running_bytes);
        if (envc < 0) {
            err = (envc == -2) ? -LINUX_E2BIG
                               : ((envc == -3) ? -LINUX_ENOMEM : -LINUX_EFAULT);
            goto fail;
        }
    }

    /* Resolve /proc/self/exe to the actual binary path. Busybox sh execs
     * applets via execve("/proc/self/exe", ["applet", ...]) and macOS has no
     * /proc filesystem.
     */
    if (!strcmp(path, "/proc/self/exe")) {
        /* Snapshot rather than proc_get_elf_path(): that pointer is shared
         * mutable state, and a sibling execve republishing it would tear the
         * string this copy -- and the fakeroot decision below -- reads.
         */
        if (!proc_elf_path_snapshot(path, sizeof(path))) {
            err = -LINUX_ENOENT;
            goto fail;
        }
        log_debug("execve resolved to \"%s\"", path);
    }

    if (!host_path) {
        path_translation_t tx;
        if (path_translate_at(LINUX_AT_FDCWD, path, PATH_TR_NONE, &tx) < 0) {
            err = linux_errno();
            goto fail;
        }
        if (tx.fuse_path) {
            err = fuse_materialize_path(tx.intercept_path, path_host_buf,
                                        sizeof(path_host_buf));
            if (err < 0)
                goto fail;
            path_host_temp = true;
        } else {
            str_copy_trunc(path_host_buf, tx.host_path, sizeof(path_host_buf));
            path_host_shm = tx.is_dev_shm;
        }
        path_host = path_host_buf;
    }
    if (!path_host) {
        err = -LINUX_ENAMETOOLONG;
        goto fail;
    }

    /* Resolve binfmt_script before probing ELF. elf_load() logs parse errors,
     * and a script is an expected non-ELF input here.
     */
    elf_info_t elf_info;
    int shebang_depth = 0;

    /* Open the directly-executed file first and bind it to an fd to avoid
     * TOCTOU.
     */
    exec_fd = exec_open_image(path_host, path_host_shm);
    if (exec_fd < 0) {
        err = linux_errno();
        goto fail;
    }

    /* Snapshot the directly-executed file's metadata before shebang resolution
     * overwrites path_host with the interpreter path. The setuid/setgid check
     * below needs the *original* file's mode bits.
     */
    bool exec_is_script = false;
    struct stat exec_st;
    bool have_exec_st = (fstat(exec_fd, &exec_st) == 0);
    if (!have_exec_st) {
        err = linux_errno();
        goto fail;
    }

    /* Judge access by the ownership the guest sees: fs-stat.c reports every
     * guest stat through the virtual chown overlay, so the physical owner would
     * refuse a file the guest's own stat says it may execute. Trusting a
     * guest-writable overlay here -- chown_result records the intended owner on
     * any EPERM, unchecked -- is a deliberate trade. A guest can chown a file
     * into its own name to pass a check the physical mode refuses, and gains
     * nothing: the host open must still succeed on the physical file.
     *
     * exec_st itself stays physical, and the set-id decision below takes both:
     * it grants only where the two agree, so the overlay can withdraw an
     * elevation but never conjure one.
     */
    struct stat exec_st_seen = exec_st;
    chown_overlay_apply(&exec_st_seen);

    err = check_exec_permission(&exec_st_seen);
    if (err < 0) {
        goto fail;
    }

    /* Decide the fakeroot transition from the directly-executed file, before
     * the shebang loop repoints path_host at an interpreter: a marked wrapper
     * script has to elevate on its own identity, not on /bin/sh's.
     *
     * Unlike the setuid rule below, a script is not excluded. That rule exists
     * because any file on the system can carry a setuid bit, so the kernel
     * cannot trust the interpreter line of one it never vetted. Here the
     * embedder named exactly one file out of band; its shebang line is as much
     * the embedder's choice as its ELF contents would be, and a marked dynamic
     * binary would trust guest-reachable shared libraries just the same.
     */
    bool enter_fakeroot = exec_matches_fakeroot_target(&exec_st);

    while (true) {
        char interp_start[256];
        char interp_arg[256];
        int rc =
            elf_read_shebang_fd(exec_fd, interp_start, sizeof(interp_start),
                                interp_arg, sizeof(interp_arg));
        if (rc < 0) {
            errno = -rc;
            err = linux_errno();
            goto fail;
        }
        if (rc == 0)
            break;

        exec_is_script = true;

        /* Bound the resolution chain only once a further shebang is confirmed,
         * so a max-depth chain ending in a real ELF still loads (matches the
         * prior elf_load-first loop).
         */
        if (shebang_depth >= ELF_SHEBANG_MAX_DEPTH) {
            err = -LINUX_ELOOP;
            goto fail;
        }
        shebang_depth++;

        bool has_arg = (interp_arg[0] != '\0');

        log_debug(
            "execve: shebang interp=\"%s\" arg=\"%s\" script=\"%s\" depth=%d",
            interp_start, has_arg ? interp_arg : "(none)", path, shebang_depth);

        /* Rebuild argv: [interpreter, optional-arg, script-path,
         * original-argv[1:]]
         */
        int prefix = (has_arg ? 2 : 1) + 1;
        if (argc + prefix - 1 > ELFUSE_MAX_ARG_STRINGS) {
            err = -LINUX_E2BIG;
            goto fail;
        }
        int ni = 0;
        int new_cap = argc + prefix;
        char **new_argv = malloc(sizeof(char *) * (new_cap + 1));
        if (!new_argv) {
            err = -LINUX_ENOMEM;
            goto fail;
        }
        new_argv[ni++] = interp_start;
        if (has_arg)
            new_argv[ni++] = interp_arg;
        new_argv[ni++] = path;
        for (int i = 1; i < argc; i++)
            new_argv[ni++] = argv[i];
        new_argv[ni] = NULL;

        /* Copy only the prefix strings (from shebang_buf/path, which go out of
         * scope) into argv_buf. Append after existing data to avoid overwriting
         * original argv[1:] strings that are already in argv_buf and are
         * referenced by new_argv[prefix_end:].
         */
        size_t buf_off = 0;
        if (argc > 0)
            buf_off = (size_t) (argv[argc - 1] - argv_buf) +
                      strlen(argv[argc - 1]) + 1;
        int prefix_end = ni - (argc > 1 ? argc - 1 : 0);
        for (int i = 0; i < prefix_end; i++) {
            size_t len = strlen(new_argv[i]);
            if (running_bytes + len + 1 > ELFUSE_MAX_ARG_BYTES) {
                free(new_argv);
                err = -LINUX_E2BIG;
                goto fail;
            }
            if (buf_off + len + 1 > argv_buf_size) {
                size_t new_size = (buf_off + len + 1 + 4095) & ~4095ULL;
                char *new_buf = realloc(argv_buf, new_size);
                if (!new_buf) {
                    free(new_argv);
                    err = -LINUX_ENOMEM;
                    goto fail;
                }
                if (new_buf != argv_buf) {
                    ptrdiff_t diff = new_buf - argv_buf;
                    for (int j = prefix_end; j < ni; j++)
                        new_argv[j] += diff;
                    argv_buf = new_buf;
                }
                argv_buf_size = new_size;
            }
            memcpy(argv_buf + buf_off, new_argv[i], len + 1);
            new_argv[i] = argv_buf + buf_off;
            buf_off += len + 1;
            running_bytes += len + 1;
        }
        free(argv);
        argv = new_argv;
        argc = ni;

        /* Continue the same exec transaction using the interpreter image. */
        str_copy_trunc(path, interp_start, sizeof(path));
        path_translation_t interp_tx;
        if (path_translate_at(LINUX_AT_FDCWD, path, PATH_TR_NONE, &interp_tx) <
            0) {
            err = linux_errno();
            goto fail;
        }
        if (path_host_temp) {
            unlink(path_host_buf);
            path_host_temp = false;
        }
        if (interp_host_temp) {
            unlink(interp_host_buf);
            interp_host_temp = false;
        }
        if (interp_tx.fuse_path) {
            err =
                fuse_materialize_path(interp_tx.intercept_path, interp_host_buf,
                                      sizeof(interp_host_buf));
            if (err < 0)
                goto fail;
            interp_host_temp = true;
            path_host = interp_host_buf;
            path_host_shm = false;
        } else {
            str_copy_trunc(path_host_buf, interp_tx.host_path,
                           sizeof(path_host_buf));
            path_host = path_host_buf;
            path_host_shm = interp_tx.is_dev_shm;
        }

        /* Close old fd and open the new interpreter */
        close(exec_fd);
        exec_fd = exec_open_image(path_host, path_host_shm);
        if (exec_fd < 0) {
            err = linux_errno();
            goto fail;
        }
        struct stat interp_st;
        if (fstat(exec_fd, &interp_st) < 0) {
            err = linux_errno();
            goto fail;
        }
        chown_overlay_apply(&interp_st);
        err = check_exec_permission(&interp_st);
        if (err < 0) {
            goto fail;
        }
    }

    if (elf_load_fd(exec_fd, path_host, &elf_info) < 0) {
        err = -LINUX_ENOEXEC;
        goto fail;
    }

    /* Compute setuid/setgid from the directly-executed file (fs/exec.c
     * bprm_fill_uid). A set-id bit on the shebang script itself is ignored, as
     * on Linux, so the interpreter named in the script cannot be manipulated
     * into carrying the script's privilege. S_ISGID is only effective when the
     * group-execute bit is also set, matching the kernel's mandatory-locking vs
     * setgid distinction.
     *
     * Where this deliberately stops short of Linux: the kernel derives file
     * creds from the file it finally executes, so a set-id *interpreter* named
     * in a "#!" line does elevate there. exec_st is the directly-executed file
     * and is never refreshed after the shebang loop, so it does not here.
     * Elevating through an interpreter is unsupported, not accidentally lost.
     */
    uint32_t new_euid = proc_get_euid();
    uint32_t new_egid = proc_get_egid();
    if (have_exec_st && !exec_is_script && S_ISREG(exec_st.st_mode)) {
        if ((exec_st.st_mode & S_ISUID) &&
            exec_id_may_elevate((uint32_t) exec_st.st_uid,
                                (uint32_t) exec_st_seen.st_uid,
                                proc_get_uid())) {
            new_euid = (uint32_t) exec_st.st_uid;
        }
        if ((exec_st.st_mode & S_ISGID) && (exec_st.st_mode & S_IXGRP) &&
            exec_id_may_elevate((uint32_t) exec_st.st_gid,
                                (uint32_t) exec_st_seen.st_gid,
                                proc_get_gid())) {
            new_egid = (uint32_t) exec_st.st_gid;
        }
    }

    /* Pre-PNR validation. All checks that can fail gracefully MUST happen
     * before guest_reset(). After guest_reset(), the old process image is gone.
     * Failures are unrecoverable, matching the Linux kernel's behavior
     * (SIGKILL).
     */

    /* x86_64 targets dispatch through guest_bootstrap_rosetta_post_reset once
     * the point-of-no-return work below clears guest state. Reject here only
     * when Rosetta is disabled via --no-rosetta or ELFUSE_NO_ROSETTA=1;
     * otherwise mark the transition and skip the aarch64-specific ELF/interp
     * setup below.
     */
    bool target_is_rosetta = false;
    if (elf_info.e_machine == EM_X86_64) {
        if (!proc_rosetta_enabled()) {
            log_error(
                "execve: x86_64 ELF rejected by --no-rosetta "
                "(or ELFUSE_NO_ROSETTA=1): %s",
                path);
            err = -LINUX_ENOEXEC;
            goto fail;
        }

        /* rosetta_finalize pre-opens the x86_64 binary at a guest fd >= 3 past
         * the point of no return, where an EMFILE would be fatal. The guest fd
         * ceiling is far below the host limit, so a guest can fill its table
         * without the pre-PNR elf_load host open failing first. Reject here
         * (recoverably) when no slot >= 3 will survive the CLOEXEC sweep below.
         */
        if (!fd_reexec_slot_available(3)) {
            log_error("execve: no free guest fd for the Rosetta binary: %s",
                      path);
            err = -LINUX_EMFILE;
            goto fail;
        }
        target_is_rosetta = true;
    }

    /* Compute load base once (used for size check and later mapping). PIE
     * (ET_DYN) binaries start near address 0 and would overlap with the shim;
     * load them at PIE_LOAD_BASE instead.
     */
    uint64_t elf_load_base = (elf_info.e_type == ET_DYN) ? PIE_LOAD_BASE : 0;

    /* Settle where the image lands before anything is torn down. The mapper
     * takes the same per-segment decision, so passing here means the map after
     * the point of no return cannot refuse the image and force exit(128). A
     * segment ending at exactly UINT64_MAX is part of that: elf_load_fd records
     * it (the extent does not wrap), and adding the load base to it does, which
     * is what elf_check_placement catches.
     *
     * Not for a Rosetta target: elfuse never maps that image, the translator
     * reads it itself, so elf_load_base describes no mapping elfuse will make.
     * The parse-time rejections in elf_load_fd still apply to it, and should:
     * those judge whether the file is a well-formed ELF, which the translator
     * needs as much as elfuse does. The forbidden window for the executable
     * runs from the reserve to the top of the slab, not just across the
     * reserve. Everything from interp_base up belongs to the interpreter and
     * the runtime, so an ET_EXEC with a PT_LOAD above it would otherwise be
     * accepted here and then have the interpreter mapped straight over it.
     */
    uint64_t pre_infra_lo, pre_infra_hi;
    guest_infra_window(g, &pre_infra_lo, &pre_infra_hi);
    if (!target_is_rosetta &&
        !elf_check_placement(&elf_info, path, g->guest_size,
                             (elf_window_t) {0, elf_load_base}, pre_infra_lo,
                             g->guest_size)) {
        err = -LINUX_ENOEXEC;
        goto fail;
    }

    /* Pre-load the interpreter before the point of no return. */
    err = exec_preload_interp(g, &elf_info, target_is_rosetta, &interp);
    if (err < 0)
        goto fail;

    /* Past pre-PNR validation. Fall through to point of no return. The fail
     * label below handles all pre-PNR error paths.
     */

    /* Linux de_thread(): the siblings die before the new image exists, and
     * before commit_creds, so ordering it first here matches begin_new_exec and
     * keeps the credential commit below from reaching a thread that Linux would
     * already have destroyed. It also has to precede the CLOEXEC sweep and
     * guest_reset: a sibling parked in read() on a fd about to close, or still
     * executing the old image's code, winds down against the memory and fd
     * table its guest still expects.
     */
    /* Teardown must run without mmap_lock: a sibling blocked in an mmap-family
     * syscall or its deferred stack unmap cannot reach a stop check while the
     * lock is held. sys_execve acquires the lock below, immediately before the
     * point of no return, after every sibling has stopped.
     */
    int survivors = thread_exec_de_thread();

    /* The refusal above is a snapshot: a sibling could have created a CLONE_VM
     * child in the window between it and here. de_thread neither reaps nor
     * waits for one (Linux leaves it on the old mm), so count it now, when
     * every thread that could have created one is gone. guest_reset would
     * otherwise zero the shim data holding its EL1 stack and unmap host memory
     * under a live foreign vCPU.
     */
    survivors += thread_count_active_vm_clones();
    if (survivors > 0) {
        /* A sibling outlived the bounded join, so it still holds registers into
         * the image guest_reset is about to zero. Past the point of no return
         * the only safe answer is the same diagnosed exit the other post-reset
         * failures take.
         */
        log_fatal(
            "execve failed after point of no return: "
            "%d guest thread(s) survived de_thread",
            survivors);
        exit(128);
    }

    /* Commit credentials right before the Point of No Return. Saved UID/GID are
     * refreshed from the final effective IDs.
     *
     * The fakeroot transition lands here, past every failure path, so an exec
     * that never happens leaves the current image unprivileged. It mirrors what
     * --fakeroot gives a process at startup (proc_identity_init): root IDs plus
     * the process-wide gate, and it reaches fork children through the
     * --fakeroot argv forkipc already derives from that gate. Nothing clears
     * the gate afterwards, so this elevates the whole process tree from here
     * on, not just the image being loaded.
     *
     * The gate is published after the IDs because no permission check
     * grants on the gate alone: proc-identity.c pairs it with "emu_euid == 0 ||
     * fakeroot", and sys_getgroups and capget require both. Publishing it last
     * can therefore only narrow the window, never open one.
     *
     * The ATTN_BIT_CRED bracket is the same protocol the setuid family uses in
     * syscall.c: without it the shim's EL1 identity cache keeps answering
     * sibling getuid fast paths with pre-exec IDs until
     * exec_republish_shim_globals_or_die runs, well past guest_reset.
     */
    uint32_t new_uid = proc_get_uid();
    uint32_t new_gid = proc_get_gid();
    if (enter_fakeroot) {
        new_uid = new_euid = 0;
        new_gid = new_egid = 0;
    }
    shim_globals_attn_or(g, ATTN_BIT_CRED);
    proc_set_ids(new_uid, new_euid, new_euid, new_gid, new_egid, new_egid);
    if (enter_fakeroot)
        proc_set_fakeroot_enabled(true);
    shim_globals_publish_creds(g, proc_get_uid(), proc_get_euid(),
                               proc_get_gid(), proc_get_egid());
    shim_globals_attn_and(g, ~ATTN_BIT_CRED);

    if (0) {
    fail:
        if (exec_fd >= 0)
            close(exec_fd);
        if (interp.fd >= 0)
            close(interp.fd);
        free(temp_str);
        if (interp.resolved_temp)
            unlink(interp.resolved);
        exec_cleanup_inputs(argv, envp, argv_buf, envp_buf, path_host_buf,
                            path_host_temp, interp_host_buf, interp_host_temp);
        return err;
    }

    /* Input copying above may fault in argv/env strings from lazy anonymous
     * mappings, so it must run without mmap_lock held. Serialize only after
     * all recoverable validation is complete and immediately before replacing
     * the guest address space. From this point every failure is fatal and both
     * successful return paths release the lock explicitly.
     */
    mmap_lock_acquire(g);

    /* Point of no return. guest_reset() zeroes all guest memory. The old
     * process image is gone. All validation that can fail gracefully MUST
     * happen above this line. Failures below are unrecoverable; elfuse exits
     * fatally, matching the Linux kernel's behavior (SIGKILL after exec PNR).
     */

    exec_close_cloexec_fds();

    /* Past this point the old image is gone; later failures are fatal like a
     * kernel exec failure after its point of no return.
     */
    fork_notify_vfork_exec();

    /* Only clear rosetta state when leaving rosetta. For rosetta-to-rosetta
     * exec the placement (rosetta_guest_base, rosetta_va_base, kbuf_gpa, ttbr1)
     * must survive guest_reset so guest_bootstrap_rosetta_post_reset hits
     * rosetta_prepare's re-entry branch and reuses the existing GPA instead of
     * picking a fresh one. Keep proc_rosetta_active in sync so /proc/self/exe
     * readlink reports the right path.
     */
    if (g->is_rosetta && !target_is_rosetta) {
        rosettad_clear_binary_path();
        guest_clear_rosetta_state(g);
        proc_set_rosetta_active(false);
    } else if (!g->is_rosetta && target_is_rosetta) {
        /* aarch64 -> rosetta: enter rosetta mode fresh. guest_clear was already
         * a no-op in this branch since the parent had no rosetta state to
         * clear.
         */
        g->is_rosetta = true;
        proc_set_rosetta_active(true);
    }

    /* Before the memset, not after: guest_reset writes through each region's
     * host VA, which for an overlaid region is the backing file's page cache.
     * Dropping the overlays first sends those zeroes to the slab instead, and
     * leaves the new image with anonymous backing at that VA rather than a host
     * file. Fatal on failure for the same reason the whole region past the
     * point of no return is: the alternative is zeroing a user's file.
     */
    int overlay_err = mmap_exec_drop_overlays(g);
    if (overlay_err < 0) {
        log_fatal(
            "execve failed after point of no return: "
            "MAP_SHARED overlay teardown failed: %d",
            overlay_err);
        exit(128);
    }

    guest_reset(g);

    /* The replacement image must not inherit process-wide shutdown requests
     * from the old thread group.
     */
    proc_clear_exit_group();
    futex_interrupt_clear();
    thread_reset_for_exec();
    exec_handoff_reset();

    /* POSIX exec signal semantics: Handlers set to SIG_DFL (except SIG_IGN
     * stays SIG_IGN), pending signals preserved, and signal mask preserved.
     */
    signal_reset_for_exec();

    /* guest_reset clears the shim bytes, so restore EL1 exception code before
     * rebuilding page tables.
     */
    const unsigned char *shim_ptr = proc_get_shim_blob();
    unsigned int shim_size = proc_get_shim_size();
    if (shim_ptr && shim_size > 0) {
        memcpy((uint8_t *) g->host_base + g->shim_base, shim_ptr, shim_size);
    }

    /* x86_64 re-bootstrap branch: hand off the post-reset work to the
     * Rosetta-aware helper, then write vCPU sysregs for kernel-VA execution and
     * return without touching the aarch64-specific block below.
     */
    if (target_is_rosetta) {
        /* Drain the previous rosettad bridge before rosetta_finalize wires a
         * fresh one. The detached handler thread only clears its global
         * client-fd marker on its own EOF/exit. 1 s is enough headroom for a
         * loaded host; a hung handler past that point will lose the
         * start_handler CAS later, and the warning here marks the cause. Soft
         * cap; the install may still succeed on timeout if the handler's CAS
         * races us favourably.
         */
        if (!rosettad_wait_for_idle(1000)) {
            log_warn(
                "execve: rosettad bridge did not drain within 1s; "
                "rosetta_finalize CAS may lose the race");
        }

        /* path_host may point at path_host_buf (normal path) or at
         * interp_host_buf (shebang resolution landed on a FUSE-backed x86_64
         * binary). Ownership of any materialized temp transfers to rosettad
         * regardless of which buffer holds the path, so capture that temp path
         * in one place and clear the matching temp flag here.
         * exec_cleanup_inputs becomes a no-op for the transferred slot, and the
         * post-PNR rollback below can unlink via owned_rosetta_temp without
         * re-discriminating which buffer was selected.
         */
        const char *owned_rosetta_temp = NULL;
        if (path_host == path_host_buf && path_host_temp) {
            owned_rosetta_temp = path_host_buf;
            path_host_temp = false;
        } else if (path_host == interp_host_buf && interp_host_temp) {
            owned_rosetta_temp = interp_host_buf;
            interp_host_temp = false;
        }

        uint64_t r_entry = 0, r_sp = 0, r_ttbr0 = 0;
        if (guest_bootstrap_rosetta_post_reset(
                g, path_host, owned_rosetta_temp != NULL, path, argc,
                (const char **) argv, envp, shim_size, false, &r_entry, &r_sp,
                &r_ttbr0) < 0) {
            /* Post-PNR fatal failure. The temp flag was cleared up front so
             * exec_cleanup_inputs would be a no-op, and rosettad never reached
             * its ownership-commit point on this failure path. Best-effort
             * unlink so the materialized temp does not orphan in /tmp on a path
             * the kernel parallels with SIGKILL.
             */
            if (owned_rosetta_temp)
                unlink(owned_rosetta_temp);
            log_fatal(
                "execve failed after point of no return: "
                "rosetta re-bootstrap failed for %s",
                path);
            exit(128);
        }
        exec_republish_shim_globals_or_die(vcpu, g, verbose);

        /* I-cache for the (possibly re-mapped) rosetta segments has already
         * been invalidated inside rosetta_prepare; only the shim needs an
         * I-cache flush from here.
         */
        sys_icache_invalidate((uint8_t *) g->host_base + g->shim_base,
                              shim_size);

        /* The kbuf alias lives under TTBR1, so the translator enters on a
         * different regime than a native image does. Everything else about
         * entering an image is the same, hence the shared helper.
         */
        const exec_addr_space_t as = {r_ttbr0, g->ttbr1, TCR_EL1_VALUE_KBUF};
        exec_enter_new_image(vcpu, g, r_entry, r_sp, &as);

        log_debug("execve: rosetta target %s, entry=0x%llx sp=0x%llx", path,
                  (unsigned long long) guest_ipa(g, r_entry),
                  (unsigned long long) guest_ipa(g, r_sp));
        free(temp_str);
        if (exec_fd >= 0) {
            close(exec_fd);
        }
        if (interp.fd >= 0) {
            close(interp.fd);
        }
        if (interp.resolved_temp)
            unlink(interp.resolved);
        exec_cleanup_inputs(argv, envp, argv_buf, envp_buf, path_host_buf,
                            path_host_temp, interp_host_buf, interp_host_temp);
        mmap_lock_release();
        return SYSCALL_EXEC_HAPPENED;
    }

    /* Load the executable image that was validated before guest_reset(). */
    uint64_t infra_lo, infra_hi;
    guest_infra_window(g, &infra_lo, &infra_hi);
    if (elf_map_segments_fd(&elf_info, exec_fd, path_host, g->host_base,
                            g->guest_size, (elf_window_t) {0, elf_load_base},
                            infra_lo, g->guest_size) < 0) {
        log_fatal(
            "execve failed after point of no return: "
            "failed to map ELF segments for %s",
            path_host);
        exit(128);
    }

    /* Track lowest loaded ELF address for the legacy fork IPC path after exec
     * replaces the previous image (see guest_get_used_regions).
     */
    g->elf_load_min = elf_info.load_min + elf_load_base;

    /* If PT_INTERP was present, map the already-validated interpreter at the
     * exec-time interp_base.
     */
    uint64_t interp_base = 0;

    if (elf_info.interp_path[0] != '\0') {
        interp_base = g->interp_base;
        if (elf_map_segments_fd(&interp.info, interp.fd, interp.resolved,
                                g->host_base, g->guest_size,
                                (elf_window_t) {0, interp_base}, infra_lo,
                                infra_hi) < 0) {
            log_fatal(
                "execve failed after point of no return: "
                "failed to map interpreter segments");
            exit(128);
        }

        log_debug(
            "execve: interpreter at base=0x%llx, entry=0x%llx, %d segments",
            (unsigned long long) interp_base,
            (unsigned long long) (interp.info.entry + interp_base),
            interp.info.num_segments);
    }

    /* memcpy wrote executable bytes through D-cache; invalidate I-cache before
     * EL0 can fetch the replacement image.
     */
    for (int i = 0; i < elf_info.num_segments; i++) {
        if (elf_info.segments[i].flags & PF_X) {
            void *host_addr = (uint8_t *) g->host_base +
                              elf_info.segments[i].gpa + elf_load_base;
            sys_icache_invalidate(host_addr, elf_info.segments[i].memsz);
        }
    }
    for (int i = 0; i < interp.info.num_segments; i++) {
        if (interp.info.segments[i].flags & PF_X) {
            void *host_addr = (uint8_t *) g->host_base +
                              interp.info.segments[i].gpa + interp_base;
            sys_icache_invalidate(host_addr, interp.info.segments[i].memsz);
        }
    }
    sys_icache_invalidate((uint8_t *) g->host_base + g->shim_base, shim_size);

    /* Reset brk to the first page after loaded executable data. */
    uint64_t brk_start = PAGE_ALIGN_UP(elf_info.load_max + elf_load_base);
    if (brk_start < BRK_BASE_DEFAULT)
        brk_start = BRK_BASE_DEFAULT;
    g->brk_base = brk_start;
    g->brk_current = brk_start;

    /* Keep exec stack placement consistent with initial process startup. */
    uint64_t stack_top = ALIGN_UP(brk_start, BLOCK_2MIB);
    stack_top += STACK_SIZE;
    if (stack_top < STACK_TOP_DEFAULT)
        stack_top = STACK_TOP_DEFAULT;
    g->stack_top = stack_top;
    g->stack_base = stack_top - STACK_SIZE;

    const exec_image_t image = {.shim_size = shim_size,
                                .elf_info = &elf_info,
                                .elf_load_base = elf_load_base,
                                .interp = &interp,
                                .interp_base = interp_base,
                                .path = path};
    uint64_t ttbr0 = exec_install_address_space(g, &image);

    exec_publish_maps(g, &image);

    /* Build argc/argv/envp/auxv for the replacement image. */
    const char **argv_const = (const char **) argv;
    const char **envp_const = (const char **) envp;
    uint64_t sp, entry_point;
    linux_stack_auxv_t auxv;

    {
        /* The vDSO supplies a stable rt_sigreturn trampoline when user handlers
         * omit sa_restorer.
         */
        uint64_t exec_vdso = vdso_build(g);
        exec_republish_shim_globals_or_die(vcpu, g, verbose);

        /* AT_EXECFN gets the same guest-visible spelling published to
         * /proc/self/exe below, so the two surfaces agree on what this process
         * is. Passing path rather than argv_const[0] also matches Linux for
         * execve(path, ["altname"], ...), where the kernel reports path.
         */
        sp = build_linux_stack(g, g->stack_top, argc, argv_const, envp_const,
                               &elf_info, elf_load_base, interp_base, exec_vdso,
                               -1 /* no AT_EXECFD */, path, &auxv);

        /* 0 is build_linux_stack's failure return. Past the point of no return
         * there is no image to go back to, and programming SP_EL0 from it would
         * ERET the guest onto a null stack. read_string_array already enforces
         * the same argc cap upstream, so the live case here is allocation
         * failure.
         */
        if (sp == 0) {
            log_fatal(
                "execve failed after point of no return: build_linux_stack");
            exit(128);
        }
        g->start_stack = sp;

        entry_point = (interp_base != 0) ? (interp.info.entry + interp_base)
                                         : (elf_info.entry + elf_load_base);

        /* Publish the guest-visible path so /proc/self/exe remains stable
         * across sysroot translation and can be re-exec'd by the guest.
         */
        proc_set_elf_path(path);
        proc_set_cmdline(argc, argv_const);
        proc_set_environ(envp_const);
        proc_set_auxv(auxv.words, auxv.nwords * sizeof(auxv.words[0]));
    }

    const exec_addr_space_t as = {ttbr0, 0, TCR_EL1_VALUE};
    exec_enter_new_image(vcpu, g, entry_point, sp, &as);
    log_debug("execve: loaded %s, entry=0x%llx sp=0x%llx", path_host,
              (unsigned long long) guest_ipa(g, entry_point),
              (unsigned long long) guest_ipa(g, sp));

    free(temp_str);
    if (exec_fd >= 0)
        close(exec_fd);
    if (interp.fd >= 0)
        close(interp.fd);
    if (interp.resolved_temp)
        unlink(interp.resolved);
    exec_cleanup_inputs(argv, envp, argv_buf, envp_buf, path_host_buf,
                        path_host_temp, interp_host_buf, interp_host_temp);

    mmap_lock_release();
    return SYSCALL_EXEC_HAPPENED;
}
