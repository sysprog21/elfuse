/* execve syscall handler
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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

#include "syscall/abi.h"
#include "syscall/exec.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/path.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

/* fd_cleanup_entry() releases type-specific fd resources after the CLOEXEC
 * entry has been removed from the shared fd table.
 */

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
    (void) vcpu_get_reg(vcpu, HV_REG_X8);
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
}

/* Release the buffers and temporary host-side files that sys_execve allocates
 * before crossing the point of no return. Used by both the Rosetta and the
 * aarch64 success paths.
 */
static void exec_cleanup_inputs(char *argv_buf,
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
    free(argv_buf);
    free(envp_buf);
}

static int exec_resolve_guest_host_path(const char *guest_path,
                                        char *host_path,
                                        size_t host_path_sz,
                                        bool *host_path_temp)
{
    path_translation_t tx;
    if (!guest_path || !host_path || host_path_sz == 0 || !host_path_temp) {
        errno = EINVAL;
        return -1;
    }

    *host_path_temp = false;
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
    return 0;
}

static int exec_resolve_interp_host_path(const char *sysroot,
                                         const char *interp_guest_path,
                                         char *interp_host_path,
                                         size_t interp_host_path_sz,
                                         bool *interp_host_temp)
{
    char interp_candidate[LINUX_PATH_MAX];
    elf_resolve_interp(sysroot, interp_guest_path, interp_candidate,
                       sizeof(interp_candidate));
    if (strcmp(interp_candidate, interp_guest_path) != 0) {
        size_t len = str_copy_trunc(interp_host_path, interp_candidate,
                                    interp_host_path_sz);
        if (len >= interp_host_path_sz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        *interp_host_temp = false;
        return 0;
    }

    return exec_resolve_guest_host_path(interp_guest_path, interp_host_path,
                                        interp_host_path_sz, interp_host_temp);
}

/* Read a NULL-terminated pointer array from guest memory. Each pointer in the
 * array is a 64-bit GVA pointing to a string.
 * Returns the count of entries (excluding the NULL terminator), or -1 on error.
 * Strings are copied into the provided buffer.
 */
static int read_string_array(guest_t *g,
                             uint64_t array_gva,
                             char **out,
                             int max_count,
                             char *str_buf,
                             size_t str_buf_size)
{
    size_t str_off = 0;
    int count = 0;

    for (int i = 0; i < max_count; i++) {
        uint64_t ptr;
        if (guest_read_small(g, array_gva + (uint64_t) i * 8, &ptr,
                             sizeof(ptr)) < 0)
            return -1;
        if (ptr == 0)
            break;

        char *dst = str_buf + str_off;
        size_t remaining = str_buf_size - str_off;
        if (remaining < 2)
            return -1;

        if (guest_read_str(g, ptr, dst, remaining) < 0)
            return -1;

        out[count] = dst;
        str_off += strlen(dst) + 1;
        count++;
    }

    /* If all max_count slots are consumed, check whether the array continues
     * (non-NULL next entry).
     *
     * Return -2 to signal E2BIG rather than silently truncating.
     */
    if (count == max_count) {
        uint64_t next;
        if (guest_read_small(g, array_gva + (uint64_t) count * 8, &next,
                             sizeof(next)) == 0 &&
            next != 0)
            return -2; /* too many entries */
    }

    return count;
}

int64_t sys_execve(hv_vcpu_t vcpu,
                   guest_t *g,
                   uint64_t path_gva,
                   uint64_t argv_gva,
                   uint64_t envp_gva,
                   bool verbose,
                   const char *host_path)
{
    /* Copy guest execve inputs before any state-reset point of no return. If
     * host_path is provided (from execveat resolution), use it directly instead
     * of reading from guest memory. This avoids writing host-resolved paths
     * into guest address space.
     */
    char path[LINUX_PATH_MAX];
    if (host_path) {
        size_t len = strlen(host_path);
        if (len >= LINUX_PATH_MAX)
            return -LINUX_ENAMETOOLONG;
        memcpy(path, host_path, len + 1);
    } else if (guest_read_str(g, path_gva, path, sizeof(path)) < 0) {
        return -LINUX_EFAULT;
    }

    log_debug("execve(\"%s\")", path);

    char path_host_buf[LINUX_PATH_MAX];
    const char *path_host = path;
    bool path_host_temp = false;
    char interp_host_buf[LINUX_PATH_MAX];
    bool interp_host_temp = false;

#define MAX_ARGS 256
#define MAX_ENVS 4096
#define STR_BUF_SIZE ((size_t) 256 * 1024)

    int64_t err = 0;
    char *argv[MAX_ARGS + 1];
    char *envp[MAX_ENVS + 1];
    char *argv_buf = malloc(STR_BUF_SIZE);
    char *envp_buf = malloc(STR_BUF_SIZE);
    if (!argv_buf || !envp_buf) {
        err = -LINUX_ENOMEM;
        goto fail;
    }

    int argc =
        read_string_array(g, argv_gva, argv, MAX_ARGS, argv_buf, STR_BUF_SIZE);
    if (argc < 0) {
        err = (argc == -2) ? -LINUX_E2BIG : -LINUX_EFAULT;
        goto fail;
    }
    argv[argc] = NULL;

    int envc = 0;
    if (envp_gva != 0) {
        envc = read_string_array(g, envp_gva, envp, MAX_ENVS, envp_buf,
                                 STR_BUF_SIZE);
        if (envc < 0) {
            err = (envc == -2) ? -LINUX_E2BIG : -LINUX_EFAULT;
            goto fail;
        }
    }
    envp[envc] = NULL;

    /* Resolve /proc/self/exe to the actual binary path. Busybox sh execs
     * applets via execve("/proc/self/exe", ["applet", ...]) and macOS has no
     * /proc filesystem.
     */
    if (!strcmp(path, "/proc/self/exe")) {
        const char *exe = proc_get_elf_path();
        if (!exe) {
            err = -LINUX_ENOENT;
            goto fail;
        }
        str_copy_trunc(path, exe, sizeof(path));
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
        }
        path_host = path_host_buf;
    }
    if (!path_host) {
        err = -LINUX_ENAMETOOLONG;
        goto fail;
    }

    /* Try loading as ELF; if that fails, emulate Linux binfmt_script for
     * shebang files. Linux kernel handles shebangs transparently in
     * binfmt_script.
     */
    elf_info_t elf_info;
    if (elf_load_quiet(path_host, &elf_info) < 0) {
        /* Not a valid ELF. Check if it's a script with a shebang line.
         * Read the first 256 bytes and look for "#!" at the start.
         */
        int script_fd = open(path_host, O_RDONLY);
        if (script_fd < 0) {
            err = -LINUX_ENOENT;
            goto fail;
        }
        char shebang_buf[256];
        ssize_t nread = read(script_fd, shebang_buf, sizeof(shebang_buf) - 1);
        close(script_fd);

        if (nread < 2 || shebang_buf[0] != '#' || shebang_buf[1] != '!') {
            err = -LINUX_ENOEXEC;
            goto fail;
        }
        shebang_buf[nread] = '\0';

        /* Ignore script bytes after the first line; only the shebang line
         * contributes interpreter arguments.
         */
        char *eol = strchr(shebang_buf + 2, '\n');
        if (eol)
            *eol = '\0';

        /* Parse interpreter path and optional argument. Format: "#!
         * /path/to/interpreter [optional-arg]"
         */
        char *interp_start = shebang_buf + 2;
        while (*interp_start == ' ' || *interp_start == '\t')
            interp_start++;
        if (*interp_start == '\0') {
            err = -LINUX_ENOEXEC;
            goto fail;
        }

        /* Linux preserves one optional shebang argument as a single argv
         * element, without shell-style splitting.
         */
        char *interp_arg = NULL;
        char *space = interp_start;
        while (*space && *space != ' ' && *space != '\t')
            space++;
        if (*space) {
            *space = '\0';
            interp_arg = space + 1;
            while (*interp_arg == ' ' || *interp_arg == '\t')
                interp_arg++;
            if (*interp_arg == '\0')
                interp_arg = NULL;
            /* Trim the line ending from the optional argument. */
            if (interp_arg) {
                char *end = interp_arg + strlen(interp_arg) - 1;
                while (end > interp_arg &&
                       (*end == ' ' || *end == '\t' || *end == '\r'))
                    *end-- = '\0';
            }
        }

        log_debug("execve: shebang interp=\"%s\" arg=\"%s\" script=\"%s\"",
                  interp_start, interp_arg ? interp_arg : "(none)", path);

        /* Rebuild argv: [interpreter, optional-arg, script-path,
         * original-argv[1:]]
         */
        int new_argc = 1 + (interp_arg ? 1 : 0) + 1 + (argc > 1 ? argc - 1 : 0);
        if (new_argc > MAX_ARGS) {
            err = -LINUX_E2BIG;
            goto fail;
        }

        /* Use a fixed-size stack array (MAX_ARGS+3 covers interpreter +
         * optional arg + script + original argv[1:]). The alloca was
         * unnecessary since the bound is compile-time known.
         */
        char *new_argv[MAX_ARGS + 3];
        int ni = 0;
        new_argv[ni++] = interp_start;
        if (interp_arg)
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
            if (buf_off + len + 1 > STR_BUF_SIZE) {
                err = -LINUX_E2BIG;
                goto fail;
            }
            memcpy(argv_buf + buf_off, new_argv[i], len + 1);
            argv[i] = argv_buf + buf_off;
            buf_off += len + 1;
        }
        for (int i = prefix_end; i < ni; i++)
            argv[i] = new_argv[i];
        argv[ni] = NULL;
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
        if (interp_tx.fuse_path) {
            err =
                fuse_materialize_path(interp_tx.intercept_path, interp_host_buf,
                                      sizeof(interp_host_buf));
            if (err < 0)
                goto fail;
            interp_host_temp = true;
            path_host = interp_host_buf;
        } else {
            str_copy_trunc(path_host_buf, interp_tx.host_path,
                           sizeof(path_host_buf));
            path_host = path_host_buf;
        }

        if (elf_load(path_host, &elf_info) < 0) {
            err = -LINUX_ENOENT;
            goto fail;
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
        target_is_rosetta = true;
    }

    /* Compute load base once (used for size check and later mapping). PIE
     * (ET_DYN) binaries start near address 0 and would overlap with the shim;
     * load them at PIE_LOAD_BASE instead.
     */
    uint64_t elf_load_base = (elf_info.e_type == ET_DYN) ? PIE_LOAD_BASE : 0;

    /* Validate that the ELF fits within the guest address space */
    uint64_t elf_end = elf_info.load_max + elf_load_base;
    if (elf_end > g->guest_size) {
        log_error(
            "execve: ELF extends beyond guest address space "
            "(0x%llx > 0x%llx) for %s",
            (unsigned long long) elf_end, (unsigned long long) g->guest_size,
            path);
        err = -LINUX_ENOEXEC;
        goto fail;
    }

    /* Pre-load interpreter (headers only) for dynamic binaries. This validates
     * the interpreter exists and is a valid ELF before exec crosses the point
     * of no return. elf_map_segments() happens post-PNR.
     */
    elf_info_t interp_info;
    memset(&interp_info, 0, sizeof(interp_info));
    char interp_resolved[LINUX_PATH_MAX];
    char interp_display_path[LINUX_PATH_MAX];
    interp_resolved[0] = '\0';
    interp_display_path[0] = '\0';

    /* x86_64 targets do not pre-load their PT_INTERP. Rosetta is statically
     * linked and loads the target binary (and any guest-side dynamic linker)
     * itself via fd 3, so the aarch64-only interpreter pre-load below is
     * skipped for rosetta exec.
     */
    if (!target_is_rosetta && elf_info.interp_path[0] != '\0') {
        char sysroot_snap[LINUX_PATH_MAX];
        bool have_sr =
            proc_sysroot_snapshot(sysroot_snap, sizeof(sysroot_snap));
        if (exec_resolve_interp_host_path(have_sr ? sysroot_snap : NULL,
                                          elf_info.interp_path, interp_resolved,
                                          sizeof(interp_resolved),
                                          &interp_host_temp) < 0) {
            log_error("execve: failed to resolve interpreter: %s",
                      elf_info.interp_path);
            err = -LINUX_ENOEXEC;
            goto fail;
        }
        str_copy_trunc(
            interp_display_path,
            interp_host_temp ? elf_info.interp_path : interp_resolved,
            sizeof(interp_display_path));

        log_debug("execve: pre-validating interpreter: %s", interp_resolved);

        if (elf_load(interp_resolved, &interp_info) < 0) {
            log_error("execve: failed to load interpreter: %s",
                      interp_resolved);
            err = -LINUX_ENOEXEC;
            goto fail;
        }

        if (interp_info.e_machine != EM_AARCH64) {
            log_error("execve: interpreter has unsupported machine type %u: %s",
                      interp_info.e_machine, interp_resolved);
            err = -LINUX_ENOEXEC;
            goto fail;
        }
    }

    /* Past pre-PNR validation. Fall through to point of no return. The fail
     * label below handles all pre-PNR error paths.
     */
    if (0) {
    fail:
        exec_cleanup_inputs(argv_buf, envp_buf, path_host_buf, path_host_temp,
                            interp_host_buf, interp_host_temp);
        return err;
    }

    /* Point of no return. guest_reset() zeroes all guest memory. The old
     * process image is gone. All validation that can fail gracefully MUST
     * happen above this line. Failures below are unrecoverable; elfuse exits
     * fatally, matching the Linux kernel's behavior (SIGKILL after exec PNR).
     */

    /* Close CLOEXEC fds by first removing them from the shared table under
     * fd_lock, then cleaning up type-specific host resources after unlock.
     * Cleanup acquires sfd_lock or inotify_lock, which must NOT be held under
     * fd_lock (lock ordering: fd_lock(3) < sfd_lock(5a) < inotify_lock(7)).
     *
     * Two passes: count first, then heap-allocate. Avoids placing a ~100KiB VLA
     * on the stack (FD_TABLE_SIZE * sizeof(fd_entry_t+int)).
     */
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
    bool fd_lock_held = true;
    if (cloexec_count > 0) {
        cloexec_list =
            malloc((size_t) cloexec_count * sizeof(struct cloexec_entry));
        if (!cloexec_list) {
            /* OOM during exec: fall back to fixed-size batches so cleanup still
             * runs outside fd_lock.
             */
            struct cloexec_entry batch[32];
            int scan = 0;
            while (scan < FD_TABLE_SIZE) {
                int batch_count = 0;
                for (; scan < FD_TABLE_SIZE &&
                       batch_count < (int) (ARRAY_SIZE(batch));
                     scan++) {
                    if (fd_table[scan].type == FD_CLOSED ||
                        !(fd_table[scan].linux_flags & LINUX_O_CLOEXEC))
                        continue;
                    batch[batch_count].fd = scan;
                    batch[batch_count].snap = fd_table[scan];
                    batch_count++;
                    fd_table[scan].dir = NULL;
                    fd_mark_closed_unlocked(scan);
                }
                pthread_mutex_unlock(&fd_lock);
                fd_lock_held = false;
                for (int j = 0; j < batch_count; j++)
                    fd_cleanup_entry(batch[j].fd, &batch[j].snap);
                if (scan < FD_TABLE_SIZE) {
                    pthread_mutex_lock(&fd_lock);
                    fd_lock_held = true;
                }
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
                    fd_table[i].dir = NULL;
                    fd_mark_closed_unlocked(i);
                }
            }
        }
    }
    if (fd_lock_held)
        pthread_mutex_unlock(&fd_lock);

    /* fd_cleanup_entry may close host fds, DIR*, epoll/kqueue state, or inotify
     * state, so keep it outside fd_lock.
     */
    for (int j = 0; j < cloexec_count; j++)
        fd_cleanup_entry(cloexec_list[j].fd, &cloexec_list[j].snap);
    free(cloexec_list);

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
    guest_reset(g);

    /* The replacement image must not inherit process-wide shutdown requests
     * from the old thread group.
     */
    proc_clear_exit_group();
    futex_interrupt_clear();

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

        uint64_t entry_ipa = guest_ipa(g, r_entry);
        uint64_t sp_ipa = guest_ipa(g, r_sp);

        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, r_ttbr0);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, TCR_EL1_VALUE_KBUF);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, g->ttbr1);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, entry_ipa);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, sp_ipa);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, 0x0);
        hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, 0);
        vcpu_zero_gprs(vcpu);
        hv_vcpu_set_reg(vcpu, HV_REG_X8, 2);
        tlbi_request_clear();

        exec_sync_vcpu_regs(vcpu);

        log_debug("execve: rosetta target %s, entry=0x%llx sp=0x%llx", path,
                  (unsigned long long) entry_ipa, (unsigned long long) sp_ipa);
        exec_cleanup_inputs(argv_buf, envp_buf, path_host_buf, path_host_temp,
                            interp_host_buf, interp_host_temp);
        return SYSCALL_EXEC_HAPPENED;
    }

    /* Load the executable image that was validated before guest_reset(). */
    uint64_t infra_lo = g->interp_base - INFRA_RESERVE;
    uint64_t infra_hi = g->interp_base;
    if (elf_map_segments(&elf_info, path_host, g->host_base, g->guest_size,
                         elf_load_base, infra_lo, infra_hi) < 0) {
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
        if (elf_map_segments(&interp_info, interp_resolved, g->host_base,
                             g->guest_size, interp_base, infra_lo,
                             infra_hi) < 0) {
            log_fatal(
                "execve failed after point of no return: "
                "failed to map interpreter segments");
            exit(128);
        }

        log_debug(
            "execve: interpreter at base=0x%llx, entry=0x%llx, %d segments",
            (unsigned long long) interp_base,
            (unsigned long long) (interp_info.entry + interp_base),
            interp_info.num_segments);
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
    for (int i = 0; i < interp_info.num_segments; i++) {
        if (interp_info.segments[i].flags & PF_X) {
            void *host_addr = (uint8_t *) g->host_base +
                              interp_info.segments[i].gpa + interp_base;
            sys_icache_invalidate(host_addr, interp_info.segments[i].memsz);
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

    /* Translate ELF p_flags into guest page permissions. Silent drops would
     * leave the loaded segment unmapped, so treat overflow as fatal (the caller
     * is already past the point of no return).
     */
    for (int i = 0; i < elf_info.num_segments; i++) {
        if (nregions >= MAX_REGIONS)
            goto too_many_regions;
        regions[nregions++] = (mem_region_t) {
            .gpa_start = elf_info.segments[i].gpa + elf_load_base,
            .gpa_end = elf_info.segments[i].gpa + elf_info.segments[i].memsz +
                       elf_load_base,
            .perms = elf_pf_to_prot(elf_info.segments[i].flags)};
    }

    /* Interpreter segments use the same permission translation, shifted by
     * interp_base. Same fatal-overflow rule as the executable's segments.
     */
    for (int i = 0; i < interp_info.num_segments; i++) {
        if (nregions >= MAX_REGIONS)
            goto too_many_regions;
        regions[nregions++] = (mem_region_t) {
            .gpa_start = interp_info.segments[i].gpa + interp_base,
            .gpa_end = interp_info.segments[i].gpa +
                       interp_info.segments[i].memsz + interp_base,
            .perms = elf_pf_to_prot(interp_info.segments[i].flags)};
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
    for (int i = 0; i < elf_info.num_segments; i++) {
        guest_region_add(g, elf_info.segments[i].gpa + elf_load_base,
                         elf_info.segments[i].gpa + elf_info.segments[i].memsz +
                             elf_load_base,
                         elf_pf_to_prot(elf_info.segments[i].flags),
                         LINUX_MAP_PRIVATE, elf_info.segments[i].offset, path);
    }
    /* interp_resolved was computed before guest_reset so no filesystem lookup
     * is needed after the point of no return.
     */
    if (interp_info.num_segments > 0) {
        for (int i = 0; i < interp_info.num_segments; i++) {
            guest_region_add(g, interp_info.segments[i].gpa + interp_base,
                             interp_info.segments[i].gpa +
                                 interp_info.segments[i].memsz + interp_base,
                             elf_pf_to_prot(interp_info.segments[i].flags),
                             LINUX_MAP_PRIVATE, interp_info.segments[i].offset,
                             interp_display_path);
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

        sp = build_linux_stack(g, g->stack_top, argc, argv_const, envp_const,
                               &elf_info, elf_load_base, interp_base, exec_vdso,
                               -1 /* no AT_EXECFD */, &auxv);

        entry_point = (interp_base != 0) ? (interp_info.entry + interp_base)
                                         : (elf_info.entry + elf_load_base);

        /* Publish the guest-visible path so /proc/self/exe remains stable
         * across sysroot translation and can be re-exec'd by the guest.
         */
        proc_set_elf_path(path);
        proc_set_cmdline(argc, argv_const);
        proc_set_environ(envp_const);
        proc_set_auxv(auxv.words, auxv.nwords * sizeof(auxv.words[0]));
    }

    /* Replace the saved syscall-return state with the new program entry. */
    uint64_t entry_ipa = guest_ipa(g, entry_point), sp_ipa = guest_ipa(g, sp);

    /* Switch EL0 translation to the rebuilt page tables. */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, ttbr0);
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, TCR_EL1_VALUE);
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR1_EL1, 0);

    /* The shim will ERET to this address after syscall dispatch returns. */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ELR_EL1, entry_ipa);

    /* SP_EL0 points at the freshly built Linux initial stack. */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SP_EL0, sp_ipa);

    /* SPSR_EL1: EL0t, AArch64 */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SPSR_EL1, 0x0);

    /* Reset TPIDR_EL0 (thread-local storage base). The previous program's TLS
     * pointer must not leak into the new program because glibc's ld-linux uses
     * TLS very early (GL() macro accesses static TLS), and a stale TPIDR_EL0
     * causes it to read garbage for its internal state (link_map l_relocated
     * flags, scope lists, etc.), breaking relocation.
     */
    hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TPIDR_EL0, 0);

    /* Drop all register contents from the old image; X8 is set below as the
     * shim control code.
     */
    vcpu_zero_gprs(vcpu);

    /* Tell the shim that execve replaced the full guest register state. X8=2
     * means: flush TLB, discard the old syscall frame, and return without
     * restoring pre-exec registers. This bypasses the normal syscall epilogue,
     * which would otherwise overwrite X8 from cpu_tlbi_req.
     */
    hv_vcpu_set_reg(vcpu, HV_REG_X8, 2);
    tlbi_request_clear();

    exec_sync_vcpu_regs(vcpu);

    log_debug("execve: loaded %s, entry=0x%llx sp=0x%llx", path_host,
              (unsigned long long) entry_ipa, (unsigned long long) sp_ipa);

    exec_cleanup_inputs(argv_buf, envp_buf, path_host_buf, path_host_temp,
                        interp_host_buf, interp_host_temp);

    return SYSCALL_EXEC_HAPPENED;

too_many_regions:
    log_fatal(
        "execve failed after point of no return: "
        "too many memory regions (max %d)",
        MAX_REGIONS);
    exit(128);
}

#undef MAX_ARGS
#undef MAX_ENVS
#undef STR_BUF_SIZE
