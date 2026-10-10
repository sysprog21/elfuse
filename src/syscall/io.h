/*
 * Core I/O syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Read/write, ioctl, splice, sendfile, and copy_file_range operations.
 * Translates Linux aarch64 I/O syscalls into macOS equivalents, handling
 * terminal attribute translation and pipe splice emulation.
 *
 * Poll/select/epoll declarations are in syscall/poll.h. Special FD types
 * (eventfd, signalfd, timerfd) are in syscall/fd.h.
 */

#pragma once

#include <stdint.h>
#include <sys/uio.h>
#include "core/guest.h"
#include "syscall/internal.h" /* fd_block_state_t */

/* I/O syscall handlers. */

/* read/write and their positional variants. */
int64_t sys_write(guest_t *g, int fd, uint64_t buf_gva, uint64_t count);
int64_t sys_read(guest_t *g, int fd, uint64_t buf_gva, uint64_t count);
void urandom_fd_cleanup(int guest_fd, uint64_t generation);
void urandom_fd_reset_cache(int guest_fd);

/* Initialize the per-fd urandom cache locks. Must run before any guest thread
 * enters sys_read or sys_readv on /dev/urandom. Called from syscall_init
 * alongside the other subsystem init hooks.
 */
void io_init(void);

/* Wait until host_fd is ready for events (POLLIN and/or POLLOUT) or a
 * guest-visible signal/exit is pending.
 *
 * Returns 0 when ready, -LINUX_EINTR when interrupted, or a negative Linux
 * errno on poll failure. Shared by the read, write, recv, accept, connect, and
 * send paths so a guest thread parked in a blocking host call stays reachable
 * by hv_vcpus_exit + the wakeup pipe.
 */
int64_t io_wait_fd_or_interrupted(int host_fd, short events);

/* Same wait, bounded by a caller's deadline. timeout_ms < 0 is the untimed wait
 * above; 0 or more caps the whole wait, not each of its interrupt-recheck
 * slices, so a bounded caller cannot be stretched by them.
 *
 * Returns 0 when ready, 1 when the timeout expired first, -LINUX_EINTR when
 * interrupted, or a negative Linux errno on poll failure. Only the SO_RCVTIMEO
 * receive path needs the bound; everything else takes the untimed spelling.
 */
int64_t io_wait_fd_timed_or_interrupted(int host_fd,
                                        short events,
                                        int timeout_ms);

/* Consecutive EAGAINs from a transfer the wait called ready, before io_xfer
 * stops retrying at full speed and starts backing off.
 *
 * Sized to tell two things apart that look identical from here. Losing a race
 * to a sibling is normal and self-limiting: the wait blocks again until the fd
 * genuinely has something, so a contended pipe can lose several times in one
 * syscall and every loss still made progress somewhere. An fd whose readiness
 * the transfer never honours -- poll reporting POLLHUP or POLLERR that a
 * nonblocking transfer answers with EAGAIN -- never blocks in the wait at all
 * and reaches this in microseconds. High enough that contention almost never
 * pays for it, low enough that the pathological case cannot hold a core.
 */
#define IO_XFER_SPIN_LIMIT 16

/* Move iov through host_fd with the blocking semantics the guest asked for,
 * without parking this vCPU thread in a host call.
 *
 * A readiness poll reserves nothing. Between the poll and the transfer a
 * sibling thread, or a forked process sharing the open file description, can
 * take the bytes the poll promised, and the transfer then blocks where neither
 * hv_vcpus_exit nor the wakeup pipe reaches it; an execve teardown counts that
 * thread as a sibling that would not leave. So the wait is interruptible and
 * the transfer itself reports EAGAIN rather than blocking, and a steal only
 * sends the caller back to the wait. A write keeps going until every byte has
 * moved, which is what a blocking write(2) promises, and reports the partial
 * count when a signal arrives with bytes already gone.
 *
 * Which order the wait and the transfer run in is decided once, at the top,
 * from the pinned state:
 *
 *                                ┌────────┐
 *                                │ the fd │
 *                                └────────┘
 *             ┌─────────────────────┘ │ └────────────────┐
 *             │                       │                  │
 *             │                   ┌───┘                  │
 *     ┌───────▾──────┐   ┌────────▾───────┐   ┌──────────▾──────────┐
 *     │ cannot block │   │ elfuse owns it │   │ elfuse does not own │
 *     └──────────────┘   └────────────────┘   └─────────────────────┘
 *             │                   │                      └──┐
 *             │                   │                         │
 *           ┌─┘                   │                         │
 *   ┌───────▾──────┐   ┌──────────▾──────────┐   ┌──────────▾──────────┐
 *   │ one transfer │   │ transfer, then wait │   │ wait, then transfer │
 *   └──────────────┘   └─────────────────────┘   └─────────────────────┘
 *
 * That last branch is the whole of the residual parking window, and a caller
 * relying on the guarantee during exec teardown has to know which fds reach it:
 * inherited stdio, whose open file description belongs to the launching
 * process, and an SCM_RIGHTS arrival that was not already nonblocking.
 * Everything else elfuse owns the flag on, sockets included. io_xfer itself
 * says why the order differs per branch.
 *
 * events picks the direction: POLLIN reads, POLLOUT writes. iov is scratch the
 * caller owns, and a partial write rewrites it. Beyond the left branch above,
 * an fd the guest set nonblocking and a direction mismatch also come back in
 * one transfer, having never reached the wait.
 *
 * Returns 0 with *out set to the raw host result (errno live when it is -1), or
 * a negative Linux errno, in which case nothing moved and iov is untouched: the
 * wait was interrupted (EINTR), the fd is a pty master whose slaves are all
 * gone (EIO), or the iovec lengths do not sum (EINVAL). A caller that cannot
 * answer those itself has to hand the value back to the guest. The same
 * transfer, classified from the state pinned with the host fd rather than
 * looked up again.
 *
 * io_xfer resolves the slot itself, which is correct only while nothing can
 * reuse the fd number underneath it. A caller that already holds a host fd took
 * it from a slot that a sibling may since have closed and reopened as another
 * kind of object; classifying that new object and transferring on the old
 * descriptor is how a pinned pipe comes to be sent recv(MSG_DONTWAIT) and
 * answers ENOTSOCK, and how a pinned socket comes to take the plain blocking
 * read this file exists to avoid. host_fd_ref_open_state takes both together.
 */
int64_t io_xfer(int fd,
                int host_fd,
                short events,
                struct iovec *iov,
                int iovcnt,
                ssize_t *out,
                const fd_block_state_t *pinned);

/* pinned is required, not optional: it is dereferenced unconditionally. Making
 * it nullable would put this function one step from the failure that already
 * happened once here -- an out-param written before its NULL check let clang
 * prove the UB and compile a whole caller to a trap. Every caller pins and
 * classifies in one window, so there is no caller that would want NULL.
 */

/* Backoff bounds for io_retry_backoff. These replace a blocking host call that
 * returned the instant the resource freed, so the ceiling is the added latency
 * a guest pays after the holder releases: 2 ms costs at most 500 wakeups/s on a
 * thread that is otherwise asleep, and keeps the worst case an order of
 * magnitude below what the execve teardown budget (200 ms of pokes plus a 500
 * ms join) would tolerate. The floor is short because the common case is a lock
 * held for microseconds; io_retry_backoff yields once before sleeping at all,
 * which catches a holder that releases inside the same quantum.
 */
#define IO_RETRY_BACKOFF_START_US 50
#define IO_RETRY_BACKOFF_MAX_US 2000

/* One backoff step for a host call that has no interruptible form: semop,
 * flock, fcntl F_SETLKW, and a blocking FIFO open. None of them participates in
 * the wakeup pipe, and hv_vcpus_exit does not reach a thread outside
 * hv_vcpu_run, so a thread parked inside one is invisible to every teardown
 * wake. Callers loop over the non-blocking form of the operation and call this
 * between attempts instead.
 *
 * Returns 0 when the caller should retry, or -LINUX_EINTR when teardown needs
 * this thread out of the guest. *backoff_us must start at 0.
 */
int64_t io_retry_backoff(unsigned *backoff_us);

int64_t sys_pread64(guest_t *g,
                    int fd,
                    uint64_t buf_gva,
                    uint64_t count,
                    int64_t offset);
int64_t sys_pwrite64(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset);
int64_t sys_readv(guest_t *g, int fd, uint64_t iov_gva, int iovcnt);
int64_t sys_writev(guest_t *g, int fd, uint64_t iov_gva, int iovcnt);
int64_t sys_preadv(guest_t *g,
                   int fd,
                   uint64_t iov_gva,
                   int iovcnt,
                   int64_t offset);
int64_t sys_pwritev(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset);
int64_t sys_preadv2(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset,
                    int flags);
int64_t sys_pwritev2(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     int iovcnt,
                     int64_t offset,
                     int flags);
int64_t sys_process_vm_readv(guest_t *g,
                             int64_t pid,
                             uint64_t local_iov_gva,
                             uint64_t local_iovcnt,
                             uint64_t remote_iov_gva,
                             uint64_t remote_iovcnt,
                             uint64_t flags);
int64_t sys_process_vm_writev(guest_t *g,
                              int64_t pid,
                              uint64_t local_iov_gva,
                              uint64_t local_iovcnt,
                              uint64_t remote_iov_gva,
                              uint64_t remote_iovcnt,
                              uint64_t flags);

/* terminal I/O */
int64_t sys_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg);

/* file space/copy */
int64_t sys_fallocate(int fd, int mode, int64_t offset, int64_t len);
int64_t sys_sendfile(guest_t *g,
                     int out_fd,
                     int in_fd,
                     uint64_t offset_gva,
                     uint64_t count);
int64_t sys_copy_file_range(guest_t *g,
                            int fd_in,
                            uint64_t off_in_gva,
                            int fd_out,
                            uint64_t off_out_gva,
                            uint64_t len,
                            unsigned int flags);

/* splice/tee */
int64_t sys_splice(guest_t *g,
                   int fd_in,
                   uint64_t off_in_gva,
                   int fd_out,
                   uint64_t off_out_gva,
                   size_t len,
                   unsigned int flags);
int64_t sys_vmsplice(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     unsigned long nr_segs,
                     unsigned int flags);
int64_t sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags);
