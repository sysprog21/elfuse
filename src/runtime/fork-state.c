/* Fork IPC state serialization
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"

#include "runtime/fork-state.h"
#include "runtime/procemu.h"

#include "debug/log.h"
#include "syscall/abi.h"
#include "syscall/internal.h"
#include "syscall/io.h"
#include "syscall/mem.h"
#include "syscall/proc.h"

int fork_ipc_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            /* Defensive: an unexpected zero return on a blocking socket would
             * otherwise spin forever, since p and len stay at the same offset.
             * Treat it as an IO failure so the parent and child both bail
             * rather than wedge.
             */
            errno = EIO;
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

int fork_ipc_read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= n;
    }
    return 0;
}

/* macOS rejects overly large SCM_RIGHTS payloads with EINVAL. Keep each control
 * message comfortably below that limit and stream large fd sets in multiple
 * chunks.
 */
#define FORK_IPC_FD_CHUNK 32

int fork_ipc_send_fds(int sock, const int *fds, int count)
{
    if (count <= 0)
        return 0;

    int sent = 0;
    while (sent < count) {
        int chunk = count - sent;
        if (chunk > FORK_IPC_FD_CHUNK)
            chunk = FORK_IPC_FD_CHUNK;

        char dummy = 'F';
        struct iovec iov = {.iov_base = &dummy, .iov_len = 1};
        size_t cmsg_size = CMSG_SPACE((size_t) chunk * sizeof(int));
        uint8_t *cmsg_buf = calloc(1, cmsg_size);
        if (!cmsg_buf)
            return -1;

        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = cmsg_size;

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN((size_t) chunk * sizeof(int));
        memcpy(CMSG_DATA(cmsg), fds + sent, (size_t) chunk * sizeof(int));

        ssize_t ret = sendmsg(sock, &msg, 0);
        free(cmsg_buf);
        if (ret < 0)
            return -1;
        sent += chunk;
    }
    return 0;
}

int fork_ipc_recv_fds(int sock, int *fds, int max_count, int *out_count)
{
    *out_count = 0;
    while (*out_count < max_count) {
        int chunk_max = max_count - *out_count;
        if (chunk_max > FORK_IPC_FD_CHUNK)
            chunk_max = FORK_IPC_FD_CHUNK;

        char dummy;
        struct iovec iov = {.iov_base = &dummy, .iov_len = 1};
        size_t cmsg_size = CMSG_SPACE((size_t) chunk_max * sizeof(int));
        uint8_t *cmsg_buf = calloc(1, cmsg_size);
        if (!cmsg_buf)
            return -1;

        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf;
        msg.msg_controllen = cmsg_size;

        ssize_t ret = recvmsg(sock, &msg, 0);
        if (ret < 0) {
            free(cmsg_buf);
            return -1;
        }
        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
            cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len < CMSG_LEN(0) ||
            (msg.msg_flags & MSG_CTRUNC)) {
            free(cmsg_buf);
            return -1;
        }

        int n = (int) ((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        if (n <= 0 || n > chunk_max) {
            free(cmsg_buf);
            return -1;
        }

        memcpy(fds + *out_count, CMSG_DATA(cmsg), (size_t) n * sizeof(int));
        *out_count += n;
        free(cmsg_buf);
    }
    return 0;
}

int fork_ipc_send_memory_regions(int ipc_sock, const guest_t *g, bool use_shm)
{
    if (use_shm) {
        uint32_t zero_regions = 0;
        return fork_ipc_write_all(ipc_sock, &zero_regions,
                                  sizeof(zero_regions));
    }

#define MAX_USED_REGIONS 16
    used_region_t used[MAX_USED_REGIONS];
    unsigned int shim_sz = proc_get_shim_size();
    pthread_mutex_lock(&mmap_lock);
    int nregions = guest_get_used_regions(g, shim_sz, used, MAX_USED_REGIONS);
    pthread_mutex_unlock(&mmap_lock);

    uint32_t num_regions = (uint32_t) nregions;
    if (fork_ipc_write_all(ipc_sock, &num_regions, sizeof(num_regions)) < 0)
        return -1;

    for (int i = 0; i < nregions; i++) {
        ipc_region_header_t rhdr = {
            .offset = used[i].offset,
            .size = used[i].size,
        };
        if (fork_ipc_write_all(ipc_sock, &rhdr, sizeof(rhdr)) < 0)
            return -1;

        uint8_t *src = (uint8_t *) g->host_base + used[i].offset;
        size_t remaining = used[i].size;
        while (remaining > 0) {
            size_t chunk = remaining > ((size_t) 1024 * 1024)
                               ? ((size_t) 1024 * 1024)
                               : remaining;
            if (fork_ipc_write_all(ipc_sock, src, chunk) < 0)
                return -1;
            src += chunk;
            remaining -= chunk;
        }
    }

    return 0;
}

int fork_ipc_recv_memory_regions(int ipc_fd, guest_t *g)
{
    uint32_t num_regions;
    if (fork_ipc_read_all(ipc_fd, &num_regions, sizeof(num_regions)) < 0) {
        log_error("fork-child: failed to read region count");
        return -1;
    }

    if (num_regions > 0)
        log_debug("fork-child: receiving %u memory regions", num_regions);

    for (uint32_t i = 0; i < num_regions; i++) {
        ipc_region_header_t rhdr;
        if (fork_ipc_read_all(ipc_fd, &rhdr, sizeof(rhdr)) < 0) {
            log_error("fork-child: failed to read region header");
            return -1;
        }

        if (rhdr.offset > g->guest_size ||
            rhdr.size > g->guest_size - rhdr.offset) {
            log_error("fork-child: region out of bounds");
            return -1;
        }

        uint8_t *dst = (uint8_t *) g->host_base + rhdr.offset;
        size_t remaining = rhdr.size;
        while (remaining > 0) {
            size_t chunk = remaining > ((size_t) 1024 * 1024)
                               ? ((size_t) 1024 * 1024)
                               : remaining;
            if (fork_ipc_read_all(ipc_fd, dst, chunk) < 0) {
                log_error("fork-child: failed to read region data");
                return -1;
            }
            dst += chunk;
            remaining -= chunk;
        }

        log_debug("fork-child: region %u: offset=0x%llx size=0x%llx", i,
                  (unsigned long long) rhdr.offset,
                  (unsigned long long) rhdr.size);
    }

    return 0;
}

int fork_ipc_send_fd_table(int ipc_sock)
{
    ipc_fd_entry_t fd_entries[FD_TABLE_SIZE];
    int host_fds_to_send[FD_TABLE_SIZE];
    bool host_fds_duped[FD_TABLE_SIZE];
    uint32_t num_fds = 0;

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].type == FD_CLOSED)
            continue;

        /* Synthetic-fd types are filtered here; see fd_type_is_synthetic in
         * syscall/internal.h for the rationale (kqueue cannot cross SCM_RIGHTS
         * on macOS, per-class side tables are not serialized). The child sees
         * these slots as FD_CLOSED and recreates them via the appropriate
         * syscall.
         */
        int t = fd_table[i].type;
        if (fd_type_is_synthetic(t))
            continue;

        int host_fd;
        bool was_duped = false;
        if (t != FD_STDIO) {
            int duped = dup(fd_table[i].host_fd);
            if (duped < 0)
                continue;
            host_fd = duped;
            was_duped = true;
        } else {
            host_fd = fd_table[i].host_fd;
        }

        fd_entries[num_fds].guest_fd = i;
        fd_entries[num_fds].type = fd_table[i].type;
        fd_entries[num_fds].linux_flags = fd_table[i].linux_flags;
        fd_entries[num_fds].seals = fd_table[i].seals;
        memcpy(fd_entries[num_fds].proc_path, fd_table[i].proc_path,
               sizeof(fd_entries[num_fds].proc_path));
        host_fds_to_send[num_fds] = host_fd;
        host_fds_duped[num_fds] = was_duped;
        num_fds++;
    }
    pthread_mutex_unlock(&fd_lock);

    if (fork_ipc_write_all(ipc_sock, &num_fds, sizeof(num_fds)) < 0)
        goto fail;

    if (num_fds > 0) {
        if (fork_ipc_write_all(ipc_sock, fd_entries,
                               num_fds * sizeof(ipc_fd_entry_t)) < 0)
            goto fail;
        if (fork_ipc_send_fds(ipc_sock, host_fds_to_send, (int) num_fds) < 0) {
            log_error("clone: failed to send fds via SCM_RIGHTS");
            goto fail;
        }
    }

    for (uint32_t fi = 0; fi < num_fds; fi++)
        if (host_fds_duped[fi])
            close(host_fds_to_send[fi]);
    return 0;

fail:
    for (uint32_t fi = 0; fi < num_fds; fi++)
        if (host_fds_duped[fi])
            close(host_fds_to_send[fi]);
    return -1;
}

int fork_ipc_recv_fd_table(int ipc_fd, guest_t *g)
{
    (void) g;

    uint32_t num_fds;
    if (fork_ipc_read_all(ipc_fd, &num_fds, sizeof(num_fds)) < 0) {
        log_error("fork-child: failed to read fd count");
        return -1;
    }

    syscall_init();

    if (num_fds > FD_TABLE_SIZE) {
        log_error("fork-child: num_fds %u exceeds FD_TABLE_SIZE", num_fds);
        return -1;
    }

    if (num_fds == 0) {
        for (int fd = 0; fd < 3; fd++)
            fd_mark_closed(fd);
        return 0;
    }

    ipc_fd_entry_t *fd_entries = calloc(num_fds, sizeof(ipc_fd_entry_t));
    if (!fd_entries)
        return -1;

    if (fork_ipc_read_all(ipc_fd, fd_entries,
                          num_fds * sizeof(ipc_fd_entry_t)) < 0) {
        free(fd_entries);
        return -1;
    }

    bool low_fd_present[3] = {false, false, false};
    for (uint32_t i = 0; i < num_fds; i++) {
        int gfd = fd_entries[i].guest_fd;
        if (RANGE_CHECK(gfd, 0, 3) && !fd_type_is_synthetic(fd_entries[i].type))
            low_fd_present[gfd] = true;
    }
    for (int fd = 0; fd < 3; fd++)
        if (!low_fd_present[fd])
            fd_mark_closed(fd);

    int *host_fds = calloc(num_fds, sizeof(int));
    if (!host_fds) {
        free(fd_entries);
        return -1;
    }

    int received_count = 0;
    if (fork_ipc_recv_fds(ipc_fd, host_fds, (int) num_fds, &received_count) <
        0) {
        log_error("fork-child: failed to receive fds");
        free(host_fds);
        free(fd_entries);
        return -1;
    }

    if (received_count != (int) num_fds) {
        log_error("fork-child: fd count mismatch: received %d, expected %u",
                  received_count, num_fds);
        for (int fi = 0; fi < received_count; fi++)
            close(host_fds[fi]);
        free(host_fds);
        free(fd_entries);
        return -1;
    }

    for (uint32_t i = 0; i < num_fds; i++) {
        int gfd = fd_entries[i].guest_fd;
        if (!RANGE_CHECK(gfd, 0, FD_TABLE_SIZE))
            continue;

        if (fd_entries[i].type == FD_STDIO) {
            close(host_fds[i]);
            fd_table[gfd].linux_flags = fd_entries[i].linux_flags;
            fd_refresh_urandom_bitmap(gfd);
            memcpy(fd_table[gfd].proc_path, fd_entries[i].proc_path,
                   sizeof(fd_table[gfd].proc_path));
            fd_table[gfd].seals = fd_entries[i].seals;
        } else if (fd_type_is_synthetic(fd_entries[i].type)) {
            /* Defense in depth: the parent's fork_ipc_send_fd_table already
             * filters synthetic types out of the SCM_RIGHTS payload (see
             * fd_type_is_synthetic in syscall/internal.h). If anything still
             * arrives here, drop the inherited host fd and leave the slot
             * FD_CLOSED so the child must recreate the fd via the appropriate
             * syscall.
             */
            log_debug(
                "fork-child: dropping unexpected synthetic-type fd %d (type "
                "%d)",
                gfd, fd_entries[i].type);
            close(host_fds[i]);
            fd_mark_closed(gfd);
            continue;
        } else {
            void (*cleanup)(int) = fd_cleanup_for_type(fd_entries[i].type);
            fd_alloc_at(gfd, fd_entries[i].type, host_fds[i], cleanup);
            fd_table[gfd].linux_flags = fd_entries[i].linux_flags;
            fd_refresh_urandom_bitmap(gfd);
            memcpy(fd_table[gfd].proc_path, fd_entries[i].proc_path,
                   sizeof(fd_table[gfd].proc_path));
            fd_table[gfd].seals = fd_entries[i].seals;
            if (fd_entries[i].type == FD_URANDOM)
                urandom_fd_reset_cache(gfd);

            if (fd_entries[i].type != FD_DIR)
                continue;
            int dir_fd = dup(host_fds[i]);
            if (dir_fd < 0) {
                log_error("fork-child: dup failed for DIR gfd %d: %s", gfd,
                          strerror(errno));
                continue;
            }
            DIR *dir = fdopendir(dir_fd);
            if (!dir) {
                close(dir_fd);
                log_error("fork-child: fdopendir failed for gfd %d", gfd);
                continue;
            }
            fd_table[gfd].dir = dir;
        }
    }

    free(host_fds);
    free(fd_entries);
    return 0;
}

/* Wire payload for one pty keepalive. The slave fd travels separately via
 * SCM_RIGHTS; the parent's master_host_fd is intentionally omitted because the
 * child's number will differ. The child re-derives it from fd_table[gfd].
 */
typedef struct {
    int32_t guest_fd;
    uint32_t linux_pts_num;
    char slave_path[64];
} ipc_pty_keepalive_t;

int fork_ipc_send_pty_keepalives(int ipc_sock)
{
    /* PTY_KEEPALIVE_MAX upper bound on entries; allocate to that. */
    proc_pty_ipc_entry_t snapshot[256];
    int snapshot_slave_fds[256];
    int num_snap = proc_pty_snapshot_keepalive(snapshot, snapshot_slave_fds,
                                               ARRAY_SIZE(snapshot));

    /* Match each keepalive's master_host_fd against a live fd_table entry to
     * recover the guest_fd, which is the stable identifier across fork.
     */
    ipc_pty_keepalive_t payload[256];
    int payload_slave_fds[256];
    uint32_t num_send = 0;

    pthread_mutex_lock(&fd_lock);
    for (int i = 0; i < num_snap; i++) {
        int matched_gfd = -1;
        for (int gfd = 0; gfd < FD_TABLE_SIZE; gfd++) {
            if (fd_table[gfd].type == FD_CLOSED)
                continue;
            if (fd_table[gfd].host_fd != snapshot[i].master_host_fd)
                continue;
            if (fd_type_is_synthetic(fd_table[gfd].type))
                continue;
            matched_gfd = gfd;
            break;
        }

        if (matched_gfd < 0) {
            /* Master was closed between snapshot and lookup, or never tracked
             * in the guest fd table (defensive). Drop the duped slave; nothing
             * else holds it.
             */
            close(snapshot_slave_fds[i]);
            continue;
        }

        payload[num_send].guest_fd = matched_gfd;
        payload[num_send].linux_pts_num = snapshot[i].linux_pts_num;
        _Static_assert(
            sizeof(payload[0].slave_path) == sizeof(snapshot[0].slave_path),
            "keepalive slave_path size must match payload");
        memcpy(payload[num_send].slave_path, snapshot[i].slave_path,
               sizeof(payload[0].slave_path));
        payload_slave_fds[num_send] = snapshot_slave_fds[i];
        num_send++;
    }
    pthread_mutex_unlock(&fd_lock);

    int rc = 0;
    if (fork_ipc_write_all(ipc_sock, &num_send, sizeof(num_send)) < 0) {
        rc = -1;
    } else if (num_send > 0) {
        if (fork_ipc_write_all(ipc_sock, payload,
                               num_send * sizeof(payload[0])) < 0) {
            rc = -1;
        } else if (fork_ipc_send_fds(ipc_sock, payload_slave_fds,
                                     (int) num_send) < 0) {
            log_error("clone: failed to send pty keepalive fds");
            rc = -1;
        }
    }
    for (uint32_t i = 0; i < num_send; i++)
        close(payload_slave_fds[i]);
    return rc;
}

int fork_ipc_recv_pty_keepalives(int ipc_fd)
{
    uint32_t num;
    if (fork_ipc_read_all(ipc_fd, &num, sizeof(num)) < 0) {
        log_error("fork-child: failed to read pty keepalive count");
        return -1;
    }
    if (num == 0)
        return 0;
    if (num > FD_TABLE_SIZE) {
        log_error("fork-child: pty keepalive count %u exceeds FD_TABLE_SIZE",
                  num);
        return -1;
    }

    ipc_pty_keepalive_t *payload = calloc(num, sizeof(*payload));
    if (!payload)
        return -1;

    if (fork_ipc_read_all(ipc_fd, payload, num * sizeof(*payload)) < 0) {
        free(payload);
        return -1;
    }

    int *slave_fds = calloc(num, sizeof(int));
    if (!slave_fds) {
        free(payload);
        return -1;
    }
    int got = 0;
    if (fork_ipc_recv_fds(ipc_fd, slave_fds, (int) num, &got) < 0 ||
        got != (int) num) {
        log_error("fork-child: pty keepalive recv mismatch: got %d expected %u",
                  got, num);
        for (int i = 0; i < got; i++)
            close(slave_fds[i]);
        free(slave_fds);
        free(payload);
        return -1;
    }

    for (uint32_t i = 0; i < num; i++) {
        int gfd = payload[i].guest_fd;
        int child_master = -1;
        if (RANGE_CHECK(gfd, 0, FD_TABLE_SIZE)) {
            pthread_mutex_lock(&fd_lock);
            if (fd_table[gfd].type != FD_CLOSED)
                child_master = fd_table[gfd].host_fd;
            pthread_mutex_unlock(&fd_lock);
        }
        if (child_master < 0) {
            /* Master fd did not survive the fd_table batch (synthetic-type
             * filter, or the slot was rejected). Drop the keepalive cleanly.
             */
            close(slave_fds[i]);
            continue;
        }

        /* Force-NUL the path before passing it on so a malformed sender cannot
         * trick the child into reading past the buffer.
         */
        payload[i].slave_path[sizeof(payload[i].slave_path) - 1] = '\0';
        proc_pty_restore_keepalive(child_master, slave_fds[i],
                                   payload[i].linux_pts_num,
                                   payload[i].slave_path);
    }

    free(slave_fds);
    free(payload);
    return 0;
}

static int fork_ipc_send_backing_fds(int ipc_sock,
                                     const guest_region_t *regions_snapshot,
                                     uint32_t num_guest_regions)
{
    int backing_fds[GUEST_MAX_REGIONS];
    uint32_t nbacking = 0;

    for (uint32_t i = 0; i < num_guest_regions; i++) {
        if (regions_snapshot[i].backing_fd >= 0) {
            if (fcntl(regions_snapshot[i].backing_fd, F_GETFD) < 0) {
                log_error("clone: region %u carries stale backing_fd=%d: %s", i,
                          regions_snapshot[i].backing_fd, strerror(errno));
                return -1;
            }
            backing_fds[nbacking++] = regions_snapshot[i].backing_fd;
        }
    }

    if (fork_ipc_write_all(ipc_sock, &nbacking, sizeof(nbacking)) < 0)
        return -1;
    if (nbacking == 0)
        return 0;

    log_debug("clone: sending %u backing fds for %u regions", nbacking,
              num_guest_regions);
    if (fork_ipc_send_fds(ipc_sock, backing_fds, (int) nbacking) < 0) {
        log_error("clone: send backing fds failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int fork_ipc_send_process_state(int ipc_sock,
                                const guest_region_t *regions_snapshot,
                                uint32_t num_guest_regions,
                                bool regions_tracker_stale_snapshot,
                                const guest_region_t *preannounced_snapshot,
                                uint32_t num_preannounced)
{
    char cwd[LINUX_PATH_MAX] = {0};
    getcwd(cwd, sizeof(cwd));
    mode_t cur_umask = umask(0);
    umask(cur_umask);
    uint32_t umask_val = (uint32_t) cur_umask;
    if (fork_ipc_write_all(ipc_sock, cwd, sizeof(cwd)) < 0 ||
        fork_ipc_write_all(ipc_sock, &umask_val, sizeof(umask_val)) < 0)
        return -1;

    char sysroot_ipc[LINUX_PATH_MAX] = {0};
    (void) proc_sysroot_snapshot(sysroot_ipc, sizeof(sysroot_ipc));
    uint8_t sysroot_casefold_ipc = proc_sysroot_casefold_enabled() ? 1 : 0;
    if (fork_ipc_write_all(ipc_sock, sysroot_ipc, sizeof(sysroot_ipc)) < 0 ||
        fork_ipc_write_all(ipc_sock, &sysroot_casefold_ipc,
                           sizeof(sysroot_casefold_ipc)) < 0)
        return -1;

    char elf_path_ipc[LINUX_PATH_MAX] = {0};
    (void) proc_elf_path_snapshot(elf_path_ipc, sizeof(elf_path_ipc));
    char elfuse_path_ipc[LINUX_PATH_MAX] = {0};
    const char *hp = proc_get_elfuse_path();
    if (hp)
        str_copy_trunc(elfuse_path_ipc, hp, sizeof(elfuse_path_ipc));
    if (fork_ipc_write_all(ipc_sock, elf_path_ipc, sizeof(elf_path_ipc)) < 0 ||
        fork_ipc_write_all(ipc_sock, elfuse_path_ipc, sizeof(elfuse_path_ipc)) <
            0)
        return -1;

    size_t cmdline_len = 0;
    const char *cmdline = proc_get_cmdline(&cmdline_len);
    uint32_t cmdline_len_u32 = (uint32_t) cmdline_len;
    if (fork_ipc_write_all(ipc_sock, &cmdline_len_u32,
                           sizeof(cmdline_len_u32)) < 0)
        return -1;
    if (cmdline_len_u32 > 0 && cmdline &&
        fork_ipc_write_all(ipc_sock, cmdline, cmdline_len_u32) < 0)
        return -1;

    uint8_t regions_tracker_stale =
        regions_tracker_stale_snapshot ? UINT8_C(1) : UINT8_C(0);
    if (fork_ipc_write_all(ipc_sock, &num_guest_regions,
                           sizeof(num_guest_regions)) < 0 ||
        fork_ipc_write_all(ipc_sock, &regions_tracker_stale,
                           sizeof(regions_tracker_stale)) < 0)
        return -1;
    if (num_guest_regions > 0 &&
        fork_ipc_write_all(ipc_sock, regions_snapshot,
                           num_guest_regions * sizeof(guest_region_t)) < 0)
        return -1;

    if (fork_ipc_write_all(ipc_sock, &num_preannounced,
                           sizeof(num_preannounced)) < 0)
        return -1;
    if (num_preannounced > 0 &&
        fork_ipc_write_all(ipc_sock, preannounced_snapshot,
                           num_preannounced * sizeof(guest_region_t)) < 0)
        return -1;

    if (fork_ipc_send_backing_fds(ipc_sock, regions_snapshot,
                                  num_guest_regions) < 0)
        return -1;

    const signal_state_t *sig = signal_get_state();
    if (fork_ipc_write_all(ipc_sock, sig, sizeof(signal_state_t)) < 0)
        return -1;

    const unsigned char *shim_ptr = proc_get_shim_blob();
    uint32_t shim_size_u32 = proc_get_shim_size();
    if (fork_ipc_write_all(ipc_sock, &shim_size_u32, sizeof(shim_size_u32)) < 0)
        return -1;
    if (shim_size_u32 > 0 && shim_ptr &&
        fork_ipc_write_all(ipc_sock, shim_ptr, shim_size_u32) < 0)
        return -1;

    uint32_t sentinel = IPC_MAGIC_SENTINEL;
    return fork_ipc_write_all(ipc_sock, &sentinel, sizeof(sentinel));
}

static int fork_ipc_drain_bytes(int ipc_fd, uint32_t len)
{
    char drain[256];
    uint32_t remaining = len;
    while (remaining > 0) {
        uint32_t chunk = remaining < sizeof(drain) ? remaining : sizeof(drain);
        if (fork_ipc_read_all(ipc_fd, drain, chunk) < 0)
            return -1;
        remaining -= chunk;
    }
    return 0;
}

static int fork_ipc_recv_backing_fds(int ipc_fd,
                                     guest_t *g,
                                     const bool *parent_had_fd)
{
    uint32_t nbacking;
    if (fork_ipc_read_all(ipc_fd, &nbacking, sizeof(nbacking)) < 0) {
        log_error("fork-child: failed to read backing fd count");
        return -1;
    }
    if (nbacking == 0 || nbacking > GUEST_MAX_REGIONS)
        return 0;

    int *region_fds = calloc(nbacking, sizeof(int));
    if (!region_fds)
        return -1;
    int received_count = 0;
    if (fork_ipc_recv_fds(ipc_fd, region_fds, (int) nbacking, &received_count) <
        0) {
        log_error("fork-child: failed to receive backing fds");
        free(region_fds);
        return -1;
    }
    uint32_t nreceived = (uint32_t) received_count;
    uint32_t fi = 0;

    /* Sender (fork_ipc_send_backing_fds) iterates regions and sends one fd per
     * region with backing_fd >= 0. The receiver must iterate in the same order
     * over regions that had backing_fd in the parent. parent_had_fd[i] is
     * captured by the caller before backing_fd is cleared.
     *
     * The original filter (!MAP_ANONYMOUS && offset != -1) matched extra
     * regions like the shim and ELF text, so the first received fd was
     * misassigned and the actual file-backed region was left without
     * backing_fd.
     */
    for (int i = 0; i < g->nregions && fi < nreceived; i++) {
        if (parent_had_fd && parent_had_fd[i])
            g->regions[i].backing_fd = region_fds[fi++];
    }

    /* Close any received fds that did not get assigned: avoids leaking host fds
     * into the child's process table when a mismatch occurs.
     */
    while (fi < nreceived)
        close(region_fds[fi++]);

    if (nreceived != nbacking) {
        log_error("fork-child: expected %u backing fds but received %u",
                  nbacking, nreceived);
        free(region_fds);
        return -1;
    }
    free(region_fds);
    return 0;
}

int fork_ipc_recv_process_state(int ipc_fd, guest_t *g, signal_state_t *sig)
{
    char cwd[LINUX_PATH_MAX];
    uint32_t umask_val;
    if (fork_ipc_read_all(ipc_fd, cwd, sizeof(cwd)) < 0 ||
        fork_ipc_read_all(ipc_fd, &umask_val, sizeof(umask_val)) < 0) {
        log_error("fork-child: failed to read process info");
        return -1;
    }
    if (cwd[0] != '\0')
        chdir(cwd);
    umask((mode_t) umask_val);

    char sysroot_ipc[LINUX_PATH_MAX];
    if (fork_ipc_read_all(ipc_fd, sysroot_ipc, sizeof(sysroot_ipc)) < 0) {
        log_error("fork-child: failed to read sysroot");
        return -1;
    }
    if (sysroot_ipc[0] != '\0')
        proc_set_sysroot(sysroot_ipc);

    uint8_t sysroot_casefold_ipc = 0;
    if (fork_ipc_read_all(ipc_fd, &sysroot_casefold_ipc,
                          sizeof(sysroot_casefold_ipc)) < 0) {
        log_error("fork-child: failed to read sysroot casefold");
        return -1;
    }
    proc_set_sysroot_casefold(sysroot_casefold_ipc != 0);

    char elf_path_ipc[LINUX_PATH_MAX];
    if (fork_ipc_read_all(ipc_fd, elf_path_ipc, sizeof(elf_path_ipc)) < 0) {
        log_error("fork-child: failed to read elf path");
        return -1;
    }
    if (elf_path_ipc[0] != '\0')
        proc_set_elf_path(elf_path_ipc);

    char elfuse_path_ipc[LINUX_PATH_MAX];
    if (fork_ipc_read_all(ipc_fd, elfuse_path_ipc, sizeof(elfuse_path_ipc)) <
        0) {
        log_error("fork-child: failed to read elfuse path");
        return -1;
    }
    if (elfuse_path_ipc[0] != '\0')
        proc_set_elfuse_path(elfuse_path_ipc);

    uint32_t cmdline_len_u32;
    if (fork_ipc_read_all(ipc_fd, &cmdline_len_u32, sizeof(cmdline_len_u32)) <
        0) {
        log_error("fork-child: failed to read cmdline len");
        return -1;
    }
    if (cmdline_len_u32 > 0) {
        char *cmdline_buf = (cmdline_len_u32 <= LINUX_PATH_MAX * 4)
                                ? malloc(cmdline_len_u32)
                                : NULL;
        if (cmdline_buf) {
            if (fork_ipc_read_all(ipc_fd, cmdline_buf, cmdline_len_u32) < 0) {
                free(cmdline_buf);
                log_error("fork-child: failed to read cmdline");
                return -1;
            }
            proc_set_cmdline_raw(cmdline_buf, cmdline_len_u32);
            free(cmdline_buf);
        } else {
            if (cmdline_len_u32 > LINUX_PATH_MAX * 4)
                log_warn("fork-child: cmdline too large (%u), skipping",
                         cmdline_len_u32);
            else
                log_error("fork-child: cmdline malloc failed");
            if (fork_ipc_drain_bytes(ipc_fd, cmdline_len_u32) < 0)
                return -1;
        }
    }

    uint32_t num_guest_regions;
    if (fork_ipc_read_all(ipc_fd, &num_guest_regions,
                          sizeof(num_guest_regions)) < 0) {
        log_error("fork-child: failed to read region count");
        return -1;
    }

    uint8_t regions_tracker_stale = 0;
    if (fork_ipc_read_all(ipc_fd, &regions_tracker_stale,
                          sizeof(regions_tracker_stale)) < 0) {
        log_error("fork-child: failed to read region tracker state");
        return -1;
    }

    uint32_t recv_regions = num_guest_regions;
    if (recv_regions > GUEST_MAX_REGIONS)
        recv_regions = GUEST_MAX_REGIONS;
    if (recv_regions > 0 &&
        fork_ipc_read_all(ipc_fd, g->regions,
                          recv_regions * sizeof(guest_region_t)) < 0) {
        log_error("fork-child: failed to read regions");
        return -1;
    }

    /* Drain any excess records the parent serialized beyond the local cap.
     * Without this drain, the next read (num_preannounced) consumes stale
     * region bytes and desynchronizes the rest of the IPC payload. Mirrors the
     * preannounced-region drain below.
     */
    if (num_guest_regions > recv_regions &&
        fork_ipc_drain_bytes(ipc_fd, (num_guest_regions - recv_regions) *
                                         sizeof(guest_region_t)) < 0)
        return -1;

    g->nregions = (int) recv_regions;
    g->regions_tracker_stale =
        (regions_tracker_stale != 0) || (num_guest_regions > recv_regions);

    uint32_t num_preannounced = 0;
    if (fork_ipc_read_all(ipc_fd, &num_preannounced, sizeof(num_preannounced)) <
        0) {
        log_error("fork-child: failed to read preannounced count");
        return -1;
    }
    uint32_t recv_preannounced = num_preannounced;
    if (recv_preannounced > GUEST_MAX_PREANNOUNCED)
        recv_preannounced = GUEST_MAX_PREANNOUNCED;
    if (recv_preannounced > 0 &&
        fork_ipc_read_all(ipc_fd, g->preannounced,
                          recv_preannounced * sizeof(guest_region_t)) < 0) {
        log_error("fork-child: failed to read preannounced regions");
        return -1;
    }
    if (num_preannounced > recv_preannounced &&
        fork_ipc_drain_bytes(ipc_fd, (num_preannounced - recv_preannounced) *
                                         sizeof(guest_region_t)) < 0)
        return -1;
    g->npreannounced = (int) recv_preannounced;

    /* Capture parent state before clearing the inherited overlay/backing fd
     * fields. parent_had_fd lets recv_backing_fds iterate in the same order the
     * sender used (regions with backing_fd >= 0); the parent_ovl_* arrays let
     * mmap_fork_restore_overlays know which regions to re-install, with what
     * overlay span. Heap-allocated to avoid pushing hundreds of KiB onto the
     * recv stack frame.
     */
    bool *parent_had_fd = NULL;
    bool *parent_active = NULL;
    uint64_t *parent_ovl_start = NULL;
    uint64_t *parent_ovl_end = NULL;
    if (g->nregions > 0) {
        parent_had_fd = calloc((size_t) g->nregions, sizeof(*parent_had_fd));
        parent_active = calloc((size_t) g->nregions, sizeof(*parent_active));
        parent_ovl_start =
            calloc((size_t) g->nregions, sizeof(*parent_ovl_start));
        parent_ovl_end = calloc((size_t) g->nregions, sizeof(*parent_ovl_end));
        if (!parent_had_fd || !parent_active || !parent_ovl_start ||
            !parent_ovl_end) {
            log_error("fork-child: parent overlay buffer alloc failed");
            free(parent_had_fd);
            free(parent_active);
            free(parent_ovl_start);
            free(parent_ovl_end);
            return -1;
        }
        for (int i = 0; i < g->nregions; i++) {
            parent_had_fd[i] = (g->regions[i].backing_fd >= 0);
            parent_active[i] = g->regions[i].overlay_active;
            parent_ovl_start[i] = g->regions[i].overlay_start;
            parent_ovl_end[i] = g->regions[i].overlay_end;
        }
    }

    for (int i = 0; i < g->nregions; i++) {
        g->regions[i].backing_fd = -1;
        /* Drop inherited overlay metadata; the host MAP_FIXED|MAP_SHARED
         * mapping does not exist yet in the child. Re-establishment runs after
         * fork_ipc_recv_backing_fds populates backing_fd from the
         * parent-supplied SCM_RIGHTS bundle.
         */
        g->regions[i].overlay_active = false;
        g->regions[i].overlay_start = 0;
        g->regions[i].overlay_end = 0;
    }

    if (fork_ipc_recv_backing_fds(ipc_fd, g, parent_had_fd) < 0) {
        free(parent_had_fd);
        free(parent_active);
        free(parent_ovl_start);
        free(parent_ovl_end);
        return -1;
    }

    /* Re-install MAP_SHARED overlays for every region the parent had as
     * overlay_active and that now carries a backing fd. Failures here fall back
     * to snapshot semantics for the affected region; the child still boots and
     * can run.
     */
    if (g->nregions > 0)
        (void) mmap_fork_restore_overlays(g, parent_active, parent_ovl_start,
                                          parent_ovl_end);
    free(parent_had_fd);
    free(parent_active);
    free(parent_ovl_start);
    free(parent_ovl_end);

    if (fork_ipc_read_all(ipc_fd, sig, sizeof(*sig)) < 0) {
        log_error("fork-child: failed to read signal state");
        return -1;
    }

    uint32_t shim_size;
    if (fork_ipc_read_all(ipc_fd, &shim_size, sizeof(shim_size)) < 0) {
        log_error("fork-child: failed to read shim size");
        return -1;
    }
    if (shim_size > 0) {
        unsigned char *shim = malloc(shim_size);
        if (!shim) {
            log_error("fork-child: shim alloc failed");
            return -1;
        }
        if (fork_ipc_read_all(ipc_fd, shim, shim_size) < 0) {
            log_error("fork-child: failed to read shim blob");
            free(shim);
            return -1;
        }
        proc_set_shim_owned(shim, shim_size);
    }

    uint32_t sentinel;
    if (fork_ipc_read_all(ipc_fd, &sentinel, sizeof(sentinel)) < 0 ||
        sentinel != IPC_MAGIC_SENTINEL) {
        log_error("fork-child: bad sentinel");
        return -1;
    }

    return 0;
}
