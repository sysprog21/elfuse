/* Core I/O syscall handlers
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Read/write, ioctl, splice, sendfile, and copy_file_range operations. All
 * functions are called from syscall_dispatch() in syscall/syscall.c.
 *
 * Poll/select/epoll handlers are in syscall/poll.c. Special FD types (eventfd,
 * signalfd, timerfd) are in syscall/fd.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "utils.h"

#include "core/rosetta.h"
#include "core/shim-globals.h"
#include "hvutil.h"
#include "runtime/procemu.h"
#include "runtime/thread.h"

#include "syscall/abi.h"
#include "syscall/fd.h"
#include "syscall/fuse.h"
#include "syscall/internal.h"
#include "syscall/inotify.h"
#include "syscall/io.h"
#include "syscall/net.h"
#include "syscall/proc.h"
#include "syscall/signal.h"

#define URANDOM_CACHE_SIZE 4096

/* Linux terminal struct types. */

/* Linux struct winsize (same layout as macOS) */
typedef struct {
    uint16_t ws_row, ws_col, ws_xpixel, ws_ypixel;
} linux_winsize_t;

/* Linux struct termios used by TCGETS/TCSETS on aarch64. Speed fields live in
 * Linux termios2, not in this ioctl ABI.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
} linux_termios_t;

/* Per-fd lock embedded in the cache so a urandom read on fd A does not
 * serialize behind a concurrent urandom read on fd B. The previous design used
 * a single global mutex covering the whole cache array, which made the per-fd
 * cache pointless under any sibling-vCPU urandom traffic. The lock array is
 * initialized at startup by io_init().
 */
typedef struct {
    pthread_mutex_t lock;
    uint8_t buf[URANDOM_CACHE_SIZE];
    size_t off;
    size_t len;
} urandom_cache_t;

static urandom_cache_t urandom_cache[FD_TABLE_SIZE];

void io_init(void)
{
    for (int i = 0; i < FD_TABLE_SIZE; i++)
        pthread_mutex_init(&urandom_cache[i].lock, NULL);
}

_Static_assert(sizeof(linux_termios_t) == 36,
               "aarch64 Linux TCGETS struct termios must be 36 bytes");

/* Linux struct termios2 used by TCGETS2/TCSETS2 on aarch64. Same layout as
 * termios but adds c_ispeed and c_ospeed at the end.
 */
typedef struct {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
    uint32_t c_ispeed, c_ospeed;
} linux_termios2_t;

_Static_assert(sizeof(linux_termios2_t) == 44,
               "aarch64 Linux TCGETS2 struct termios2 must be 44 bytes");

/* Linux <-> macOS c_cc index mapping: linux_mac_cc[linux_idx] = mac_idx. Shared
 * by TCGETS/TCSETS and their termios2 variants.
 *
 * Linux: VINTR=0 VQUIT=1 VERASE=2 VKILL=3 VEOF=4 VTIME=5
 *        VMIN=6 VSWTC=7 VSTART=8 VSTOP=9 VSUSP=10 VEOL=11
 *        VREPRINT=12 VDISCARD=13 VWERASE=14 VLNEXT=15 VEOL2=16
 * macOS: VEOF=0 VEOL=1 VEOL2=2 VERASE=3 VWERASE=4 VKILL=5
 *        VREPRINT=6 (7=spare) VINTR=8 VQUIT=9 VSUSP=10 VDSUSP=11
 *        VSTART=12 VSTOP=13 VLNEXT=14 VDISCARD=15 VMIN=16 VTIME=17
 */
static const int linux_mac_cc[19] = {
    8, 9, 3, 5, 0, 17, 16, -1, 12, 13, 10, 1, 6, 15, 4, 14, 2, -1, -1,
};

static void termios_copy_cc_to_linux(uint8_t linux_cc[19], const cc_t mac_cc[])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        /* cppcheck-suppress negativeIndex RANGE_CHECK guards mac_idx >= 0
         * before the array access.
         */
        linux_cc[i] = RANGE_CHECK(mac_idx, 0, NCCS) ? mac_cc[mac_idx] : 0;
    }
}

static void termios_copy_cc_to_mac(cc_t mac_cc[], const uint8_t linux_cc[19])
{
    for (int i = 0; i < 19; i++) {
        int mac_idx = linux_mac_cc[i];
        if (RANGE_CHECK(mac_idx, 0, NCCS))
            mac_cc[mac_idx] = linux_cc[i];
    }
}

static int termios_action_for(unsigned long request)
{
    return (request == LINUX_TCSETSF || request == LINUX_TCSETSF2)   ? TCSAFLUSH
           : (request == LINUX_TCSETSW || request == LINUX_TCSETSW2) ? TCSADRAIN
                                                                     : TCSANOW;
}

static int64_t io_return_zero(host_fd_ref_t *host_ref)
{
    host_fd_ref_close(host_ref);
    return 0;
}

void urandom_fd_reset_cache(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    /* Preserve the embedded lock; reset only the entropy fields. memset of the
     * whole struct would clobber the mutex state.
     */
    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    memset(c->buf, 0, sizeof(c->buf));
    c->off = 0;
    c->len = 0;
    pthread_mutex_unlock(&c->lock);
}

void urandom_fd_cleanup(int guest_fd)
{
    if (!RANGE_CHECK(guest_fd, 0, FD_TABLE_SIZE))
        return;

    urandom_fd_reset_cache(guest_fd);
}

static int64_t urandom_check_readable(int guest_fd)
{
    fd_entry_t snap;
    if (!fd_snapshot(guest_fd, &snap) || snap.type != FD_URANDOM)
        return -LINUX_EBADF;
    if ((snap.linux_flags & 3) == LINUX_O_WRONLY)
        return -LINUX_EBADF;
    return 0;
}

static int64_t urandom_fill_iov(int guest_fd,
                                const struct iovec *iov,
                                int iovcnt)
{
    int64_t err = urandom_check_readable(guest_fd);
    if (err < 0)
        return err;

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len > (size_t) SSIZE_MAX - total)
            return -LINUX_EINVAL;
        total += iov[i].iov_len;
    }
    if (total == 0)
        return 0;

    urandom_cache_t *c = &urandom_cache[guest_fd];
    pthread_mutex_lock(&c->lock);
    size_t done = 0;
    for (int i = 0; i < iovcnt && done < total; i++) {
        uint8_t *dst = iov[i].iov_base;
        size_t iov_done = 0;
        size_t iov_len = iov[i].iov_len;
        if (iov_len > total - done)
            iov_len = total - done;
        while (iov_done < iov_len) {
            if (c->off == c->len) {
                arc4random_buf(c->buf, sizeof(c->buf));
                c->off = 0;
                c->len = sizeof(c->buf);
            }
            size_t chunk = c->len - c->off;
            if (chunk > iov_len - iov_done)
                chunk = iov_len - iov_done;
            memcpy(dst + iov_done, c->buf + c->off, chunk);
            c->off += chunk;
            iov_done += chunk;
            done += chunk;
        }
    }
    pthread_mutex_unlock(&c->lock);
    return (int64_t) done;
}

static int64_t validate_iov_total(guest_t *g, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt <= 0 || iovcnt > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;

    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva + (uint64_t) i * sizeof(giov), &giov,
                             sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        if (giov.iov_len > (uint64_t) SSIZE_MAX - total)
            return -LINUX_EINVAL;
        total += (size_t) giov.iov_len;
    }
    return 0;
}

static int64_t urandom_read(guest_t *g,
                            int guest_fd,
                            uint64_t buf_gva,
                            uint64_t count)
{
    if (count > SSIZE_MAX)
        count = SSIZE_MAX;
    if (count == 0) {
        struct iovec empty = {0};
        return urandom_fill_iov(guest_fd, &empty, 1);
    }

    uint64_t avail = 0;
    void *dst = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!dst)
        return -LINUX_EFAULT;
    if (count > avail)
        count = avail;

    struct iovec iov = {.iov_base = dst, .iov_len = (size_t) count};
    int64_t rc = urandom_fill_iov(guest_fd, &iov, 1);

    /* This slow path runs when the shim's identity-class fast path could not
     * serve the read: either the request was larger than the shim's inline
     * limit, or the ring was empty. Refill the shim's entropy ring before
     * returning so a subsequent read(/dev/urandom) from the same vCPU sees a
     * populated ring and stays on the fast path.
     */
    shim_globals_refill_urandom_ring(g);
    return rc;
}

static bool rosetta_ioctl_target_fd(guest_t *g, int host_fd)
{
    if (!g->is_rosetta)
        return false;

    /* Rosetta opens /proc/self/exe (which under rosetta resolves to the rosetta
     * translator, not elfuse) and issues the VZ probe ioctls on that
     * descriptor. Match against ROSETTA_PATH so the gate triggers regardless of
     * where elfuse itself lives on disk.
     */
    char resolved[PATH_MAX];
    if (fcntl(host_fd, F_GETPATH, resolved) < 0)
        return false;
    if (strcmp(resolved, ROSETTA_PATH) != 0)
        return false;

    /* Defense in depth: require the syscall to originate from inside the
     * rosetta translator image. The /proc/self/exe redirection makes the
     * launcher fd reachable to any code running under a rosetta-enabled VM, so
     * without this check a guest-launched helper that opened /proc/self/exe
     * could exercise the synthetic VZ probe path. Today the responses are
     * public constants, but the gate guards against future synthetic responses
     * that leak host state. ELR_EL1 carries the EL0 return PC captured at SVC
     * entry on aarch64.
     *
     * Skip if the rosetta image bounds are not yet known (pre-finalize); the
     * F_GETPATH match above is the only gate in that window, and
     * rosetta_finalize publishes the bounds before issuing any ioctl.
     */
    if (g->rosetta_va_base && g->rosetta_size) {
        if (!current_thread)
            return false;
        uint64_t pc = vcpu_get_sysreg(current_thread->vcpu, HV_SYS_REG_ELR_EL1);
        if (pc < g->rosetta_va_base ||
            pc - g->rosetta_va_base >= g->rosetta_size)
            return false;
    }
    return true;
}

/* Returns true if request matches one of the Rosetta VZ probe ioctls. */
static bool rosetta_vz_request(uint64_t request)
{
    return request == ROSETTA_VZ_CHECK || request == ROSETTA_VZ_CAPS ||
           request == ROSETTA_VZ_ACTIVATE;
}

/* Handle the Rosetta VZ probe ioctl trio. Writes synthetic responses to the
 * guest buffer at arg and returns the value the guest sees (1 on success,
 * negative Linux errno on a guest_write fault). Caller is responsible for
 * dispatch gating (see rosetta_vz_request + rosetta_ioctl_target_fd).
 */
static int64_t rosetta_vz_ioctl(guest_t *g, uint64_t request, uint64_t arg)
{
    switch (request) {
    case ROSETTA_VZ_CHECK: {
        static const char rosetta_sig[ROSETTA_VZ_SIG_LEN] =
            "Our hard work\nby these words guarded\n"
            "please don't steal\n\xc2\xa9 Apple Inc";
        if (guest_write(g, arg, rosetta_sig, sizeof(rosetta_sig)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_CAPS: {
        /* caps is zero-initialized: VZ_SECONDARY and the trailing NUL of any
         * partially-copied binary path are already in place.
         */
        uint8_t caps[ROSETTA_CAPS_SIZE] = {0};
        caps[ROSETTA_CAPS_VZ_ENABLE] = 1;
        static const char fake_sock_path[] = ROSETTAD_SOCKET_PATH;
        memcpy(&caps[ROSETTA_CAPS_SOCKET_PATH], fake_sock_path,
               sizeof(fake_sock_path));
        /* Snapshot the caps binary path under the rosetta path lock so a
         * concurrent execve cannot tear the string between length probe and
         * copy. Inline buffer matches the cap exactly; the snapshot helper
         * bounds the write itself.
         */
        char bin[ROSETTA_CAPS_BINARY_PATH_LEN];
        size_t bin_n = rosettad_snapshot_caps_binary_path(bin, sizeof(bin));
        if (bin_n > 0)
            memcpy(&caps[ROSETTA_CAPS_BINARY_PATH], bin, bin_n);
        if (guest_write(g, arg, caps, sizeof(caps)) < 0)
            return -LINUX_EFAULT;
        return 1;
    }
    case ROSETTA_VZ_ACTIVATE:
        return 1;
    }
    /* Caller gates dispatch; this is unreachable in practice. */
    return -LINUX_ENOTTY;
}

/* termios flag translation helpers. */

/* Linux aarch64 c_iflag bits (from asm-generic/termbits-common.h). Low 9 bits
 * (IGNBRK..ICRNL) match macOS exactly. Bits from 0x200 onward differ: Linux
 * IUCLC=0x200 has no macOS equivalent; Linux IXON=0x400/IXOFF=0x1000 vs macOS
 * IXON=0x200/IXOFF=0x400.
 */
#define LINUX_IFLAG_LOW_MASK 0x1ff /* bits 0-8: same on Linux and macOS */
#define LINUX_IXON 0x0400
#define LINUX_IXOFF 0x1000
#define LINUX_IMAXBEL 0x2000 /* same value on both */
#define LINUX_IUTF8 0x4000   /* same value on both */

/* Translate Linux c_iflag to macOS c_iflag. */
static tcflag_t linux_iflag_to_mac(uint32_t lf)
{
    tcflag_t mf = lf & LINUX_IFLAG_LOW_MASK; /* IGNBRK..ICRNL identical */
    /* IXANY=0x800 is the same on both; pass through */
    if (lf & 0x800)
        mf |= IXANY;
    if (lf & LINUX_IXON)
        mf |= IXON; /* Linux 0x400 -> macOS 0x200 */
    if (lf & LINUX_IXOFF)
        mf |= IXOFF; /* Linux 0x1000 -> macOS 0x400 */
    if (lf & LINUX_IMAXBEL)
        mf |= IMAXBEL;
    if (lf & LINUX_IUTF8)
        mf |= IUTF8;
    /* IUCLC (Linux 0x200) has no macOS equivalent; drop it */
    return mf;
}

/* Translate macOS c_iflag to Linux c_iflag. */
static uint32_t mac_iflag_to_linux(tcflag_t mf)
{
    uint32_t lf = mf & LINUX_IFLAG_LOW_MASK; /* IGNBRK..ICRNL identical */
    if (mf & IXANY)
        lf |= 0x800;
    if (mf & IXON)
        lf |= LINUX_IXON;
    if (mf & IXOFF)
        lf |= LINUX_IXOFF;
    if (mf & IMAXBEL)
        lf |= LINUX_IMAXBEL;
    if (mf & IUTF8)
        lf |= LINUX_IUTF8;
    return lf;
}

/* Linux aarch64 c_oflag bits (asm-generic/termbits-common.h + termbits.h). Only
 * OPOST (0x01) has the same value on both platforms. macOS 0x02 = ONLCR; Linux
 * 0x02 = OLCUC (output lowercase->uppercase, rare). macOS 0x04 = OXTABS; Linux
 * 0x04 = ONLCR. All other bits shift by one.
 */
/* OLCUC (Linux 0x002, output lowercase->uppercase) has no macOS equivalent and
 * is silently dropped. macOS uses 0x002 for ONLCR.
 */
#define LINUX_OPOST 0x001
#define LINUX_ONLCR 0x004  /* macOS ONLCR=0x002 */
#define LINUX_OCRNL 0x008  /* macOS OCRNL=0x010 */
#define LINUX_ONOCR 0x010  /* macOS ONOCR=0x020 */
#define LINUX_ONLRET 0x020 /* macOS ONLRET=0x040 */
#define LINUX_OFILL 0x040  /* macOS OFILL=0x080 */
#define LINUX_OFDEL 0x080  /* macOS OFDEL=0x020000 */
/* Linux NLDLY/CRDLY/TABDLY/BSDLY/VTDLY/FFDLY have no macOS equivalents */

/* Translate Linux c_oflag to macOS c_oflag. */
static tcflag_t linux_oflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    if (lf & LINUX_OPOST)
        mf |= OPOST;
    /* LINUX_OLCUC (0x002) has no macOS equivalent; drop it */
    if (lf & LINUX_ONLCR)
        mf |= ONLCR;
    if (lf & LINUX_OCRNL)
        mf |= OCRNL;
    if (lf & LINUX_ONOCR)
        mf |= ONOCR;
    if (lf & LINUX_ONLRET)
        mf |= ONLRET;
    if (lf & LINUX_OFILL)
        mf |= OFILL;
    if (lf & LINUX_OFDEL)
        mf |= OFDEL;
    /* NLDLY, CRDLY, TABDLY, BSDLY, VTDLY, FFDLY: no macOS equivalents */
    return mf;
}

/* Translate macOS c_oflag to Linux c_oflag. */
static uint32_t mac_oflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    if (mf & OPOST)
        lf |= LINUX_OPOST;
    if (mf & ONLCR)
        lf |= LINUX_ONLCR;
    if (mf & OCRNL)
        lf |= LINUX_OCRNL;
    if (mf & ONOCR)
        lf |= LINUX_ONOCR;
    if (mf & ONLRET)
        lf |= LINUX_ONLRET;
    if (mf & OFILL)
        lf |= LINUX_OFILL;
    if (mf & OFDEL)
        lf |= LINUX_OFDEL;
    return lf;
}

/* Linux aarch64 c_cflag bits (asm-generic/termbits.h). All standard flags
 * differ from macOS: macOS shifts everything left by 4 bits (e.g., Linux
 * CS8=0x30, macOS CS8=0x300; Linux CSTOPB=0x40, macOS=0x400). The CBAUD field
 * (Linux 0x0000100f) encodes baud rate symbolically; macOS uses raw numeric
 * speeds via cfgetispeed/cfsetispeed, so termios translation drops CBAUD from
 * c_cflag and always uses the speed accessors.
 */
#define LINUX_CSIZE 0x0030
#define LINUX_CS5 0x0000
#define LINUX_CS6 0x0010
#define LINUX_CS7 0x0020
#define LINUX_CS8 0x0030
#define LINUX_CSTOPB 0x0040
#define LINUX_CREAD 0x0080
#define LINUX_PARENB 0x0100
#define LINUX_PARODD 0x0200
#define LINUX_HUPCL 0x0400
#define LINUX_CLOCAL 0x0800
/* LINUX_CBAUD 0x0000100f and LINUX_CBAUDEX 0x00001000 encode baud in c_cflag;
 * macOS uses dedicated speed fields, so termios translation ignores CBAUD on
 * translation. TCGETS2/TCSETS2 use BOTHER to signal numeric c_ispeed/c_ospeed.
 */
#define LINUX_CBAUD 0x100f
#define LINUX_BOTHER 0x1000

/* Decode a Linux CBAUD field value to a numeric baud rate.
 * Returns the numeric rate, or 0 for B0 / unknown. Standard rates B0-B38400 are
 * in the low nibble (0-15); extended rates B57600-B4000000 use CBAUDEX (0x1000)
 * + low nibble.
 */
static speed_t linux_cbaud_to_speed(uint32_t cbaud)
{
    static const speed_t std_rates[16] = {
        0,   50,   75,   110,  134,  150,  200,   300,
        600, 1200, 1800, 2400, 4800, 9600, 19200, 38400,
    };
    static const speed_t ext_rates[16] = {
        0,       57600,   115200,  230400,  460800,  500000,  576000,  921600,
        1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
    };
    uint32_t rate_idx = cbaud & 0xF;

    if (cbaud == LINUX_BOTHER)
        return 0; /* caller should use c_ispeed/c_ospeed directly */
    if (cbaud < 16)
        return std_rates[cbaud];
    if (cbaud & LINUX_BOTHER)
        return ext_rates[rate_idx];
    return 0;
}

/* Translate Linux c_cflag to macOS c_cflag. */
static tcflag_t linux_cflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    /* CSIZE: Linux CS5=0x00, CS6=0x10, CS7=0x20, CS8=0x30
     *        macOS CS5=0x00, CS6=0x100, CS7=0x200, CS8=0x300
     */
    switch (lf & LINUX_CSIZE) {
    case LINUX_CS5:
        mf |= CS5;
        break;
    case LINUX_CS6:
        mf |= CS6;
        break;
    case LINUX_CS7:
        mf |= CS7;
        break;
    case LINUX_CS8:
        mf |= CS8;
        break;
    default:
        break;
    }
    if (lf & LINUX_CSTOPB)
        mf |= CSTOPB;
    if (lf & LINUX_CREAD)
        mf |= CREAD;
    if (lf & LINUX_PARENB)
        mf |= PARENB;
    if (lf & LINUX_PARODD)
        mf |= PARODD;
    if (lf & LINUX_HUPCL)
        mf |= HUPCL;
    if (lf & LINUX_CLOCAL)
        mf |= CLOCAL;
    /* CBAUD/CBAUDEX: drop (baud rate comes from c_ispeed/c_ospeed fields) */
    return mf;
}

/* Translate macOS c_cflag to Linux c_cflag. */
static uint32_t mac_cflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    switch (mf & CSIZE) {
    case CS5:
        lf |= LINUX_CS5;
        break;
    case CS6:
        lf |= LINUX_CS6;
        break;
    case CS7:
        lf |= LINUX_CS7;
        break;
    case CS8:
        lf |= LINUX_CS8;
        break;
    default:
        break;
    }
    if (mf & CSTOPB)
        lf |= LINUX_CSTOPB;
    if (mf & CREAD)
        lf |= LINUX_CREAD;
    if (mf & PARENB)
        lf |= LINUX_PARENB;
    if (mf & PARODD)
        lf |= LINUX_PARODD;
    if (mf & HUPCL)
        lf |= LINUX_HUPCL;
    if (mf & CLOCAL)
        lf |= LINUX_CLOCAL;
    return lf;
}

/* Linux aarch64 c_lflag bits (asm-generic/termbits.h). Virtually every flag has
 * a different value from macOS. Only ECHO (0x0008) is the same on both
 * platforms.
 */
/* XCASE (Linux 0x004, rarely used, no macOS equivalent) is dropped; macOS 0x004
 * has different semantics and is not translated here.
 */
#define LINUX_ISIG 0x00001
#define LINUX_ICANON 0x00002
#define LINUX_ECHO 0x00008 /* same on macOS */
#define LINUX_ECHOE 0x00010
#define LINUX_ECHOK 0x00020
#define LINUX_ECHONL 0x00040
#define LINUX_NOFLSH 0x00080
#define LINUX_TOSTOP 0x00100
#define LINUX_ECHOCTL 0x00200
#define LINUX_ECHOPRT 0x00400
#define LINUX_ECHOKE 0x00800
#define LINUX_FLUSHO 0x01000
#define LINUX_PENDIN 0x04000
#define LINUX_IEXTEN 0x08000
#define LINUX_EXTPROC 0x10000

/* Translate Linux c_lflag to macOS c_lflag. */
static tcflag_t linux_lflag_to_mac(uint32_t lf)
{
    tcflag_t mf = 0;
    if (lf & LINUX_ISIG)
        mf |= ISIG;
    if (lf & LINUX_ICANON)
        mf |= ICANON;
    /* LINUX_XCASE (0x004) has no macOS equivalent; drop it */
    if (lf & LINUX_ECHO)
        mf |= ECHO;
    if (lf & LINUX_ECHOE)
        mf |= ECHOE;
    if (lf & LINUX_ECHOK)
        mf |= ECHOK;
    if (lf & LINUX_ECHONL)
        mf |= ECHONL;
    if (lf & LINUX_NOFLSH)
        mf |= NOFLSH;
    if (lf & LINUX_TOSTOP)
        mf |= TOSTOP;
    if (lf & LINUX_ECHOCTL)
        mf |= ECHOCTL;
    if (lf & LINUX_ECHOPRT)
        mf |= ECHOPRT;
    if (lf & LINUX_ECHOKE)
        mf |= ECHOKE;
    if (lf & LINUX_FLUSHO)
        mf |= FLUSHO;
    if (lf & LINUX_PENDIN)
        mf |= PENDIN;
    if (lf & LINUX_IEXTEN)
        mf |= IEXTEN;
    if (lf & LINUX_EXTPROC)
        mf |= EXTPROC;
    return mf;
}

/* Translate macOS c_lflag to Linux c_lflag. */
static uint32_t mac_lflag_to_linux(tcflag_t mf)
{
    uint32_t lf = 0;
    if (mf & ISIG)
        lf |= LINUX_ISIG;
    if (mf & ICANON)
        lf |= LINUX_ICANON;
    if (mf & ECHO)
        lf |= LINUX_ECHO;
    if (mf & ECHOE)
        lf |= LINUX_ECHOE;
    if (mf & ECHOK)
        lf |= LINUX_ECHOK;
    if (mf & ECHONL)
        lf |= LINUX_ECHONL;
    if (mf & NOFLSH)
        lf |= LINUX_NOFLSH;
    if (mf & TOSTOP)
        lf |= LINUX_TOSTOP;
    if (mf & ECHOCTL)
        lf |= LINUX_ECHOCTL;
    if (mf & ECHOPRT)
        lf |= LINUX_ECHOPRT;
    if (mf & ECHOKE)
        lf |= LINUX_ECHOKE;
    if (mf & FLUSHO)
        lf |= LINUX_FLUSHO;
    if (mf & PENDIN)
        lf |= LINUX_PENDIN;
    if (mf & IEXTEN)
        lf |= LINUX_IEXTEN;
    if (mf & EXTPROC)
        lf |= LINUX_EXTPROC;
    return lf;
}

/* read/write and positional variants. */

/* Open a host fd reference for regular I/O, checking type and seals under
 * fd_lock for thread safety.
 *
 * Returns -LINUX_EBADF for path-only or closed fds, -LINUX_EPERM for
 * write-sealed fds (when check_seal is set), or 0 on success.
 */
static int64_t host_fd_ref_open_checked(int guest_fd,
                                        host_fd_ref_t *ref,
                                        bool check_write_seal)
{
    if (check_write_seal) {
        fd_entry_t snap;
        if (!fd_snapshot(guest_fd, &snap))
            return -LINUX_EBADF;
        if (snap.type == FD_PATH)
            return -LINUX_EBADF;
        if (snap.seals & LINUX_F_SEAL_WRITE)
            return -LINUX_EPERM;
        return host_fd_ref_open(guest_fd, ref) < 0 ? -LINUX_EBADF : 0;
    }
    return host_fd_ref_open_io(guest_fd, ref);
}

static int64_t host_fd_ref_open_regular_io(int guest_fd, host_fd_ref_t *ref)
{
    return host_fd_ref_open_io(guest_fd, ref);
}

static int64_t proc_try_read_intercept(int fd,
                                       int host_fd,
                                       void *buf,
                                       size_t count,
                                       int64_t offset,
                                       int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_read(fd, buf, count, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

static int64_t proc_try_readv_intercept(int fd,
                                        int host_fd,
                                        const struct iovec *iov,
                                        int iovcnt,
                                        int64_t offset,
                                        int use_pread)
{
    ssize_t intercepted = 0;
    int handled = proc_intercept_readv(fd, iov, iovcnt, offset, &intercepted);
    if (handled < 0)
        return linux_errno();
    if (handled > 0) {
        if (!use_pread &&
            lseek(host_fd, offset + (int64_t) intercepted, SEEK_SET) < 0)
            return linux_errno();
        return intercepted;
    }
    return INT64_MIN;
}

/* Sendfile/copy_file_range chunk read: route the chunk through proc_intercept
 * when the source fd is a synthetic /proc node, otherwise fall through
 * (INT64_MIN). For the streaming (use_pread=0) variant the input offset is
 * irrelevant; the helper queries the live host fd cursor.
 */
static int64_t proc_try_chunk_read_intercept(int fd,
                                             int host_fd,
                                             void *buf,
                                             size_t count,
                                             int64_t offset,
                                             int use_pread)
{
    if (!use_pread) {
        offset = lseek(host_fd, 0, SEEK_CUR);
        if (offset < 0)
            return INT64_MIN;
    }
    return proc_try_read_intercept(fd, host_fd, buf, count, offset, use_pread);
}

static int64_t proc_try_writev_intercept(int fd,
                                         int host_fd,
                                         const struct iovec *iov,
                                         int iovcnt,
                                         int64_t offset,
                                         int use_pwrite)
{
    size_t total = 0;
    char stack_buf[256];
    char *buf = stack_buf;
    ssize_t written = 0;
    int handled;

    for (int i = 0; i < iovcnt; i++)
        total += iov[i].iov_len;
    if (total > sizeof(stack_buf)) {
        buf = malloc(total);
        if (!buf)
            return -LINUX_ENOMEM;
    }

    size_t off = 0;
    for (int i = 0; i < iovcnt; i++) {
        memcpy(buf + off, iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    handled = proc_intercept_write(fd, host_fd, buf, total, offset, use_pwrite,
                                   &written);
    if (buf != stack_buf)
        free(buf);
    if (handled < 0)
        return linux_errno();
    if (handled > 0)
        return written;
    return INT64_MIN;
}

static int64_t io_write_result(ssize_t ret)
{
    if (ret >= 0)
        return ret;

    return linux_errno();
}

int64_t sys_write(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    int type = fd_get_type(fd);
    if (type == FD_FUSE_DEV)
        return fuse_dev_write(g, fd, buf_gva, count);
    if (type == FD_EVENTFD)
        return eventfd_write(fd, g, buf_gva, count);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: write(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    /* Resolve buffer and cap count to available contiguous guest bytes.
     * guest_ptr_avail returns the host pointer and remaining bytes in the
     * current region. This prevents host write() from reading past the guest
     * buffer boundary.
     */
    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_R, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        ssize_t intercepted = 0;
        int handled = proc_intercept_write(fd, host_ref.fd, buf, count, offset,
                                           0, &intercepted);
        if (handled < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        if (handled > 0) {
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    ssize_t ret = write(host_ref.fd, buf, count);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

int64_t sys_read(guest_t *g, int fd, uint64_t buf_gva, uint64_t count)
{
    /* Read the type once under fd_lock so a concurrent close/reopen cannot make
     * different dispatch checks disagree. Each handler still re-validates
     * internally and returns EBADF if its slot changed.
     */
    int type = fd_get_type(fd);
    switch (type) {
    case FD_FUSE_DEV:
        return fuse_dev_read(fd, g, buf_gva, count);
    case FD_FUSE_FILE:
        return fuse_read_fd(g, fd, buf_gva, count);
    case FD_EVENTFD:
        return eventfd_read(fd, g, buf_gva, count);
    case FD_SIGNALFD:
        return signalfd_read(fd, g, buf_gva, count);
    case FD_TIMERFD:
        return timerfd_read(fd, g, buf_gva, count);
    case FD_INOTIFY:
        return inotify_read(fd, g, buf_gva, count);
    case FD_NETLINK:
        return netlink_read(fd, g, buf_gva, count);
    case FD_URANDOM:
        return urandom_read(g, fd, buf_gva, count);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux: read(fd, NULL, 0) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    /* Resolve buffer and cap count to available contiguous guest bytes.
     * Prevents host read() from writing past the guest buffer boundary.
     */
    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted =
            proc_try_read_intercept(fd, host_ref.fd, buf, count, offset, 0);
        if (intercepted != INT64_MIN) {
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    ssize_t ret = read(host_ref.fd, buf, count);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : ret;
}

int64_t sys_pread64(guest_t *g,
                    int fd,
                    uint64_t buf_gva,
                    uint64_t count,
                    int64_t offset)
{
    if (fuse_is_file_fd(fd))
        return fuse_pread_fd(g, fd, buf_gva, count, offset);

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux: pread(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_W, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    int64_t intercepted =
        proc_try_read_intercept(fd, host_ref.fd, buf, count, offset, 1);
    if (intercepted != INT64_MIN) {
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pread(host_ref.fd, buf, count, offset);
    host_fd_ref_close(&host_ref);
    return ret < 0 ? linux_errno() : ret;
}

int64_t sys_pwrite64(guest_t *g,
                     int fd,
                     uint64_t buf_gva,
                     uint64_t count,
                     int64_t offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    /* Linux: pwrite(fd, NULL, 0, off) returns 0, not EFAULT */
    if (count == 0)
        return io_return_zero(&host_ref);

    uint64_t avail = 0;
    void *buf = guest_ptr_bound(g, buf_gva, &avail, MEM_PERM_R, count);
    if (!buf) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFAULT;
    }
    if (count > avail)
        count = avail;

    ssize_t intercepted = 0;
    int handled = proc_intercept_write(fd, host_ref.fd, buf, count, offset, 1,
                                       &intercepted);
    if (handled < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }
    if (handled > 0) {
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwrite(host_ref.fd, buf, count, offset);
    host_fd_ref_close(&host_ref);
    return io_write_result(ret);
}

/* Helper: build host iovec array from guest iovec array. Uses guest_read for
 * the iovec array (may cross 2MiB block boundary) and guest_ptr_avail for each
 * buffer (caps to contiguous bytes). required_perms: MEM_PERM_W for readv (host
 * writes to guest buffers),
 *                 MEM_PERM_R for writev (host reads from guest buffers).
 * Returns 0 on success, -LINUX_EFAULT on bad guest pointer.
 */
static int64_t build_host_iov(guest_t *g,
                              uint64_t iov_gva,
                              int iovcnt,
                              struct iovec *host_iov,
                              int required_perms)
{
    linux_iovec_t stack_giov[SYSCALL_IOV_STACK_MAX];
    linux_iovec_t *guest_iov = stack_giov;
    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        guest_iov = malloc((size_t) iovcnt * sizeof(*guest_iov));
        if (!guest_iov)
            return -LINUX_ENOMEM;
    }
    if (guest_read(g, iov_gva, guest_iov,
                   (size_t) iovcnt * sizeof(*guest_iov)) < 0) {
        if (guest_iov != stack_giov)
            free(guest_iov);
        return -LINUX_EFAULT;
    }
    for (int i = 0; i < iovcnt; i++) {
        if (guest_iov[i].iov_len == 0) {
            host_iov[i].iov_base = NULL;
            host_iov[i].iov_len = 0;
            continue;
        }
        uint64_t avail = 0;
        void *base = guest_ptr_bound(g, guest_iov[i].iov_base, &avail,
                                     required_perms, guest_iov[i].iov_len);
        if (!base) {
            if (guest_iov != stack_giov)
                free(guest_iov);
            return -LINUX_EFAULT;
        }
        /* Cap to contiguous permitted bytes. When the guest iov entry spans a
         * non-contiguous boundary (different mapping or permission), zero every
         * subsequent host iov length so the host readv/writev returns a
         * POSIX-compliant short I/O rather than silently packing the truncated
         * tail of buffer i into buffer i+1 -- which corrupts the guest's data
         * layout.
         */
        uint64_t len = guest_iov[i].iov_len;
        host_iov[i].iov_base = base;
        if (len > avail) {
            host_iov[i].iov_len = avail;
            for (int j = i + 1; j < iovcnt; j++) {
                host_iov[j].iov_base = NULL;
                host_iov[j].iov_len = 0;
            }
            break;
        }
        host_iov[i].iov_len = len;
    }
    if (guest_iov != stack_giov)
        free(guest_iov);
    return 0;
}

int64_t host_iov_prepare(guest_t *g,
                         uint64_t iov_gva,
                         int iovcnt,
                         int required_perms,
                         host_iov_buf_t *buf)
{
    if (iovcnt <= 0 || iovcnt > SYSCALL_IOV_MAX)
        return -LINUX_EINVAL;

    buf->iov = buf->stack;

    if (iovcnt > SYSCALL_IOV_STACK_MAX) {
        buf->iov = malloc((size_t) iovcnt * sizeof(*buf->iov));
        if (!buf->iov)
            return -LINUX_ENOMEM;
    }

    int64_t err = build_host_iov(g, iov_gva, iovcnt, buf->iov, required_perms);
    if (err < 0) {
        if (buf->iov != buf->stack)
            free(buf->iov);
        buf->iov = NULL;
        return err;
    }

    return 0;
}

int64_t host_iov_prepare_msg(guest_t *g,
                             uint64_t iov_gva,
                             int iovcnt,
                             int required_perms,
                             host_iov_buf_t *buf)
{
    if (iovcnt == 0) {
        buf->iov = buf->stack;
        return 0;
    }
    return host_iov_prepare(g, iov_gva, iovcnt, required_perms, buf);
}

void host_iov_free(host_iov_buf_t *buf)
{
    if (buf->iov != buf->stack)
        free(buf->iov);
    buf->iov = NULL;
}

static int64_t single_guest_iov(guest_t *g,
                                uint64_t iov_gva,
                                linux_iovec_t *iov)
{
    if (guest_read_small(g, iov_gva, iov, sizeof(*iov)) < 0)
        return -LINUX_EFAULT;
    return 0;
}

int64_t sys_readv(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        if (fd_get_type(fd) == FD_URANDOM &&
            giov.iov_len > (uint64_t) SSIZE_MAX) {
            err = urandom_check_readable(fd);
            if (err < 0)
                return err;
            return -LINUX_EINVAL;
        }
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types need their custom read handlers because glibc may use
     * readv() instead of read() for the same logical operation. Delegate scalar
     * special fds to the first iov entry's buffer. Use the first iov's length
     * (not the sum of all iovs) because the data goes into giov[0].iov_base
     * which is only giov[0].iov_len bytes long.
     */
    int type = fd_get_type(fd);
    if (type == FD_URANDOM) {
        int64_t err = urandom_check_readable(fd);
        if (err < 0)
            return err;
        err = validate_iov_total(g, iov_gva, iovcnt);
        if (err < 0)
            return err;
        host_iov_buf_t host_iov;
        err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
        if (err < 0)
            return err;
        int64_t ret = urandom_fill_iov(fd, host_iov.iov, iovcnt);
        host_iov_free(&host_iov);
        /* Mirror sys_read's slow-path refill so a readv consumer that drains
         * the shim ring leaves it ready for the next call, instead of forcing
         * every subsequent EL1 fast-path attempt back through HVC until some
         * other path triggers a refill.
         */
        shim_globals_refill_urandom_ring(g);
        return ret;
    }
    if (type == FD_EVENTFD || type == FD_SIGNALFD || type == FD_TIMERFD ||
        type == FD_INOTIFY) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;
        /* Use guest_read for the iov array since guest_ptr alone is unsafe if
         * the array spans a 2MiB block boundary.
         */
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return sys_read(g, fd, giov.iov_base, giov.iov_len);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_readv_intercept(
            fd, host_ref.fd, host_iov.iov, iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    ssize_t ret = readv(host_ref.fd, host_iov.iov, iovcnt);
    int64_t result = ret < 0 ? linux_errno() : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_writev(guest_t *g, int fd, uint64_t iov_gva, int iovcnt)
{
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_write(g, fd, giov.iov_base, giov.iov_len);
    }

    /* Special FD types: glibc may use writev() for eventfd wakeup writes.
     * Delegate using the first iov entry. Use giov.iov_len (not the sum of all
     * iovs) because the data is at giov.iov_base which is only giov.iov_len
     * bytes. eventfd expects exactly 8 bytes.
     */
    if (fd_get_type(fd) == FD_EVENTFD) {
        if (iovcnt <= 0)
            return -LINUX_EINVAL;
        linux_iovec_t giov;
        if (guest_read_small(g, iov_gva, &giov, sizeof(giov)) < 0)
            return -LINUX_EFAULT;
        return eventfd_write(fd, g, giov.iov_base, giov.iov_len);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    off_t offset = lseek(host_ref.fd, 0, SEEK_CUR);
    if (offset >= 0) {
        int64_t intercepted = proc_try_writev_intercept(
            fd, host_ref.fd, host_iov.iov, iovcnt, offset, 0);
        if (intercepted != INT64_MIN) {
            host_iov_free(&host_iov);
            host_fd_ref_close(&host_ref);
            return intercepted;
        }
    }

    ssize_t ret = writev(host_ref.fd, host_iov.iov, iovcnt);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_preadv(guest_t *g,
                   int fd,
                   uint64_t iov_gva,
                   int iovcnt,
                   int64_t offset)
{
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pread64(g, fd, giov.iov_base, giov.iov_len, offset);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_W, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_readv_intercept(
        fd, host_ref.fd, host_iov.iov, iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = preadv(host_ref.fd, host_iov.iov, iovcnt, offset);
    int64_t result = ret < 0 ? linux_errno() : ret;
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

int64_t sys_pwritev(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset)
{
    if (iovcnt == 1) {
        linux_iovec_t giov;
        int64_t err = single_guest_iov(g, iov_gva, &giov);
        if (err < 0)
            return err;
        return sys_pwrite64(g, fd, giov.iov_base, giov.iov_len, offset);
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    int64_t intercepted = proc_try_writev_intercept(
        fd, host_ref.fd, host_iov.iov, iovcnt, offset, 1);
    if (intercepted != INT64_MIN) {
        host_iov_free(&host_iov);
        host_fd_ref_close(&host_ref);
        return intercepted;
    }

    ssize_t ret = pwritev(host_ref.fd, host_iov.iov, iovcnt, offset);
    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

static int64_t sys_pwritev_append(guest_t *g,
                                  int fd,
                                  uint64_t iov_gva,
                                  int iovcnt,
                                  bool update_file_offset)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_checked(fd, &host_ref, true);
    if (err < 0)
        return err;

    host_iov_buf_t host_iov;
    err = host_iov_prepare(g, iov_gva, iovcnt, MEM_PERM_R, &host_iov);
    if (err < 0) {
        host_fd_ref_close(&host_ref);
        return err;
    }

    ssize_t ret;
    if (update_file_offset) {
        if (lseek(host_ref.fd, 0, SEEK_END) < 0) {
            ret = -1;
        } else {
            ret = writev(host_ref.fd, host_iov.iov, iovcnt);
        }
    } else {
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            ret = -1;
        } else {
            ret = pwritev(host_ref.fd, host_iov.iov, iovcnt, st.st_size);
        }
    }

    int64_t result = io_write_result(ret);
    host_iov_free(&host_iov);
    host_fd_ref_close(&host_ref);
    return result;
}

/* Linux RWF_* flags for preadv2/pwritev2 (include/uapi/linux/fs.h) */
#define RWF_HIPRI 0x00000001  /* High priority hint (best-effort) */
#define RWF_DSYNC 0x00000002  /* Per-I/O data integrity sync */
#define RWF_SYNC 0x00000004   /* Per-I/O file integrity sync */
#define RWF_NOWAIT 0x00000008 /* Nonblocking hint (best-effort) */
#define RWF_APPEND 0x00000010 /* Append mode (pwritev2 only) */
#define RWF_SUPPORTED \
    (RWF_HIPRI | RWF_DSYNC | RWF_SYNC | RWF_NOWAIT | RWF_APPEND)

int64_t sys_preadv2(guest_t *g,
                    int fd,
                    uint64_t iov_gva,
                    int iovcnt,
                    int64_t offset,
                    int flags)
{
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    if (flags & RWF_APPEND)
        return -LINUX_EINVAL; /* RWF_APPEND is write-only */
    /* RWF_HIPRI, RWF_NOWAIT: best-effort hints, safe to ignore. RWF_DSYNC,
     * RWF_SYNC: no effect on reads.
     */
    if (offset == -1)
        return sys_readv(g, fd, iov_gva, iovcnt);
    return sys_preadv(g, fd, iov_gva, iovcnt, offset);
}

int64_t sys_pwritev2(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     int iovcnt,
                     int64_t offset,
                     int flags)
{
    if (flags & ~RWF_SUPPORTED)
        return -LINUX_EOPNOTSUPP;
    int64_t r;
    if (flags & RWF_APPEND)
        r = sys_pwritev_append(g, fd, iov_gva, iovcnt, offset == -1);
    else if (offset == -1)
        r = sys_writev(g, fd, iov_gva, iovcnt);
    else
        r = sys_pwritev(g, fd, iov_gva, iovcnt, offset);
    /* RWF_SYNC/RWF_DSYNC: sync after successful write */
    if (r > 0 && (flags & (RWF_SYNC | RWF_DSYNC))) {
        host_fd_ref_t host_ref;
        if (host_fd_ref_open_regular_io(fd, &host_ref) == 0) {
            fsync(host_ref.fd);
            host_fd_ref_close(&host_ref);
        }
    }
    return r;
}

/* terminal I/O. */

int64_t sys_ioctl(guest_t *g, int fd, uint64_t request, uint64_t arg)
{
    /* FIOCLEX/FIONCLEX are the ioctl form of fcntl(F_SETFD): they set/clear the
     * guest close-on-exec flag, which lives in fd_table linux_flags (not the
     * host fd's FD_CLOEXEC, which is per-descriptor and would be lost on the
     * dup that host_fd_ref hands multi-threaded callers, so mirror the F_SETFD
     * path in sys_fcntl). They need no host fd, so dispatch them before
     * host_fd_ref_open_regular_io(): that helper rejects O_PATH (FD_PATH) fds
     * with EBADF, but Linux allows these ioctls -- like fcntl(F_SETFD) -- on
     * O_PATH descriptors. Validate the slot and mutate the flag in a single
     * fd_lock section so there is no validate-then-mutate window in which a
     * concurrent close/reuse could flip CLOEXEC on a different file that took
     * the slot. The arg is ignored.
     */
    if (request == LINUX_FIOCLEX || request == LINUX_FIONCLEX) {
        if (!RANGE_CHECK(fd, 0, FD_TABLE_SIZE))
            return -LINUX_EBADF;
        pthread_mutex_lock(&fd_lock);
        if (fd_table[fd].type == FD_CLOSED) {
            pthread_mutex_unlock(&fd_lock);
            return -LINUX_EBADF;
        }
        if (request == LINUX_FIOCLEX)
            fd_table[fd].linux_flags |= LINUX_O_CLOEXEC;
        else
            fd_table[fd].linux_flags &= ~LINUX_O_CLOEXEC;
        pthread_mutex_unlock(&fd_lock);
        return 0;
    }

    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;
    int host_fd = host_ref.fd;

    /* Rosetta's Virtualization.framework probe ioctls are issued on the
     * /proc/self/exe launcher fd very early at startup. Gate on that actual
     * host file rather than on every fd in a Rosetta guest, but do not key on
     * ROSETTA_PATH itself: the probe is against the launcher, not the
     * translator image.
     */
    if (rosetta_vz_request(request) && rosetta_ioctl_target_fd(g, host_fd)) {
        int64_t r = rosetta_vz_ioctl(g, request, arg);
        host_fd_ref_close(&host_ref);
        return r;
    }

    switch (request) {
    case LINUX_TIOCSPGRP: {
        /* Set foreground process group for controlling terminal. */
        int32_t pgrp = 0;
        host_fd_ref_close(&host_ref);
        if (guest_read_small(g, arg, &pgrp, sizeof(pgrp)) < 0)
            return -LINUX_EFAULT;
        proc_set_fg_pgrp((int64_t) pgrp);
        return 0;
    }
    case LINUX_TIOCSCTTY:
        /* Set controlling terminal.  arg is a flag (usually 0). */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(1);
        return 0;
    case LINUX_TIOCNOTTY:
        /* Detach from controlling terminal. */
        host_fd_ref_close(&host_ref);
        proc_set_ctty(0);
        return 0;
    case LINUX_TIOCGSID: {
        /* Get session ID of the controlling terminal. */
        int32_t val = (int32_t) proc_get_sid();
        host_fd_ref_close(&host_ref);
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }
    case LINUX_TIOCGWINSZ: {
        /* Get terminal window size */
        (void) proc_pty_master_adopt(fd);
        struct winsize ws;
        if (ioctl(host_fd, TIOCGWINSZ, &ws) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_winsize_t lws = {
            .ws_row = ws.ws_row,
            .ws_col = ws.ws_col,
            .ws_xpixel = ws.ws_xpixel,
            .ws_ypixel = ws.ws_ypixel,
        };
        if (guest_write_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case LINUX_TIOCSWINSZ: {
        /* Set terminal window size. Same struct as TIOCGWINSZ; foot, sshd,
         * tmux, and any libvte-derived emulator call this on the PTY master
         * after spawning the slave child. Without it, terminal startup fails
         * with -ENOTTY from the default arm below.
         *
         * A master received through SCM_RIGHTS bypasses /dev/ptmx open
         * interception, so lazily create its keepalive before the host ioctl.
         * The helper is a no-op for non-pty fds; the real ioctl below still
         * supplies the final errno.
         */
        linux_winsize_t lws;
        if (guest_read_small(g, arg, &lws, sizeof(lws)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct winsize ws = {
            .ws_row = lws.ws_row,
            .ws_col = lws.ws_col,
            .ws_xpixel = lws.ws_xpixel,
            .ws_ypixel = lws.ws_ypixel,
        };
        (void) proc_pty_master_adopt(fd);
        int rc = ioctl(host_fd, TIOCSWINSZ, &ws);
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }

    case LINUX_TCGETS: {
        /* Get terminal attributes. c_cc index mapping is in file-scope
         * linux_mac_cc[].
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios_t lt = {0};
        lt.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt.c_oflag = mac_oflag_to_linux(t.c_oflag);
        lt.c_cflag = mac_cflag_to_linux(t.c_cflag);
        lt.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt.c_cc, t.c_cc);
        if (guest_write_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS:
    case LINUX_TCSETSW:
    case LINUX_TCSETSF: {
        linux_termios_t lt;
        if (guest_read_small(g, arg, &lt, sizeof(lt)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY; /* Not a terminal */
        }
        t.c_iflag = linux_iflag_to_mac(lt.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt.c_cc);
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCGETS2: {
        /* termios2 variant: same as TCGETS but with c_ispeed/c_ospeed. Set
         * BOTHER in c_cflag so the guest uses the numeric speed fields rather
         * than decoding CBAUD (which mac_cflag_to_linux drops).
         */
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        linux_termios2_t lt2 = {0};
        lt2.c_iflag = mac_iflag_to_linux(t.c_iflag);
        lt2.c_oflag = mac_oflag_to_linux(t.c_oflag);
        lt2.c_cflag = mac_cflag_to_linux(t.c_cflag) | LINUX_BOTHER;
        lt2.c_lflag = mac_lflag_to_linux(t.c_lflag);
        termios_copy_cc_to_linux(lt2.c_cc, t.c_cc);
        lt2.c_ispeed = (uint32_t) cfgetispeed(&t);
        lt2.c_ospeed = (uint32_t) cfgetospeed(&t);
        if (guest_write_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TCSETS2:
    case LINUX_TCSETSW2:
    case LINUX_TCSETSF2: {
        /* termios2 set: decode CBAUD for standard rates, use c_ispeed/ c_ospeed
         * when BOTHER is set.
         */
        linux_termios2_t lt2;
        if (guest_read_small(g, arg, &lt2, sizeof(lt2)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        struct termios t;
        if (tcgetattr(host_fd, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        t.c_iflag = linux_iflag_to_mac(lt2.c_iflag);
        t.c_oflag = linux_oflag_to_mac(lt2.c_oflag);
        t.c_cflag = linux_cflag_to_mac(lt2.c_cflag);
        t.c_lflag = linux_lflag_to_mac(lt2.c_lflag);
        termios_copy_cc_to_mac(t.c_cc, lt2.c_cc);
        /* Resolve baud rate: BOTHER means use numeric c_ispeed/c_ospeed;
         * otherwise decode the standard CBAUD index to a numeric rate.
         */
        uint32_t cbaud = lt2.c_cflag & LINUX_CBAUD;
        speed_t ispeed, ospeed;
        if (cbaud == LINUX_BOTHER) {
            ispeed = (speed_t) lt2.c_ispeed;
            ospeed = (speed_t) lt2.c_ospeed;
        } else {
            speed_t rate = linux_cbaud_to_speed(cbaud);
            ispeed = rate;
            ospeed = rate;
        }
        if (cfsetispeed(&t, ispeed) < 0 || cfsetospeed(&t, ospeed) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int action = termios_action_for(request);
        if (tcsetattr(host_fd, action, &t) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCGPGRP: {
        /* Get foreground process group from guest state. */
        host_fd_ref_close(&host_ref);
        int32_t val = (int32_t) proc_get_fg_pgrp();
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0)
            return -LINUX_EFAULT;
        return 0;
    }

    case LINUX_FIONREAD: {
        /* Get bytes available for reading */
        int avail = 0;
        if (ioctl(host_fd, FIONREAD, &avail) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        int32_t val = (int32_t) avail;
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    case LINUX_TIOCGPTN: {
        /* Get the slave pty number associated with a /dev/ptmx master fd. Pass
         * the guest fd: proc_pty_master_adopt snapshots the canonical (host_fd,
         * generation) under fd_lock, performs the slave open on a private dup,
         * then re-validates the slot before publishing the keepalive. Passing
         * the per-syscall host_fd_ref dup or a raw host fd would race with
         * sibling close+reuse.
         */
        uint32_t val = proc_pty_master_adopt(fd);
        if (val == UINT32_MAX) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        if (guest_write_small(g, arg, &val, sizeof(val)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }
    case LINUX_TIOCSPTLCK: {
        /* Lock/unlock the slave side of a pty. glibc unlockpt() always passes 0
         * (unlock); util-linux's setlock(1) passes 1 to lock. macOS exposes
         * unlockpt(3) but no re-lock primitive, so the lock branch is accepted
         * as a best-effort no-op for real ptmx masters rather than surfacing as
         * -EINVAL: an application probing the result would otherwise misread
         * the failure as "this kernel has no devpts".
         */
        int32_t lock = 0;
        if (guest_read_small(g, arg, &lock, sizeof(lock)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int rc = 0;
        if (lock == 0) {
            rc = unlockpt(host_fd);
        } else {
            char slave[64];
            if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
                host_fd_ref_close(&host_ref);
                return -LINUX_ENOTTY;
            }
        }
        host_fd_ref_close(&host_ref);
        return rc < 0 ? linux_errno() : 0;
    }
    case LINUX_TIOCGPTPEER: {
        /* Return a fresh fd referring to the slave side of a /dev/ptmx master.
         * Linux added this in 4.13 so callers can avoid the ptsname(3) round
         * trip and any /dev/pts visibility races. The arg holds open(2)-style
         * flags. Restrict to the bits Linux's pty driver actually honors
         * (accmode + O_NOCTTY + O_NONBLOCK + O_CLOEXEC); any other bit, in
         * particular O_CREAT / O_TRUNC / O_EXCL / O_PATH, would be silently
         * ignored on Linux and is rejected with EINVAL here so misuse does not
         * leak nonsense flags into the guest fd table.
         */
        int linux_flags = (int) arg;
        const int allowed = LINUX_O_ACCMODE | LINUX_O_NOCTTY |
                            LINUX_O_NONBLOCK | LINUX_O_CLOEXEC;
        if (linux_flags & ~allowed) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EINVAL;
        }
        char slave[64];
        if (ptsname_r(host_fd, slave, sizeof(slave)) != 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_ENOTTY;
        }
        int oflags = translate_open_flags(linux_flags);
        int host_slave_fd = open(slave, oflags);
        if (host_slave_fd < 0) {
            int saved_errno = errno;
            host_fd_ref_close(&host_ref);
            errno = saved_errno;
            return linux_errno();
        }
        host_fd_ref_close(&host_ref);
        int guest_fd = fd_alloc(FD_REGULAR, host_slave_fd, NULL);
        if (guest_fd < 0) {
            close(host_slave_fd);
            return -LINUX_EMFILE;
        }
        /* Track CLOEXEC + accmode in the guest table so exec honors them; the
         * host fd's own FD_CLOEXEC is per-descriptor and would be lost on the
         * dup that host_fd_ref hands multi-threaded callers.
         */
        fd_publish_linux_flags(guest_fd, linux_flags);
        return guest_fd;
    }

    case LINUX_FIONBIO: {
        /* Set/clear O_NONBLOCK on the fd. Linux FIONBIO takes an int* arg:
         * nonzero enables non-blocking, zero disables it. libuv's
         * uv__nonblock_ioctl() (its default on Linux) issues this on pipe and
         * socket fds at setup; without it the guest's uv_pipe_open() fails with
         * ENOTTY and Node's stdio stream construction throws.
         */
        int32_t on = 0;
        if (guest_read_small(g, arg, &on, sizeof(on)) < 0) {
            host_fd_ref_close(&host_ref);
            return -LINUX_EFAULT;
        }
        int flags = fcntl(host_fd, F_GETFL);
        if (flags < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        int r = fcntl(host_fd, F_SETFL, flags);
        host_fd_ref_close(&host_ref);
        return r < 0 ? linux_errno() : 0;
    }

    default:
        host_fd_ref_close(&host_ref);
        return -LINUX_ENOTTY;
    }
}

/* file space/copy. */

int64_t sys_fallocate(int fd, int mode, int64_t offset, int64_t len)
{
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;

    /* Linux validates offset >= 0 and len > 0 */
    if (offset < 0 || len <= 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL;
    }

    /* FALLOC_FL_PUNCH_HOLE always requires FALLOC_FL_KEEP_SIZE on Linux; map
     * both to macOS F_PUNCHHOLE on the host fd, with a pwrite-zeros fallback
     * for misalignment.
     *
     * The Linux semantic is "reads in [offset, offset+len) return zero; file
     * size unchanged". macOS F_PUNCHHOLE enforces filesystem block alignment on
     * both ends and rejects sub-block requests with EINVAL -- that one-byte
     * probe (offset=0 len=1) foot's wl_shm pool issues surfaces as
     * "fallocate(FALLOC_FL_PUNCH_HOLE) not supported (Invalid argument)"
     * otherwise, and foot disables punch-hole for the whole session.
     *
     * Writing zeros over the region produces the same observable result: reads
     * return zero, file size unchanged. The disk-space deallocation
     * optimisation is lost on the pwrite path, but the probe succeeds, so foot
     * keeps punch-hole enabled and the later, properly aligned calls
     * (page-sized buffers) still take the F_PUNCHHOLE fast path.
     */
    const int kPunchHole =
        LINUX_FALLOC_FL_PUNCH_HOLE | LINUX_FALLOC_FL_KEEP_SIZE;
    if (mode == kPunchHole) {
        struct fpunchhole hole = {
            .fp_flags = 0,
            .reserved = 0,
            .fp_offset = (off_t) offset,
            .fp_length = (off_t) len,
        };
        if (fcntl(host_ref.fd, F_PUNCHHOLE, &hole) == 0) {
            host_fd_ref_close(&host_ref);
            return 0;
        }
        /* EINVAL: misaligned, sub-block, or non-regular file. pwrite zeros only
         * through the current EOF so KEEP_SIZE remains guest-visible. Any other
         * host errno propagates verbatim.
         */
        if (errno != EINVAL) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        struct stat st;
        if (fstat(host_ref.fd, &st) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
        if (offset >= st.st_size) {
            host_fd_ref_close(&host_ref);
            return 0;
        }
        int64_t remaining = st.st_size - offset;
        if (remaining > len)
            remaining = len;

        static const char zeros[4096];
        off_t cur = (off_t) offset;
        while (remaining > 0) {
            size_t chunk = remaining > (int64_t) sizeof(zeros)
                               ? sizeof(zeros)
                               : (size_t) remaining;
            ssize_t nw = pwrite(host_ref.fd, zeros, chunk, cur);
            if (nw < 0) {
                if (errno == EINTR)
                    continue;
                host_fd_ref_close(&host_ref);
                return linux_errno();
            }
            if (nw == 0)
                break; /* defensive; pwrite on a regular file should not 0 */
            cur += nw;
            remaining -= nw;
        }
        host_fd_ref_close(&host_ref);
        return 0;
    }

    /* mode 0 = basic allocation -> ftruncate fallback. Anything else (collapse
     * range, zero range, insert range, unshare range) stays unsupported and
     * surfaces as -EOPNOTSUPP for the guest to handle.
     */
    if (mode != 0) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EOPNOTSUPP;
    }

    struct stat st;
    if (fstat(host_ref.fd, &st) < 0) {
        host_fd_ref_close(&host_ref);
        return linux_errno();
    }

    /* Extend file if needed (ftruncate only extends, does not shrink) */
    int64_t new_size = offset + len;
    if (new_size < offset) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EFBIG; /* Overflow check */
    }
    if (new_size > st.st_size) {
        if (ftruncate(host_ref.fd, new_size) < 0) {
            host_fd_ref_close(&host_ref);
            return linux_errno();
        }
    }
    host_fd_ref_close(&host_ref);
    return 0;
}

int64_t sys_sendfile(guest_t *g,
                     int out_fd,
                     int in_fd,
                     uint64_t offset_gva,
                     uint64_t count)
{
    host_fd_ref_t out_ref, in_ref;
    int64_t err = host_fd_ref_open_regular_io(out_fd, &out_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(in_fd, &in_ref);
    if (err < 0) {
        host_fd_ref_close(&out_ref);
        return err;
    }

    /* macOS sendfile() requires a socket destination, so sendfile emulation
     * uses a pread/write loop for general file-to-file copies.
     */
    int64_t offset = -1;
    if (offset_gva != 0) {
        if (guest_read_small(g, offset_gva, &offset, sizeof(offset)) < 0) {
            err = -LINUX_EFAULT;
            goto out_sendfile;
        }
        if (offset < 0) {
            err = -LINUX_EINVAL;
            goto out_sendfile;
        }
    }

    char buf[65536];
    size_t total = 0, remaining = count;
    while (remaining > 0) {
        size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
        ssize_t nr;
        if (offset >= 0) {
            int64_t intercepted = proc_try_chunk_read_intercept(
                in_fd, in_ref.fd, buf, chunk, offset, 1);
            if (intercepted != INT64_MIN)
                nr = intercepted;
            else
                nr = pread(in_ref.fd, buf, chunk, offset);
        } else {
            int64_t intercepted = proc_try_chunk_read_intercept(
                in_fd, in_ref.fd, buf, chunk, 0, 0);
            if (intercepted != INT64_MIN)
                nr = intercepted;
            else
                nr = read(in_ref.fd, buf, chunk);
        }
        if (nr < 0) {
            if (total > 0)
                break; /* Partial success: report bytes sent */
            err = linux_errno();
            goto out_sendfile;
        }
        if (nr == 0)
            break; /* EOF */

        ssize_t nw = write(out_ref.fd, buf, nr);
        if (nw < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            if (total > 0)
                break; /* Report partial success below */
            err = linux_errno();
            goto out_sendfile;
        }

        total += nw;
        remaining -= nw;
        if (offset >= 0)
            offset += nw;
        if (nw < nr)
            break; /* Short write */
    }

    /* Write back updated offset (even on partial transfer). Preserve partial
     * success: if bytes were transferred but offset writeback fails, return the
     * count rather than -EFAULT.
     */
    if (offset_gva != 0) {
        if (guest_write_small(g, offset_gva, &offset, sizeof(offset)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_sendfile:
    host_fd_ref_close(&in_ref);
    host_fd_ref_close(&out_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

int64_t sys_copy_file_range(guest_t *g,
                            int fd_in,
                            uint64_t off_in_gva,
                            int fd_out,
                            uint64_t off_out_gva,
                            uint64_t len,
                            unsigned int flags)
{
    (void) flags;
    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Read optional offsets from guest memory */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva != 0) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }
    if (off_out_gva != 0) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            err = -LINUX_EFAULT;
            goto out_copy_file_range;
        }
    }

    /* Emulate with pread/pwrite loop */
    char buf[65536];
    size_t total = 0, remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining > sizeof(buf) ? sizeof(buf) : remaining;
        ssize_t nr;
        if (off_in >= 0) {
            int64_t intercepted = proc_try_chunk_read_intercept(
                fd_in, in_ref.fd, buf, chunk, off_in, 1);
            if (intercepted != INT64_MIN)
                nr = intercepted;
            else
                nr = pread(in_ref.fd, buf, chunk, off_in);
        } else {
            int64_t intercepted = proc_try_chunk_read_intercept(
                fd_in, in_ref.fd, buf, chunk, 0, 0);
            if (intercepted != INT64_MIN)
                nr = intercepted;
            else
                nr = read(in_ref.fd, buf, chunk);
        }
        if (nr < 0) {
            if (total > 0)
                break; /* Partial success: report bytes sent */
            err = linux_errno();
            goto out_copy_file_range;
        }
        if (nr == 0)
            break; /* EOF */

        ssize_t nw;
        if (off_out >= 0) {
            nw = pwrite(out_ref.fd, buf, nr, off_out);
        } else {
            nw = write(out_ref.fd, buf, nr);
        }
        if (nw < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            if (total > 0)
                break; /* Report partial success below */
            err = linux_errno();
            goto out_copy_file_range;
        }

        total += nw;
        remaining -= nw;
        if (off_in >= 0)
            off_in += nw;
        if (off_out >= 0)
            off_out += nw;
        if (nw < nr)
            break;
    }

    /* Write back updated offsets (even on partial transfer). Preserve partial
     * success on writeback failure.
     */
    if (off_in_gva != 0) {
        if (guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }
    if (off_out_gva != 0) {
        if (guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0)
            err = total > 0 ? (int64_t) total : -LINUX_EFAULT;
    }

out_copy_file_range:
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    if (err != 0)
        return err;
    return (int64_t) total;
}

/* splice/tee. */

/* splice: emulate by reading from in_fd and writing to out_fd */
int64_t sys_splice(guest_t *g,
                   int fd_in,
                   uint64_t off_in_gva,
                   int fd_out,
                   uint64_t off_out_gva,
                   size_t len,
                   unsigned int flags)
{
    (void) flags;
    host_fd_ref_t in_ref, out_ref;
    int64_t err = host_fd_ref_open_regular_io(fd_in, &in_ref);
    if (err < 0)
        return err;
    err = host_fd_ref_open_regular_io(fd_out, &out_ref);
    if (err < 0) {
        host_fd_ref_close(&in_ref);
        return err;
    }

    /* Handle offsets */
    int64_t off_in = -1, off_out = -1;
    if (off_in_gva) {
        if (guest_read_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }
    if (off_out_gva) {
        if (guest_read_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
            host_fd_ref_close(&out_ref);
            host_fd_ref_close(&in_ref);
            return -LINUX_EFAULT;
        }
    }

    /* Emulate with read/write loop using a stack buffer (matching
     * sendfile/copy_file_range which also use stack buffers).
     */
    uint8_t buf[65536];
    size_t chunk = len > sizeof(buf) ? sizeof(buf) : len;

    size_t total = 0;
    int saved_errno = 0;   /* Preserve errno across guest_write */
    bool rw_error = false; /* Track whether read or write failed */
    while (total < len) {
        size_t n = (len - total) > chunk ? chunk : (len - total);
        ssize_t r = (off_in >= 0) ? pread(in_ref.fd, buf, n, off_in)
                                  : read(in_ref.fd, buf, n);
        if (r < 0) {
            rw_error = true;
            saved_errno = errno;
            break;
        }
        if (r == 0)
            break; /* EOF */
        if (off_in >= 0)
            off_in += r;

        size_t written = 0;
        while (written < (size_t) r) {
            ssize_t w =
                (off_out >= 0)
                    ? pwrite(out_ref.fd, buf + written, r - written, off_out)
                    : write(out_ref.fd, buf + written, r - written);
            if (w <= 0) {
                if (w < 0) {
                    rw_error = true;
                    saved_errno = errno;
                }
                if (w < 0 && saved_errno == EPIPE)
                    signal_queue(LINUX_SIGPIPE);
                total += written; /* Account for partial bytes written */
                goto done;
            }
            written += w;
            if (off_out >= 0)
                off_out += w;
        }
        total += r;
    }

done:
    /* Write back updated offsets. Preserve partial transfer success: if bytes
     * were already moved, return that count even if the offset writeback fails
     * (consistent with sendfile/copy_file_range).
     */
    if (off_in_gva && off_in >= 0 &&
        guest_write_small(g, off_in_gva, &off_in, sizeof(off_in)) < 0) {
        int64_t ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return ret;
    }
    if (off_out_gva && off_out >= 0 &&
        guest_write_small(g, off_out_gva, &off_out, sizeof(off_out)) < 0) {
        int64_t ret = total > 0 ? (int64_t) total : -LINUX_EFAULT;
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return ret;
    }

    /* Return bytes transferred, or errno only if read/write failed. Restore
     * saved_errno since free/guest_write may have clobbered it.
     */
    if (total > 0) {
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return (int64_t) total;
    }
    if (rw_error) {
        errno = saved_errno;
        host_fd_ref_close(&out_ref);
        host_fd_ref_close(&in_ref);
        return linux_errno();
    }
    host_fd_ref_close(&out_ref);
    host_fd_ref_close(&in_ref);
    return 0;
}

/* vmsplice: emulate as writev to the pipe fd */
int64_t sys_vmsplice(guest_t *g,
                     int fd,
                     uint64_t iov_gva,
                     unsigned long nr_segs,
                     unsigned int flags)
{
    (void) flags;
    host_fd_ref_t host_ref;
    int64_t err = host_fd_ref_open_regular_io(fd, &host_ref);
    if (err < 0)
        return err;
    if (nr_segs > 1024) {
        host_fd_ref_close(&host_ref);
        return -LINUX_EINVAL; /* UIO_MAXIOV */
    }

    size_t total = 0;
    for (unsigned long i = 0; i < nr_segs; i++) {
        linux_iovec_t liov;
        if (guest_read_small(g, iov_gva + i * sizeof(linux_iovec_t), &liov,
                             sizeof(liov)) < 0) {
            host_fd_ref_close(&host_ref);
            return total > 0 ? (int64_t) total : -LINUX_EFAULT;
        }

        if (liov.iov_len == 0)
            continue;
        uint64_t avail = 0;
        void *src =
            guest_ptr_bound(g, liov.iov_base, &avail, MEM_PERM_R, liov.iov_len);
        if (!src)
            return host_fd_ref_close(&host_ref),
                   (total > 0 ? (int64_t) total : -LINUX_EFAULT);
        uint64_t len = liov.iov_len;
        if (len > avail)
            len = avail;

        ssize_t w = write(host_ref.fd, src, len);
        if (w < 0) {
            if (errno == EPIPE)
                signal_queue(LINUX_SIGPIPE);
            err = total > 0 ? (int64_t) total : linux_errno();
            host_fd_ref_close(&host_ref);
            return err;
        }
        total += w;
        if ((uint64_t) w < len)
            break;
    }

    host_fd_ref_close(&host_ref);
    return (int64_t) total;
}

/* tee: copy data between two pipes without consuming it. Full emulation would
 * need pipe peeking semantics that macOS does not expose; report EINVAL rather
 * than consuming data incorrectly.
 */
int64_t sys_tee(int fd_in, int fd_out, size_t len, unsigned int flags)
{
    (void) fd_in;
    (void) fd_out;
    (void) len;
    (void) flags;
    return -LINUX_EINVAL;
}
