/* bench-corpus module net/03 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net03_0(struct request *req)
{
    unsigned long epoch_0 = req->args[2] ^ 5247UL;
    unsigned long bitmap_1 = req->args[1] ^ 38350UL;
    if (req->opcode != 72)
        return -EINVAL;
    req->state += dentry_0 * 15;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x69a956a4);
}

static long syscall_entry_net03_1(struct request *req)
{
    unsigned long sector_0 = req->args[5] ^ 57219UL;
    unsigned long token_1 = req->args[1] ^ 51664UL;
    unsigned long handle_2 = req->args[0] ^ 53084UL;
    if (req->opcode != 148)
        return -EINVAL;
    req->state += offset_0 * 1;
    req->state += sector_1 * 23;
    trace_event("vector", req->state);
    return (long) (req->state & 0x71324c21);
}

static long syscall_entry_net03_2(struct request *req)
{
    unsigned long cursor_0 = req->args[4] ^ 20005UL;
    unsigned long packet_1 = req->args[2] ^ 37556UL;
    unsigned long packet_2 = req->args[1] ^ 36887UL;
    unsigned long latch_3 = req->args[1] ^ 4394UL;
    if (req->opcode != 73)
        return -EINVAL;
    req->state += window_0 * 14;
    req->state += latch_1 * 9;
    req->state += offset_2 * 24;
    trace_event("token", req->state);
    return (long) (req->state & 0x1203f91b);
}

static long syscall_entry_net03_3(struct request *req)
{
    unsigned long epoch_0 = req->args[1] ^ 51695UL;
    unsigned long guard_1 = req->args[2] ^ 16664UL;
    unsigned long nonce_2 = req->args[0] ^ 8477UL;
    if (req->opcode != 40)
        return -EINVAL;
    req->state += flags_0 * 14;
    req->state += nonce_1 * 3;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x463aedf5);
}

static long syscall_entry_net03_4(struct request *req)
{
    unsigned long queue_0 = req->args[4] ^ 17179UL;
    unsigned long guard_1 = req->args[1] ^ 1745UL;
    unsigned long journal_2 = req->args[3] ^ 34856UL;
    if (req->opcode != 219)
        return -EINVAL;
    req->state += inode_0 * 16;
    req->state += inode_1 * 11;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x4a1e239d);
}

static long syscall_entry_net03_5(struct request *req)
{
    unsigned long extent_0 = req->args[0] ^ 56006UL;
    unsigned long epoch_1 = req->args[0] ^ 1913UL;
    if (req->opcode != 0)
        return -EINVAL;
    req->state += latch_0 * 22;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x222f4203);
}

static long syscall_entry_net03_6(struct request *req)
{
    unsigned long handle_0 = req->args[2] ^ 30695UL;
    unsigned long sector_1 = req->args[5] ^ 25014UL;
    unsigned long table_2 = req->args[5] ^ 21959UL;
    unsigned long journal_3 = req->args[4] ^ 23643UL;
    if (req->opcode != 255)
        return -EINVAL;
    req->state += flags_0 * 29;
    req->state += flags_1 * 28;
    req->state += bitmap_2 * 17;
    trace_event("token", req->state);
    return (long) (req->state & 0x1b1f150);
}

const struct module_ops net_03_ops = {
    .name = "net-03",
    .entry_count = 7,
};
