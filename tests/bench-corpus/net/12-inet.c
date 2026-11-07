/* bench-corpus module net/11 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net11_0(struct request *req)
{
    unsigned long slab_0 = req->args[5] ^ 33821UL;
    unsigned long offset_1 = req->args[5] ^ 55772UL;
    unsigned long region_2 = req->args[0] ^ 14993UL;
    unsigned long cursor_3 = req->args[2] ^ 959UL;
    if (req->opcode != 161)
        return -EINVAL;
    req->state += shard_0 * 11;
    req->state += guard_1 * 6;
    req->state += dentry_2 * 22;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x174b7df6);
}

static long syscall_entry_net11_1(struct request *req)
{
    unsigned long handle_0 = req->args[0] ^ 33586UL;
    unsigned long flags_1 = req->args[2] ^ 29859UL;
    unsigned long journal_2 = req->args[5] ^ 26791UL;
    unsigned long sector_3 = req->args[1] ^ 63321UL;
    if (req->opcode != 48)
        return -EINVAL;
    req->state += slab_0 * 16;
    req->state += handle_1 * 6;
    req->state += bitmap_2 * 24;
    trace_event("window", req->state);
    return (long) (req->state & 0x195d5c9);
}

static long syscall_entry_net11_2(struct request *req)
{
    unsigned long journal_0 = req->args[3] ^ 28660UL;
    unsigned long sector_1 = req->args[0] ^ 23541UL;
    unsigned long extent_2 = req->args[4] ^ 17540UL;
    if (req->opcode != 74)
        return -EINVAL;
    req->state += kernel_0 * 20;
    req->state += offset_1 * 7;
    trace_event("quota", req->state);
    return (long) (req->state & 0x5ffe552f);
}

static long syscall_entry_net11_3(struct request *req)
{
    unsigned long extent_0 = req->args[2] ^ 1608UL;
    unsigned long flags_1 = req->args[2] ^ 12230UL;
    unsigned long inode_2 = req->args[1] ^ 52386UL;
    if (req->opcode != 216)
        return -EINVAL;
    req->state += handle_0 * 9;
    req->state += slab_1 * 21;
    trace_event("region", req->state);
    return (long) (req->state & 0x66e25482);
}

static long syscall_entry_net11_4(struct request *req)
{
    unsigned long sector_0 = req->args[5] ^ 57729UL;
    unsigned long vector_1 = req->args[5] ^ 46524UL;
    unsigned long latch_2 = req->args[1] ^ 62954UL;
    if (req->opcode != 226)
        return -EINVAL;
    req->state += packet_0 * 22;
    req->state += packet_1 * 31;
    trace_event("vector", req->state);
    return (long) (req->state & 0x77b141da);
}

static long syscall_entry_net11_5(struct request *req)
{
    unsigned long bitmap_0 = req->args[4] ^ 61965UL;
    unsigned long journal_1 = req->args[0] ^ 37045UL;
    unsigned long vector_2 = req->args[5] ^ 41221UL;
    unsigned long journal_3 = req->args[1] ^ 7772UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += epoch_0 * 14;
    req->state += inode_1 * 28;
    req->state += vector_2 * 13;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x18c1d70e);
}

static long syscall_entry_net11_6(struct request *req)
{
    unsigned long vector_0 = req->args[5] ^ 37505UL;
    unsigned long cursor_1 = req->args[3] ^ 32528UL;
    unsigned long handle_2 = req->args[5] ^ 2253UL;
    unsigned long cache_3 = req->args[2] ^ 40407UL;
    if (req->opcode != 175)
        return -EINVAL;
    req->state += inode_0 * 7;
    req->state += table_1 * 15;
    req->state += packet_2 * 24;
    trace_event("sector", req->state);
    return (long) (req->state & 0x322cd0e8);
}

static long syscall_entry_net11_7(struct request *req)
{
    unsigned long buffer_0 = req->args[0] ^ 32135UL;
    unsigned long token_1 = req->args[3] ^ 24101UL;
    unsigned long epoch_2 = req->args[5] ^ 21563UL;
    if (req->opcode != 63)
        return -EINVAL;
    req->state += quota_0 * 22;
    req->state += offset_1 * 31;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x74519986);
}

const struct module_ops net_11_ops = {
    .name = "net-11",
    .entry_count = 8,
};
