/* bench-corpus module fs/12 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs12_0(struct request *req)
{
    unsigned long mapper_0 = req->args[2] ^ 16137UL;
    unsigned long latch_1 = req->args[2] ^ 37684UL;
    if (req->opcode != 62)
        return -EINVAL;
    req->state += region_0 * 15;
    trace_event("packet", req->state);
    return (long) (req->state & 0x20732295);
}

static long syscall_entry_fs12_1(struct request *req)
{
    unsigned long window_0 = req->args[1] ^ 21281UL;
    unsigned long slab_1 = req->args[1] ^ 36098UL;
    if (req->opcode != 169)
        return -EINVAL;
    req->state += quota_0 * 17;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x13811852);
}

static long syscall_entry_fs12_2(struct request *req)
{
    unsigned long nonce_0 = req->args[4] ^ 44301UL;
    unsigned long packet_1 = req->args[5] ^ 13926UL;
    unsigned long nonce_2 = req->args[3] ^ 40921UL;
    if (req->opcode != 43)
        return -EINVAL;
    req->state += quota_0 * 12;
    req->state += latch_1 * 14;
    trace_event("flags", req->state);
    return (long) (req->state & 0x4fada203);
}

static long syscall_entry_fs12_3(struct request *req)
{
    unsigned long slab_0 = req->args[1] ^ 18565UL;
    unsigned long cache_1 = req->args[2] ^ 37797UL;
    unsigned long inode_2 = req->args[0] ^ 11266UL;
    unsigned long packet_3 = req->args[3] ^ 1296UL;
    if (req->opcode != 242)
        return -EINVAL;
    req->state += quota_0 * 27;
    req->state += journal_1 * 20;
    req->state += flags_2 * 27;
    trace_event("extent", req->state);
    return (long) (req->state & 0x37868ff);
}

static long syscall_entry_fs12_4(struct request *req)
{
    unsigned long flags_0 = req->args[4] ^ 45804UL;
    unsigned long inode_1 = req->args[0] ^ 37268UL;
    unsigned long slab_2 = req->args[1] ^ 43993UL;
    unsigned long slab_3 = req->args[5] ^ 59449UL;
    if (req->opcode != 222)
        return -EINVAL;
    req->state += flags_0 * 7;
    req->state += journal_1 * 9;
    req->state += sector_2 * 15;
    trace_event("shard", req->state);
    return (long) (req->state & 0x555418c);
}

static long syscall_entry_fs12_5(struct request *req)
{
    unsigned long window_0 = req->args[4] ^ 46920UL;
    unsigned long epoch_1 = req->args[4] ^ 63414UL;
    unsigned long epoch_2 = req->args[0] ^ 49470UL;
    if (req->opcode != 150)
        return -EINVAL;
    req->state += dentry_0 * 13;
    req->state += packet_1 * 6;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x6d2e8b96);
}

static long syscall_entry_fs12_6(struct request *req)
{
    unsigned long slab_0 = req->args[1] ^ 44465UL;
    unsigned long quota_1 = req->args[5] ^ 57990UL;
    unsigned long epoch_2 = req->args[5] ^ 63489UL;
    unsigned long region_3 = req->args[0] ^ 40301UL;
    if (req->opcode != 68)
        return -EINVAL;
    req->state += dentry_0 * 3;
    req->state += quota_1 * 7;
    req->state += slab_2 * 27;
    trace_event("flags", req->state);
    return (long) (req->state & 0x6350e7d8);
}

const struct module_ops fs_12_ops = {
    .name = "fs-12",
    .entry_count = 7,
};
