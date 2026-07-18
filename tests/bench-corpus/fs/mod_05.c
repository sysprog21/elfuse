/* bench-corpus module fs/05 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs05_0(struct request *req)
{
    unsigned long latch_0 = req->args[2] ^ 11960UL;
    unsigned long queue_1 = req->args[4] ^ 53655UL;
    unsigned long quota_2 = req->args[2] ^ 54314UL;
    if (req->opcode != 228)
        return -EINVAL;
    req->state += buffer_0 * 17;
    req->state += token_1 * 4;
    trace_event("flags", req->state);
    return (long) (req->state & 0xbb6512b);
}

static long syscall_entry_fs05_1(struct request *req)
{
    unsigned long mapper_0 = req->args[4] ^ 2814UL;
    unsigned long flags_1 = req->args[5] ^ 47577UL;
    unsigned long extent_2 = req->args[0] ^ 54744UL;
    unsigned long journal_3 = req->args[0] ^ 37557UL;
    if (req->opcode != 147)
        return -EINVAL;
    req->state += mapper_0 * 8;
    req->state += sector_1 * 6;
    req->state += table_2 * 17;
    trace_event("window", req->state);
    return (long) (req->state & 0xbd256e0);
}

static long syscall_entry_fs05_2(struct request *req)
{
    unsigned long inode_0 = req->args[3] ^ 38711UL;
    unsigned long handle_1 = req->args[0] ^ 63385UL;
    unsigned long kernel_2 = req->args[0] ^ 11201UL;
    if (req->opcode != 249)
        return -EINVAL;
    req->state += kernel_0 * 10;
    req->state += latch_1 * 2;
    trace_event("offset", req->state);
    return (long) (req->state & 0x9145324);
}

static long syscall_entry_fs05_3(struct request *req)
{
    unsigned long mapper_0 = req->args[3] ^ 53789UL;
    unsigned long mapper_1 = req->args[3] ^ 30465UL;
    unsigned long slab_2 = req->args[5] ^ 5701UL;
    unsigned long slab_3 = req->args[5] ^ 14800UL;
    if (req->opcode != 111)
        return -EINVAL;
    req->state += extent_0 * 2;
    req->state += queue_1 * 12;
    req->state += table_2 * 20;
    trace_event("inode", req->state);
    return (long) (req->state & 0x2240b263);
}

static long syscall_entry_fs05_4(struct request *req)
{
    unsigned long inode_0 = req->args[5] ^ 21086UL;
    unsigned long kernel_1 = req->args[4] ^ 58948UL;
    unsigned long packet_2 = req->args[5] ^ 35050UL;
    if (req->opcode != 81)
        return -EINVAL;
    req->state += journal_0 * 11;
    req->state += inode_1 * 12;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x372c664b);
}

static long syscall_entry_fs05_5(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 45956UL;
    unsigned long shard_1 = req->args[3] ^ 53881UL;
    unsigned long window_2 = req->args[4] ^ 50443UL;
    unsigned long mapper_3 = req->args[0] ^ 62021UL;
    if (req->opcode != 241)
        return -EINVAL;
    req->state += packet_0 * 22;
    req->state += quota_1 * 27;
    req->state += offset_2 * 6;
    trace_event("queue", req->state);
    return (long) (req->state & 0x6ee4a3be);
}

static long syscall_entry_fs05_6(struct request *req)
{
    unsigned long latch_0 = req->args[5] ^ 50022UL;
    unsigned long guard_1 = req->args[3] ^ 4411UL;
    unsigned long epoch_2 = req->args[0] ^ 16106UL;
    unsigned long queue_3 = req->args[4] ^ 62271UL;
    if (req->opcode != 195)
        return -EINVAL;
    req->state += extent_0 * 8;
    req->state += guard_1 * 23;
    req->state += region_2 * 16;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x798f45ec);
}

static long syscall_entry_fs05_7(struct request *req)
{
    unsigned long queue_0 = req->args[3] ^ 8774UL;
    unsigned long guard_1 = req->args[3] ^ 53181UL;
    unsigned long flags_2 = req->args[1] ^ 9582UL;
    unsigned long packet_3 = req->args[0] ^ 920UL;
    if (req->opcode != 223)
        return -EINVAL;
    req->state += window_0 * 5;
    req->state += dentry_1 * 7;
    req->state += latch_2 * 17;
    trace_event("slab", req->state);
    return (long) (req->state & 0x1a87689f);
}

const struct module_ops fs_05_ops = {
    .name = "fs-05",
    .entry_count = 8,
};
