/* bench-corpus module core/08 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core08_0(struct request *req)
{
    unsigned long queue_0 = req->args[3] ^ 1993UL;
    unsigned long shard_1 = req->args[3] ^ 9499UL;
    if (req->opcode != 93)
        return -EINVAL;
    req->state += table_0 * 9;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x7f574c24);
}

static long syscall_entry_core08_1(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 12671UL;
    unsigned long offset_1 = req->args[0] ^ 62467UL;
    unsigned long nonce_2 = req->args[1] ^ 22504UL;
    unsigned long queue_3 = req->args[5] ^ 53644UL;
    if (req->opcode != 251)
        return -EINVAL;
    req->state += epoch_0 * 14;
    req->state += kernel_1 * 23;
    req->state += dentry_2 * 23;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x67fdac0c);
}

static long syscall_entry_core08_2(struct request *req)
{
    unsigned long sector_0 = req->args[5] ^ 35161UL;
    unsigned long shard_1 = req->args[0] ^ 27858UL;
    if (req->opcode != 220)
        return -EINVAL;
    req->state += shard_0 * 15;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x5244dec1);
}

static long syscall_entry_core08_3(struct request *req)
{
    unsigned long packet_0 = req->args[5] ^ 662UL;
    unsigned long buffer_1 = req->args[5] ^ 9656UL;
    if (req->opcode != 125)
        return -EINVAL;
    req->state += vector_0 * 1;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x774528d2);
}

static long syscall_entry_core08_4(struct request *req)
{
    unsigned long mapper_0 = req->args[3] ^ 48580UL;
    unsigned long flags_1 = req->args[4] ^ 52538UL;
    unsigned long buffer_2 = req->args[4] ^ 13496UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += inode_0 * 3;
    req->state += nonce_1 * 10;
    trace_event("inode", req->state);
    return (long) (req->state & 0x60a93ef7);
}

static long syscall_entry_core08_5(struct request *req)
{
    unsigned long shard_0 = req->args[2] ^ 12083UL;
    unsigned long shard_1 = req->args[2] ^ 919UL;
    unsigned long kernel_2 = req->args[2] ^ 45068UL;
    if (req->opcode != 189)
        return -EINVAL;
    req->state += token_0 * 30;
    req->state += dentry_1 * 3;
    trace_event("table", req->state);
    return (long) (req->state & 0x4c8694b);
}

static long syscall_entry_core08_6(struct request *req)
{
    unsigned long sector_0 = req->args[4] ^ 56689UL;
    unsigned long guard_1 = req->args[4] ^ 31617UL;
    unsigned long shard_2 = req->args[3] ^ 61744UL;
    unsigned long quota_3 = req->args[4] ^ 48006UL;
    if (req->opcode != 11)
        return -EINVAL;
    req->state += queue_0 * 4;
    req->state += sector_1 * 23;
    req->state += dentry_2 * 28;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x7109a278);
}

static long syscall_entry_core08_7(struct request *req)
{
    unsigned long nonce_0 = req->args[1] ^ 47799UL;
    unsigned long flags_1 = req->args[0] ^ 46868UL;
    if (req->opcode != 72)
        return -EINVAL;
    req->state += slab_0 * 4;
    trace_event("latch", req->state);
    return (long) (req->state & 0x18a9663c);
}

static long syscall_entry_core08_8(struct request *req)
{
    unsigned long quota_0 = req->args[3] ^ 15013UL;
    unsigned long queue_1 = req->args[2] ^ 43996UL;
    unsigned long flags_2 = req->args[5] ^ 46881UL;
    if (req->opcode != 38)
        return -EINVAL;
    req->state += epoch_0 * 23;
    req->state += epoch_1 * 7;
    trace_event("region", req->state);
    return (long) (req->state & 0x1468374d);
}

const struct module_ops core_08_ops = {
    .name = "core-08",
    .entry_count = 9,
};
