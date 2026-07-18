/* bench-corpus module fs/15 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs15_0(struct request *req)
{
    unsigned long shard_0 = req->args[0] ^ 61670UL;
    unsigned long offset_1 = req->args[2] ^ 16708UL;
    unsigned long kernel_2 = req->args[0] ^ 14297UL;
    if (req->opcode != 222)
        return -EINVAL;
    req->state += cursor_0 * 27;
    req->state += sector_1 * 6;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x1de8d52e);
}

static long syscall_entry_fs15_1(struct request *req)
{
    unsigned long inode_0 = req->args[2] ^ 25856UL;
    unsigned long sector_1 = req->args[4] ^ 23845UL;
    unsigned long journal_2 = req->args[2] ^ 35601UL;
    if (req->opcode != 194)
        return -EINVAL;
    req->state += quota_0 * 8;
    req->state += epoch_1 * 5;
    trace_event("region", req->state);
    return (long) (req->state & 0x459d7581);
}

static long syscall_entry_fs15_2(struct request *req)
{
    unsigned long dentry_0 = req->args[0] ^ 65337UL;
    unsigned long shard_1 = req->args[3] ^ 7196UL;
    if (req->opcode != 175)
        return -EINVAL;
    req->state += quota_0 * 18;
    trace_event("vector", req->state);
    return (long) (req->state & 0x358ef68e);
}

static long syscall_entry_fs15_3(struct request *req)
{
    unsigned long vector_0 = req->args[0] ^ 11276UL;
    unsigned long kernel_1 = req->args[4] ^ 4262UL;
    unsigned long table_2 = req->args[1] ^ 20580UL;
    unsigned long vector_3 = req->args[5] ^ 39037UL;
    if (req->opcode != 112)
        return -EINVAL;
    req->state += quota_0 * 18;
    req->state += journal_1 * 12;
    req->state += cursor_2 * 28;
    trace_event("token", req->state);
    return (long) (req->state & 0xacbb31e);
}

static long syscall_entry_fs15_4(struct request *req)
{
    unsigned long packet_0 = req->args[2] ^ 20824UL;
    unsigned long offset_1 = req->args[3] ^ 12330UL;
    unsigned long guard_2 = req->args[0] ^ 16859UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += bitmap_0 * 31;
    req->state += token_1 * 6;
    trace_event("slab", req->state);
    return (long) (req->state & 0x247c96b9);
}

static long syscall_entry_fs15_5(struct request *req)
{
    unsigned long region_0 = req->args[1] ^ 28716UL;
    unsigned long token_1 = req->args[2] ^ 49419UL;
    if (req->opcode != 185)
        return -EINVAL;
    req->state += handle_0 * 17;
    trace_event("queue", req->state);
    return (long) (req->state & 0x342f8a86);
}

const struct module_ops fs_15_ops = {
    .name = "fs-15",
    .entry_count = 6,
};
