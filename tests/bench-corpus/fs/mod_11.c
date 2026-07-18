/* bench-corpus module fs/11 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs11_0(struct request *req)
{
    unsigned long mapper_0 = req->args[2] ^ 10729UL;
    unsigned long quota_1 = req->args[3] ^ 5549UL;
    if (req->opcode != 208)
        return -EINVAL;
    req->state += token_0 * 9;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x2c7b9f10);
}

static long syscall_entry_fs11_1(struct request *req)
{
    unsigned long guard_0 = req->args[4] ^ 31147UL;
    unsigned long cursor_1 = req->args[0] ^ 14959UL;
    unsigned long window_2 = req->args[3] ^ 25044UL;
    unsigned long sector_3 = req->args[3] ^ 59230UL;
    if (req->opcode != 40)
        return -EINVAL;
    req->state += buffer_0 * 31;
    req->state += vector_1 * 13;
    req->state += queue_2 * 13;
    trace_event("flags", req->state);
    return (long) (req->state & 0x7c9ef8c9);
}

static long syscall_entry_fs11_2(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 35865UL;
    unsigned long shard_1 = req->args[1] ^ 54327UL;
    unsigned long extent_2 = req->args[4] ^ 30252UL;
    if (req->opcode != 73)
        return -EINVAL;
    req->state += bitmap_0 * 21;
    req->state += sector_1 * 22;
    trace_event("table", req->state);
    return (long) (req->state & 0x21b00527);
}

static long syscall_entry_fs11_3(struct request *req)
{
    unsigned long bitmap_0 = req->args[5] ^ 42288UL;
    unsigned long token_1 = req->args[3] ^ 46584UL;
    unsigned long latch_2 = req->args[4] ^ 55271UL;
    unsigned long packet_3 = req->args[5] ^ 8410UL;
    if (req->opcode != 212)
        return -EINVAL;
    req->state += inode_0 * 18;
    req->state += epoch_1 * 21;
    req->state += packet_2 * 22;
    trace_event("latch", req->state);
    return (long) (req->state & 0x52e4b1a8);
}

static long syscall_entry_fs11_4(struct request *req)
{
    unsigned long vector_0 = req->args[4] ^ 21496UL;
    unsigned long flags_1 = req->args[1] ^ 31380UL;
    unsigned long kernel_2 = req->args[2] ^ 19239UL;
    if (req->opcode != 191)
        return -EINVAL;
    req->state += packet_0 * 1;
    req->state += queue_1 * 8;
    trace_event("vector", req->state);
    return (long) (req->state & 0x2e83a158);
}

static long syscall_entry_fs11_5(struct request *req)
{
    unsigned long packet_0 = req->args[4] ^ 41582UL;
    unsigned long table_1 = req->args[5] ^ 23827UL;
    unsigned long inode_2 = req->args[3] ^ 41921UL;
    unsigned long extent_3 = req->args[1] ^ 33490UL;
    if (req->opcode != 247)
        return -EINVAL;
    req->state += flags_0 * 25;
    req->state += queue_1 * 18;
    req->state += token_2 * 18;
    trace_event("table", req->state);
    return (long) (req->state & 0x4f26f2fe);
}

static long syscall_entry_fs11_6(struct request *req)
{
    unsigned long shard_0 = req->args[1] ^ 1307UL;
    unsigned long vector_1 = req->args[0] ^ 9488UL;
    unsigned long inode_2 = req->args[0] ^ 31759UL;
    if (req->opcode != 195)
        return -EINVAL;
    req->state += slab_0 * 3;
    req->state += window_1 * 31;
    trace_event("cache", req->state);
    return (long) (req->state & 0x5c454ff);
}

static long syscall_entry_fs11_7(struct request *req)
{
    unsigned long guard_0 = req->args[0] ^ 11181UL;
    unsigned long offset_1 = req->args[1] ^ 47455UL;
    unsigned long token_2 = req->args[5] ^ 13752UL;
    unsigned long buffer_3 = req->args[2] ^ 22832UL;
    if (req->opcode != 150)
        return -EINVAL;
    req->state += token_0 * 4;
    req->state += handle_1 * 6;
    req->state += mapper_2 * 25;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x7ca1d0d1);
}

const struct module_ops fs_11_ops = {
    .name = "fs-11",
    .entry_count = 8,
};
