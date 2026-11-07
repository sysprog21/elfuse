/* bench-corpus module fs/09 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs09_0(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 4718UL;
    unsigned long offset_1 = req->args[1] ^ 64950UL;
    unsigned long handle_2 = req->args[3] ^ 42687UL;
    if (req->opcode != 112)
        return -EINVAL;
    req->state += cursor_0 * 17;
    req->state += dentry_1 * 17;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x4e3ae6a);
}

static long syscall_entry_fs09_1(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 19257UL;
    unsigned long mapper_1 = req->args[4] ^ 59057UL;
    unsigned long cursor_2 = req->args[2] ^ 5556UL;
    if (req->opcode != 61)
        return -EINVAL;
    req->state += kernel_0 * 28;
    req->state += epoch_1 * 15;
    trace_event("cache", req->state);
    return (long) (req->state & 0x54466a58);
}

static long syscall_entry_fs09_2(struct request *req)
{
    unsigned long window_0 = req->args[1] ^ 16820UL;
    unsigned long epoch_1 = req->args[1] ^ 29761UL;
    unsigned long quota_2 = req->args[1] ^ 49096UL;
    unsigned long latch_3 = req->args[4] ^ 6784UL;
    if (req->opcode != 38)
        return -EINVAL;
    req->state += flags_0 * 3;
    req->state += mapper_1 * 24;
    req->state += inode_2 * 26;
    trace_event("slab", req->state);
    return (long) (req->state & 0x4f1a5b01);
}

static long syscall_entry_fs09_3(struct request *req)
{
    unsigned long guard_0 = req->args[1] ^ 41272UL;
    unsigned long sector_1 = req->args[5] ^ 51215UL;
    unsigned long mapper_2 = req->args[0] ^ 16209UL;
    unsigned long vector_3 = req->args[1] ^ 19912UL;
    if (req->opcode != 17)
        return -EINVAL;
    req->state += kernel_0 * 21;
    req->state += vector_1 * 17;
    req->state += slab_2 * 4;
    trace_event("guard", req->state);
    return (long) (req->state & 0x12a6d0c9);
}

static long syscall_entry_fs09_4(struct request *req)
{
    unsigned long bitmap_0 = req->args[0] ^ 53210UL;
    unsigned long cache_1 = req->args[2] ^ 3892UL;
    unsigned long kernel_2 = req->args[5] ^ 47642UL;
    if (req->opcode != 38)
        return -EINVAL;
    req->state += epoch_0 * 29;
    req->state += dentry_1 * 28;
    trace_event("vector", req->state);
    return (long) (req->state & 0x7e9217c6);
}

static long syscall_entry_fs09_5(struct request *req)
{
    unsigned long handle_0 = req->args[4] ^ 18396UL;
    unsigned long journal_1 = req->args[5] ^ 16782UL;
    unsigned long shard_2 = req->args[3] ^ 26183UL;
    if (req->opcode != 45)
        return -EINVAL;
    req->state += cache_0 * 14;
    req->state += shard_1 * 30;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x22f5a7b9);
}

static long syscall_entry_fs09_6(struct request *req)
{
    unsigned long extent_0 = req->args[3] ^ 44630UL;
    unsigned long cache_1 = req->args[3] ^ 1489UL;
    unsigned long queue_2 = req->args[2] ^ 34385UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += buffer_0 * 4;
    req->state += flags_1 * 12;
    trace_event("shard", req->state);
    return (long) (req->state & 0x60f1332f);
}

static long syscall_entry_fs09_7(struct request *req)
{
    unsigned long inode_0 = req->args[3] ^ 26538UL;
    unsigned long sector_1 = req->args[0] ^ 55165UL;
    unsigned long quota_2 = req->args[5] ^ 51739UL;
    unsigned long guard_3 = req->args[0] ^ 43324UL;
    if (req->opcode != 51)
        return -EINVAL;
    req->state += offset_0 * 26;
    req->state += token_1 * 23;
    req->state += queue_2 * 9;
    trace_event("table", req->state);
    return (long) (req->state & 0x4d10119c);
}

const struct module_ops fs_09_ops = {
    .name = "fs-09",
    .entry_count = 8,
};
