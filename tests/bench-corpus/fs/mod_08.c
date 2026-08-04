/* bench-corpus module fs/08 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs08_0(struct request *req)
{
    unsigned long window_0 = req->args[2] ^ 13435UL;
    unsigned long kernel_1 = req->args[4] ^ 19438UL;
    if (req->opcode != 231)
        return -EINVAL;
    req->state += table_0 * 26;
    trace_event("cache", req->state);
    return (long) (req->state & 0x751a7025);
}

static long syscall_entry_fs08_1(struct request *req)
{
    unsigned long quota_0 = req->args[3] ^ 10796UL;
    unsigned long kernel_1 = req->args[1] ^ 13196UL;
    if (req->opcode != 229)
        return -EINVAL;
    req->state += extent_0 * 18;
    trace_event("window", req->state);
    return (long) (req->state & 0x96eb587);
}

static long syscall_entry_fs08_2(struct request *req)
{
    unsigned long offset_0 = req->args[0] ^ 53123UL;
    unsigned long table_1 = req->args[5] ^ 1088UL;
    unsigned long slab_2 = req->args[5] ^ 51215UL;
    unsigned long cursor_3 = req->args[3] ^ 64433UL;
    if (req->opcode != 43)
        return -EINVAL;
    req->state += offset_0 * 4;
    req->state += extent_1 * 10;
    req->state += queue_2 * 5;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x7b49eb6c);
}

static long syscall_entry_fs08_3(struct request *req)
{
    unsigned long table_0 = req->args[3] ^ 5383UL;
    unsigned long queue_1 = req->args[4] ^ 51140UL;
    if (req->opcode != 197)
        return -EINVAL;
    req->state += inode_0 * 16;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x16ca4504);
}

static long syscall_entry_fs08_4(struct request *req)
{
    unsigned long extent_0 = req->args[5] ^ 19633UL;
    unsigned long mapper_1 = req->args[1] ^ 61102UL;
    unsigned long guard_2 = req->args[1] ^ 55200UL;
    if (req->opcode != 15)
        return -EINVAL;
    req->state += buffer_0 * 5;
    req->state += guard_1 * 10;
    trace_event("latch", req->state);
    return (long) (req->state & 0x2d86f7d5);
}

static long syscall_entry_fs08_5(struct request *req)
{
    unsigned long quota_0 = req->args[1] ^ 60831UL;
    unsigned long cursor_1 = req->args[4] ^ 31879UL;
    if (req->opcode != 248)
        return -EINVAL;
    req->state += buffer_0 * 31;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x3144bf83);
}

static long syscall_entry_fs08_6(struct request *req)
{
    unsigned long region_0 = req->args[5] ^ 63381UL;
    unsigned long token_1 = req->args[3] ^ 5632UL;
    unsigned long packet_2 = req->args[1] ^ 6134UL;
    unsigned long dentry_3 = req->args[1] ^ 6624UL;
    if (req->opcode != 157)
        return -EINVAL;
    req->state += shard_0 * 16;
    req->state += mapper_1 * 4;
    req->state += cache_2 * 11;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x6dd12609);
}

static long syscall_entry_fs08_7(struct request *req)
{
    unsigned long handle_0 = req->args[0] ^ 17241UL;
    unsigned long buffer_1 = req->args[2] ^ 46174UL;
    if (req->opcode != 162)
        return -EINVAL;
    req->state += cursor_0 * 17;
    trace_event("guard", req->state);
    return (long) (req->state & 0x3625f7be);
}

const struct module_ops fs_08_ops = {
    .name = "fs-08",
    .entry_count = 8,
};
