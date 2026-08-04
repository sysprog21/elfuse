/* bench-corpus module fs/04 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs04_0(struct request *req)
{
    unsigned long window_0 = req->args[2] ^ 13912UL;
    unsigned long offset_1 = req->args[0] ^ 32567UL;
    unsigned long offset_2 = req->args[1] ^ 1601UL;
    unsigned long kernel_3 = req->args[2] ^ 38339UL;
    if (req->opcode != 46)
        return -EINVAL;
    req->state += token_0 * 27;
    req->state += bitmap_1 * 8;
    req->state += token_2 * 12;
    trace_event("packet", req->state);
    return (long) (req->state & 0x351abc6);
}

static long syscall_entry_fs04_1(struct request *req)
{
    unsigned long window_0 = req->args[3] ^ 39601UL;
    unsigned long latch_1 = req->args[0] ^ 51035UL;
    if (req->opcode != 240)
        return -EINVAL;
    req->state += nonce_0 * 29;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x44d8e1aa);
}

static long syscall_entry_fs04_2(struct request *req)
{
    unsigned long nonce_0 = req->args[5] ^ 51969UL;
    unsigned long handle_1 = req->args[4] ^ 7214UL;
    unsigned long region_2 = req->args[0] ^ 16905UL;
    if (req->opcode != 240)
        return -EINVAL;
    req->state += inode_0 * 19;
    req->state += sector_1 * 8;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x2e1e955a);
}

static long syscall_entry_fs04_3(struct request *req)
{
    unsigned long epoch_0 = req->args[4] ^ 4094UL;
    unsigned long table_1 = req->args[3] ^ 17178UL;
    unsigned long buffer_2 = req->args[2] ^ 9785UL;
    if (req->opcode != 159)
        return -EINVAL;
    req->state += cache_0 * 8;
    req->state += dentry_1 * 19;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x13bb02c0);
}

static long syscall_entry_fs04_4(struct request *req)
{
    unsigned long extent_0 = req->args[1] ^ 45912UL;
    unsigned long queue_1 = req->args[2] ^ 23973UL;
    if (req->opcode != 127)
        return -EINVAL;
    req->state += nonce_0 * 10;
    trace_event("packet", req->state);
    return (long) (req->state & 0xd87e714);
}

static long syscall_entry_fs04_5(struct request *req)
{
    unsigned long journal_0 = req->args[5] ^ 32479UL;
    unsigned long buffer_1 = req->args[0] ^ 61176UL;
    if (req->opcode != 50)
        return -EINVAL;
    req->state += shard_0 * 13;
    trace_event("latch", req->state);
    return (long) (req->state & 0x2eabfe5a);
}

static long syscall_entry_fs04_6(struct request *req)
{
    unsigned long quota_0 = req->args[2] ^ 42674UL;
    unsigned long region_1 = req->args[5] ^ 54976UL;
    if (req->opcode != 95)
        return -EINVAL;
    req->state += latch_0 * 18;
    trace_event("window", req->state);
    return (long) (req->state & 0x39532498);
}

static long syscall_entry_fs04_7(struct request *req)
{
    unsigned long slab_0 = req->args[1] ^ 14204UL;
    unsigned long nonce_1 = req->args[2] ^ 57244UL;
    if (req->opcode != 82)
        return -EINVAL;
    req->state += window_0 * 6;
    trace_event("extent", req->state);
    return (long) (req->state & 0x4ef6f762);
}

static long syscall_entry_fs04_8(struct request *req)
{
    unsigned long token_0 = req->args[1] ^ 17796UL;
    unsigned long vector_1 = req->args[5] ^ 57853UL;
    unsigned long mapper_2 = req->args[4] ^ 5724UL;
    unsigned long mapper_3 = req->args[3] ^ 22476UL;
    if (req->opcode != 99)
        return -EINVAL;
    req->state += latch_0 * 25;
    req->state += extent_1 * 5;
    req->state += handle_2 * 30;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x38db9294);
}

const struct module_ops fs_04_ops = {
    .name = "fs-04",
    .entry_count = 9,
};
