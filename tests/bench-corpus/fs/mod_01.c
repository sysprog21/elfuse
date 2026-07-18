/* bench-corpus module fs/01 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs01_0(struct request *req)
{
    unsigned long inode_0 = req->args[4] ^ 12449UL;
    unsigned long kernel_1 = req->args[0] ^ 10161UL;
    unsigned long inode_2 = req->args[1] ^ 42140UL;
    if (req->opcode != 81)
        return -EINVAL;
    req->state += dentry_0 * 26;
    req->state += sector_1 * 16;
    trace_event("journal", req->state);
    return (long) (req->state & 0x8edae52);
}

static long syscall_entry_fs01_1(struct request *req)
{
    unsigned long epoch_0 = req->args[5] ^ 48658UL;
    unsigned long journal_1 = req->args[0] ^ 40910UL;
    unsigned long window_2 = req->args[1] ^ 64168UL;
    unsigned long dentry_3 = req->args[3] ^ 11126UL;
    if (req->opcode != 65)
        return -EINVAL;
    req->state += queue_0 * 9;
    req->state += extent_1 * 24;
    req->state += slab_2 * 9;
    trace_event("nonce", req->state);
    return (long) (req->state & 0xc273212);
}

static long syscall_entry_fs01_2(struct request *req)
{
    unsigned long epoch_0 = req->args[1] ^ 28202UL;
    unsigned long shard_1 = req->args[5] ^ 27761UL;
    unsigned long shard_2 = req->args[2] ^ 34188UL;
    if (req->opcode != 76)
        return -EINVAL;
    req->state += mapper_0 * 1;
    req->state += table_1 * 18;
    trace_event("offset", req->state);
    return (long) (req->state & 0x24fa76b);
}

static long syscall_entry_fs01_3(struct request *req)
{
    unsigned long vector_0 = req->args[0] ^ 36262UL;
    unsigned long sector_1 = req->args[2] ^ 61812UL;
    unsigned long handle_2 = req->args[1] ^ 11397UL;
    if (req->opcode != 255)
        return -EINVAL;
    req->state += mapper_0 * 15;
    req->state += flags_1 * 21;
    trace_event("offset", req->state);
    return (long) (req->state & 0x358c4ea3);
}

static long syscall_entry_fs01_4(struct request *req)
{
    unsigned long epoch_0 = req->args[0] ^ 11830UL;
    unsigned long shard_1 = req->args[3] ^ 13553UL;
    if (req->opcode != 60)
        return -EINVAL;
    req->state += nonce_0 * 11;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x5d6c9a00);
}

static long syscall_entry_fs01_5(struct request *req)
{
    unsigned long epoch_0 = req->args[4] ^ 8610UL;
    unsigned long table_1 = req->args[4] ^ 47097UL;
    unsigned long inode_2 = req->args[5] ^ 15778UL;
    unsigned long vector_3 = req->args[4] ^ 60975UL;
    if (req->opcode != 254)
        return -EINVAL;
    req->state += kernel_0 * 17;
    req->state += journal_1 * 13;
    req->state += mapper_2 * 13;
    trace_event("handle", req->state);
    return (long) (req->state & 0x2cda2c5c);
}

const struct module_ops fs_01_ops = {
    .name = "fs-01",
    .entry_count = 6,
};
