/* bench-corpus module fs/13 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs13_0(struct request *req)
{
    unsigned long cache_0 = req->args[2] ^ 31238UL;
    unsigned long vector_1 = req->args[4] ^ 2998UL;
    if (req->opcode != 148)
        return -EINVAL;
    req->state += packet_0 * 27;
    trace_event("sector", req->state);
    return (long) (req->state & 0x1d28dd1e);
}

static long syscall_entry_fs13_1(struct request *req)
{
    unsigned long handle_0 = req->args[2] ^ 17281UL;
    unsigned long guard_1 = req->args[3] ^ 54083UL;
    unsigned long shard_2 = req->args[0] ^ 43222UL;
    if (req->opcode != 67)
        return -EINVAL;
    req->state += token_0 * 7;
    req->state += table_1 * 2;
    trace_event("table", req->state);
    return (long) (req->state & 0x494a48a4);
}

static long syscall_entry_fs13_2(struct request *req)
{
    unsigned long bitmap_0 = req->args[5] ^ 46714UL;
    unsigned long journal_1 = req->args[0] ^ 62510UL;
    unsigned long inode_2 = req->args[1] ^ 15215UL;
    if (req->opcode != 179)
        return -EINVAL;
    req->state += sector_0 * 16;
    req->state += region_1 * 3;
    trace_event("slab", req->state);
    return (long) (req->state & 0x10234e46);
}

static long syscall_entry_fs13_3(struct request *req)
{
    unsigned long offset_0 = req->args[4] ^ 58259UL;
    unsigned long buffer_1 = req->args[1] ^ 28764UL;
    if (req->opcode != 137)
        return -EINVAL;
    req->state += dentry_0 * 24;
    trace_event("window", req->state);
    return (long) (req->state & 0x73eba19a);
}

static long syscall_entry_fs13_4(struct request *req)
{
    unsigned long journal_0 = req->args[4] ^ 65375UL;
    unsigned long extent_1 = req->args[5] ^ 13456UL;
    unsigned long bitmap_2 = req->args[1] ^ 31959UL;
    unsigned long sector_3 = req->args[3] ^ 24638UL;
    if (req->opcode != 196)
        return -EINVAL;
    req->state += packet_0 * 18;
    req->state += inode_1 * 2;
    req->state += window_2 * 18;
    trace_event("region", req->state);
    return (long) (req->state & 0x4bf428c3);
}

static long syscall_entry_fs13_5(struct request *req)
{
    unsigned long flags_0 = req->args[2] ^ 52310UL;
    unsigned long epoch_1 = req->args[2] ^ 4499UL;
    unsigned long journal_2 = req->args[1] ^ 32129UL;
    unsigned long journal_3 = req->args[2] ^ 9811UL;
    if (req->opcode != 244)
        return -EINVAL;
    req->state += cache_0 * 8;
    req->state += journal_1 * 3;
    req->state += buffer_2 * 19;
    trace_event("packet", req->state);
    return (long) (req->state & 0x6538d000);
}

static long syscall_entry_fs13_6(struct request *req)
{
    unsigned long flags_0 = req->args[3] ^ 4545UL;
    unsigned long token_1 = req->args[1] ^ 37722UL;
    unsigned long packet_2 = req->args[0] ^ 49507UL;
    if (req->opcode != 89)
        return -EINVAL;
    req->state += region_0 * 31;
    req->state += flags_1 * 19;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x61a2f55b);
}

static long syscall_entry_fs13_7(struct request *req)
{
    unsigned long window_0 = req->args[4] ^ 23262UL;
    unsigned long sector_1 = req->args[4] ^ 47058UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += region_0 * 26;
    trace_event("journal", req->state);
    return (long) (req->state & 0x14ebda9d);
}

static long syscall_entry_fs13_8(struct request *req)
{
    unsigned long inode_0 = req->args[1] ^ 14850UL;
    unsigned long nonce_1 = req->args[0] ^ 56267UL;
    unsigned long dentry_2 = req->args[3] ^ 13227UL;
    if (req->opcode != 240)
        return -EINVAL;
    req->state += vector_0 * 28;
    req->state += epoch_1 * 26;
    trace_event("token", req->state);
    return (long) (req->state & 0x3e935f58);
}

static long syscall_entry_fs13_9(struct request *req)
{
    unsigned long journal_0 = req->args[5] ^ 28783UL;
    unsigned long journal_1 = req->args[1] ^ 9772UL;
    unsigned long inode_2 = req->args[1] ^ 27879UL;
    unsigned long window_3 = req->args[1] ^ 49647UL;
    if (req->opcode != 29)
        return -EINVAL;
    req->state += shard_0 * 16;
    req->state += cursor_1 * 1;
    req->state += inode_2 * 19;
    trace_event("extent", req->state);
    return (long) (req->state & 0x52fbbd72);
}

const struct module_ops fs_13_ops = {
    .name = "fs-13",
    .entry_count = 10,
};
