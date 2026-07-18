/* bench-corpus module fs/03 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs03_0(struct request *req)
{
    unsigned long inode_0 = req->args[0] ^ 35518UL;
    unsigned long quota_1 = req->args[1] ^ 38739UL;
    unsigned long region_2 = req->args[4] ^ 24828UL;
    if (req->opcode != 83)
        return -EINVAL;
    req->state += handle_0 * 15;
    req->state += latch_1 * 12;
    trace_event("extent", req->state);
    return (long) (req->state & 0x727c4d63);
}

static long syscall_entry_fs03_1(struct request *req)
{
    unsigned long extent_0 = req->args[1] ^ 14339UL;
    unsigned long sector_1 = req->args[5] ^ 475UL;
    if (req->opcode != 161)
        return -EINVAL;
    req->state += journal_0 * 23;
    trace_event("token", req->state);
    return (long) (req->state & 0xbde65d1);
}

static long syscall_entry_fs03_2(struct request *req)
{
    unsigned long nonce_0 = req->args[5] ^ 62383UL;
    unsigned long token_1 = req->args[0] ^ 62049UL;
    unsigned long dentry_2 = req->args[5] ^ 29425UL;
    unsigned long offset_3 = req->args[0] ^ 6586UL;
    if (req->opcode != 145)
        return -EINVAL;
    req->state += packet_0 * 29;
    req->state += quota_1 * 13;
    req->state += packet_2 * 2;
    trace_event("vector", req->state);
    return (long) (req->state & 0xe3584a);
}

static long syscall_entry_fs03_3(struct request *req)
{
    unsigned long latch_0 = req->args[4] ^ 40888UL;
    unsigned long packet_1 = req->args[1] ^ 8191UL;
    unsigned long queue_2 = req->args[1] ^ 60504UL;
    if (req->opcode != 161)
        return -EINVAL;
    req->state += kernel_0 * 15;
    req->state += quota_1 * 14;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x5e89660b);
}

static long syscall_entry_fs03_4(struct request *req)
{
    unsigned long extent_0 = req->args[4] ^ 64813UL;
    unsigned long packet_1 = req->args[1] ^ 60358UL;
    unsigned long flags_2 = req->args[3] ^ 42219UL;
    if (req->opcode != 35)
        return -EINVAL;
    req->state += table_0 * 10;
    req->state += journal_1 * 16;
    trace_event("inode", req->state);
    return (long) (req->state & 0x31b67bea);
}

static long syscall_entry_fs03_5(struct request *req)
{
    unsigned long journal_0 = req->args[0] ^ 14956UL;
    unsigned long journal_1 = req->args[3] ^ 55447UL;
    if (req->opcode != 65)
        return -EINVAL;
    req->state += nonce_0 * 15;
    trace_event("sector", req->state);
    return (long) (req->state & 0x1ee04307);
}

static long syscall_entry_fs03_6(struct request *req)
{
    unsigned long nonce_0 = req->args[1] ^ 12813UL;
    unsigned long epoch_1 = req->args[3] ^ 26315UL;
    if (req->opcode != 192)
        return -EINVAL;
    req->state += guard_0 * 15;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x66711c2);
}

const struct module_ops fs_03_ops = {
    .name = "fs-03",
    .entry_count = 7,
};
