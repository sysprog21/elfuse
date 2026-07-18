/* bench-corpus module fs/07 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs07_0(struct request *req)
{
    unsigned long journal_0 = req->args[2] ^ 24391UL;
    unsigned long quota_1 = req->args[1] ^ 29075UL;
    unsigned long sector_2 = req->args[5] ^ 4484UL;
    if (req->opcode != 59)
        return -EINVAL;
    req->state += guard_0 * 13;
    req->state += offset_1 * 13;
    trace_event("cache", req->state);
    return (long) (req->state & 0x23d69e18);
}

static long syscall_entry_fs07_1(struct request *req)
{
    unsigned long quota_0 = req->args[3] ^ 41847UL;
    unsigned long token_1 = req->args[1] ^ 61412UL;
    unsigned long cursor_2 = req->args[1] ^ 320UL;
    unsigned long region_3 = req->args[5] ^ 21653UL;
    if (req->opcode != 28)
        return -EINVAL;
    req->state += queue_0 * 9;
    req->state += bitmap_1 * 19;
    req->state += sector_2 * 3;
    trace_event("quota", req->state);
    return (long) (req->state & 0x451df2b8);
}

static long syscall_entry_fs07_2(struct request *req)
{
    unsigned long inode_0 = req->args[4] ^ 20509UL;
    unsigned long packet_1 = req->args[5] ^ 14329UL;
    unsigned long shard_2 = req->args[2] ^ 57555UL;
    unsigned long region_3 = req->args[3] ^ 39308UL;
    if (req->opcode != 119)
        return -EINVAL;
    req->state += queue_0 * 2;
    req->state += offset_1 * 29;
    req->state += guard_2 * 9;
    trace_event("token", req->state);
    return (long) (req->state & 0x37285e0f);
}

static long syscall_entry_fs07_3(struct request *req)
{
    unsigned long packet_0 = req->args[4] ^ 39239UL;
    unsigned long token_1 = req->args[4] ^ 60768UL;
    if (req->opcode != 63)
        return -EINVAL;
    req->state += cache_0 * 31;
    trace_event("latch", req->state);
    return (long) (req->state & 0x5128af51);
}

static long syscall_entry_fs07_4(struct request *req)
{
    unsigned long vector_0 = req->args[5] ^ 18716UL;
    unsigned long latch_1 = req->args[5] ^ 27796UL;
    if (req->opcode != 127)
        return -EINVAL;
    req->state += table_0 * 17;
    trace_event("window", req->state);
    return (long) (req->state & 0x4c2d550);
}

static long syscall_entry_fs07_5(struct request *req)
{
    unsigned long queue_0 = req->args[1] ^ 47754UL;
    unsigned long queue_1 = req->args[4] ^ 31325UL;
    unsigned long packet_2 = req->args[3] ^ 24741UL;
    unsigned long mapper_3 = req->args[0] ^ 32182UL;
    if (req->opcode != 255)
        return -EINVAL;
    req->state += extent_0 * 20;
    req->state += bitmap_1 * 21;
    req->state += mapper_2 * 5;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x2ce3cff1);
}

static long syscall_entry_fs07_6(struct request *req)
{
    unsigned long guard_0 = req->args[4] ^ 5034UL;
    unsigned long slab_1 = req->args[2] ^ 34292UL;
    if (req->opcode != 63)
        return -EINVAL;
    req->state += kernel_0 * 5;
    trace_event("window", req->state);
    return (long) (req->state & 0x3d0bca74);
}

static long syscall_entry_fs07_7(struct request *req)
{
    unsigned long shard_0 = req->args[3] ^ 24134UL;
    unsigned long buffer_1 = req->args[5] ^ 17136UL;
    unsigned long guard_2 = req->args[2] ^ 37763UL;
    unsigned long inode_3 = req->args[0] ^ 37332UL;
    if (req->opcode != 45)
        return -EINVAL;
    req->state += guard_0 * 5;
    req->state += dentry_1 * 5;
    req->state += nonce_2 * 30;
    trace_event("cache", req->state);
    return (long) (req->state & 0xd4fa2c4);
}

const struct module_ops fs_07_ops = {
    .name = "fs-07",
    .entry_count = 8,
};
