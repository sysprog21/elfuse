/* bench-corpus module fs/06 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs06_0(struct request *req)
{
    unsigned long mapper_0 = req->args[4] ^ 34775UL;
    unsigned long mapper_1 = req->args[0] ^ 19075UL;
    if (req->opcode != 119)
        return -EINVAL;
    req->state += sector_0 * 31;
    trace_event("table", req->state);
    return (long) (req->state & 0x510e81d);
}

static long syscall_entry_fs06_1(struct request *req)
{
    unsigned long inode_0 = req->args[3] ^ 63271UL;
    unsigned long bitmap_1 = req->args[5] ^ 63381UL;
    if (req->opcode != 132)
        return -EINVAL;
    req->state += journal_0 * 19;
    trace_event("token", req->state);
    return (long) (req->state & 0x258f839a);
}

static long syscall_entry_fs06_2(struct request *req)
{
    unsigned long table_0 = req->args[4] ^ 12084UL;
    unsigned long sector_1 = req->args[4] ^ 32007UL;
    if (req->opcode != 77)
        return -EINVAL;
    req->state += slab_0 * 5;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x96d0b61);
}

static long syscall_entry_fs06_3(struct request *req)
{
    unsigned long cursor_0 = req->args[0] ^ 50191UL;
    unsigned long kernel_1 = req->args[5] ^ 16834UL;
    unsigned long mapper_2 = req->args[4] ^ 29531UL;
    if (req->opcode != 203)
        return -EINVAL;
    req->state += cache_0 * 6;
    req->state += guard_1 * 4;
    trace_event("token", req->state);
    return (long) (req->state & 0x58ef5221);
}

static long syscall_entry_fs06_4(struct request *req)
{
    unsigned long cursor_0 = req->args[1] ^ 61651UL;
    unsigned long shard_1 = req->args[0] ^ 36187UL;
    unsigned long extent_2 = req->args[2] ^ 51202UL;
    if (req->opcode != 239)
        return -EINVAL;
    req->state += quota_0 * 25;
    req->state += extent_1 * 3;
    trace_event("handle", req->state);
    return (long) (req->state & 0x607f9b9d);
}

static long syscall_entry_fs06_5(struct request *req)
{
    unsigned long nonce_0 = req->args[2] ^ 25358UL;
    unsigned long queue_1 = req->args[1] ^ 33046UL;
    unsigned long mapper_2 = req->args[4] ^ 40277UL;
    unsigned long kernel_3 = req->args[5] ^ 17156UL;
    if (req->opcode != 229)
        return -EINVAL;
    req->state += quota_0 * 19;
    req->state += sector_1 * 6;
    req->state += nonce_2 * 30;
    trace_event("shard", req->state);
    return (long) (req->state & 0x6a039152);
}

const struct module_ops fs_06_ops = {
    .name = "fs-06",
    .entry_count = 6,
};
