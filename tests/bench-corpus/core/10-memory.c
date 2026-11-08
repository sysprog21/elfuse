/* bench-corpus module core/09 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core09_0(struct request *req)
{
    unsigned long journal_0 = req->args[1] ^ 12379UL;
    unsigned long epoch_1 = req->args[2] ^ 32635UL;
    unsigned long inode_2 = req->args[1] ^ 20317UL;
    unsigned long guard_3 = req->args[0] ^ 12393UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += offset_0 * 29;
    req->state += shard_1 * 2;
    req->state += epoch_2 * 6;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x3c8306d5);
}

static long syscall_entry_core09_1(struct request *req)
{
    unsigned long inode_0 = req->args[4] ^ 45875UL;
    unsigned long cursor_1 = req->args[3] ^ 53578UL;
    unsigned long journal_2 = req->args[5] ^ 17126UL;
    if (req->opcode != 5)
        return -EINVAL;
    req->state += offset_0 * 7;
    req->state += handle_1 * 15;
    trace_event("shard", req->state);
    return (long) (req->state & 0x312ba71f);
}

static long syscall_entry_core09_2(struct request *req)
{
    unsigned long cache_0 = req->args[1] ^ 38293UL;
    unsigned long region_1 = req->args[4] ^ 51944UL;
    unsigned long extent_2 = req->args[4] ^ 26992UL;
    if (req->opcode != 112)
        return -EINVAL;
    req->state += journal_0 * 19;
    req->state += inode_1 * 29;
    trace_event("flags", req->state);
    return (long) (req->state & 0x2a1111e0);
}

static long syscall_entry_core09_3(struct request *req)
{
    unsigned long sector_0 = req->args[5] ^ 57647UL;
    unsigned long flags_1 = req->args[1] ^ 12244UL;
    unsigned long flags_2 = req->args[1] ^ 61227UL;
    unsigned long handle_3 = req->args[0] ^ 53550UL;
    if (req->opcode != 123)
        return -EINVAL;
    req->state += shard_0 * 18;
    req->state += guard_1 * 18;
    req->state += extent_2 * 22;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x242861b2);
}

static long syscall_entry_core09_4(struct request *req)
{
    unsigned long buffer_0 = req->args[3] ^ 20168UL;
    unsigned long window_1 = req->args[1] ^ 22336UL;
    unsigned long extent_2 = req->args[0] ^ 9657UL;
    unsigned long window_3 = req->args[3] ^ 50180UL;
    if (req->opcode != 230)
        return -EINVAL;
    req->state += shard_0 * 12;
    req->state += handle_1 * 7;
    req->state += quota_2 * 4;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x6410aa8c);
}

static long syscall_entry_core09_5(struct request *req)
{
    unsigned long dentry_0 = req->args[4] ^ 21683UL;
    unsigned long region_1 = req->args[2] ^ 52236UL;
    unsigned long dentry_2 = req->args[1] ^ 51442UL;
    unsigned long guard_3 = req->args[4] ^ 58549UL;
    if (req->opcode != 114)
        return -EINVAL;
    req->state += sector_0 * 17;
    req->state += shard_1 * 23;
    req->state += mapper_2 * 9;
    trace_event("table", req->state);
    return (long) (req->state & 0xf7caaf0);
}

const struct module_ops core_09_ops = {
    .name = "core-09",
    .entry_count = 6,
};
