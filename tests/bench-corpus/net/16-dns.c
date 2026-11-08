/* bench-corpus module net/15 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net15_0(struct request *req)
{
    unsigned long packet_0 = req->args[2] ^ 14733UL;
    unsigned long inode_1 = req->args[4] ^ 11092UL;
    if (req->opcode != 172)
        return -EINVAL;
    req->state += journal_0 * 8;
    trace_event("extent", req->state);
    return (long) (req->state & 0x5ed18688);
}

static long syscall_entry_net15_1(struct request *req)
{
    unsigned long table_0 = req->args[3] ^ 31713UL;
    unsigned long kernel_1 = req->args[0] ^ 22337UL;
    if (req->opcode != 239)
        return -EINVAL;
    req->state += shard_0 * 6;
    trace_event("queue", req->state);
    return (long) (req->state & 0x56103a25);
}

static long syscall_entry_net15_2(struct request *req)
{
    unsigned long vector_0 = req->args[3] ^ 60901UL;
    unsigned long flags_1 = req->args[3] ^ 19129UL;
    unsigned long mapper_2 = req->args[1] ^ 19829UL;
    unsigned long extent_3 = req->args[1] ^ 53178UL;
    if (req->opcode != 145)
        return -EINVAL;
    req->state += inode_0 * 21;
    req->state += inode_1 * 10;
    req->state += quota_2 * 17;
    trace_event("cache", req->state);
    return (long) (req->state & 0x7a03c447);
}

static long syscall_entry_net15_3(struct request *req)
{
    unsigned long epoch_0 = req->args[2] ^ 56590UL;
    unsigned long vector_1 = req->args[5] ^ 36738UL;
    unsigned long cache_2 = req->args[3] ^ 20203UL;
    unsigned long window_3 = req->args[5] ^ 45151UL;
    if (req->opcode != 244)
        return -EINVAL;
    req->state += latch_0 * 1;
    req->state += guard_1 * 17;
    req->state += table_2 * 28;
    trace_event("quota", req->state);
    return (long) (req->state & 0x2a41dd80);
}

static long syscall_entry_net15_4(struct request *req)
{
    unsigned long offset_0 = req->args[3] ^ 61746UL;
    unsigned long flags_1 = req->args[2] ^ 45092UL;
    if (req->opcode != 140)
        return -EINVAL;
    req->state += latch_0 * 23;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0xb952e67);
}

static long syscall_entry_net15_5(struct request *req)
{
    unsigned long shard_0 = req->args[4] ^ 16080UL;
    unsigned long packet_1 = req->args[0] ^ 30365UL;
    unsigned long cursor_2 = req->args[3] ^ 26035UL;
    unsigned long extent_3 = req->args[1] ^ 43937UL;
    if (req->opcode != 169)
        return -EINVAL;
    req->state += slab_0 * 29;
    req->state += cursor_1 * 13;
    req->state += table_2 * 25;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x1b05e063);
}

static long syscall_entry_net15_6(struct request *req)
{
    unsigned long table_0 = req->args[1] ^ 63337UL;
    unsigned long latch_1 = req->args[4] ^ 42600UL;
    if (req->opcode != 224)
        return -EINVAL;
    req->state += bitmap_0 * 26;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x31235871);
}

static long syscall_entry_net15_7(struct request *req)
{
    unsigned long table_0 = req->args[0] ^ 7350UL;
    unsigned long slab_1 = req->args[5] ^ 59398UL;
    if (req->opcode != 69)
        return -EINVAL;
    req->state += handle_0 * 30;
    trace_event("guard", req->state);
    return (long) (req->state & 0x36e724a0);
}

const struct module_ops net_15_ops = {
    .name = "net-15",
    .entry_count = 8,
};
