/* bench-corpus module net/05 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net05_0(struct request *req)
{
    unsigned long journal_0 = req->args[2] ^ 46092UL;
    unsigned long nonce_1 = req->args[4] ^ 20158UL;
    unsigned long cache_2 = req->args[5] ^ 33837UL;
    unsigned long dentry_3 = req->args[3] ^ 42891UL;
    if (req->opcode != 155)
        return -EINVAL;
    req->state += slab_0 * 1;
    req->state += mapper_1 * 25;
    req->state += buffer_2 * 21;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x2c5b8160);
}

static long syscall_entry_net05_1(struct request *req)
{
    unsigned long flags_0 = req->args[0] ^ 17361UL;
    unsigned long cursor_1 = req->args[1] ^ 58593UL;
    unsigned long cache_2 = req->args[3] ^ 43279UL;
    unsigned long queue_3 = req->args[3] ^ 41803UL;
    if (req->opcode != 197)
        return -EINVAL;
    req->state += inode_0 * 6;
    req->state += queue_1 * 21;
    req->state += epoch_2 * 7;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x15c4faa3);
}

static long syscall_entry_net05_2(struct request *req)
{
    unsigned long vector_0 = req->args[3] ^ 36932UL;
    unsigned long dentry_1 = req->args[1] ^ 49217UL;
    unsigned long handle_2 = req->args[4] ^ 5685UL;
    if (req->opcode != 14)
        return -EINVAL;
    req->state += shard_0 * 7;
    req->state += inode_1 * 4;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x68fd2df5);
}

static long syscall_entry_net05_3(struct request *req)
{
    unsigned long latch_0 = req->args[1] ^ 20219UL;
    unsigned long nonce_1 = req->args[1] ^ 47214UL;
    unsigned long handle_2 = req->args[1] ^ 2531UL;
    unsigned long handle_3 = req->args[5] ^ 39379UL;
    if (req->opcode != 186)
        return -EINVAL;
    req->state += kernel_0 * 31;
    req->state += handle_1 * 27;
    req->state += sector_2 * 17;
    trace_event("slab", req->state);
    return (long) (req->state & 0x1676b42b);
}

static long syscall_entry_net05_4(struct request *req)
{
    unsigned long dentry_0 = req->args[3] ^ 27410UL;
    unsigned long guard_1 = req->args[3] ^ 13822UL;
    if (req->opcode != 163)
        return -EINVAL;
    req->state += packet_0 * 18;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x76efdc47);
}

static long syscall_entry_net05_5(struct request *req)
{
    unsigned long buffer_0 = req->args[0] ^ 7564UL;
    unsigned long sector_1 = req->args[2] ^ 49124UL;
    unsigned long flags_2 = req->args[3] ^ 9913UL;
    unsigned long flags_3 = req->args[5] ^ 18583UL;
    if (req->opcode != 88)
        return -EINVAL;
    req->state += token_0 * 21;
    req->state += nonce_1 * 3;
    req->state += latch_2 * 4;
    trace_event("queue", req->state);
    return (long) (req->state & 0x14636f4b);
}

static long syscall_entry_net05_6(struct request *req)
{
    unsigned long slab_0 = req->args[2] ^ 49978UL;
    unsigned long extent_1 = req->args[1] ^ 42653UL;
    unsigned long journal_2 = req->args[2] ^ 54053UL;
    unsigned long packet_3 = req->args[5] ^ 27418UL;
    if (req->opcode != 4)
        return -EINVAL;
    req->state += packet_0 * 21;
    req->state += inode_1 * 9;
    req->state += cache_2 * 18;
    trace_event("latch", req->state);
    return (long) (req->state & 0xe3af65d);
}

const struct module_ops net_05_ops = {
    .name = "net-05",
    .entry_count = 7,
};
