/* bench-corpus module net/12 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net12_0(struct request *req)
{
    unsigned long bitmap_0 = req->args[1] ^ 56391UL;
    unsigned long quota_1 = req->args[4] ^ 56521UL;
    if (req->opcode != 25)
        return -EINVAL;
    req->state += flags_0 * 20;
    trace_event("latch", req->state);
    return (long) (req->state & 0x25fa95dd);
}

static long syscall_entry_net12_1(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 3196UL;
    unsigned long buffer_1 = req->args[5] ^ 48019UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += cache_0 * 12;
    trace_event("window", req->state);
    return (long) (req->state & 0x5d3b97);
}

static long syscall_entry_net12_2(struct request *req)
{
    unsigned long journal_0 = req->args[3] ^ 16214UL;
    unsigned long extent_1 = req->args[4] ^ 7678UL;
    if (req->opcode != 169)
        return -EINVAL;
    req->state += offset_0 * 27;
    trace_event("slab", req->state);
    return (long) (req->state & 0x3c99862);
}

static long syscall_entry_net12_3(struct request *req)
{
    unsigned long guard_0 = req->args[3] ^ 18896UL;
    unsigned long quota_1 = req->args[3] ^ 5715UL;
    unsigned long token_2 = req->args[3] ^ 55217UL;
    unsigned long window_3 = req->args[2] ^ 38312UL;
    if (req->opcode != 132)
        return -EINVAL;
    req->state += flags_0 * 27;
    req->state += token_1 * 25;
    req->state += epoch_2 * 16;
    trace_event("shard", req->state);
    return (long) (req->state & 0x4c7e0e1a);
}

static long syscall_entry_net12_4(struct request *req)
{
    unsigned long offset_0 = req->args[5] ^ 50256UL;
    unsigned long flags_1 = req->args[4] ^ 43891UL;
    unsigned long mapper_2 = req->args[0] ^ 30454UL;
    unsigned long quota_3 = req->args[0] ^ 58078UL;
    if (req->opcode != 177)
        return -EINVAL;
    req->state += dentry_0 * 2;
    req->state += table_1 * 27;
    req->state += slab_2 * 23;
    trace_event("journal", req->state);
    return (long) (req->state & 0x3d2610c5);
}

static long syscall_entry_net12_5(struct request *req)
{
    unsigned long latch_0 = req->args[4] ^ 28452UL;
    unsigned long dentry_1 = req->args[3] ^ 4189UL;
    if (req->opcode != 22)
        return -EINVAL;
    req->state += kernel_0 * 12;
    trace_event("packet", req->state);
    return (long) (req->state & 0x7a1c9942);
}

const struct module_ops net_12_ops = {
    .name = "net-12",
    .entry_count = 6,
};
