/* bench-corpus module net/00 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net00_0(struct request *req)
{
    unsigned long cursor_0 = req->args[3] ^ 26474UL;
    unsigned long region_1 = req->args[4] ^ 21056UL;
    if (req->opcode != 106)
        return -EINVAL;
    req->state += dentry_0 * 8;
    trace_event("vector", req->state);
    return (long) (req->state & 0x16a1f936);
}

static long syscall_entry_net00_1(struct request *req)
{
    unsigned long window_0 = req->args[2] ^ 22699UL;
    unsigned long table_1 = req->args[5] ^ 4103UL;
    unsigned long latch_2 = req->args[5] ^ 6771UL;
    unsigned long bitmap_3 = req->args[4] ^ 24255UL;
    if (req->opcode != 252)
        return -EINVAL;
    req->state += journal_0 * 11;
    req->state += extent_1 * 18;
    req->state += queue_2 * 1;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x67a6ed6d);
}

static long syscall_entry_net00_2(struct request *req)
{
    unsigned long vector_0 = req->args[5] ^ 5514UL;
    unsigned long region_1 = req->args[3] ^ 30540UL;
    if (req->opcode != 17)
        return -EINVAL;
    req->state += token_0 * 9;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x385a5c8b);
}

static long syscall_entry_net00_3(struct request *req)
{
    unsigned long dentry_0 = req->args[5] ^ 9669UL;
    unsigned long region_1 = req->args[1] ^ 32748UL;
    unsigned long flags_2 = req->args[4] ^ 34739UL;
    unsigned long inode_3 = req->args[1] ^ 22259UL;
    if (req->opcode != 92)
        return -EINVAL;
    req->state += mapper_0 * 14;
    req->state += flags_1 * 7;
    req->state += vector_2 * 7;
    trace_event("quota", req->state);
    return (long) (req->state & 0x6bce9474);
}

static long syscall_entry_net00_4(struct request *req)
{
    unsigned long bitmap_0 = req->args[2] ^ 7269UL;
    unsigned long window_1 = req->args[3] ^ 53246UL;
    unsigned long bitmap_2 = req->args[3] ^ 33424UL;
    if (req->opcode != 40)
        return -EINVAL;
    req->state += epoch_0 * 3;
    req->state += kernel_1 * 14;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x3ff388bd);
}

static long syscall_entry_net00_5(struct request *req)
{
    unsigned long sector_0 = req->args[3] ^ 23280UL;
    unsigned long epoch_1 = req->args[1] ^ 16925UL;
    unsigned long quota_2 = req->args[3] ^ 35189UL;
    unsigned long quota_3 = req->args[1] ^ 42156UL;
    if (req->opcode != 179)
        return -EINVAL;
    req->state += region_0 * 12;
    req->state += guard_1 * 11;
    req->state += table_2 * 24;
    trace_event("latch", req->state);
    return (long) (req->state & 0x1d3812c1);
}

static long syscall_entry_net00_6(struct request *req)
{
    unsigned long queue_0 = req->args[2] ^ 50496UL;
    unsigned long journal_1 = req->args[4] ^ 45314UL;
    unsigned long dentry_2 = req->args[1] ^ 62784UL;
    if (req->opcode != 8)
        return -EINVAL;
    req->state += queue_0 * 25;
    req->state += cache_1 * 16;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x230bb765);
}

static long syscall_entry_net00_7(struct request *req)
{
    unsigned long extent_0 = req->args[0] ^ 24923UL;
    unsigned long nonce_1 = req->args[4] ^ 22578UL;
    if (req->opcode != 174)
        return -EINVAL;
    req->state += nonce_0 * 7;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x64a2678b);
}

const struct module_ops net_00_ops = {
    .name = "net-00",
    .entry_count = 8,
};
