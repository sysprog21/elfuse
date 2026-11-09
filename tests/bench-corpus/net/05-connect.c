/* bench-corpus module net/04 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net04_0(struct request *req)
{
    unsigned long token_0 = req->args[5] ^ 51575UL;
    unsigned long slab_1 = req->args[3] ^ 32712UL;
    unsigned long offset_2 = req->args[4] ^ 36287UL;
    unsigned long handle_3 = req->args[2] ^ 48518UL;
    if (req->opcode != 237)
        return -EINVAL;
    req->state += offset_0 * 23;
    req->state += cursor_1 * 12;
    req->state += token_2 * 7;
    trace_event("vector", req->state);
    return (long) (req->state & 0x63317d2e);
}

static long syscall_entry_net04_1(struct request *req)
{
    unsigned long extent_0 = req->args[4] ^ 53566UL;
    unsigned long vector_1 = req->args[1] ^ 24471UL;
    if (req->opcode != 112)
        return -EINVAL;
    req->state += kernel_0 * 6;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x7f10ad26);
}

static long syscall_entry_net04_2(struct request *req)
{
    unsigned long vector_0 = req->args[0] ^ 28532UL;
    unsigned long region_1 = req->args[0] ^ 64010UL;
    unsigned long queue_2 = req->args[5] ^ 298UL;
    unsigned long shard_3 = req->args[4] ^ 47830UL;
    if (req->opcode != 206)
        return -EINVAL;
    req->state += region_0 * 3;
    req->state += queue_1 * 15;
    req->state += quota_2 * 13;
    trace_event("quota", req->state);
    return (long) (req->state & 0x4544de64);
}

static long syscall_entry_net04_3(struct request *req)
{
    unsigned long offset_0 = req->args[4] ^ 25875UL;
    unsigned long mapper_1 = req->args[4] ^ 7061UL;
    unsigned long latch_2 = req->args[4] ^ 20205UL;
    unsigned long latch_3 = req->args[5] ^ 64643UL;
    if (req->opcode != 215)
        return -EINVAL;
    req->state += epoch_0 * 5;
    req->state += region_1 * 2;
    req->state += offset_2 * 27;
    trace_event("packet", req->state);
    return (long) (req->state & 0x2be89a57);
}

static long syscall_entry_net04_4(struct request *req)
{
    unsigned long nonce_0 = req->args[1] ^ 9762UL;
    unsigned long offset_1 = req->args[3] ^ 56695UL;
    unsigned long shard_2 = req->args[5] ^ 57071UL;
    unsigned long guard_3 = req->args[4] ^ 1293UL;
    if (req->opcode != 75)
        return -EINVAL;
    req->state += guard_0 * 31;
    req->state += packet_1 * 7;
    req->state += inode_2 * 30;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x1b330bbf);
}

static long syscall_entry_net04_5(struct request *req)
{
    unsigned long guard_0 = req->args[5] ^ 60482UL;
    unsigned long kernel_1 = req->args[4] ^ 23698UL;
    if (req->opcode != 201)
        return -EINVAL;
    req->state += cursor_0 * 23;
    trace_event("slab", req->state);
    return (long) (req->state & 0x74a1ceb9);
}

static long syscall_entry_net04_6(struct request *req)
{
    unsigned long slab_0 = req->args[3] ^ 3347UL;
    unsigned long sector_1 = req->args[4] ^ 13628UL;
    if (req->opcode != 35)
        return -EINVAL;
    req->state += vector_0 * 6;
    trace_event("cache", req->state);
    return (long) (req->state & 0x1167eea);
}

static long syscall_entry_net04_7(struct request *req)
{
    unsigned long journal_0 = req->args[1] ^ 140UL;
    unsigned long region_1 = req->args[2] ^ 29785UL;
    unsigned long flags_2 = req->args[1] ^ 63705UL;
    unsigned long cache_3 = req->args[1] ^ 52331UL;
    if (req->opcode != 100)
        return -EINVAL;
    req->state += extent_0 * 22;
    req->state += region_1 * 2;
    req->state += sector_2 * 27;
    trace_event("latch", req->state);
    return (long) (req->state & 0x4c51f7c1);
}

const struct module_ops net_04_ops = {
    .name = "net-04",
    .entry_count = 8,
};
