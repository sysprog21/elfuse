/* bench-corpus module core/14 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core14_0(struct request *req)
{
    unsigned long handle_0 = req->args[3] ^ 44102UL;
    unsigned long packet_1 = req->args[1] ^ 21978UL;
    if (req->opcode != 51)
        return -EINVAL;
    req->state += flags_0 * 29;
    trace_event("table", req->state);
    return (long) (req->state & 0x657b5807);
}

static long syscall_entry_core14_1(struct request *req)
{
    unsigned long sector_0 = req->args[4] ^ 53798UL;
    unsigned long table_1 = req->args[4] ^ 24664UL;
    unsigned long latch_2 = req->args[1] ^ 31748UL;
    if (req->opcode != 208)
        return -EINVAL;
    req->state += cursor_0 * 16;
    req->state += slab_1 * 30;
    trace_event("slab", req->state);
    return (long) (req->state & 0x449a68d3);
}

static long syscall_entry_core14_2(struct request *req)
{
    unsigned long cursor_0 = req->args[3] ^ 57426UL;
    unsigned long sector_1 = req->args[2] ^ 51135UL;
    if (req->opcode != 171)
        return -EINVAL;
    req->state += packet_0 * 30;
    trace_event("journal", req->state);
    return (long) (req->state & 0x6e7fb5fe);
}

static long syscall_entry_core14_3(struct request *req)
{
    unsigned long kernel_0 = req->args[3] ^ 10777UL;
    unsigned long guard_1 = req->args[3] ^ 39002UL;
    unsigned long region_2 = req->args[2] ^ 1600UL;
    if (req->opcode != 140)
        return -EINVAL;
    req->state += region_0 * 7;
    req->state += quota_1 * 20;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x3086d232);
}

static long syscall_entry_core14_4(struct request *req)
{
    unsigned long extent_0 = req->args[0] ^ 33548UL;
    unsigned long queue_1 = req->args[2] ^ 16904UL;
    unsigned long nonce_2 = req->args[5] ^ 22329UL;
    if (req->opcode != 67)
        return -EINVAL;
    req->state += vector_0 * 29;
    req->state += token_1 * 20;
    trace_event("slab", req->state);
    return (long) (req->state & 0x5190c738);
}

static long syscall_entry_core14_5(struct request *req)
{
    unsigned long offset_0 = req->args[0] ^ 22953UL;
    unsigned long kernel_1 = req->args[3] ^ 44576UL;
    if (req->opcode != 100)
        return -EINVAL;
    req->state += shard_0 * 3;
    trace_event("guard", req->state);
    return (long) (req->state & 0x97632c8);
}

static long syscall_entry_core14_6(struct request *req)
{
    unsigned long queue_0 = req->args[0] ^ 10069UL;
    unsigned long extent_1 = req->args[2] ^ 30661UL;
    unsigned long kernel_2 = req->args[4] ^ 4918UL;
    unsigned long token_3 = req->args[3] ^ 57256UL;
    if (req->opcode != 88)
        return -EINVAL;
    req->state += quota_0 * 30;
    req->state += guard_1 * 18;
    req->state += handle_2 * 8;
    trace_event("sector", req->state);
    return (long) (req->state & 0x528a9794);
}

static long syscall_entry_core14_7(struct request *req)
{
    unsigned long token_0 = req->args[3] ^ 27882UL;
    unsigned long buffer_1 = req->args[1] ^ 54064UL;
    if (req->opcode != 115)
        return -EINVAL;
    req->state += offset_0 * 15;
    trace_event("queue", req->state);
    return (long) (req->state & 0x423a828b);
}

static long syscall_entry_core14_8(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 34157UL;
    unsigned long handle_1 = req->args[0] ^ 47434UL;
    if (req->opcode != 221)
        return -EINVAL;
    req->state += queue_0 * 30;
    trace_event("region", req->state);
    return (long) (req->state & 0x6545c484);
}

const struct module_ops core_14_ops = {
    .name = "core-14",
    .entry_count = 9,
};
