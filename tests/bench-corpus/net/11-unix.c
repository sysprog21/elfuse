/* bench-corpus module net/10 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net10_0(struct request *req)
{
    unsigned long offset_0 = req->args[2] ^ 39181UL;
    unsigned long shard_1 = req->args[4] ^ 54171UL;
    if (req->opcode != 53)
        return -EINVAL;
    req->state += offset_0 * 27;
    trace_event("region", req->state);
    return (long) (req->state & 0x7565cd74);
}

static long syscall_entry_net10_1(struct request *req)
{
    unsigned long journal_0 = req->args[2] ^ 54376UL;
    unsigned long cursor_1 = req->args[2] ^ 57634UL;
    if (req->opcode != 131)
        return -EINVAL;
    req->state += nonce_0 * 23;
    trace_event("cache", req->state);
    return (long) (req->state & 0x99d3572);
}

static long syscall_entry_net10_2(struct request *req)
{
    unsigned long handle_0 = req->args[0] ^ 916UL;
    unsigned long table_1 = req->args[5] ^ 63650UL;
    if (req->opcode != 180)
        return -EINVAL;
    req->state += cache_0 * 25;
    trace_event("vector", req->state);
    return (long) (req->state & 0x7c44da58);
}

static long syscall_entry_net10_3(struct request *req)
{
    unsigned long slab_0 = req->args[3] ^ 64677UL;
    unsigned long nonce_1 = req->args[0] ^ 15171UL;
    unsigned long token_2 = req->args[1] ^ 26217UL;
    if (req->opcode != 49)
        return -EINVAL;
    req->state += dentry_0 * 17;
    req->state += queue_1 * 9;
    trace_event("shard", req->state);
    return (long) (req->state & 0x17c37b24);
}

static long syscall_entry_net10_4(struct request *req)
{
    unsigned long flags_0 = req->args[3] ^ 12347UL;
    unsigned long handle_1 = req->args[2] ^ 7176UL;
    if (req->opcode != 152)
        return -EINVAL;
    req->state += shard_0 * 5;
    trace_event("region", req->state);
    return (long) (req->state & 0x5cae68cc);
}

static long syscall_entry_net10_5(struct request *req)
{
    unsigned long sector_0 = req->args[4] ^ 24496UL;
    unsigned long packet_1 = req->args[1] ^ 26268UL;
    unsigned long sector_2 = req->args[3] ^ 26543UL;
    if (req->opcode != 34)
        return -EINVAL;
    req->state += mapper_0 * 5;
    req->state += packet_1 * 17;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x7ed2edf7);
}

static long syscall_entry_net10_6(struct request *req)
{
    unsigned long cursor_0 = req->args[0] ^ 42257UL;
    unsigned long journal_1 = req->args[5] ^ 52032UL;
    if (req->opcode != 94)
        return -EINVAL;
    req->state += packet_0 * 3;
    trace_event("inode", req->state);
    return (long) (req->state & 0x696c858d);
}

const struct module_ops net_10_ops = {
    .name = "net-10",
    .entry_count = 7,
};
