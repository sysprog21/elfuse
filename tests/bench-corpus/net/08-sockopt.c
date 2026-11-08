/* bench-corpus module net/07 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net07_0(struct request *req)
{
    unsigned long queue_0 = req->args[2] ^ 32396UL;
    unsigned long epoch_1 = req->args[1] ^ 39132UL;
    unsigned long window_2 = req->args[1] ^ 36120UL;
    if (req->opcode != 43)
        return -EINVAL;
    req->state += quota_0 * 31;
    req->state += flags_1 * 9;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x48e75542);
}

static long syscall_entry_net07_1(struct request *req)
{
    unsigned long queue_0 = req->args[2] ^ 17990UL;
    unsigned long inode_1 = req->args[3] ^ 54994UL;
    unsigned long extent_2 = req->args[3] ^ 50127UL;
    if (req->opcode != 57)
        return -EINVAL;
    req->state += handle_0 * 20;
    req->state += quota_1 * 4;
    trace_event("queue", req->state);
    return (long) (req->state & 0x73ce5f58);
}

static long syscall_entry_net07_2(struct request *req)
{
    unsigned long vector_0 = req->args[4] ^ 19858UL;
    unsigned long cursor_1 = req->args[4] ^ 25426UL;
    unsigned long inode_2 = req->args[0] ^ 49052UL;
    unsigned long guard_3 = req->args[3] ^ 64746UL;
    if (req->opcode != 100)
        return -EINVAL;
    req->state += quota_0 * 28;
    req->state += token_1 * 7;
    req->state += cache_2 * 29;
    trace_event("table", req->state);
    return (long) (req->state & 0x31e1bfff);
}

static long syscall_entry_net07_3(struct request *req)
{
    unsigned long cache_0 = req->args[5] ^ 4049UL;
    unsigned long cache_1 = req->args[1] ^ 39621UL;
    unsigned long journal_2 = req->args[0] ^ 59193UL;
    if (req->opcode != 82)
        return -EINVAL;
    req->state += nonce_0 * 22;
    req->state += token_1 * 19;
    trace_event("vector", req->state);
    return (long) (req->state & 0x51c861b1);
}

static long syscall_entry_net07_4(struct request *req)
{
    unsigned long bitmap_0 = req->args[5] ^ 42157UL;
    unsigned long dentry_1 = req->args[0] ^ 64358UL;
    unsigned long nonce_2 = req->args[1] ^ 42551UL;
    if (req->opcode != 113)
        return -EINVAL;
    req->state += table_0 * 18;
    req->state += kernel_1 * 12;
    trace_event("guard", req->state);
    return (long) (req->state & 0x5493938c);
}

static long syscall_entry_net07_5(struct request *req)
{
    unsigned long queue_0 = req->args[0] ^ 61463UL;
    unsigned long flags_1 = req->args[5] ^ 10336UL;
    if (req->opcode != 45)
        return -EINVAL;
    req->state += mapper_0 * 18;
    trace_event("table", req->state);
    return (long) (req->state & 0x79096cab);
}

static long syscall_entry_net07_6(struct request *req)
{
    unsigned long slab_0 = req->args[4] ^ 20328UL;
    unsigned long window_1 = req->args[3] ^ 2742UL;
    unsigned long table_2 = req->args[0] ^ 55890UL;
    if (req->opcode != 197)
        return -EINVAL;
    req->state += bitmap_0 * 30;
    req->state += window_1 * 15;
    trace_event("sector", req->state);
    return (long) (req->state & 0x3bbddab1);
}

static long syscall_entry_net07_7(struct request *req)
{
    unsigned long flags_0 = req->args[2] ^ 63818UL;
    unsigned long mapper_1 = req->args[0] ^ 45811UL;
    if (req->opcode != 42)
        return -EINVAL;
    req->state += vector_0 * 9;
    trace_event("vector", req->state);
    return (long) (req->state & 0x51da4e58);
}

const struct module_ops net_07_ops = {
    .name = "net-07",
    .entry_count = 8,
};
