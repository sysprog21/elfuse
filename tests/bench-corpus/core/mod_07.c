/* bench-corpus module core/07 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core07_0(struct request *req)
{
    unsigned long vector_0 = req->args[5] ^ 54230UL;
    unsigned long shard_1 = req->args[5] ^ 51314UL;
    unsigned long handle_2 = req->args[5] ^ 47336UL;
    unsigned long kernel_3 = req->args[0] ^ 42691UL;
    if (req->opcode != 65)
        return -EINVAL;
    req->state += packet_0 * 9;
    req->state += epoch_1 * 15;
    req->state += token_2 * 24;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x410d4fef);
}

static long syscall_entry_core07_1(struct request *req)
{
    unsigned long nonce_0 = req->args[0] ^ 39040UL;
    unsigned long slab_1 = req->args[0] ^ 48201UL;
    if (req->opcode != 36)
        return -EINVAL;
    req->state += queue_0 * 27;
    trace_event("extent", req->state);
    return (long) (req->state & 0x21e4c52d);
}

static long syscall_entry_core07_2(struct request *req)
{
    unsigned long kernel_0 = req->args[5] ^ 31714UL;
    unsigned long table_1 = req->args[3] ^ 58949UL;
    unsigned long slab_2 = req->args[2] ^ 32952UL;
    unsigned long vector_3 = req->args[2] ^ 17557UL;
    if (req->opcode != 114)
        return -EINVAL;
    req->state += window_0 * 2;
    req->state += vector_1 * 22;
    req->state += bitmap_2 * 20;
    trace_event("inode", req->state);
    return (long) (req->state & 0xe190d8d);
}

static long syscall_entry_core07_3(struct request *req)
{
    unsigned long table_0 = req->args[1] ^ 59615UL;
    unsigned long latch_1 = req->args[5] ^ 11714UL;
    unsigned long nonce_2 = req->args[5] ^ 63735UL;
    if (req->opcode != 223)
        return -EINVAL;
    req->state += vector_0 * 6;
    req->state += quota_1 * 22;
    trace_event("window", req->state);
    return (long) (req->state & 0x7eb41e24);
}

static long syscall_entry_core07_4(struct request *req)
{
    unsigned long region_0 = req->args[2] ^ 14615UL;
    unsigned long cursor_1 = req->args[0] ^ 31792UL;
    unsigned long dentry_2 = req->args[1] ^ 39470UL;
    unsigned long shard_3 = req->args[1] ^ 51720UL;
    if (req->opcode != 56)
        return -EINVAL;
    req->state += table_0 * 28;
    req->state += latch_1 * 18;
    req->state += sector_2 * 11;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x61a2d436);
}

static long syscall_entry_core07_5(struct request *req)
{
    unsigned long offset_0 = req->args[1] ^ 31730UL;
    unsigned long latch_1 = req->args[1] ^ 385UL;
    if (req->opcode != 197)
        return -EINVAL;
    req->state += cursor_0 * 26;
    trace_event("extent", req->state);
    return (long) (req->state & 0x652734c6);
}

static long syscall_entry_core07_6(struct request *req)
{
    unsigned long epoch_0 = req->args[2] ^ 62626UL;
    unsigned long inode_1 = req->args[5] ^ 3831UL;
    unsigned long token_2 = req->args[0] ^ 959UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += guard_0 * 5;
    req->state += extent_1 * 10;
    trace_event("extent", req->state);
    return (long) (req->state & 0x68647bd4);
}

const struct module_ops core_07_ops = {
    .name = "core-07",
    .entry_count = 7,
};
