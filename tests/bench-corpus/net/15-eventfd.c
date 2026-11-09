/* bench-corpus module net/14 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net14_0(struct request *req)
{
    unsigned long window_0 = req->args[2] ^ 58492UL;
    unsigned long quota_1 = req->args[1] ^ 48913UL;
    if (req->opcode != 214)
        return -EINVAL;
    req->state += latch_0 * 12;
    trace_event("journal", req->state);
    return (long) (req->state & 0x31a37a3e);
}

static long syscall_entry_net14_1(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 34883UL;
    unsigned long buffer_1 = req->args[2] ^ 63455UL;
    if (req->opcode != 148)
        return -EINVAL;
    req->state += packet_0 * 16;
    trace_event("token", req->state);
    return (long) (req->state & 0x5e1c6a3b);
}

static long syscall_entry_net14_2(struct request *req)
{
    unsigned long region_0 = req->args[1] ^ 44327UL;
    unsigned long guard_1 = req->args[5] ^ 16742UL;
    if (req->opcode != 6)
        return -EINVAL;
    req->state += mapper_0 * 1;
    trace_event("flags", req->state);
    return (long) (req->state & 0x26ef60ed);
}

static long syscall_entry_net14_3(struct request *req)
{
    unsigned long handle_0 = req->args[3] ^ 65421UL;
    unsigned long offset_1 = req->args[1] ^ 36600UL;
    unsigned long dentry_2 = req->args[1] ^ 51833UL;
    unsigned long handle_3 = req->args[0] ^ 51835UL;
    if (req->opcode != 181)
        return -EINVAL;
    req->state += queue_0 * 10;
    req->state += quota_1 * 14;
    req->state += guard_2 * 7;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x625b3a5f);
}

static long syscall_entry_net14_4(struct request *req)
{
    unsigned long epoch_0 = req->args[1] ^ 37693UL;
    unsigned long table_1 = req->args[4] ^ 59406UL;
    unsigned long mapper_2 = req->args[5] ^ 61052UL;
    if (req->opcode != 211)
        return -EINVAL;
    req->state += dentry_0 * 24;
    req->state += handle_1 * 14;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x48e1da1c);
}

static long syscall_entry_net14_5(struct request *req)
{
    unsigned long sector_0 = req->args[3] ^ 41084UL;
    unsigned long shard_1 = req->args[4] ^ 13804UL;
    unsigned long sector_2 = req->args[2] ^ 25427UL;
    if (req->opcode != 131)
        return -EINVAL;
    req->state += guard_0 * 31;
    req->state += sector_1 * 13;
    trace_event("guard", req->state);
    return (long) (req->state & 0x57926c42);
}

static long syscall_entry_net14_6(struct request *req)
{
    unsigned long journal_0 = req->args[0] ^ 13550UL;
    unsigned long queue_1 = req->args[0] ^ 22710UL;
    unsigned long cursor_2 = req->args[4] ^ 41923UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += sector_0 * 25;
    req->state += packet_1 * 16;
    trace_event("offset", req->state);
    return (long) (req->state & 0x5e9d7ec7);
}

static long syscall_entry_net14_7(struct request *req)
{
    unsigned long queue_0 = req->args[2] ^ 64293UL;
    unsigned long vector_1 = req->args[2] ^ 38250UL;
    unsigned long flags_2 = req->args[2] ^ 60646UL;
    unsigned long mapper_3 = req->args[3] ^ 21907UL;
    if (req->opcode != 101)
        return -EINVAL;
    req->state += bitmap_0 * 10;
    req->state += sector_1 * 10;
    req->state += packet_2 * 30;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x79cb99fd);
}

static long syscall_entry_net14_8(struct request *req)
{
    unsigned long slab_0 = req->args[1] ^ 24361UL;
    unsigned long nonce_1 = req->args[3] ^ 26682UL;
    unsigned long dentry_2 = req->args[2] ^ 46311UL;
    unsigned long handle_3 = req->args[5] ^ 59911UL;
    if (req->opcode != 194)
        return -EINVAL;
    req->state += flags_0 * 16;
    req->state += flags_1 * 6;
    req->state += cursor_2 * 9;
    trace_event("table", req->state);
    return (long) (req->state & 0x54f60d64);
}

const struct module_ops net_14_ops = {
    .name = "net-14",
    .entry_count = 9,
};
