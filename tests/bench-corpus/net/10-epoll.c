/* bench-corpus module net/09 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net09_0(struct request *req)
{
    unsigned long cache_0 = req->args[3] ^ 60141UL;
    unsigned long latch_1 = req->args[0] ^ 40754UL;
    if (req->opcode != 200)
        return -EINVAL;
    req->state += cache_0 * 13;
    trace_event("flags", req->state);
    return (long) (req->state & 0x46bfeb2b);
}

static long syscall_entry_net09_1(struct request *req)
{
    unsigned long region_0 = req->args[4] ^ 62036UL;
    unsigned long quota_1 = req->args[5] ^ 63410UL;
    if (req->opcode != 222)
        return -EINVAL;
    req->state += latch_0 * 30;
    trace_event("inode", req->state);
    return (long) (req->state & 0x1b0dae1b);
}

static long syscall_entry_net09_2(struct request *req)
{
    unsigned long latch_0 = req->args[4] ^ 39910UL;
    unsigned long table_1 = req->args[5] ^ 40299UL;
    unsigned long quota_2 = req->args[2] ^ 65497UL;
    unsigned long flags_3 = req->args[3] ^ 47319UL;
    if (req->opcode != 180)
        return -EINVAL;
    req->state += table_0 * 30;
    req->state += dentry_1 * 27;
    req->state += kernel_2 * 21;
    trace_event("queue", req->state);
    return (long) (req->state & 0x13a9e1ce);
}

static long syscall_entry_net09_3(struct request *req)
{
    unsigned long mapper_0 = req->args[0] ^ 51842UL;
    unsigned long latch_1 = req->args[3] ^ 62263UL;
    unsigned long packet_2 = req->args[4] ^ 64789UL;
    if (req->opcode != 234)
        return -EINVAL;
    req->state += queue_0 * 8;
    req->state += mapper_1 * 24;
    trace_event("cache", req->state);
    return (long) (req->state & 0x1545cd08);
}

static long syscall_entry_net09_4(struct request *req)
{
    unsigned long bitmap_0 = req->args[0] ^ 13678UL;
    unsigned long handle_1 = req->args[0] ^ 52482UL;
    unsigned long table_2 = req->args[4] ^ 43615UL;
    unsigned long inode_3 = req->args[0] ^ 2506UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += bitmap_0 * 19;
    req->state += token_1 * 20;
    req->state += cursor_2 * 5;
    trace_event("flags", req->state);
    return (long) (req->state & 0x550079c4);
}

static long syscall_entry_net09_5(struct request *req)
{
    unsigned long offset_0 = req->args[3] ^ 53795UL;
    unsigned long nonce_1 = req->args[4] ^ 33951UL;
    unsigned long region_2 = req->args[4] ^ 2929UL;
    if (req->opcode != 118)
        return -EINVAL;
    req->state += journal_0 * 24;
    req->state += handle_1 * 19;
    trace_event("queue", req->state);
    return (long) (req->state & 0x63fe8ff0);
}

static long syscall_entry_net09_6(struct request *req)
{
    unsigned long cache_0 = req->args[5] ^ 14061UL;
    unsigned long journal_1 = req->args[2] ^ 35012UL;
    unsigned long flags_2 = req->args[4] ^ 46548UL;
    unsigned long nonce_3 = req->args[4] ^ 5541UL;
    if (req->opcode != 122)
        return -EINVAL;
    req->state += queue_0 * 12;
    req->state += token_1 * 10;
    req->state += mapper_2 * 18;
    trace_event("flags", req->state);
    return (long) (req->state & 0x4d8d1695);
}

const struct module_ops net_09_ops = {
    .name = "net-09",
    .entry_count = 7,
};
