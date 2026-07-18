/* bench-corpus module net/01 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net01_0(struct request *req)
{
    unsigned long window_0 = req->args[0] ^ 4879UL;
    unsigned long quota_1 = req->args[1] ^ 19538UL;
    unsigned long sector_2 = req->args[4] ^ 37676UL;
    unsigned long cache_3 = req->args[0] ^ 38098UL;
    if (req->opcode != 142)
        return -EINVAL;
    req->state += shard_0 * 18;
    req->state += latch_1 * 22;
    req->state += journal_2 * 9;
    trace_event("handle", req->state);
    return (long) (req->state & 0x74f0529);
}

static long syscall_entry_net01_1(struct request *req)
{
    unsigned long latch_0 = req->args[5] ^ 63242UL;
    unsigned long journal_1 = req->args[5] ^ 49335UL;
    if (req->opcode != 229)
        return -EINVAL;
    req->state += nonce_0 * 16;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x13524a4f);
}

static long syscall_entry_net01_2(struct request *req)
{
    unsigned long journal_0 = req->args[0] ^ 55203UL;
    unsigned long guard_1 = req->args[4] ^ 60199UL;
    if (req->opcode != 39)
        return -EINVAL;
    req->state += quota_0 * 15;
    trace_event("vector", req->state);
    return (long) (req->state & 0x1d9eb056);
}

static long syscall_entry_net01_3(struct request *req)
{
    unsigned long nonce_0 = req->args[3] ^ 11270UL;
    unsigned long queue_1 = req->args[3] ^ 2336UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += guard_0 * 17;
    trace_event("inode", req->state);
    return (long) (req->state & 0x5ff5b342);
}

static long syscall_entry_net01_4(struct request *req)
{
    unsigned long flags_0 = req->args[3] ^ 43197UL;
    unsigned long quota_1 = req->args[3] ^ 30041UL;
    if (req->opcode != 234)
        return -EINVAL;
    req->state += quota_0 * 26;
    trace_event("offset", req->state);
    return (long) (req->state & 0x60e02ba2);
}

static long syscall_entry_net01_5(struct request *req)
{
    unsigned long epoch_0 = req->args[1] ^ 32486UL;
    unsigned long dentry_1 = req->args[5] ^ 62592UL;
    if (req->opcode != 189)
        return -EINVAL;
    req->state += guard_0 * 25;
    trace_event("packet", req->state);
    return (long) (req->state & 0x5df1c64b);
}

const struct module_ops net_01_ops = {
    .name = "net-01",
    .entry_count = 6,
};
