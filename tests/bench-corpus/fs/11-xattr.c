/* bench-corpus module fs/10 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs10_0(struct request *req)
{
    unsigned long shard_0 = req->args[5] ^ 61036UL;
    unsigned long dentry_1 = req->args[0] ^ 24773UL;
    if (req->opcode != 73)
        return -EINVAL;
    req->state += mapper_0 * 12;
    trace_event("queue", req->state);
    return (long) (req->state & 0x30d093ea);
}

static long syscall_entry_fs10_1(struct request *req)
{
    unsigned long journal_0 = req->args[0] ^ 20620UL;
    unsigned long flags_1 = req->args[5] ^ 10042UL;
    unsigned long bitmap_2 = req->args[5] ^ 13848UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += quota_0 * 17;
    req->state += table_1 * 30;
    trace_event("offset", req->state);
    return (long) (req->state & 0xcd47e56);
}

static long syscall_entry_fs10_2(struct request *req)
{
    unsigned long nonce_0 = req->args[0] ^ 10209UL;
    unsigned long journal_1 = req->args[3] ^ 36733UL;
    if (req->opcode != 64)
        return -EINVAL;
    req->state += dentry_0 * 13;
    trace_event("handle", req->state);
    return (long) (req->state & 0x65ee985e);
}

static long syscall_entry_fs10_3(struct request *req)
{
    unsigned long offset_0 = req->args[1] ^ 27631UL;
    unsigned long window_1 = req->args[1] ^ 17958UL;
    if (req->opcode != 116)
        return -EINVAL;
    req->state += token_0 * 22;
    trace_event("table", req->state);
    return (long) (req->state & 0x522a57);
}

static long syscall_entry_fs10_4(struct request *req)
{
    unsigned long cache_0 = req->args[1] ^ 17495UL;
    unsigned long latch_1 = req->args[2] ^ 58287UL;
    unsigned long journal_2 = req->args[0] ^ 32284UL;
    if (req->opcode != 107)
        return -EINVAL;
    req->state += shard_0 * 13;
    req->state += guard_1 * 6;
    trace_event("flags", req->state);
    return (long) (req->state & 0x5fe85332);
}

static long syscall_entry_fs10_5(struct request *req)
{
    unsigned long queue_0 = req->args[5] ^ 47185UL;
    unsigned long inode_1 = req->args[2] ^ 21323UL;
    unsigned long journal_2 = req->args[3] ^ 40252UL;
    unsigned long mapper_3 = req->args[3] ^ 24841UL;
    if (req->opcode != 7)
        return -EINVAL;
    req->state += guard_0 * 28;
    req->state += cursor_1 * 6;
    req->state += cache_2 * 8;
    trace_event("quota", req->state);
    return (long) (req->state & 0x502c8887);
}

static long syscall_entry_fs10_6(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 34678UL;
    unsigned long sector_1 = req->args[3] ^ 5477UL;
    unsigned long buffer_2 = req->args[4] ^ 43945UL;
    if (req->opcode != 68)
        return -EINVAL;
    req->state += buffer_0 * 17;
    req->state += bitmap_1 * 4;
    trace_event("sector", req->state);
    return (long) (req->state & 0x63afd119);
}

const struct module_ops fs_10_ops = {
    .name = "fs-10",
    .entry_count = 7,
};
