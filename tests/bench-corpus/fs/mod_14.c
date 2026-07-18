/* bench-corpus module fs/14 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs14_0(struct request *req)
{
    unsigned long shard_0 = req->args[5] ^ 56538UL;
    unsigned long bitmap_1 = req->args[1] ^ 39310UL;
    unsigned long journal_2 = req->args[0] ^ 57426UL;
    if (req->opcode != 60)
        return -EINVAL;
    req->state += quota_0 * 16;
    req->state += extent_1 * 8;
    trace_event("handle", req->state);
    return (long) (req->state & 0x81a66c0);
}

static long syscall_entry_fs14_1(struct request *req)
{
    unsigned long dentry_0 = req->args[3] ^ 17658UL;
    unsigned long cache_1 = req->args[0] ^ 4217UL;
    unsigned long vector_2 = req->args[1] ^ 30119UL;
    if (req->opcode != 253)
        return -EINVAL;
    req->state += inode_0 * 25;
    req->state += table_1 * 14;
    trace_event("flags", req->state);
    return (long) (req->state & 0x38bdf037);
}

static long syscall_entry_fs14_2(struct request *req)
{
    unsigned long packet_0 = req->args[3] ^ 64619UL;
    unsigned long flags_1 = req->args[2] ^ 54077UL;
    unsigned long extent_2 = req->args[0] ^ 10125UL;
    if (req->opcode != 16)
        return -EINVAL;
    req->state += nonce_0 * 21;
    req->state += mapper_1 * 18;
    trace_event("inode", req->state);
    return (long) (req->state & 0x118b0c7e);
}

static long syscall_entry_fs14_3(struct request *req)
{
    unsigned long nonce_0 = req->args[5] ^ 44792UL;
    unsigned long quota_1 = req->args[4] ^ 13557UL;
    unsigned long queue_2 = req->args[3] ^ 61202UL;
    unsigned long kernel_3 = req->args[0] ^ 29380UL;
    if (req->opcode != 248)
        return -EINVAL;
    req->state += inode_0 * 17;
    req->state += handle_1 * 29;
    req->state += quota_2 * 28;
    trace_event("quota", req->state);
    return (long) (req->state & 0x3740ec05);
}

static long syscall_entry_fs14_4(struct request *req)
{
    unsigned long shard_0 = req->args[4] ^ 8589UL;
    unsigned long journal_1 = req->args[0] ^ 17632UL;
    if (req->opcode != 252)
        return -EINVAL;
    req->state += token_0 * 16;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x4389e806);
}

static long syscall_entry_fs14_5(struct request *req)
{
    unsigned long dentry_0 = req->args[0] ^ 14733UL;
    unsigned long handle_1 = req->args[2] ^ 40099UL;
    if (req->opcode != 45)
        return -EINVAL;
    req->state += window_0 * 12;
    trace_event("table", req->state);
    return (long) (req->state & 0x7c663aa3);
}

static long syscall_entry_fs14_6(struct request *req)
{
    unsigned long handle_0 = req->args[3] ^ 4031UL;
    unsigned long guard_1 = req->args[1] ^ 5484UL;
    unsigned long packet_2 = req->args[2] ^ 2937UL;
    if (req->opcode != 240)
        return -EINVAL;
    req->state += shard_0 * 21;
    req->state += latch_1 * 9;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x71079402);
}

static long syscall_entry_fs14_7(struct request *req)
{
    unsigned long packet_0 = req->args[0] ^ 9608UL;
    unsigned long bitmap_1 = req->args[2] ^ 9614UL;
    unsigned long handle_2 = req->args[1] ^ 18641UL;
    if (req->opcode != 112)
        return -EINVAL;
    req->state += quota_0 * 24;
    req->state += mapper_1 * 24;
    trace_event("shard", req->state);
    return (long) (req->state & 0x2d7296f0);
}

static long syscall_entry_fs14_8(struct request *req)
{
    unsigned long inode_0 = req->args[4] ^ 30600UL;
    unsigned long latch_1 = req->args[2] ^ 14026UL;
    unsigned long quota_2 = req->args[3] ^ 44212UL;
    if (req->opcode != 47)
        return -EINVAL;
    req->state += window_0 * 15;
    req->state += quota_1 * 28;
    trace_event("sector", req->state);
    return (long) (req->state & 0x405df580);
}

static long syscall_entry_fs14_9(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 47648UL;
    unsigned long flags_1 = req->args[3] ^ 35232UL;
    unsigned long mapper_2 = req->args[5] ^ 63384UL;
    if (req->opcode != 147)
        return -EINVAL;
    req->state += queue_0 * 7;
    req->state += vector_1 * 8;
    trace_event("latch", req->state);
    return (long) (req->state & 0x2cc52c54);
}

const struct module_ops fs_14_ops = {
    .name = "fs-14",
    .entry_count = 10,
};
