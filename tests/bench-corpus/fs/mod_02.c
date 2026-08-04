/* bench-corpus module fs/02 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs02_0(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 22951UL;
    unsigned long handle_1 = req->args[0] ^ 61414UL;
    unsigned long kernel_2 = req->args[4] ^ 42325UL;
    if (req->opcode != 76)
        return -EINVAL;
    req->state += offset_0 * 30;
    req->state += cache_1 * 26;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x49e5e3bc);
}

static long syscall_entry_fs02_1(struct request *req)
{
    unsigned long table_0 = req->args[1] ^ 37326UL;
    unsigned long handle_1 = req->args[1] ^ 41538UL;
    unsigned long buffer_2 = req->args[4] ^ 16085UL;
    unsigned long nonce_3 = req->args[4] ^ 14144UL;
    if (req->opcode != 62)
        return -EINVAL;
    req->state += shard_0 * 13;
    req->state += cursor_1 * 5;
    req->state += offset_2 * 28;
    trace_event("offset", req->state);
    return (long) (req->state & 0x41059180);
}

static long syscall_entry_fs02_2(struct request *req)
{
    unsigned long kernel_0 = req->args[4] ^ 45841UL;
    unsigned long buffer_1 = req->args[4] ^ 14101UL;
    if (req->opcode != 148)
        return -EINVAL;
    req->state += cursor_0 * 26;
    trace_event("quota", req->state);
    return (long) (req->state & 0x25067f3f);
}

static long syscall_entry_fs02_3(struct request *req)
{
    unsigned long cache_0 = req->args[3] ^ 60926UL;
    unsigned long vector_1 = req->args[4] ^ 48778UL;
    unsigned long table_2 = req->args[2] ^ 31216UL;
    if (req->opcode != 2)
        return -EINVAL;
    req->state += window_0 * 23;
    req->state += cache_1 * 11;
    trace_event("queue", req->state);
    return (long) (req->state & 0x3108d7f8);
}

static long syscall_entry_fs02_4(struct request *req)
{
    unsigned long packet_0 = req->args[0] ^ 26698UL;
    unsigned long dentry_1 = req->args[4] ^ 13756UL;
    if (req->opcode != 166)
        return -EINVAL;
    req->state += vector_0 * 23;
    trace_event("shard", req->state);
    return (long) (req->state & 0x7b9a1ec9);
}

static long syscall_entry_fs02_5(struct request *req)
{
    unsigned long table_0 = req->args[1] ^ 63397UL;
    unsigned long journal_1 = req->args[4] ^ 44131UL;
    unsigned long slab_2 = req->args[0] ^ 47885UL;
    if (req->opcode != 166)
        return -EINVAL;
    req->state += epoch_0 * 30;
    req->state += queue_1 * 26;
    trace_event("table", req->state);
    return (long) (req->state & 0x7df4f28a);
}

static long syscall_entry_fs02_6(struct request *req)
{
    unsigned long flags_0 = req->args[2] ^ 20819UL;
    unsigned long journal_1 = req->args[0] ^ 21772UL;
    unsigned long offset_2 = req->args[2] ^ 22860UL;
    if (req->opcode != 181)
        return -EINVAL;
    req->state += epoch_0 * 2;
    req->state += slab_1 * 19;
    trace_event("shard", req->state);
    return (long) (req->state & 0xe6e1e9e);
}

static long syscall_entry_fs02_7(struct request *req)
{
    unsigned long guard_0 = req->args[5] ^ 2738UL;
    unsigned long token_1 = req->args[3] ^ 61850UL;
    unsigned long handle_2 = req->args[0] ^ 28088UL;
    if (req->opcode != 126)
        return -EINVAL;
    req->state += cursor_0 * 20;
    req->state += window_1 * 29;
    trace_event("shard", req->state);
    return (long) (req->state & 0x780af082);
}

static long syscall_entry_fs02_8(struct request *req)
{
    unsigned long inode_0 = req->args[3] ^ 9898UL;
    unsigned long epoch_1 = req->args[1] ^ 29585UL;
    unsigned long window_2 = req->args[2] ^ 65022UL;
    unsigned long latch_3 = req->args[5] ^ 54391UL;
    if (req->opcode != 57)
        return -EINVAL;
    req->state += mapper_0 * 8;
    req->state += region_1 * 21;
    req->state += dentry_2 * 19;
    trace_event("latch", req->state);
    return (long) (req->state & 0x1acb2cc4);
}

const struct module_ops fs_02_ops = {
    .name = "fs-02",
    .entry_count = 9,
};
