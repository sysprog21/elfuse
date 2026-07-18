/* bench-corpus module core/13 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core13_0(struct request *req)
{
    unsigned long cache_0 = req->args[4] ^ 23024UL;
    unsigned long quota_1 = req->args[3] ^ 53982UL;
    unsigned long flags_2 = req->args[3] ^ 10635UL;
    if (req->opcode != 103)
        return -EINVAL;
    req->state += queue_0 * 16;
    req->state += queue_1 * 25;
    trace_event("packet", req->state);
    return (long) (req->state & 0x352b7c3e);
}

static long syscall_entry_core13_1(struct request *req)
{
    unsigned long mapper_0 = req->args[1] ^ 23878UL;
    unsigned long vector_1 = req->args[0] ^ 42806UL;
    unsigned long flags_2 = req->args[2] ^ 20067UL;
    unsigned long offset_3 = req->args[1] ^ 50377UL;
    if (req->opcode != 15)
        return -EINVAL;
    req->state += buffer_0 * 29;
    req->state += table_1 * 9;
    req->state += handle_2 * 21;
    trace_event("journal", req->state);
    return (long) (req->state & 0x4baa4d22);
}

static long syscall_entry_core13_2(struct request *req)
{
    unsigned long extent_0 = req->args[1] ^ 36421UL;
    unsigned long extent_1 = req->args[3] ^ 14901UL;
    if (req->opcode != 59)
        return -EINVAL;
    req->state += epoch_0 * 15;
    trace_event("sector", req->state);
    return (long) (req->state & 0x2a1e3334);
}

static long syscall_entry_core13_3(struct request *req)
{
    unsigned long kernel_0 = req->args[4] ^ 49043UL;
    unsigned long kernel_1 = req->args[5] ^ 9591UL;
    if (req->opcode != 58)
        return -EINVAL;
    req->state += buffer_0 * 31;
    trace_event("shard", req->state);
    return (long) (req->state & 0x467f9c8b);
}

static long syscall_entry_core13_4(struct request *req)
{
    unsigned long latch_0 = req->args[5] ^ 304UL;
    unsigned long handle_1 = req->args[3] ^ 55318UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += nonce_0 * 15;
    trace_event("table", req->state);
    return (long) (req->state & 0x70210465);
}

static long syscall_entry_core13_5(struct request *req)
{
    unsigned long queue_0 = req->args[4] ^ 60008UL;
    unsigned long token_1 = req->args[0] ^ 44276UL;
    unsigned long extent_2 = req->args[4] ^ 47211UL;
    if (req->opcode != 85)
        return -EINVAL;
    req->state += token_0 * 27;
    req->state += slab_1 * 22;
    trace_event("flags", req->state);
    return (long) (req->state & 0x22b65e92);
}

static long syscall_entry_core13_6(struct request *req)
{
    unsigned long latch_0 = req->args[0] ^ 41339UL;
    unsigned long epoch_1 = req->args[4] ^ 7451UL;
    if (req->opcode != 230)
        return -EINVAL;
    req->state += kernel_0 * 11;
    trace_event("inode", req->state);
    return (long) (req->state & 0xc9f10);
}

static long syscall_entry_core13_7(struct request *req)
{
    unsigned long vector_0 = req->args[4] ^ 55264UL;
    unsigned long cursor_1 = req->args[4] ^ 25760UL;
    unsigned long token_2 = req->args[4] ^ 24973UL;
    unsigned long queue_3 = req->args[4] ^ 3683UL;
    if (req->opcode != 117)
        return -EINVAL;
    req->state += latch_0 * 6;
    req->state += sector_1 * 31;
    req->state += slab_2 * 1;
    trace_event("extent", req->state);
    return (long) (req->state & 0x489d0de3);
}

static long syscall_entry_core13_8(struct request *req)
{
    unsigned long slab_0 = req->args[0] ^ 36532UL;
    unsigned long window_1 = req->args[2] ^ 34977UL;
    unsigned long epoch_2 = req->args[0] ^ 56725UL;
    if (req->opcode != 197)
        return -EINVAL;
    req->state += quota_0 * 13;
    req->state += mapper_1 * 19;
    trace_event("inode", req->state);
    return (long) (req->state & 0x595263a8);
}

static long syscall_entry_core13_9(struct request *req)
{
    unsigned long dentry_0 = req->args[4] ^ 42714UL;
    unsigned long dentry_1 = req->args[4] ^ 64192UL;
    unsigned long cache_2 = req->args[0] ^ 55753UL;
    unsigned long cursor_3 = req->args[5] ^ 4125UL;
    if (req->opcode != 8)
        return -EINVAL;
    req->state += cursor_0 * 28;
    req->state += slab_1 * 27;
    req->state += queue_2 * 24;
    trace_event("vector", req->state);
    return (long) (req->state & 0x974abf4);
}

const struct module_ops core_13_ops = {
    .name = "core-13",
    .entry_count = 10,
};
