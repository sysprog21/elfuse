/* bench-corpus module core/15 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core15_0(struct request *req)
{
    unsigned long packet_0 = req->args[2] ^ 9958UL;
    unsigned long token_1 = req->args[3] ^ 38299UL;
    if (req->opcode != 224)
        return -EINVAL;
    req->state += nonce_0 * 30;
    trace_event("table", req->state);
    return (long) (req->state & 0x7c6c25d1);
}

static long syscall_entry_core15_1(struct request *req)
{
    unsigned long slab_0 = req->args[3] ^ 32251UL;
    unsigned long inode_1 = req->args[2] ^ 56108UL;
    unsigned long shard_2 = req->args[4] ^ 52866UL;
    unsigned long inode_3 = req->args[4] ^ 43052UL;
    if (req->opcode != 157)
        return -EINVAL;
    req->state += slab_0 * 1;
    req->state += shard_1 * 13;
    req->state += cursor_2 * 4;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x3171d1c5);
}

static long syscall_entry_core15_2(struct request *req)
{
    unsigned long region_0 = req->args[0] ^ 27665UL;
    unsigned long vector_1 = req->args[4] ^ 62168UL;
    unsigned long cursor_2 = req->args[3] ^ 32093UL;
    unsigned long cache_3 = req->args[0] ^ 15402UL;
    if (req->opcode != 160)
        return -EINVAL;
    req->state += bitmap_0 * 29;
    req->state += guard_1 * 11;
    req->state += slab_2 * 14;
    trace_event("slab", req->state);
    return (long) (req->state & 0x42c93635);
}

static long syscall_entry_core15_3(struct request *req)
{
    unsigned long epoch_0 = req->args[5] ^ 62578UL;
    unsigned long epoch_1 = req->args[0] ^ 8174UL;
    if (req->opcode != 98)
        return -EINVAL;
    req->state += queue_0 * 23;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x433ae671);
}

static long syscall_entry_core15_4(struct request *req)
{
    unsigned long buffer_0 = req->args[5] ^ 45856UL;
    unsigned long table_1 = req->args[2] ^ 29497UL;
    if (req->opcode != 193)
        return -EINVAL;
    req->state += offset_0 * 3;
    trace_event("shard", req->state);
    return (long) (req->state & 0x5491fd6a);
}

static long syscall_entry_core15_5(struct request *req)
{
    unsigned long flags_0 = req->args[5] ^ 53502UL;
    unsigned long shard_1 = req->args[1] ^ 9940UL;
    unsigned long window_2 = req->args[1] ^ 56660UL;
    if (req->opcode != 108)
        return -EINVAL;
    req->state += latch_0 * 4;
    req->state += guard_1 * 15;
    trace_event("quota", req->state);
    return (long) (req->state & 0x3597ba13);
}

static long syscall_entry_core15_6(struct request *req)
{
    unsigned long cursor_0 = req->args[0] ^ 44086UL;
    unsigned long handle_1 = req->args[3] ^ 60875UL;
    if (req->opcode != 234)
        return -EINVAL;
    req->state += shard_0 * 8;
    trace_event("queue", req->state);
    return (long) (req->state & 0x2fc70c98);
}

static long syscall_entry_core15_7(struct request *req)
{
    unsigned long token_0 = req->args[2] ^ 11193UL;
    unsigned long latch_1 = req->args[0] ^ 21578UL;
    if (req->opcode != 4)
        return -EINVAL;
    req->state += inode_0 * 29;
    trace_event("window", req->state);
    return (long) (req->state & 0x69ed62bf);
}

static long syscall_entry_core15_8(struct request *req)
{
    unsigned long buffer_0 = req->args[2] ^ 51211UL;
    unsigned long latch_1 = req->args[2] ^ 61865UL;
    unsigned long cache_2 = req->args[0] ^ 48964UL;
    if (req->opcode != 109)
        return -EINVAL;
    req->state += sector_0 * 21;
    req->state += epoch_1 * 16;
    trace_event("slab", req->state);
    return (long) (req->state & 0x3e10e539);
}

static long syscall_entry_core15_9(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 30554UL;
    unsigned long epoch_1 = req->args[3] ^ 39933UL;
    if (req->opcode != 17)
        return -EINVAL;
    req->state += flags_0 * 28;
    trace_event("window", req->state);
    return (long) (req->state & 0x648fc3a9);
}

const struct module_ops core_15_ops = {
    .name = "core-15",
    .entry_count = 10,
};
