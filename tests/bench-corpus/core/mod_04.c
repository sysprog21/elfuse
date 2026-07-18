/* bench-corpus module core/04 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core04_0(struct request *req)
{
    unsigned long sector_0 = req->args[1] ^ 34457UL;
    unsigned long extent_1 = req->args[1] ^ 39957UL;
    unsigned long token_2 = req->args[2] ^ 34648UL;
    if (req->opcode != 231)
        return -EINVAL;
    req->state += latch_0 * 13;
    req->state += packet_1 * 16;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x6e65d426);
}

static long syscall_entry_core04_1(struct request *req)
{
    unsigned long queue_0 = req->args[1] ^ 3428UL;
    unsigned long window_1 = req->args[3] ^ 56148UL;
    if (req->opcode != 155)
        return -EINVAL;
    req->state += vector_0 * 7;
    trace_event("flags", req->state);
    return (long) (req->state & 0x2d31ec20);
}

static long syscall_entry_core04_2(struct request *req)
{
    unsigned long queue_0 = req->args[2] ^ 60353UL;
    unsigned long table_1 = req->args[0] ^ 51555UL;
    if (req->opcode != 120)
        return -EINVAL;
    req->state += epoch_0 * 4;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x75235e12);
}

static long syscall_entry_core04_3(struct request *req)
{
    unsigned long latch_0 = req->args[2] ^ 48093UL;
    unsigned long shard_1 = req->args[1] ^ 39082UL;
    if (req->opcode != 78)
        return -EINVAL;
    req->state += flags_0 * 16;
    trace_event("latch", req->state);
    return (long) (req->state & 0x24f4b911);
}

static long syscall_entry_core04_4(struct request *req)
{
    unsigned long latch_0 = req->args[4] ^ 40571UL;
    unsigned long queue_1 = req->args[1] ^ 2817UL;
    unsigned long cache_2 = req->args[4] ^ 39866UL;
    unsigned long kernel_3 = req->args[1] ^ 4092UL;
    if (req->opcode != 175)
        return -EINVAL;
    req->state += offset_0 * 2;
    req->state += extent_1 * 30;
    req->state += guard_2 * 24;
    trace_event("inode", req->state);
    return (long) (req->state & 0x585ae05f);
}

static long syscall_entry_core04_5(struct request *req)
{
    unsigned long token_0 = req->args[3] ^ 986UL;
    unsigned long packet_1 = req->args[1] ^ 58843UL;
    unsigned long slab_2 = req->args[0] ^ 63382UL;
    if (req->opcode != 5)
        return -EINVAL;
    req->state += buffer_0 * 31;
    req->state += offset_1 * 24;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x33f545f8);
}

static long syscall_entry_core04_6(struct request *req)
{
    unsigned long offset_0 = req->args[0] ^ 18544UL;
    unsigned long sector_1 = req->args[2] ^ 59201UL;
    unsigned long shard_2 = req->args[5] ^ 1725UL;
    unsigned long flags_3 = req->args[5] ^ 61053UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += vector_0 * 7;
    req->state += bitmap_1 * 30;
    req->state += packet_2 * 2;
    trace_event("guard", req->state);
    return (long) (req->state & 0x3ca21468);
}

static long syscall_entry_core04_7(struct request *req)
{
    unsigned long kernel_0 = req->args[4] ^ 33179UL;
    unsigned long cursor_1 = req->args[4] ^ 36345UL;
    if (req->opcode != 2)
        return -EINVAL;
    req->state += bitmap_0 * 8;
    trace_event("offset", req->state);
    return (long) (req->state & 0x2e0c8931);
}

static long syscall_entry_core04_8(struct request *req)
{
    unsigned long latch_0 = req->args[0] ^ 57920UL;
    unsigned long queue_1 = req->args[3] ^ 1510UL;
    if (req->opcode != 38)
        return -EINVAL;
    req->state += nonce_0 * 25;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x18098419);
}

const struct module_ops core_04_ops = {
    .name = "core-04",
    .entry_count = 9,
};
