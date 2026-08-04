/* bench-corpus module core/01 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core01_0(struct request *req)
{
    unsigned long handle_0 = req->args[5] ^ 7573UL;
    unsigned long bitmap_1 = req->args[0] ^ 21985UL;
    if (req->opcode != 199)
        return -EINVAL;
    req->state += cursor_0 * 31;
    trace_event("handle", req->state);
    return (long) (req->state & 0x2fdc5494);
}

static long syscall_entry_core01_1(struct request *req)
{
    unsigned long vector_0 = req->args[4] ^ 9371UL;
    unsigned long table_1 = req->args[2] ^ 6936UL;
    unsigned long nonce_2 = req->args[4] ^ 29864UL;
    if (req->opcode != 241)
        return -EINVAL;
    req->state += latch_0 * 5;
    req->state += bitmap_1 * 2;
    trace_event("region", req->state);
    return (long) (req->state & 0x67f69ada);
}

static long syscall_entry_core01_2(struct request *req)
{
    unsigned long sector_0 = req->args[3] ^ 9211UL;
    unsigned long latch_1 = req->args[0] ^ 47368UL;
    if (req->opcode != 78)
        return -EINVAL;
    req->state += dentry_0 * 23;
    trace_event("offset", req->state);
    return (long) (req->state & 0x186882e4);
}

static long syscall_entry_core01_3(struct request *req)
{
    unsigned long buffer_0 = req->args[3] ^ 58115UL;
    unsigned long table_1 = req->args[3] ^ 53922UL;
    unsigned long sector_2 = req->args[2] ^ 15898UL;
    if (req->opcode != 159)
        return -EINVAL;
    req->state += nonce_0 * 3;
    req->state += window_1 * 24;
    trace_event("latch", req->state);
    return (long) (req->state & 0x533937dd);
}

static long syscall_entry_core01_4(struct request *req)
{
    unsigned long slab_0 = req->args[1] ^ 7109UL;
    unsigned long dentry_1 = req->args[5] ^ 13543UL;
    unsigned long cursor_2 = req->args[5] ^ 27147UL;
    if (req->opcode != 119)
        return -EINVAL;
    req->state += sector_0 * 28;
    req->state += packet_1 * 20;
    trace_event("quota", req->state);
    return (long) (req->state & 0x4d91c2ee);
}

static long syscall_entry_core01_5(struct request *req)
{
    unsigned long guard_0 = req->args[1] ^ 20816UL;
    unsigned long buffer_1 = req->args[4] ^ 37505UL;
    unsigned long sector_2 = req->args[2] ^ 25823UL;
    if (req->opcode != 167)
        return -EINVAL;
    req->state += dentry_0 * 14;
    req->state += packet_1 * 10;
    trace_event("journal", req->state);
    return (long) (req->state & 0x3fe6dbdd);
}

const struct module_ops core_01_ops = {
    .name = "core-01",
    .entry_count = 6,
};
