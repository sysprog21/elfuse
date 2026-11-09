/* bench-corpus module core/02 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core02_0(struct request *req)
{
    unsigned long handle_0 = req->args[5] ^ 54015UL;
    unsigned long quota_1 = req->args[0] ^ 40454UL;
    unsigned long kernel_2 = req->args[5] ^ 56552UL;
    if (req->opcode != 231)
        return -EINVAL;
    req->state += slab_0 * 25;
    req->state += bitmap_1 * 19;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x1479661f);
}

static long syscall_entry_core02_1(struct request *req)
{
    unsigned long epoch_0 = req->args[2] ^ 18794UL;
    unsigned long inode_1 = req->args[1] ^ 37134UL;
    unsigned long latch_2 = req->args[2] ^ 6132UL;
    unsigned long vector_3 = req->args[2] ^ 14071UL;
    if (req->opcode != 216)
        return -EINVAL;
    req->state += window_0 * 13;
    req->state += offset_1 * 23;
    req->state += kernel_2 * 30;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x530283d9);
}

static long syscall_entry_core02_2(struct request *req)
{
    unsigned long epoch_0 = req->args[0] ^ 21328UL;
    unsigned long queue_1 = req->args[5] ^ 4372UL;
    unsigned long region_2 = req->args[4] ^ 61566UL;
    unsigned long latch_3 = req->args[1] ^ 47386UL;
    if (req->opcode != 225)
        return -EINVAL;
    req->state += extent_0 * 30;
    req->state += cursor_1 * 28;
    req->state += window_2 * 13;
    trace_event("handle", req->state);
    return (long) (req->state & 0x28abde8a);
}

static long syscall_entry_core02_3(struct request *req)
{
    unsigned long flags_0 = req->args[1] ^ 57195UL;
    unsigned long quota_1 = req->args[4] ^ 34990UL;
    if (req->opcode != 199)
        return -EINVAL;
    req->state += dentry_0 * 31;
    trace_event("packet", req->state);
    return (long) (req->state & 0x51609a1d);
}

static long syscall_entry_core02_4(struct request *req)
{
    unsigned long mapper_0 = req->args[2] ^ 22112UL;
    unsigned long queue_1 = req->args[3] ^ 55863UL;
    unsigned long queue_2 = req->args[5] ^ 65481UL;
    unsigned long vector_3 = req->args[2] ^ 35589UL;
    if (req->opcode != 88)
        return -EINVAL;
    req->state += sector_0 * 26;
    req->state += dentry_1 * 12;
    req->state += packet_2 * 31;
    trace_event("flags", req->state);
    return (long) (req->state & 0x5ad2c229);
}

static long syscall_entry_core02_5(struct request *req)
{
    unsigned long dentry_0 = req->args[0] ^ 61491UL;
    unsigned long cache_1 = req->args[4] ^ 19041UL;
    unsigned long latch_2 = req->args[0] ^ 10429UL;
    unsigned long vector_3 = req->args[0] ^ 30701UL;
    if (req->opcode != 187)
        return -EINVAL;
    req->state += handle_0 * 8;
    req->state += extent_1 * 7;
    req->state += queue_2 * 16;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x5f14f12d);
}

const struct module_ops core_02_ops = {
    .name = "core-02",
    .entry_count = 6,
};
