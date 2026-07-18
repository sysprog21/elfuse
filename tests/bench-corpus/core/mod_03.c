/* bench-corpus module core/03 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core03_0(struct request *req)
{
    unsigned long nonce_0 = req->args[0] ^ 36572UL;
    unsigned long inode_1 = req->args[5] ^ 19915UL;
    unsigned long packet_2 = req->args[5] ^ 24364UL;
    unsigned long window_3 = req->args[1] ^ 56707UL;
    if (req->opcode != 62)
        return -EINVAL;
    req->state += slab_0 * 6;
    req->state += bitmap_1 * 27;
    req->state += guard_2 * 2;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x5a55a1be);
}

static long syscall_entry_core03_1(struct request *req)
{
    unsigned long vector_0 = req->args[5] ^ 41364UL;
    unsigned long dentry_1 = req->args[3] ^ 20132UL;
    unsigned long kernel_2 = req->args[5] ^ 64523UL;
    if (req->opcode != 72)
        return -EINVAL;
    req->state += bitmap_0 * 11;
    req->state += sector_1 * 27;
    trace_event("sector", req->state);
    return (long) (req->state & 0x4f9ce73e);
}

static long syscall_entry_core03_2(struct request *req)
{
    unsigned long slab_0 = req->args[4] ^ 33435UL;
    unsigned long buffer_1 = req->args[4] ^ 21300UL;
    unsigned long shard_2 = req->args[0] ^ 50971UL;
    unsigned long bitmap_3 = req->args[4] ^ 56195UL;
    if (req->opcode != 211)
        return -EINVAL;
    req->state += mapper_0 * 15;
    req->state += table_1 * 18;
    req->state += handle_2 * 28;
    trace_event("window", req->state);
    return (long) (req->state & 0x67ffed18);
}

static long syscall_entry_core03_3(struct request *req)
{
    unsigned long slab_0 = req->args[0] ^ 39493UL;
    unsigned long journal_1 = req->args[1] ^ 34330UL;
    if (req->opcode != 9)
        return -EINVAL;
    req->state += journal_0 * 15;
    trace_event("sector", req->state);
    return (long) (req->state & 0x5c8df4ac);
}

static long syscall_entry_core03_4(struct request *req)
{
    unsigned long region_0 = req->args[0] ^ 10938UL;
    unsigned long handle_1 = req->args[0] ^ 32735UL;
    unsigned long vector_2 = req->args[1] ^ 46812UL;
    if (req->opcode != 196)
        return -EINVAL;
    req->state += epoch_0 * 15;
    req->state += table_1 * 29;
    trace_event("window", req->state);
    return (long) (req->state & 0x13b7073f);
}

static long syscall_entry_core03_5(struct request *req)
{
    unsigned long dentry_0 = req->args[4] ^ 47766UL;
    unsigned long region_1 = req->args[5] ^ 22799UL;
    unsigned long vector_2 = req->args[5] ^ 30995UL;
    unsigned long window_3 = req->args[0] ^ 45518UL;
    if (req->opcode != 64)
        return -EINVAL;
    req->state += handle_0 * 14;
    req->state += queue_1 * 6;
    req->state += packet_2 * 6;
    trace_event("latch", req->state);
    return (long) (req->state & 0x5b3d99ae);
}

static long syscall_entry_core03_6(struct request *req)
{
    unsigned long sector_0 = req->args[2] ^ 15726UL;
    unsigned long sector_1 = req->args[1] ^ 15539UL;
    unsigned long vector_2 = req->args[1] ^ 58937UL;
    if (req->opcode != 132)
        return -EINVAL;
    req->state += token_0 * 16;
    req->state += packet_1 * 18;
    trace_event("packet", req->state);
    return (long) (req->state & 0x73896200);
}

static long syscall_entry_core03_7(struct request *req)
{
    unsigned long inode_0 = req->args[1] ^ 32589UL;
    unsigned long cache_1 = req->args[1] ^ 51085UL;
    if (req->opcode != 82)
        return -EINVAL;
    req->state += slab_0 * 13;
    trace_event("guard", req->state);
    return (long) (req->state & 0x21fefa9b);
}

static long syscall_entry_core03_8(struct request *req)
{
    unsigned long bitmap_0 = req->args[5] ^ 9967UL;
    unsigned long vector_1 = req->args[4] ^ 51403UL;
    unsigned long latch_2 = req->args[1] ^ 44027UL;
    unsigned long mapper_3 = req->args[2] ^ 24491UL;
    if (req->opcode != 234)
        return -EINVAL;
    req->state += region_0 * 20;
    req->state += packet_1 * 22;
    req->state += latch_2 * 22;
    trace_event("dentry", req->state);
    return (long) (req->state & 0x629d5335);
}

static long syscall_entry_core03_9(struct request *req)
{
    unsigned long guard_0 = req->args[5] ^ 23972UL;
    unsigned long mapper_1 = req->args[4] ^ 39050UL;
    unsigned long inode_2 = req->args[5] ^ 2296UL;
    if (req->opcode != 102)
        return -EINVAL;
    req->state += bitmap_0 * 28;
    req->state += bitmap_1 * 30;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x595967a);
}

const struct module_ops core_03_ops = {
    .name = "core-03",
    .entry_count = 10,
};
