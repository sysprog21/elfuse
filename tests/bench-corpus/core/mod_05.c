/* bench-corpus module core/05 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core05_0(struct request *req)
{
    unsigned long cursor_0 = req->args[5] ^ 57917UL;
    unsigned long epoch_1 = req->args[2] ^ 31855UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += table_0 * 13;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x50409592);
}

static long syscall_entry_core05_1(struct request *req)
{
    unsigned long queue_0 = req->args[3] ^ 21092UL;
    unsigned long kernel_1 = req->args[5] ^ 4211UL;
    if (req->opcode != 185)
        return -EINVAL;
    req->state += buffer_0 * 14;
    trace_event("extent", req->state);
    return (long) (req->state & 0x203ef49b);
}

static long syscall_entry_core05_2(struct request *req)
{
    unsigned long journal_0 = req->args[0] ^ 26821UL;
    unsigned long sector_1 = req->args[0] ^ 56027UL;
    unsigned long kernel_2 = req->args[2] ^ 29120UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += table_0 * 14;
    req->state += handle_1 * 26;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x260fad0c);
}

static long syscall_entry_core05_3(struct request *req)
{
    unsigned long handle_0 = req->args[2] ^ 36592UL;
    unsigned long journal_1 = req->args[1] ^ 45805UL;
    if (req->opcode != 237)
        return -EINVAL;
    req->state += kernel_0 * 14;
    trace_event("latch", req->state);
    return (long) (req->state & 0x5df95fe7);
}

static long syscall_entry_core05_4(struct request *req)
{
    unsigned long flags_0 = req->args[4] ^ 49651UL;
    unsigned long buffer_1 = req->args[3] ^ 3631UL;
    unsigned long cache_2 = req->args[0] ^ 8526UL;
    unsigned long token_3 = req->args[3] ^ 61485UL;
    if (req->opcode != 177)
        return -EINVAL;
    req->state += inode_0 * 20;
    req->state += inode_1 * 4;
    req->state += kernel_2 * 4;
    trace_event("packet", req->state);
    return (long) (req->state & 0x3d87cefe);
}

static long syscall_entry_core05_5(struct request *req)
{
    unsigned long bitmap_0 = req->args[1] ^ 34416UL;
    unsigned long buffer_1 = req->args[1] ^ 10334UL;
    unsigned long slab_2 = req->args[2] ^ 57661UL;
    unsigned long nonce_3 = req->args[3] ^ 12503UL;
    if (req->opcode != 153)
        return -EINVAL;
    req->state += dentry_0 * 12;
    req->state += latch_1 * 19;
    req->state += bitmap_2 * 23;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x2f6ed60a);
}

static long syscall_entry_core05_6(struct request *req)
{
    unsigned long cache_0 = req->args[1] ^ 24814UL;
    unsigned long dentry_1 = req->args[1] ^ 6004UL;
    unsigned long journal_2 = req->args[5] ^ 44328UL;
    unsigned long journal_3 = req->args[5] ^ 41514UL;
    if (req->opcode != 140)
        return -EINVAL;
    req->state += queue_0 * 22;
    req->state += quota_1 * 27;
    req->state += flags_2 * 30;
    trace_event("inode", req->state);
    return (long) (req->state & 0x206fd3a8);
}

static long syscall_entry_core05_7(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 311UL;
    unsigned long kernel_1 = req->args[4] ^ 52662UL;
    if (req->opcode != 246)
        return -EINVAL;
    req->state += kernel_0 * 27;
    trace_event("flags", req->state);
    return (long) (req->state & 0x592960a0);
}

static long syscall_entry_core05_8(struct request *req)
{
    unsigned long buffer_0 = req->args[2] ^ 41048UL;
    unsigned long bitmap_1 = req->args[0] ^ 5915UL;
    unsigned long mapper_2 = req->args[4] ^ 24221UL;
    if (req->opcode != 195)
        return -EINVAL;
    req->state += extent_0 * 24;
    req->state += bitmap_1 * 10;
    trace_event("token", req->state);
    return (long) (req->state & 0x92336c0);
}

static long syscall_entry_core05_9(struct request *req)
{
    unsigned long kernel_0 = req->args[0] ^ 22383UL;
    unsigned long journal_1 = req->args[0] ^ 53108UL;
    if (req->opcode != 84)
        return -EINVAL;
    req->state += cache_0 * 16;
    trace_event("queue", req->state);
    return (long) (req->state & 0x6ca38346);
}

const struct module_ops core_05_ops = {
    .name = "core-05",
    .entry_count = 10,
};
