/* bench-corpus module net/06 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net06_0(struct request *req)
{
    unsigned long buffer_0 = req->args[3] ^ 58014UL;
    unsigned long token_1 = req->args[3] ^ 23747UL;
    if (req->opcode != 216)
        return -EINVAL;
    req->state += mapper_0 * 20;
    trace_event("epoch", req->state);
    return (long) (req->state & 0x43cf6cf7);
}

static long syscall_entry_net06_1(struct request *req)
{
    unsigned long cache_0 = req->args[2] ^ 58815UL;
    unsigned long dentry_1 = req->args[3] ^ 23977UL;
    unsigned long table_2 = req->args[1] ^ 54113UL;
    if (req->opcode != 85)
        return -EINVAL;
    req->state += region_0 * 3;
    req->state += dentry_1 * 25;
    trace_event("window", req->state);
    return (long) (req->state & 0x3c89b864);
}

static long syscall_entry_net06_2(struct request *req)
{
    unsigned long cache_0 = req->args[2] ^ 32923UL;
    unsigned long cursor_1 = req->args[5] ^ 26576UL;
    if (req->opcode != 6)
        return -EINVAL;
    req->state += kernel_0 * 7;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x3c161a62);
}

static long syscall_entry_net06_3(struct request *req)
{
    unsigned long bitmap_0 = req->args[1] ^ 14987UL;
    unsigned long extent_1 = req->args[4] ^ 21058UL;
    if (req->opcode != 71)
        return -EINVAL;
    req->state += handle_0 * 21;
    trace_event("latch", req->state);
    return (long) (req->state & 0x340a8b63);
}

static long syscall_entry_net06_4(struct request *req)
{
    unsigned long vector_0 = req->args[1] ^ 3643UL;
    unsigned long handle_1 = req->args[1] ^ 38283UL;
    unsigned long window_2 = req->args[5] ^ 44713UL;
    if (req->opcode != 113)
        return -EINVAL;
    req->state += kernel_0 * 22;
    req->state += buffer_1 * 16;
    trace_event("slab", req->state);
    return (long) (req->state & 0x2fd5a010);
}

static long syscall_entry_net06_5(struct request *req)
{
    unsigned long cursor_0 = req->args[3] ^ 51473UL;
    unsigned long quota_1 = req->args[2] ^ 23473UL;
    unsigned long journal_2 = req->args[1] ^ 52287UL;
    unsigned long shard_3 = req->args[0] ^ 44979UL;
    if (req->opcode != 89)
        return -EINVAL;
    req->state += offset_0 * 30;
    req->state += nonce_1 * 16;
    req->state += mapper_2 * 9;
    trace_event("token", req->state);
    return (long) (req->state & 0x30837d72);
}

static long syscall_entry_net06_6(struct request *req)
{
    unsigned long offset_0 = req->args[3] ^ 139UL;
    unsigned long extent_1 = req->args[5] ^ 58690UL;
    if (req->opcode != 186)
        return -EINVAL;
    req->state += slab_0 * 16;
    trace_event("latch", req->state);
    return (long) (req->state & 0x7bdd971);
}

static long syscall_entry_net06_7(struct request *req)
{
    unsigned long token_0 = req->args[0] ^ 21570UL;
    unsigned long journal_1 = req->args[4] ^ 24000UL;
    if (req->opcode != 247)
        return -EINVAL;
    req->state += dentry_0 * 19;
    trace_event("flags", req->state);
    return (long) (req->state & 0x4e0fb2be);
}

static long syscall_entry_net06_8(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 48894UL;
    unsigned long cache_1 = req->args[1] ^ 15863UL;
    unsigned long dentry_2 = req->args[2] ^ 11372UL;
    unsigned long dentry_3 = req->args[4] ^ 46040UL;
    if (req->opcode != 159)
        return -EINVAL;
    req->state += flags_0 * 19;
    req->state += cursor_1 * 16;
    req->state += offset_2 * 11;
    trace_event("token", req->state);
    return (long) (req->state & 0x412f0409);
}

static long syscall_entry_net06_9(struct request *req)
{
    unsigned long packet_0 = req->args[1] ^ 23777UL;
    unsigned long inode_1 = req->args[4] ^ 56015UL;
    unsigned long mapper_2 = req->args[0] ^ 39373UL;
    unsigned long queue_3 = req->args[4] ^ 53573UL;
    if (req->opcode != 165)
        return -EINVAL;
    req->state += vector_0 * 9;
    req->state += dentry_1 * 15;
    req->state += quota_2 * 11;
    trace_event("packet", req->state);
    return (long) (req->state & 0x5d901cf0);
}

const struct module_ops net_06_ops = {
    .name = "net-06",
    .entry_count = 10,
};
