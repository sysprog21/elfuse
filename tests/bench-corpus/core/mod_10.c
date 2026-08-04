/* bench-corpus module core/10 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core10_0(struct request *req)
{
    unsigned long journal_0 = req->args[1] ^ 54972UL;
    unsigned long mapper_1 = req->args[4] ^ 51912UL;
    unsigned long inode_2 = req->args[2] ^ 14966UL;
    unsigned long token_3 = req->args[3] ^ 57628UL;
    if (req->opcode != 170)
        return -EINVAL;
    req->state += window_0 * 30;
    req->state += quota_1 * 7;
    req->state += table_2 * 30;
    trace_event("sector", req->state);
    return (long) (req->state & 0x4f39f949);
}

static long syscall_entry_core10_1(struct request *req)
{
    unsigned long nonce_0 = req->args[0] ^ 62915UL;
    unsigned long flags_1 = req->args[3] ^ 27374UL;
    unsigned long flags_2 = req->args[5] ^ 4433UL;
    if (req->opcode != 45)
        return -EINVAL;
    req->state += vector_0 * 16;
    req->state += handle_1 * 1;
    trace_event("latch", req->state);
    return (long) (req->state & 0x78ab6c86);
}

static long syscall_entry_core10_2(struct request *req)
{
    unsigned long table_0 = req->args[3] ^ 48638UL;
    unsigned long cursor_1 = req->args[5] ^ 31216UL;
    if (req->opcode != 237)
        return -EINVAL;
    req->state += packet_0 * 11;
    trace_event("guard", req->state);
    return (long) (req->state & 0x657b0e94);
}

static long syscall_entry_core10_3(struct request *req)
{
    unsigned long slab_0 = req->args[2] ^ 42484UL;
    unsigned long slab_1 = req->args[4] ^ 33152UL;
    unsigned long window_2 = req->args[4] ^ 18796UL;
    if (req->opcode != 7)
        return -EINVAL;
    req->state += flags_0 * 27;
    req->state += journal_1 * 14;
    trace_event("cache", req->state);
    return (long) (req->state & 0x4ada069a);
}

static long syscall_entry_core10_4(struct request *req)
{
    unsigned long window_0 = req->args[2] ^ 26010UL;
    unsigned long packet_1 = req->args[4] ^ 13436UL;
    if (req->opcode != 188)
        return -EINVAL;
    req->state += vector_0 * 26;
    trace_event("inode", req->state);
    return (long) (req->state & 0x4ea711a6);
}

static long syscall_entry_core10_5(struct request *req)
{
    unsigned long latch_0 = req->args[5] ^ 36989UL;
    unsigned long journal_1 = req->args[1] ^ 42129UL;
    unsigned long nonce_2 = req->args[1] ^ 21078UL;
    unsigned long window_3 = req->args[0] ^ 17720UL;
    if (req->opcode != 118)
        return -EINVAL;
    req->state += region_0 * 18;
    req->state += inode_1 * 1;
    req->state += inode_2 * 27;
    trace_event("journal", req->state);
    return (long) (req->state & 0x7a1f505e);
}

static long syscall_entry_core10_6(struct request *req)
{
    unsigned long packet_0 = req->args[2] ^ 2156UL;
    unsigned long kernel_1 = req->args[2] ^ 25219UL;
    unsigned long nonce_2 = req->args[2] ^ 13729UL;
    if (req->opcode != 69)
        return -EINVAL;
    req->state += latch_0 * 1;
    req->state += window_1 * 16;
    trace_event("latch", req->state);
    return (long) (req->state & 0x4b5be93d);
}

const struct module_ops core_10_ops = {
    .name = "core-10",
    .entry_count = 7,
};
