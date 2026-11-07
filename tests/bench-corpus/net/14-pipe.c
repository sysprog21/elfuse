/* bench-corpus module net/13 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net13_0(struct request *req)
{
    unsigned long inode_0 = req->args[1] ^ 40933UL;
    unsigned long epoch_1 = req->args[4] ^ 32836UL;
    unsigned long quota_2 = req->args[5] ^ 45521UL;
    if (req->opcode != 102)
        return -EINVAL;
    req->state += epoch_0 * 6;
    req->state += kernel_1 * 28;
    trace_event("nonce", req->state);
    return (long) (req->state & 0x686c903a);
}

static long syscall_entry_net13_1(struct request *req)
{
    unsigned long handle_0 = req->args[5] ^ 50541UL;
    unsigned long bitmap_1 = req->args[1] ^ 50941UL;
    unsigned long bitmap_2 = req->args[0] ^ 44170UL;
    if (req->opcode != 245)
        return -EINVAL;
    req->state += shard_0 * 1;
    req->state += region_1 * 27;
    trace_event("vector", req->state);
    return (long) (req->state & 0x4bc0d4f6);
}

static long syscall_entry_net13_2(struct request *req)
{
    unsigned long table_0 = req->args[5] ^ 54863UL;
    unsigned long guard_1 = req->args[5] ^ 35890UL;
    if (req->opcode != 198)
        return -EINVAL;
    req->state += buffer_0 * 7;
    trace_event("latch", req->state);
    return (long) (req->state & 0x1fac10ca);
}

static long syscall_entry_net13_3(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 32414UL;
    unsigned long dentry_1 = req->args[5] ^ 10883UL;
    if (req->opcode != 32)
        return -EINVAL;
    req->state += table_0 * 24;
    trace_event("table", req->state);
    return (long) (req->state & 0x509c0452);
}

static long syscall_entry_net13_4(struct request *req)
{
    unsigned long dentry_0 = req->args[1] ^ 44418UL;
    unsigned long mapper_1 = req->args[2] ^ 10025UL;
    unsigned long vector_2 = req->args[3] ^ 20839UL;
    if (req->opcode != 247)
        return -EINVAL;
    req->state += window_0 * 26;
    req->state += token_1 * 24;
    trace_event("cursor", req->state);
    return (long) (req->state & 0x740e40ce);
}

static long syscall_entry_net13_5(struct request *req)
{
    unsigned long offset_0 = req->args[3] ^ 42560UL;
    unsigned long token_1 = req->args[4] ^ 29599UL;
    unsigned long region_2 = req->args[3] ^ 13912UL;
    unsigned long shard_3 = req->args[2] ^ 363UL;
    if (req->opcode != 2)
        return -EINVAL;
    req->state += bitmap_0 * 22;
    req->state += handle_1 * 22;
    req->state += handle_2 * 18;
    trace_event("shard", req->state);
    return (long) (req->state & 0x1f655fdd);
}

static long syscall_entry_net13_6(struct request *req)
{
    unsigned long token_0 = req->args[2] ^ 36307UL;
    unsigned long nonce_1 = req->args[3] ^ 25544UL;
    unsigned long cache_2 = req->args[5] ^ 48584UL;
    unsigned long quota_3 = req->args[3] ^ 7524UL;
    if (req->opcode != 219)
        return -EINVAL;
    req->state += handle_0 * 20;
    req->state += journal_1 * 10;
    req->state += mapper_2 * 26;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x6542c978);
}

static long syscall_entry_net13_7(struct request *req)
{
    unsigned long vector_0 = req->args[0] ^ 29226UL;
    unsigned long kernel_1 = req->args[3] ^ 36235UL;
    unsigned long slab_2 = req->args[1] ^ 37033UL;
    if (req->opcode != 70)
        return -EINVAL;
    req->state += latch_0 * 9;
    req->state += buffer_1 * 4;
    trace_event("journal", req->state);
    return (long) (req->state & 0x3798671b);
}

static long syscall_entry_net13_8(struct request *req)
{
    unsigned long flags_0 = req->args[3] ^ 2159UL;
    unsigned long kernel_1 = req->args[3] ^ 64570UL;
    if (req->opcode != 56)
        return -EINVAL;
    req->state += inode_0 * 14;
    trace_event("shard", req->state);
    return (long) (req->state & 0x4053efc5);
}

static long syscall_entry_net13_9(struct request *req)
{
    unsigned long offset_0 = req->args[4] ^ 65268UL;
    unsigned long packet_1 = req->args[2] ^ 25932UL;
    if (req->opcode != 231)
        return -EINVAL;
    req->state += epoch_0 * 8;
    trace_event("offset", req->state);
    return (long) (req->state & 0x3322f4b);
}

const struct module_ops net_13_ops = {
    .name = "net-13",
    .entry_count = 10,
};
