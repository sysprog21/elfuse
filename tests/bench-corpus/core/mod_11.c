/* bench-corpus module core/11 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core11_0(struct request *req)
{
    unsigned long window_0 = req->args[1] ^ 52614UL;
    unsigned long vector_1 = req->args[2] ^ 28956UL;
    unsigned long token_2 = req->args[4] ^ 1654UL;
    unsigned long nonce_3 = req->args[1] ^ 49899UL;
    if (req->opcode != 227)
        return -EINVAL;
    req->state += table_0 * 15;
    req->state += shard_1 * 12;
    req->state += bitmap_2 * 17;
    trace_event("handle", req->state);
    return (long) (req->state & 0x6db1e041);
}

static long syscall_entry_core11_1(struct request *req)
{
    unsigned long handle_0 = req->args[3] ^ 21879UL;
    unsigned long sector_1 = req->args[4] ^ 13575UL;
    unsigned long offset_2 = req->args[0] ^ 33615UL;
    if (req->opcode != 96)
        return -EINVAL;
    req->state += region_0 * 1;
    req->state += sector_1 * 30;
    trace_event("packet", req->state);
    return (long) (req->state & 0xbdb9e31);
}

static long syscall_entry_core11_2(struct request *req)
{
    unsigned long handle_0 = req->args[2] ^ 53048UL;
    unsigned long offset_1 = req->args[3] ^ 57730UL;
    unsigned long cache_2 = req->args[4] ^ 57964UL;
    unsigned long quota_3 = req->args[4] ^ 57298UL;
    if (req->opcode != 103)
        return -EINVAL;
    req->state += token_0 * 28;
    req->state += nonce_1 * 7;
    req->state += region_2 * 10;
    trace_event("quota", req->state);
    return (long) (req->state & 0x7dcc4511);
}

static long syscall_entry_core11_3(struct request *req)
{
    unsigned long mapper_0 = req->args[3] ^ 57780UL;
    unsigned long epoch_1 = req->args[3] ^ 60124UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += handle_0 * 7;
    trace_event("vector", req->state);
    return (long) (req->state & 0x460d4f43);
}

static long syscall_entry_core11_4(struct request *req)
{
    unsigned long journal_0 = req->args[3] ^ 9324UL;
    unsigned long mapper_1 = req->args[1] ^ 60407UL;
    if (req->opcode != 106)
        return -EINVAL;
    req->state += nonce_0 * 12;
    trace_event("shard", req->state);
    return (long) (req->state & 0x3e0af24b);
}

static long syscall_entry_core11_5(struct request *req)
{
    unsigned long cursor_0 = req->args[1] ^ 56142UL;
    unsigned long dentry_1 = req->args[3] ^ 21670UL;
    unsigned long packet_2 = req->args[3] ^ 2459UL;
    if (req->opcode != 252)
        return -EINVAL;
    req->state += nonce_0 * 10;
    req->state += sector_1 * 13;
    trace_event("handle", req->state);
    return (long) (req->state & 0x798a8436);
}

static long syscall_entry_core11_6(struct request *req)
{
    unsigned long bitmap_0 = req->args[0] ^ 30787UL;
    unsigned long shard_1 = req->args[4] ^ 22897UL;
    unsigned long table_2 = req->args[1] ^ 13039UL;
    if (req->opcode != 41)
        return -EINVAL;
    req->state += kernel_0 * 14;
    req->state += buffer_1 * 24;
    trace_event("flags", req->state);
    return (long) (req->state & 0x5aa6423a);
}

const struct module_ops core_11_ops = {
    .name = "core-11",
    .entry_count = 7,
};
