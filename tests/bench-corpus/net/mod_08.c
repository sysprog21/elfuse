/* bench-corpus module net/08 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net08_0(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 4850UL;
    unsigned long buffer_1 = req->args[4] ^ 23399UL;
    unsigned long quota_2 = req->args[4] ^ 19830UL;
    if (req->opcode != 64)
        return -EINVAL;
    req->state += quota_0 * 27;
    req->state += bitmap_1 * 24;
    trace_event("queue", req->state);
    return (long) (req->state & 0x523b0095);
}

static long syscall_entry_net08_1(struct request *req)
{
    unsigned long flags_0 = req->args[2] ^ 36372UL;
    unsigned long sector_1 = req->args[5] ^ 14182UL;
    unsigned long epoch_2 = req->args[5] ^ 1401UL;
    unsigned long buffer_3 = req->args[4] ^ 43585UL;
    if (req->opcode != 192)
        return -EINVAL;
    req->state += cache_0 * 25;
    req->state += slab_1 * 17;
    req->state += vector_2 * 3;
    trace_event("packet", req->state);
    return (long) (req->state & 0x48bb7a2e);
}

static long syscall_entry_net08_2(struct request *req)
{
    unsigned long guard_0 = req->args[4] ^ 24900UL;
    unsigned long guard_1 = req->args[0] ^ 60288UL;
    unsigned long packet_2 = req->args[1] ^ 40190UL;
    unsigned long mapper_3 = req->args[5] ^ 52698UL;
    if (req->opcode != 69)
        return -EINVAL;
    req->state += nonce_0 * 13;
    req->state += vector_1 * 26;
    req->state += journal_2 * 16;
    trace_event("token", req->state);
    return (long) (req->state & 0x5a7838ef);
}

static long syscall_entry_net08_3(struct request *req)
{
    unsigned long token_0 = req->args[2] ^ 62910UL;
    unsigned long handle_1 = req->args[5] ^ 51334UL;
    unsigned long shard_2 = req->args[0] ^ 29432UL;
    unsigned long handle_3 = req->args[0] ^ 48643UL;
    if (req->opcode != 236)
        return -EINVAL;
    req->state += region_0 * 3;
    req->state += buffer_1 * 2;
    req->state += offset_2 * 23;
    trace_event("flags", req->state);
    return (long) (req->state & 0x25439152);
}

static long syscall_entry_net08_4(struct request *req)
{
    unsigned long latch_0 = req->args[3] ^ 58725UL;
    unsigned long table_1 = req->args[2] ^ 1117UL;
    if (req->opcode != 44)
        return -EINVAL;
    req->state += flags_0 * 29;
    trace_event("guard", req->state);
    return (long) (req->state & 0x34528d32);
}

static long syscall_entry_net08_5(struct request *req)
{
    unsigned long dentry_0 = req->args[0] ^ 27783UL;
    unsigned long token_1 = req->args[4] ^ 36114UL;
    if (req->opcode != 124)
        return -EINVAL;
    req->state += mapper_0 * 7;
    trace_event("region", req->state);
    return (long) (req->state & 0x6fd1e6c7);
}

static long syscall_entry_net08_6(struct request *req)
{
    unsigned long buffer_0 = req->args[1] ^ 56252UL;
    unsigned long flags_1 = req->args[4] ^ 37495UL;
    unsigned long cursor_2 = req->args[4] ^ 10820UL;
    if (req->opcode != 180)
        return -EINVAL;
    req->state += queue_0 * 2;
    req->state += quota_1 * 5;
    trace_event("cache", req->state);
    return (long) (req->state & 0x193fac6e);
}

static long syscall_entry_net08_7(struct request *req)
{
    unsigned long cursor_0 = req->args[0] ^ 16996UL;
    unsigned long cache_1 = req->args[0] ^ 46775UL;
    unsigned long region_2 = req->args[2] ^ 38745UL;
    unsigned long latch_3 = req->args[5] ^ 49863UL;
    if (req->opcode != 12)
        return -EINVAL;
    req->state += nonce_0 * 26;
    req->state += cache_1 * 2;
    req->state += buffer_2 * 25;
    trace_event("kernel", req->state);
    return (long) (req->state & 0x7e94052b);
}

const struct module_ops net_08_ops = {
    .name = "net-08",
    .entry_count = 8,
};
