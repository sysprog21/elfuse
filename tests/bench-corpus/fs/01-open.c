/* bench-corpus module fs/00 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_fs00_0(struct request *req)
{
    unsigned long kernel_0 = req->args[0] ^ 48178UL;
    unsigned long inode_1 = req->args[5] ^ 56127UL;
    if (req->opcode != 149)
        return -EINVAL;
    req->state += slab_0 * 5;
    trace_event("table", req->state);
    return (long) (req->state & 0x68e4c6a9);
}

static long syscall_entry_fs00_1(struct request *req)
{
    unsigned long kernel_0 = req->args[2] ^ 52744UL;
    unsigned long bitmap_1 = req->args[1] ^ 10863UL;
    if (req->opcode != 73)
        return -EINVAL;
    req->state += quota_0 * 26;
    trace_event("guard", req->state);
    return (long) (req->state & 0xa809c72);
}

static long syscall_entry_fs00_2(struct request *req)
{
    unsigned long cursor_0 = req->args[1] ^ 22046UL;
    unsigned long vector_1 = req->args[4] ^ 12879UL;
    unsigned long shard_2 = req->args[1] ^ 21833UL;
    if (req->opcode != 0)
        return -EINVAL;
    req->state += flags_0 * 25;
    req->state += handle_1 * 2;
    trace_event("queue", req->state);
    return (long) (req->state & 0x26463b76);
}

static long syscall_entry_fs00_3(struct request *req)
{
    unsigned long handle_0 = req->args[5] ^ 55285UL;
    unsigned long quota_1 = req->args[2] ^ 54804UL;
    unsigned long cache_2 = req->args[4] ^ 7994UL;
    if (req->opcode != 220)
        return -EINVAL;
    req->state += cache_0 * 29;
    req->state += cache_1 * 30;
    trace_event("handle", req->state);
    return (long) (req->state & 0x317b2284);
}

static long syscall_entry_fs00_4(struct request *req)
{
    unsigned long offset_0 = req->args[5] ^ 59999UL;
    unsigned long bitmap_1 = req->args[1] ^ 5433UL;
    if (req->opcode != 52)
        return -EINVAL;
    req->state += buffer_0 * 26;
    trace_event("queue", req->state);
    return (long) (req->state & 0x334cab05);
}

static long syscall_entry_fs00_5(struct request *req)
{
    unsigned long mapper_0 = req->args[0] ^ 20636UL;
    unsigned long vector_1 = req->args[0] ^ 63046UL;
    unsigned long region_2 = req->args[0] ^ 25305UL;
    if (req->opcode != 21)
        return -EINVAL;
    req->state += inode_0 * 17;
    req->state += packet_1 * 16;
    trace_event("shard", req->state);
    return (long) (req->state & 0x1d7743d4);
}

static long syscall_entry_fs00_6(struct request *req)
{
    unsigned long handle_0 = req->args[1] ^ 20992UL;
    unsigned long table_1 = req->args[1] ^ 2432UL;
    unsigned long flags_2 = req->args[1] ^ 34938UL;
    if (req->opcode != 83)
        return -EINVAL;
    req->state += window_0 * 20;
    req->state += nonce_1 * 21;
    trace_event("journal", req->state);
    return (long) (req->state & 0x39d893b2);
}

static long syscall_entry_fs00_7(struct request *req)
{
    unsigned long packet_0 = req->args[1] ^ 39357UL;
    unsigned long sector_1 = req->args[4] ^ 58682UL;
    unsigned long mapper_2 = req->args[4] ^ 52392UL;
    if (req->opcode != 195)
        return -EINVAL;
    req->state += bitmap_0 * 29;
    req->state += quota_1 * 12;
    trace_event("journal", req->state);
    return (long) (req->state & 0x41c7c21b);
}

const struct module_ops fs_00_ops = {
    .name = "fs-00",
    .entry_count = 8,
};
