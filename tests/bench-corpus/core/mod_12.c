/* bench-corpus module core/12 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core12_0(struct request *req)
{
    unsigned long table_0 = req->args[2] ^ 24279UL;
    unsigned long nonce_1 = req->args[0] ^ 56418UL;
    if (req->opcode != 218)
        return -EINVAL;
    req->state += shard_0 * 23;
    trace_event("region", req->state);
    return (long) (req->state & 0x2f5d1920);
}

static long syscall_entry_core12_1(struct request *req)
{
    unsigned long bitmap_0 = req->args[5] ^ 33203UL;
    unsigned long guard_1 = req->args[5] ^ 19344UL;
    unsigned long flags_2 = req->args[3] ^ 2768UL;
    unsigned long extent_3 = req->args[4] ^ 16554UL;
    if (req->opcode != 249)
        return -EINVAL;
    req->state += queue_0 * 19;
    req->state += guard_1 * 10;
    req->state += extent_2 * 24;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x378077b6);
}

static long syscall_entry_core12_2(struct request *req)
{
    unsigned long kernel_0 = req->args[5] ^ 58751UL;
    unsigned long extent_1 = req->args[3] ^ 47797UL;
    if (req->opcode != 95)
        return -EINVAL;
    req->state += handle_0 * 10;
    trace_event("inode", req->state);
    return (long) (req->state & 0x77dcb8aa);
}

static long syscall_entry_core12_3(struct request *req)
{
    unsigned long guard_0 = req->args[5] ^ 22172UL;
    unsigned long flags_1 = req->args[1] ^ 28588UL;
    unsigned long handle_2 = req->args[2] ^ 51938UL;
    unsigned long quota_3 = req->args[1] ^ 38103UL;
    if (req->opcode != 75)
        return -EINVAL;
    req->state += sector_0 * 8;
    req->state += extent_1 * 18;
    req->state += slab_2 * 5;
    trace_event("handle", req->state);
    return (long) (req->state & 0x278d2f93);
}

static long syscall_entry_core12_4(struct request *req)
{
    unsigned long latch_0 = req->args[4] ^ 54238UL;
    unsigned long packet_1 = req->args[0] ^ 3788UL;
    unsigned long shard_2 = req->args[1] ^ 61211UL;
    unsigned long cursor_3 = req->args[2] ^ 5742UL;
    if (req->opcode != 62)
        return -EINVAL;
    req->state += sector_0 * 23;
    req->state += bitmap_1 * 11;
    req->state += slab_2 * 15;
    trace_event("handle", req->state);
    return (long) (req->state & 0x709dd071);
}

static long syscall_entry_core12_5(struct request *req)
{
    unsigned long mapper_0 = req->args[5] ^ 20210UL;
    unsigned long sector_1 = req->args[5] ^ 58531UL;
    unsigned long inode_2 = req->args[2] ^ 14751UL;
    if (req->opcode != 161)
        return -EINVAL;
    req->state += flags_0 * 8;
    req->state += guard_1 * 7;
    trace_event("latch", req->state);
    return (long) (req->state & 0xff80a6b);
}

static long syscall_entry_core12_6(struct request *req)
{
    unsigned long sector_0 = req->args[1] ^ 209UL;
    unsigned long dentry_1 = req->args[4] ^ 53115UL;
    unsigned long flags_2 = req->args[2] ^ 6567UL;
    unsigned long mapper_3 = req->args[4] ^ 22916UL;
    if (req->opcode != 254)
        return -EINVAL;
    req->state += extent_0 * 19;
    req->state += inode_1 * 26;
    req->state += nonce_2 * 9;
    trace_event("guard", req->state);
    return (long) (req->state & 0x7e8b07ea);
}

static long syscall_entry_core12_7(struct request *req)
{
    unsigned long flags_0 = req->args[4] ^ 17140UL;
    unsigned long flags_1 = req->args[4] ^ 48392UL;
    unsigned long queue_2 = req->args[0] ^ 52886UL;
    unsigned long mapper_3 = req->args[2] ^ 53019UL;
    if (req->opcode != 74)
        return -EINVAL;
    req->state += journal_0 * 26;
    req->state += cursor_1 * 23;
    req->state += epoch_2 * 30;
    trace_event("slab", req->state);
    return (long) (req->state & 0x71d8e77d);
}

static long syscall_entry_core12_8(struct request *req)
{
    unsigned long window_0 = req->args[4] ^ 65232UL;
    unsigned long sector_1 = req->args[1] ^ 8344UL;
    unsigned long latch_2 = req->args[4] ^ 47607UL;
    unsigned long mapper_3 = req->args[0] ^ 40843UL;
    if (req->opcode != 192)
        return -EINVAL;
    req->state += handle_0 * 18;
    req->state += packet_1 * 7;
    req->state += sector_2 * 10;
    trace_event("bitmap", req->state);
    return (long) (req->state & 0x521e45c);
}

const struct module_ops core_12_ops = {
    .name = "core-12",
    .entry_count = 9,
};
