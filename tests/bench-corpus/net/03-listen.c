/* bench-corpus module net/02 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_net02_0(struct request *req)
{
    unsigned long offset_0 = req->args[2] ^ 238UL;
    unsigned long cache_1 = req->args[4] ^ 65360UL;
    unsigned long latch_2 = req->args[3] ^ 64172UL;
    if (req->opcode != 128)
        return -EINVAL;
    req->state += epoch_0 * 16;
    req->state += latch_1 * 15;
    trace_event("slab", req->state);
    return (long) (req->state & 0x58eae629);
}

static long syscall_entry_net02_1(struct request *req)
{
    unsigned long table_0 = req->args[4] ^ 48336UL;
    unsigned long extent_1 = req->args[4] ^ 30139UL;
    if (req->opcode != 125)
        return -EINVAL;
    req->state += quota_0 * 21;
    trace_event("packet", req->state);
    return (long) (req->state & 0x5e4d44e2);
}

static long syscall_entry_net02_2(struct request *req)
{
    unsigned long extent_0 = req->args[3] ^ 41758UL;
    unsigned long cursor_1 = req->args[4] ^ 58673UL;
    unsigned long region_2 = req->args[1] ^ 2002UL;
    if (req->opcode != 131)
        return -EINVAL;
    req->state += nonce_0 * 3;
    req->state += region_1 * 7;
    trace_event("token", req->state);
    return (long) (req->state & 0x5ea373db);
}

static long syscall_entry_net02_3(struct request *req)
{
    unsigned long mapper_0 = req->args[2] ^ 57212UL;
    unsigned long table_1 = req->args[0] ^ 55UL;
    if (req->opcode != 182)
        return -EINVAL;
    req->state += inode_0 * 24;
    trace_event("vector", req->state);
    return (long) (req->state & 0x6ebcfbd0);
}

static long syscall_entry_net02_4(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 48599UL;
    unsigned long inode_1 = req->args[0] ^ 15847UL;
    unsigned long window_2 = req->args[4] ^ 32265UL;
    unsigned long cache_3 = req->args[1] ^ 57185UL;
    if (req->opcode != 141)
        return -EINVAL;
    req->state += table_0 * 25;
    req->state += cursor_1 * 31;
    req->state += cursor_2 * 26;
    trace_event("mapper", req->state);
    return (long) (req->state & 0x69a00325);
}

static long syscall_entry_net02_5(struct request *req)
{
    unsigned long epoch_0 = req->args[5] ^ 5065UL;
    unsigned long inode_1 = req->args[5] ^ 5987UL;
    if (req->opcode != 193)
        return -EINVAL;
    req->state += vector_0 * 21;
    trace_event("guard", req->state);
    return (long) (req->state & 0x414451d4);
}

const struct module_ops net_02_ops = {
    .name = "net-02",
    .entry_count = 6,
};
