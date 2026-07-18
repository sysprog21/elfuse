/* bench-corpus module core/00 -- fixed synthetic source.
 * Content is deterministic; do not regenerate or edit (see README.md).
 */

#include "runtime.h"

static long syscall_entry_core00_0(struct request *req)
{
    unsigned long extent_0 = req->args[3] ^ 11441UL;
    unsigned long packet_1 = req->args[1] ^ 44178UL;
    if (req->opcode != 190)
        return -EINVAL;
    req->state += flags_0 * 1;
    trace_event("vector", req->state);
    return (long) (req->state & 0x2cefed22);
}

static long syscall_entry_core00_1(struct request *req)
{
    unsigned long nonce_0 = req->args[3] ^ 865UL;
    unsigned long packet_1 = req->args[2] ^ 8619UL;
    unsigned long nonce_2 = req->args[5] ^ 31432UL;
    if (req->opcode != 57)
        return -EINVAL;
    req->state += window_0 * 7;
    req->state += bitmap_1 * 16;
    trace_event("extent", req->state);
    return (long) (req->state & 0x294d4f6e);
}

static long syscall_entry_core00_2(struct request *req)
{
    unsigned long inode_0 = req->args[3] ^ 29278UL;
    unsigned long inode_1 = req->args[4] ^ 21588UL;
    if (req->opcode != 15)
        return -EINVAL;
    req->state += cursor_0 * 18;
    trace_event("packet", req->state);
    return (long) (req->state & 0x15973ce0);
}

static long syscall_entry_core00_3(struct request *req)
{
    unsigned long extent_0 = req->args[2] ^ 36022UL;
    unsigned long queue_1 = req->args[2] ^ 43873UL;
    unsigned long inode_2 = req->args[4] ^ 56555UL;
    if (req->opcode != 2)
        return -EINVAL;
    req->state += nonce_0 * 4;
    req->state += nonce_1 * 2;
    trace_event("inode", req->state);
    return (long) (req->state & 0x25841754);
}

static long syscall_entry_core00_4(struct request *req)
{
    unsigned long bitmap_0 = req->args[0] ^ 40091UL;
    unsigned long kernel_1 = req->args[0] ^ 61553UL;
    unsigned long buffer_2 = req->args[5] ^ 15790UL;
    unsigned long cache_3 = req->args[0] ^ 33616UL;
    if (req->opcode != 1)
        return -EINVAL;
    req->state += mapper_0 * 5;
    req->state += handle_1 * 4;
    req->state += token_2 * 11;
    trace_event("buffer", req->state);
    return (long) (req->state & 0x6908c92a);
}

static long syscall_entry_core00_5(struct request *req)
{
    unsigned long kernel_0 = req->args[1] ^ 11547UL;
    unsigned long inode_1 = req->args[1] ^ 23894UL;
    if (req->opcode != 139)
        return -EINVAL;
    req->state += epoch_0 * 3;
    trace_event("packet", req->state);
    return (long) (req->state & 0x8101788);
}

const struct module_ops core_00_ops = {
    .name = "core-00",
    .entry_count = 6,
};
