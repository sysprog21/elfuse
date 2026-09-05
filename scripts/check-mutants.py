#!/usr/bin/env python3
"""Assert that each proof target actually rejects a known-broken source.

"PROVED N of N" is not evidence on its own. check-wp-result.py's MIN_GOALS floor
catches a gutted body or a dropped contract, and check-acsl-coverage.py catches a
contracted helper left out of the proof set, but neither shows that the clauses a
target does carry are load-bearing. Establishing that by hand, editing a body and
watching the target fail, left nothing behind for the next contract change.

Each entry below is a mutation that MUST make its target fail. The mutation is
applied to a COPY of the source under build/mutants and the target is re-run
against that copy through VERIFY_<TARGET>_SRC, so a mutation run never edits the
tree. That is deliberate: doing this by hand with cp-and-restore left a mutated
source on disk more than once during development.

A mutation counts as caught only when a goal goes UNPROVED. Tripping the
MIN_GOALS floor does not count: the floor sits at exactly the baseline count for
every target, so removing any obligation fails it even when the code is correct,
and scoring that as caught would credit the gate for rejecting nothing.

The recipe runs check-acsl-coverage.py against SCAN, which stays the pristine
tree rather than the mutated copy. That is the right choice, but it means the
four entries below that mutate a contract are not coverage-checked.

Scoping a run to a changed diff lives in proof-scope.py, which answers the
same question for the CI proof matrix. --changed-since here is that answer
applied to mutations.

Runs inherit the proof's own per-goal prover timeout, and lowering it for
mutation runs is unsound however tempting the speedup looks. A broken contract
does not get refuted; the goal simply becomes unprovable and the prover grinds
until the budget expires, so "caught" is reported as a timeout. A goal that is
merely hard but still true times out the same way. The two are indistinguishable
by verdict, so a shorter budget silently converts a genuine MISS into a "caught"
and hides exactly the gap this file exists to find. Proving the unmutated file
at the shorter budget does not rescue the argument: it shows the budget suits
correct code, not that it suits weakly-broken code. Measured, the cut was worth
about 40 percent of the wall time; parallelism buys most of that back soundly.

Mutations are (old, new) string pairs rather than patch files. A patch carries
context lines that rot when anything nearby moves; a distinctive snippet either
still matches or fails loudly as STALE, which is the report you want. "old" must
appear exactly once, so a snippet that becomes ambiguous is also reported rather
than silently mutating the wrong site.

Usage:
    check-mutants.py [--target NAME] [--list]
"""

import argparse
import collections
import concurrent.futures
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


# scripts/ filenames are kebab-case per CLAUDE.md, which no plain "import"
# statement can name, so a sibling module is loaded by path. The alternative
# was an underscore in the filename, which the tree does not use anywhere.
def _load(stem, name):
    import importlib.util

    path = pathlib.Path(__file__).resolve().parent / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proof_scope = _load("proof-scope", "proof_scope")
# Loaded here rather than taken as proof_scope.verify_mk, even though that
# would save one parse of mk/verify.mk. This table decides which file each
# mutation copies and mutates, so reaching it through proof-scope.py would make
# that file a judging input; proof-scope.py's own SCHEDULING_FILES says it is
# not one, and a diff touching only it therefore runs no mutation leg at all.
# Two module objects over one silent contradiction.
verify_mk = _load("verify-mk", "verify_mk")
BUILD = ROOT / "build" / "mutants"
# The recipe writes $(BUILD_DIR)/verify-$(NAME).log, and NAME is overridden per
# run to keep concurrent mutations off a shared log. That path must exist first:
# a failed redirect makes the recipe exit non-zero, which would otherwise be
# scored as the proof rejecting the mutation.
LOGS = ROOT / "build" / "verify-mutants"

# (target, source, function, description, old, new).
#
# "function" names the proved function the mutation breaks; it is what the
# coverage summary at the end counts, not decoration.
MUTATIONS = [
    # ---- verify-netlink ---------------------------------------------------
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_align_up",
        "do not round up (the walk lands on a misaligned header)",
        "    uint64_t padded = len + (NETLINK_ALIGNTO - 1);\n"
        "    return padded - padded % NETLINK_ALIGNTO;\n",
        "    return len;\n",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_rta_bounds",
        "drop the lower guard (data_len underflows below the header)",
        "    if (rta_len < RTA_HDRLEN || rta_len > total - off)\n",
        "    if (rta_len > total - off)\n",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_msg_span",
        "span the raw length (the next message starts misaligned)",
        "    *span = netlink_align_up(nlmsg_len);\n",
        "    *span = nlmsg_len;\n",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_attr_extent",
        "drop the wire-field guard (the 16-bit total wraps)",
        "    if (datalen > NETLINK_ATTR_LEN_MAX - RTA_HDRLEN)\n        return 0;\n\n",
        "",
    ),
    # ---- verify-futexhash -------------------------------------------------
    (
        "futexhash",
        "src/proved/futexhash.h",
        "futex_bucket_index",
        "drop the reduction (the index can run off the end of the table)",
        "    return (uint32_t) (mixed % (uint64_t) nbuckets);\n",
        "    return (uint32_t) mixed;\n",
    ),
    (
        "futexhash",
        "src/proved/futexhash.h",
        "futex_bucket_index",
        "reduce by one too few (the index can reach nbuckets, one off the end)",
        "    return (uint32_t) (mixed % (uint64_t) nbuckets);\n",
        "    return (uint32_t) (mixed % ((uint64_t) nbuckets + 1));\n",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_valid_capped",
        "drop the ceiling (a capped caller then accepts what it cannot convert)",
        "    return timespec_valid(sec, nsec) && sec <= cap;\n",
        "    return timespec_valid(sec, nsec);\n",
    ),
    # ---- verify-futexdeadline ----------------------------------------------
    (
        "futexdeadline",
        "src/runtime/futex.c",
        "futex_remaining_ns",
        "drop the cap (the quantum then exceeds what the caller asked for)",
        "    return rem < cap_ns ? rem : cap_ns;\n",
        "    return rem;\n",
    ),
    (
        "futexdeadline",
        "src/runtime/futex.c",
        "futex_quantum_deadline",
        "drop the saturating add (now + rem overflows near INT64_MAX)",
        "    int64_t at_ns = now_ns > INT64_MAX - add ? INT64_MAX : now_ns + add;\n",
        "    int64_t at_ns = now_ns + add;\n",
    ),
    (
        "futexdeadline",
        "src/runtime/futex.c",
        "linux_timespec_is_valid",
        "drop both bounds (a full-second nsec and an over-cap tv_sec get through)",
        "    return timespec_valid_capped(lts->tv_sec, lts->tv_nsec,\n"
        "                                 FUTEX_TIMESPEC_SEC_MAX);\n",
        "    return lts->tv_sec >= 0 && lts->tv_nsec >= 0;\n",
    ),
    # ---- verify-futexop ----------------------------------------------------
    (
        "futexop",
        "src/proved/futexop.h",
        "futex_op_sign_extend12",
        "restore the signed-shift form (UB for every operand at or above 0x800)",
        "    uint32_t v = raw % FUTEX_OP_ARG_SPANU;\n"
        "    if (v < FUTEX_OP_ARG_SIGN)\n"
        "        return (int32_t) v;\n"
        "    return (int32_t) v - FUTEX_OP_ARG_SPAN;\n",
        "    int r = (int) (raw % FUTEX_OP_ARG_SPANU);\n"
        "    return (int32_t) ((r << 20) >> 20);\n",
    ),
    (
        "futexop",
        "src/proved/futexop.h",
        "futex_op_sign_extend12",
        "drop the extension (the operand stays unsigned, so no value is negative)",
        "    if (v < FUTEX_OP_ARG_SIGN)\n"
        "        return (int32_t) v;\n"
        "    return (int32_t) v - FUTEX_OP_ARG_SPAN;\n",
        "    return (int32_t) v;\n",
    ),
    (
        "futexop",
        "src/proved/futexop.h",
        "futex_op_shift_arg_mask",
        "drop the mask (a negative operand reaches the shift: undefined)",
        "    return (int32_t) ((uint32_t) arg % 32u);\n",
        "    return arg;\n",
    ),
    # ---- verify-align ------------------------------------------------------
    (
        "align",
        "src/proved/align.h",
        "align_up_ok",
        "drop the overflow guard (the top multiple wraps to a lower address)",
        "        if (k >= UINT64_MAX / align)\n            return 0;\n",
        "",
    ),
    (
        "align",
        "src/proved/align.h",
        "align_up_ok",
        "round down instead of up (the result can sit below the input)",
        "    if (k * align != x) {\n"
        "        if (k >= UINT64_MAX / align)\n"
        "            return 0;\n"
        "        k++;\n"
        "    }\n",
        "",
    ),
    (
        "align",
        "src/proved/align.h",
        "window_fits",
        "test the sum instead of the difference (the sum wraps first)",
        "    return start <= limit && length <= limit - start;",
        "    return start + length <= limit;",
    ),
    (
        "align",
        "src/proved/align.h",
        "window_fits",
        "accept a window that overruns the limit by one",
        "    return start <= limit && length <= limit - start;",
        "    return start <= limit && length <= limit - start + 1;",
    ),
    # ---- verify-mmapfastpath ----------------------------------------------
    (
        "mmapfastpath",
        "src/proved/mmap-fastpath.h",
        "mmap_fastpath_request_fits",
        "accept every non-empty request (an allocation can pass the limit)",
        "    return window_fits(start, len, limit);",
        "    return true;",
    ),
    (
        "mmapfastpath",
        "src/proved/mmap-fastpath.h",
        "mmap_fastpath_pow2_clamped",
        "clamp an oversized arena request to the lower bound",
        "    if (value >= MMAP_FAST_ARENA_MAX)\n"
        "        return MMAP_FAST_ARENA_MAX;",
        "    if (value >= MMAP_FAST_ARENA_MAX)\n"
        "        return MMAP_FAST_ARENA_MIN;",
    ),
    (
        "mmapfastpath",
        "src/proved/mmap-fastpath.h",
        "mmap_fastpath_window_max",
        "discard a new maximum (the arena can be undersized)",
        "        if (window[i] > max)\n            max = window[i];",
        "        if (window[i] > max)\n            max = 0;",
    ),
    (
        "mmapfastpath",
        "src/proved/mmap-fastpath.h",
        "mmap_fastpath_arena_size",
        "return an arena size above the configured maximum",
        "    return adaptive > covering ? adaptive : covering;",
        "    return UINT64_MAX;",
    ),
    # ---- verify-cmsg -------------------------------------------------------
    (
        "cmsg",
        "src/proved/cmsg.h",
        "cmsg_entry_bounds",
        "drop the minimum-length guard (payload length underflows)",
        "    if (cmsg_len < CMSG_LINUX_HDR_BYTES)\n        return 0;\n",
        "",
    ),
    (
        "cmsg",
        "src/proved/cmsg.h",
        "cmsg_entry_bounds",
        "drop the fits-in-buffer guard (payload runs past the control buffer)",
        "    if (cmsg_len > ctl_len - pos)\n        return 0;\n",
        "",
    ),
    (
        "cmsg",
        "src/proved/cmsg.h",
        "cmsg_entry_bounds",
        "align up by ALIGN rather than ALIGN-1 (overshoots by one word)",
        "    uint64_t advance = cmsg_len + (CMSG_LINUX_ALIGN - 1);",
        "    uint64_t advance = cmsg_len + CMSG_LINUX_ALIGN;",
    ),
    (
        "cmsg",
        "src/proved/cmsg.h",
        "cmsg_entry_bounds",
        "drop the align-up entirely (walks to a misaligned next header)",
        "    uint64_t advance = cmsg_len + (CMSG_LINUX_ALIGN - 1);\n"
        "    advance -= advance % CMSG_LINUX_ALIGN;\n"
        "    *next_pos = pos + advance;",
        "    *next_pos = pos + cmsg_len;",
    ),
    (
        "cmsg",
        "src/proved/cmsg.h",
        "cmsg_entry_bounds",
        "scribble on the outputs before rejecting the entry",
        "    if (cmsg_len < CMSG_LINUX_HDR_BYTES)\n        return 0;\n",
        "    if (cmsg_len < CMSG_LINUX_HDR_BYTES) {\n"
        "        *data_len = 1;\n"
        "        return 0;\n"
        "    }\n",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_slot",
        "drop the upper bound (the split indexes past the bitmap)",
        "    if (fd < 0 || fd >= FDSET_MAX_FDS)\n        return 0;",
        "    if (fd < 0)\n        return 0;",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_slot",
        "accept the fd one past the table (off-by-one on the bound)",
        "    if (fd < 0 || fd >= FDSET_MAX_FDS)",
        "    if (fd < 0 || fd > FDSET_MAX_FDS)",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_slot",
        "swap word and bit (the split no longer reconstructs the fd)",
        "    *word = (uint64_t) fd / FDSET_BITS_PER_WORD;\n"
        "    *bit = (uint64_t) fd % FDSET_BITS_PER_WORD;",
        "    *word = (uint64_t) fd % FDSET_BITS_PER_WORD;\n"
        "    *bit = (uint64_t) fd / FDSET_BITS_PER_WORD;",
    ),
    # ---- verify-fuse -------------------------------------------------------
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_reply_extent",
        "drop the header-size guard (reply length underflows)",
        "    if (hdr_len < FUSE_OUT_HDR_BYTES || hdr_len > count)",
        "    if (hdr_len > count)",
    ),
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_reply_extent",
        "drop the fits-the-write guard (copy runs past the frame)",
        "    if (hdr_len < FUSE_OUT_HDR_BYTES || hdr_len > count)",
        "    if (hdr_len < FUSE_OUT_HDR_BYTES)",
    ),
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_frame_count_ok",
        "drop the frame ceiling (unbounded daemon allocation)",
        "    return count >= FUSE_OUT_HDR_BYTES && count <= FUSE_FRAME_CAP;",
        "    return count >= FUSE_OUT_HDR_BYTES;",
    ),
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_clamp_negotiated_write",
        "make the negotiation clamp a no-op",
        "    if (requested > FUSE_MAX_NEGOTIATED_WRITE)\n"
        "        return FUSE_MAX_NEGOTIATED_WRITE;\n"
        "    return requested;",
        "    return requested;",
    ),
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_clamp_negotiated_write",
        "remove the header slack (a legal max_write no longer leaves room)",
        "#define FUSE_MAX_NEGOTIATED_WRITE (FUSE_FRAME_CAP - 256)",
        "#define FUSE_MAX_NEGOTIATED_WRITE FUSE_FRAME_CAP",
    ),
    # ---- verify-gva --------------------------------------------------------
    (
        "gva",
        "src/proved/gva.h",
        "gva_leaf_target_args_ok",
        "predicate drops the granule upper bound",
        "    return granule > 0 && granule <= GVA_PT_ADDR_MASK &&\n"
        "           ipa <= GVA_PT_ADDR_MASK;",
        "    return granule > 0 && ipa <= GVA_PT_ADDR_MASK;",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_leaf_target_args_ok",
        "predicate drops the ipa bound",
        "    return granule > 0 && granule <= GVA_PT_ADDR_MASK &&\n"
        "           ipa <= GVA_PT_ADDR_MASK;",
        "    return granule > 0 && granule <= GVA_PT_ADDR_MASK;",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_chunk_clamp_args_ok",
        "predicate drops the total < limit conjunct",
        "    return chunk >= 1 && gpa < region_end && total < limit;",
        "    return chunk >= 1 && gpa < region_end;",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_chunk_clamp_args_ok",
        "predicate accepts everything",
        "    return chunk >= 1 && gpa < region_end && total < limit;",
        "    return 1;",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_chunk_clamp",
        "call site permutes limit and total",
        "        gva_chunk_clamp_args_ok(chunk, gpa, region_end, limit, total));",
        "        gva_chunk_clamp_args_ok(chunk, gpa, region_end, total, limit));",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_leaf_target",
        "call site permutes granule and ipa",
        "    GVA_CONTRACT_ASSERT(gva_leaf_target_args_ok(granule, ipa));",
        "    GVA_CONTRACT_ASSERT(gva_leaf_target_args_ok(ipa, granule));",
    ),
    # ---- verify-stack ------------------------------------------------------
    (
        "stack",
        "src/proved/stack.h",
        "stack_take",
        "drop the floor check (descent leaves the stack region)",
        "    if (bytes > *ptr - floor)\n        return 0;\n\n    *ptr -= bytes;",
        "    *ptr -= bytes;",
    ),
    (
        "stack",
        "src/proved/stack.h",
        "stack_take",
        "move before refusing (partial move on the reject path)",
        "    if (bytes > *ptr - floor)\n        return 0;\n",
        "    *ptr -= bytes;\n    if (bytes > *ptr - floor)\n        return 0;\n",
    ),
    (
        "stack",
        "src/proved/stack.h",
        "stack_align_down",
        "round up instead of down",
        "    return sp - sp % STACK_ALIGN;",
        "    return sp + sp % STACK_ALIGN;",
    ),
    (
        "stack",
        "src/proved/stack.h",
        "stack_pushed_words",
        "drop the alignment padding word",
        "    return entries + entries % 2;",
        "    return entries;",
    ),
    (
        "stack",
        "src/proved/stack.h",
        "stack_final_sp",
        "drop the underflow guard (SP lands below the region)",
        "    if (bytes > base - floor)\n        return 0;\n\n    *sp = base - bytes;",
        "    *sp = base - bytes;",
    ),
    # ---- verify-sockaddr ---------------------------------------------------
    (
        "sockaddr",
        "src/proved/sockaddr.h",
        "sockaddr_payload_len",
        "drop the destination clamp (copy overruns the destination)",
        "    if (payload > room)\n        payload = room;\n",
        "",
    ),
    (
        "sockaddr",
        "src/proved/sockaddr.h",
        "sockaddr_len_ok",
        "accept addresses too short to hold a family",
        "    return len >= SOCKADDR_FAMILY_BYTES;",
        "    return 1;",
    ),
    (
        "sockaddr",
        "src/proved/sockaddr.h",
        "sockaddr_payload_len",
        "return no payload at all",
        "    return payload;",
        "    return 0;",
    ),
    (
        "sockaddr",
        "src/proved/sockaddr.h",
        "sockaddr_payload_len",
        "drop the source-length precondition",
        "  requires src_len >= SOCKADDR_FAMILY_BYTES;\n",
        "",
    ),
    (
        "fuse",
        "src/proved/fuse.h",
        "fuse_reply_extent",
        "write the reply length before rejecting the header",
        "    if (hdr_len < FUSE_OUT_HDR_BYTES || hdr_len > count)\n        return 0;",
        "    if (hdr_len < FUSE_OUT_HDR_BYTES || hdr_len > count) {\n"
        "        *reply_len = hdr_len;\n"
        "        return 0;\n"
        "    }",
    ),
    # ---- verify-netlink ----------------------------------------------------
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_rta_bounds",
        "drop the minimum-length guard (payload length underflows)",
        "    if (rta_len < RTA_HDRLEN || rta_len > total - off)",
        "    if (rta_len > total - off)",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_rta_bounds",
        "drop the fits-the-message guard (attribute runs past the message)",
        "    if (rta_len < RTA_HDRLEN || rta_len > total - off)",
        "    if (rta_len < RTA_HDRLEN)",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_msg_span",
        "drop the header-length guard (span can be shorter than a header)",
        "    if (nlmsg_len < NLMSG_HDRLEN)\n        return 0;\n\n",
        "",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_align_up",
        "round down instead of up (the walk stops advancing)",
        "    uint64_t padded = len + (NETLINK_ALIGNTO - 1);",
        "    uint64_t padded = len;",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_attr_extent",
        "drop the wire-field ceiling (the caller's cast to rta_len truncates)",
        "    if (datalen > NETLINK_ATTR_LEN_MAX - RTA_HDRLEN)\n        return 0;\n\n",
        "",
    ),
    (
        "netlink",
        "src/proved/netlink.h",
        "netlink_attr_extent",
        "drop the remaining-space guard (the payload runs past the buffer)",
        "    if (a > max)\n        return 0;\n\n",
        "",
    ),
    # ---- verify-netlinkwalk ------------------------------------------------
    (
        "netlinkwalk",
        "src/syscall/netlink.c",
        "nl_parse_link_filter",
        "leave no room for the terminator (name_out[name_cap] is written)",
        "            for (; i < dlen && i + 1 < name_cap && req[off + RTA_HDRLEN + i];",
        "            for (; i < dlen && i < name_cap && req[off + RTA_HDRLEN + i];",
    ),
    (
        "netlinkwalk",
        "src/syscall/netlink.c",
        "nl_complete_span",
        "drop the fits-the-copy guard (the span reported exceeds to_copy)",
        "        if (msg_bytes > to_copy)\n            break;\n",
        "",
    ),
    (
        "netlinkwalk",
        "src/syscall/netlink.c",
        "nl_put_attr",
        "pad one byte past the aligned extent (writes past max)",
        "        memset(buf + total, 0, (size_t) (aligned - total));",
        "        memset(buf + total, 0, (size_t) (aligned - total) + 1);",
    ),
    # ---- verify-sigframe ---------------------------------------------------
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "drop the underflow guard (frame base wraps to a huge address)",
        "    if (frame_bytes > sp)\n        return 0;\n",
        "",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "drop the floor check (frame lands below the alternate stack)",
        "    if (candidate < floor)\n        return 0;\n",
        "",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "skip the align-down (handler runs on a misaligned stack)",
        "    candidate -= candidate % SIGFRAME_ALIGN;\n",
        "",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "refuse a frame that exactly reaches the floor (off-by-one rejection)",
        "    if (candidate < floor)",
        "    if (candidate <= floor)",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "place the frame one aligned slot lower than it must be",
        "    *base = candidate;",
        "    *base = candidate - floor >= SIGFRAME_ALIGN ? candidate - SIGFRAME_ALIGN\n                                                  : candidate;",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_base",
        "place the frame at the floor rather than below sp",
        "    *base = candidate;",
        "    *base = floor - floor % SIGFRAME_ALIGN;",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_fpsimd_vreg_offset",
        "shift every vector register one slot up (V31 writes past the record)",
        "    return SIGFRAME_FPSIMD_VREG_BASE + n * SIGFRAME_FPSIMD_VREG_BYTES;",
        "    return SIGFRAME_FPSIMD_VREG_BASE + (n + 1) * SIGFRAME_FPSIMD_VREG_BYTES;",
    ),
    (
        "sigframe",
        "src/proved/sigframe.h",
        "sigframe_fpsimd_vreg_offset",
        "drop the header base (V0 lands on FPSR and FPCR)",
        "    return SIGFRAME_FPSIMD_VREG_BASE + n * SIGFRAME_FPSIMD_VREG_BYTES;",
        "    return n * SIGFRAME_FPSIMD_VREG_BYTES;",
    ),
    # ---- verify-elf --------------------------------------------------------
    (
        "elf",
        "src/core/elf.c",
        "elf_phdr_fetch",
        "drop the tail bound (reads a header past the end of the table)",
        "    if (off > buflen || buflen - off < sizeof(*out))",
        "    if (off > buflen)",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_segment_extent",
        "drop the guest_size clamp (segment maps outside the slab)",
        "    if (memsz > guest_size || gpa > guest_size - memsz)",
        "    if (memsz > guest_size)",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_read_interp",
        "drop the interp_path ceiling (the pread runs past the buffer)",
        "    if (len < 2 || len >= sizeof(info->interp_path)) {",
        "    if (len < 2) {",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_record_load",
        "drop the segment-table ceiling (the write runs past segments[])",
        "    if (*seg_count >= ELF_MAX_SEGMENTS) {",
        "    if (false) {",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_check_placement",
        "drop the loop variant (the placement sweep is no longer finite)",
        "      loop variant info->num_segments - i;",
        "      loop variant 0;",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_pt_table_offset",
        "write the offset before rejecting a descriptor below the base",
        "    uint64_t ipa = desc & GVA_PT_ADDR_MASK;\n    if (ipa < base)\n        return 0;",
        "    uint64_t ipa = desc & GVA_PT_ADDR_MASK;\n    if (ipa < base) {\n"
        "        *off = ipa;\n        return 0;\n    }",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_pt_table_offset",
        "write the offset before rejecting a table that runs past the slab",
        "    uint64_t candidate = ipa - base;\n    if (guest_size < GVA_PT_TABLE_BYTES ||",
        "    uint64_t candidate = ipa - base;\n    *off = candidate;\n"
        "    if (guest_size < GVA_PT_TABLE_BYTES ||",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_leaf_target",
        "scribble on both outputs before rejecting an IPA below the base",
        "    if (ipa < base)\n        return 0;\n\n    uint64_t offset = gva % granule;",
        "    if (ipa < base) {\n        *gpa = 0;\n        *chunk = 1;\n"
        "        return 0;\n    }\n\n    uint64_t offset = gva % granule;",
    ),
    # ---- verify-pathdepth --------------------------------------------------
    (
        "pathdepth",
        "src/proved/pathdepth.h",
        "path_depth_pop",
        "drop the root floor (the depth wraps and indexes marks[] wild)",
        "    if (depth == 0)\n        return 0;\n",
        "",
    ),
    (
        "pathdepth",
        "src/proved/pathdepth.h",
        "path_depth_pop",
        "pop at the root too (a .. at / escapes one level)",
        "    if (depth == 0)",
        "    if (depth == UINT64_MAX)",
    ),
    (
        "pathdepth",
        "src/proved/pathdepth.h",
        "path_depth_push",
        "drop the capacity check (the next mark write leaves the array)",
        "    if (depth >= cap)\n        return 0;\n",
        "",
    ),
    (
        "pathdepth",
        "src/proved/pathdepth.h",
        "path_depth_push",
        "accept a push at capacity (off-by-one past the mark array)",
        "    if (depth >= cap)",
        "    if (depth > cap)",
    ),
    # ---- verify-rsp --------------------------------------------------------
    #
    # hex_nibble lives in src/utils.h, which verify-rsp includes rather than
    # analyzes, so the historical "gut hex_nibble" mutation cannot be expressed
    # here: this harness mutates a target's own source. Mutating an included
    # header would need the copy to shadow the original ahead of -Isrc on the
    # include path, which the shared recipe has no hook for.
    (
        "rsp",
        "src/debug/gdbstub-rsp.c",
        "gdb_hex_pair",
        "drop the low-nibble validation",
        "    int l = hex_nibble((unsigned char) lo);\n    if (l < 0)\n        return false;\n",
        "    int l = hex_nibble((unsigned char) lo);\n",
    ),
    (
        "rsp",
        "src/debug/gdbstub-rsp.c",
        "gdb_hex_decode",
        "drop the high-digit check (low digit read before rejecting)",
        "        int hi = hex_nibble((unsigned char) src[i * 2]);\n"
        "        if (hi < 0)\n            return -1;\n",
        "        int hi = hex_nibble((unsigned char) src[i * 2]);\n",
    ),
    (
        "rsp",
        "src/debug/gdbstub-rsp.c",
        "gdb_hex_decode",
        "off-by-one on the low digit (reads past the pair)",
        "        int lo = hex_nibble((unsigned char) src[i * 2 + 1]);",
        "        int lo = hex_nibble((unsigned char) src[i * 2 + 2]);",
    ),
    (
        "rsp",
        "src/debug/gdbstub-rsp.c",
        "rsp_checksum",
        "read the plain char without the unsigned cast",
        "        sum += (uint8_t) data[i];",
        "        sum += (unsigned int) data[i];",
    ),
    # ---- verify-elf: the three helpers that had no mutation ----------------
    (
        "elf",
        "src/core/elf.c",
        "elf_add_no_wrap",
        "drop the overflow guard (the sum wraps and is reported as valid)",
        "    if (a > UINT64_MAX - b)\n        return false;\n",
        "",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_phdr_gpa_in_segment",
        "drop the fits-the-segment guard (the table runs past p_filesz)",
        "    if (rel > p_filesz || p_filesz - rel < total)\n        return false;",
        "    if (rel > p_filesz)\n        return false;",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_phdr_gpa_in_segment",
        "drop the below-segment guard (the relative offset underflows)",
        "    if (phoff < p_offset)\n        return false;\n",
        "",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_phdr_table_bytes",
        "accept an entry stride below the header size (entries overlap)",
        "    if (phnum == 0 || phentsize < sizeof(elf64_phdr_t))",
        "    if (phnum == 0)",
    ),
    (
        "elf",
        "src/core/elf.c",
        "elf_phdr_table_bytes",
        "drop the table ceiling (phnum * phentsize is unbounded)",
        "    if (bytes > ELF_PHDR_TABLE_MAX)\n        return false;\n",
        "",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_span_ok",
        "accept a zero-length span (callers treat the result as non-empty)",
        "    if (len == 0)\n        return 0;\n",
        "",
    ),
    (
        "gva",
        "src/proved/gva.h",
        "gva_span_ok",
        "reject a span that exactly reaches the end of the address space",
        "    return gva <= UINT64_MAX - len;",
        "    return gva < UINT64_MAX - len;",
    ),
    (
        "rsp",
        "src/debug/gdbstub-rsp.c",
        "gdb_parse_hex",
        "advance two characters per digit (steps over the NUL terminator)",
        "        val = val * 16u + (uint64_t) d;\n        p++;",
        "        val = val * 16u + (uint64_t) d;\n        p += 2;",
    ),
    # ---- verify-dirent -----------------------------------------------------
    (
        "dirent",
        "src/proved/dirent.h",
        "dirent_reclen",
        "drop the align-up (records stop landing 8-byte aligned)",
        "    uint64_t padded = DIRENT64_HDR_BYTES + name_len + 1 + (DIRENT64_ALIGN - 1);",
        "    uint64_t padded = DIRENT64_HDR_BYTES + name_len + 1;",
    ),
    (
        "dirent",
        "src/proved/dirent.h",
        "dirent_reclen",
        "forget the NUL byte (a NAME_MAX name loses its terminator)",
        "    uint64_t padded = DIRENT64_HDR_BYTES + name_len + 1 + (DIRENT64_ALIGN - 1);",
        "    uint64_t padded = DIRENT64_HDR_BYTES + name_len + (DIRENT64_ALIGN - 1);",
    ),
    (
        "dirent",
        "src/proved/dirent.h",
        "dirent_record_bounds",
        "drop the fits-the-buffer guard (record runs past the guest count)",
        "    if (len > count - pos)\n        return 0;\n\n",
        "",
    ),
    (
        "dirent",
        "src/proved/dirent.h",
        "dirent_record_bounds",
        "accept a record that overruns by one (off-by-one fit test)",
        "    if (len > count - pos)",
        "    if (len > count - pos + 1)",
    ),
    (
        "dirent",
        "src/proved/dirent.h",
        "dirent_record_bounds",
        "start the padding one byte early (memset clobbers the NUL)",
        "    *pad_start = DIRENT64_HDR_BYTES + name_len + 1;",
        "    *pad_start = DIRENT64_HDR_BYTES + name_len;",
    ),
    # ---- verify-asyncudata -------------------------------------------------
    # Not "drop the reduction": (g % 2^48) * 2^16 and g * 2^16 are the same
    # value in 64-bit arithmetic, since the multiply discards the high bits the
    # reduction would have. That mutant is equivalent, and a target that
    # "catches" it is only reporting that the prover could not see the identity.
    # Reduce by the wrong span instead, which really does lose generation bits.
    (
        "asyncudata",
        "src/proved/asyncudata.h",
        "async_udata_pack",
        "reduce the generation by the fd span, truncating it to 16 bits",
        "    return (generation % ASYNC_UDATA_GEN_SPAN) * ASYNC_UDATA_FD_SPAN +",
        "    return (generation % ASYNC_UDATA_FD_SPAN) * ASYNC_UDATA_FD_SPAN +",
    ),
    (
        "asyncudata",
        "src/proved/asyncudata.h",
        "async_udata_pack",
        "scale the fd instead of the generation (the two fields swap places)",
        "    return (generation % ASYNC_UDATA_GEN_SPAN) * ASYNC_UDATA_FD_SPAN +\n"
        "           (uint64_t) guest_fd;",
        "    return (generation % ASYNC_UDATA_GEN_SPAN) +\n"
        "           (uint64_t) guest_fd * ASYNC_UDATA_FD_SPAN;",
    ),
    (
        "asyncudata",
        "src/proved/asyncudata.h",
        "async_udata_fd",
        "read the fd out of the generation field",
        "    return (int) (v % ASYNC_UDATA_FD_SPAN);",
        "    return (int) (v / ASYNC_UDATA_FD_SPAN);",
    ),
    (
        "asyncudata",
        "src/proved/asyncudata.h",
        "async_udata_gen",
        "drop the shift, so the generation carries the fd bits with it",
        "    return (v / ASYNC_UDATA_FD_SPAN) % ASYNC_UDATA_GEN_SPAN;",
        "    return v % ASYNC_UDATA_GEN_SPAN;",
    ),
    # ---- verify-iov --------------------------------------------------------
    (
        "iov",
        "src/proved/iov.h",
        "iov_total_add",
        "test the sum after adding rather than before (the add wraps first)",
        "    if (len > IOV_TOTAL_MAX - total)",
        "    if (total + len > IOV_TOTAL_MAX)",
    ),
    (
        "iov",
        "src/proved/iov.h",
        "iov_total_add",
        "drop the overflow guard entirely",
        "    if (len > IOV_TOTAL_MAX - total)\n        return 0;\n\n",
        "",
    ),
    (
        "iov",
        "src/proved/iov.h",
        "iov_count_ok",
        "accept iovcnt 0 (an empty vector reaches the per-entry loop)",
        "    return iovcnt >= 1 && iovcnt <= IOV_COUNT_MAX;",
        "    return iovcnt >= 0 && iovcnt <= IOV_COUNT_MAX;",
    ),
    (
        "iov",
        "src/proved/iov.h",
        "iov_advance_index",
        "consume an entry the transfer only partly filled (the remainder is "
        "no longer strictly inside the survivor)",
        "    while (spent < iovcnt && rem >= iov[spent].iov_len) {",
        "    while (spent < iovcnt && rem >= iov[spent].iov_len - 1) {",
    ),
    (
        "iov",
        "src/proved/iov.h",
        "iov_advance_index",
        "stop subtracting the entries already spent, so the remainder can "
        "exceed the entry it indexes",
        "        rem -= iov[spent].iov_len;\n",
        "",
    ),
    (
        "iov",
        "src/proved/iov.h",
        "iov_count_ok",
        "reject iovcnt at the cap (off-by-one rejection)",
        "    return iovcnt >= 1 && iovcnt <= IOV_COUNT_MAX;",
        "    return iovcnt >= 1 && iovcnt < IOV_COUNT_MAX;",
    ),
    # ---- verify-fdset ------------------------------------------------------
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_words",
        "round the word count down (the last partial word is never read)",
        "    *words =\n"
        "        ((uint64_t) nfds + (FDSET_BITS_PER_WORD - 1)) / FDSET_BITS_PER_WORD;",
        "    *words = (uint64_t) nfds / FDSET_BITS_PER_WORD;",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_words",
        "drop the upper bound on nfds (the read extent leaves the buffers)",
        "    if (nfds < 0 || nfds > FDSET_MAX_FDS)",
        "    if (nfds < 0)",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_fd_index",
        "accept the bit one past nfds (polls an fd the caller did not ask for)",
        "    if (index >= (uint64_t) nfds)",
        "    if (index > (uint64_t) nfds)",
    ),
    (
        "fdset",
        "src/proved/fdset.h",
        "fdset_fd_index",
        "drop the nfds bound (every bit of the last word is honored)",
        "    if (index >= (uint64_t) nfds)\n        return 0;\n\n",
        "",
    ),
    # ---- verify-timespec ---------------------------------------------------
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_ns_sat",
        "drop the tv_sec ceiling (the product overflows int64_t)",
        "    if (sec > TIMESPEC_SEC_MAX)\n        return INT64_MAX;\n",
        "",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_ns_sat",
        "drop the headroom check on the addition (a huge tv_nsec overflows)",
        "    if (nsec > INT64_MAX - whole)\n        return INT64_MAX;\n",
        "",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_ns_sat",
        "accept the tv_sec one past the ceiling (off-by-one saturation)",
        "    if (sec > TIMESPEC_SEC_MAX)",
        "    if (sec > TIMESPEC_SEC_MAX + 1)",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_poll_ms",
        "truncate the sub-millisecond remainder (a short wait becomes a spin)",
        "    if (ns % TIMESPEC_NSEC_PER_MSEC != 0)\n        ms++;\n",
        "",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_poll_ms",
        "drop the int clamp (the ms value wraps negative, poll waits forever)",
        "    if (ms > INT32_MAX)\n        return INT32_MAX;\n",
        "",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_valid",
        "accept a tv_nsec of exactly one second (off-by-one on the range)",
        "    return sec >= 0 && nsec >= 0 && nsec < TIMESPEC_NSEC_PER_SEC;",
        "    return sec >= 0 && nsec >= 0 && nsec <= TIMESPEC_NSEC_PER_SEC;",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_ns_sat",
        "return 0 rather than saturating when tv_nsec overflows the sum",
        "    if (nsec > INT64_MAX - whole)\n        return INT64_MAX;",
        "    if (nsec > INT64_MAX - whole)\n        return 0;",
    ),
    (
        "timespec",
        "src/proved/timespec.h",
        "timespec_to_poll_ms",
        "halve the timeout (poll returns before the caller asked)",
        "    int64_t ms = ns / TIMESPEC_NSEC_PER_MSEC;",
        "    int64_t ms = ns / (2 * TIMESPEC_NSEC_PER_MSEC);",
    ),
    # ---- verify-slice ------------------------------------------------------
    (
        "slice",
        "src/proved/slice.h",
        "slice_clamp",
        "drop the end-of-buffer guard (the remaining count underflows)",
        "    if (offset >= src_len) {\n        *n = 0;\n        return 0;\n    }\n\n",
        "",
    ),
    (
        "slice",
        "src/proved/slice.h",
        "slice_clamp",
        "serve the byte at the end offset (reads one past the buffer)",
        "    if (offset >= src_len) {",
        "    if (offset > src_len) {",
    ),
    (
        "slice",
        "src/proved/slice.h",
        "slice_clamp",
        "return the requested count unclamped (copy runs past the end)",
        "    *n = count < avail ? count : avail;",
        "    *n = count;",
    ),
]


def target_sources():
    """VERIFY_<T>_SRC for every target, as {target: path}."""
    return verify_mk.target_sources()


def target_mutable_files():
    """Files a target's mutation may edit, as {target: {paths}}.

    Only VERIFY_<T>_SRC, and that restriction is structural rather than
    cautious: run_mutation copies one file and points the prover at the copy,
    so a mutation to any other file leaves the proof reading the original
    through -Isrc and produces a verdict about unmutated code. src/utils.h is
    the case that comes up, since hex_nibble lives there and both verify-elf
    and verify-rsp prove it; covering it by mutation would need a runner that
    stages a whole tree.
    """
    return {target: {src} for target, src in target_sources().items()}


def proved_functions():
    """Every function named in a VERIFY_*_FCTS list, as {target: [names]}."""
    text = verify_mk.joined_text()
    shared = re.search(r"^VERIFY_UTILS_FCTS\s*:=\s*(.*)$", text, re.MULTILINE)
    utils = shared.group(1) if shared else ""
    out = {}
    for m in re.finditer(r"^VERIFY_([A-Z0-9_]+)_FCTS\s*:=\s*(.*)$", text, re.MULTILINE):
        name = m.group(1).lower()
        if name == "utils":
            continue
        fcts = m.group(2).replace("$(VERIFY_UTILS_FCTS)", utils)
        out[name] = [f for f in fcts.split() if not f.startswith("$")]
    return out


# check-wp-result.py's vocabulary for a run that produced no usable verdict, as
# opposed to one where the prover genuinely could not discharge a goal. These
# mean the harness broke, not that the proof rejected the mutation.
INFRA_MARKERS = (
    "frama-c rejected the input",  # User Error: the mutant does not parse
    "its own summary is not trusted",  # frama-c crashed
    "emitted no result",  # frama-c never ran
)


# Mutations run against the same prover set as the proofs, deliberately.
#
# Narrowing to one prover was tried and is unsound for the reason the timeout
# shortcut is: the baseline only shows that the ORIGINAL goals discharge with
# that prover, and a mutation does not fail a goal, it replaces it. The
# replacement can be true but awkward, provable by the dropped prover and not
# by the kept one, and that scores as caught while the contract rejected
# nothing. It is the same trap in a different variable, and the baseline cannot
# see it either.


# ACSL lives in comments, so a mutation that edits a contract cannot be told
# from one that edits a body by looking at the function name. These markers can.
ACSL_MARKERS = ("ensures", "requires", "assigns", "@")


def mutation_scope(function, old, new):
    """The single function worth proving for this mutation, or None for all.

    WP proves each function against its callees' CONTRACTS, never their bodies,
    so editing a body can only move that one function's goals. Editing a
    contract moves its callers' goals too, and the caller is not named anywhere
    in the entry, so those run at full scope.
    """
    if any(m in old or m in new for m in ACSL_MARKERS):
        return None
    return function


def run_target(target, source_copy, name, fct=None):
    """Run verify-<target> against @source_copy. Returns (ok, output)."""
    var = f"VERIFY_{target.upper()}_SRC"
    args = [
        "make",
        f"verify-{target}",
        f"{var}={source_copy}",
        f"NAME={name}",
    ]

    # Narrowing the proof set also drops the goal count below the target's
    # floor, so the floor has to come down with it. The unrestricted baseline
    # keeps the real floor, and any run that fails to catch its mutation is
    # repeated at full scope before the verdict stands, so nothing rests on the
    # narrowed run alone.
    if fct:
        args += [f"FCT_ARG={fct}", "MIN_GOALS=1"]
    proc = subprocess.run(
        args,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode == 0, proc.stdout


def check_baseline(target, src):
    """An UNMUTATED copy must still prove through the same path.

    Without this control every infrastructure failure (a bad make override, a
    log path that cannot be written, a missing include) makes the target exit
    non-zero and reads as "the mutation was caught". That is not hypothetical:
    an earlier version of this script wrote its logs to a directory that did not
    exist, and reported all 27 mutations caught while proving nothing at all.
    """
    work = BUILD / f"baseline-{target}"
    work.mkdir(parents=True, exist_ok=True)
    copy = work / pathlib.Path(src).name
    copy.write_text((ROOT / src).read_text())
    ok, _out = run_target(target, copy, f"mutants/baseline-{target}")
    return ok


def run_mutation(idx, mutation):
    """Apply one mutation to a copy and return (status, detail)."""
    target, src, _function, _desc, old, new = mutation
    original = (ROOT / src).read_text()
    hits = original.count(old)
    if hits != 1:
        return "STALE", f"snippet appears {hits} times, expected exactly 1"

    work = BUILD / f"{idx:02d}-{target}"
    work.mkdir(parents=True, exist_ok=True)
    copy = work / pathlib.Path(src).name
    copy.write_text(original.replace(old, new, 1))

    # NAME picks the log path, so each mutation gets its own. Concurrent
    # mutations of one target would otherwise clobber a shared log, and a
    # clobbered log makes the target FAIL, which reads as "caught".
    # Prove only what this mutation can have moved. A caught mutation is the
    # common case and is where the time goes, so the narrow run carries it; a
    # run that does NOT catch is repeated over the whole target before it is
    # allowed to read as MISSED, which is what keeps the narrowing from turning
    # a real gap into a pass.
    scope = mutation_scope(_function, old, new)
    ok, out = run_target(target, copy, f"mutants/{target}-mut{idx:02d}", scope)
    if ok and scope:
        ok, out = run_target(target, copy, f"mutants/{target}-mut{idx:02d}")
    if ok:
        return "MISSED", "the target still passed"

    # A non-zero exit is not evidence on its own. It is equally what a crashed
    # prover, an unparsable mutant, or a broken override produces, and scoring
    # those as "caught" is how a harness reports success while checking nothing.
    # Require the verdict to name a reason the gate is supposed to give.
    for marker in INFRA_MARKERS:
        if marker in out:
            return "INFRA", f"target failed without a verdict ({marker})"
    # Proof-level rejection means a goal went unproved. Tripping the MIN_GOALS
    # floor is NOT that: the floor sits at exactly the baseline count for every
    # target, so removing any obligation fails it even when the code is correct
    # and every remaining goal still proves. Deleting a documented-redundant
    # ensures clause does exactly that, which would score as "caught" while
    # nothing was rejected.
    if "open: " in out:
        return "caught", ""
    if "obligations generated" in out:
        return "FLOOR", "only the MIN_GOALS floor fired; no goal went unproved"
    return "INFRA", "target failed but printed no recognizable verdict"


def pack_targets(targets, buckets):
    """@targets split into at most @buckets groups, longest first.

    GitHub bills a job's wall time rounded up to the minute, and a mutation leg
    spends about 90 seconds installing Homebrew and restoring a 1 GB opam
    switch before it proves anything. Seventeen legs pay that seventeen times
    to do about 51 minutes of work; five pay it five times. Measured on a real
    full-scope run, that is 85 macOS-minutes against 61.

    Packed by mutation count, which is a rough proxy and known to be rough:
    netlinkwalk carries three mutations and the slowest prover time in the set,
    because its control proof alone is 92 seconds locally. A cost table would
    be exact and would rot the first time a contract changed, so the imbalance
    stays and costs a few minutes on whichever bucket draws that target.
    """
    counts = collections.Counter(m[0] for m in MUTATIONS)
    order = sorted(targets, key=lambda t: (-counts.get(t, 0), t))
    if not order:
        return []
    packed = [[] for _ in range(min(buckets, len(order)))]
    for target in order:
        packed.sort(key=lambda b: sum(counts.get(t, 0) for t in b))
        packed[0].append(target)
    return [sorted(b) for b in packed if b]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", help="run only mutations for this target")
    ap.add_argument(
        "--list", action="store_true", help="list mutations without running them"
    )
    # Each mutation is an independent Frama-C run against its own copy, so they
    # parallelize cleanly. Serial, the full set runs longer than the whole rest
    # of "make verify", which is how a gate stops being run.
    # Scope to what a change could actually have broken. A mutation only tests
    # its own target's source, so on a branch that does not touch that source
    # the verdict is whatever it already was on the base. The full set still
    # runs wherever the base is built, which is where the guarantee lives; this
    # only keeps a per-PR run proportional to the diff.
    ap.add_argument(
        "--changed-since",
        metavar="REF",
        help="only run mutations whose target source differs from REF",
    )
    # CI groups the matrix with this rather than one leg per target; see
    # pack_targets for why, and .github/workflows/verify.yml for the caller.
    ap.add_argument(
        "--pack",
        type=int,
        metavar="N",
        help="print the named targets packed into at most N whitespace-"
        "separated groups, one per line, then exit",
    )
    ap.add_argument("targets", nargs="*", help="target names, with --pack")
    ap.add_argument(
        "--jobs",
        type=int,
        default=max(1, os.cpu_count() or 2),
        help="mutations to run concurrently (default: one per core)",
    )
    # Only used to compute --changed-since's include closure; the mutation
    # runs themselves go through "make", which resolves CC on its own. Split
    # rather than exec directly, since CC is routinely a wrapper or carries
    # flags ("ccache clang", "cc -DTEST").
    ap.add_argument(
        "--cc", default="cc", help="compiler for --changed-since's include scan"
    )
    args = ap.parse_args()
    cc = shlex.split(args.cc) or ["cc"]

    if args.targets and not args.pack:
        # Otherwise "check-mutants.py fuse" runs every mutation in the table
        # and says nothing about the name it was handed.
        print(
            f"target names are only read with --pack; use --target for one "
            f"target (got {' '.join(args.targets)})",
            file=sys.stderr,
        )
        return 2
    if args.pack:
        if args.pack < 1:
            print(f"--pack must be at least 1, got {args.pack}", file=sys.stderr)
            return 2
        # No fallback to the full set when no target is named. The caller is
        # CI passing the mutation scope, and that scope is empty on most pull
        # requests; defaulting to everything there would expand a full matrix
        # at exactly the moment the answer was "nothing to do".
        for bucket in pack_targets(args.targets, args.pack):
            print(" ".join(bucket))
        return 0

    # ThreadPoolExecutor raises on max_workers < 1, which would surface as a
    # traceback after the argument was already accepted. Reject it here.
    if args.jobs < 1:
        print(f"--jobs must be at least 1, got {args.jobs}", file=sys.stderr)
        return 2

    # Number by position in MUTATIONS, not in the filtered list, so a mutation
    # keeps the same log name whether or not --target was used.
    numbered = list(enumerate(MUTATIONS, 1))
    selected_pairs = [
        (i, m) for i, m in numbered if not args.target or m[0] == args.target
    ]
    selected = [m for _i, m in selected_pairs]

    # Validate before filtering, not after. This is a MUTATIONS-versus-
    # mk/verify.mk consistency check with nothing to do with any diff, and
    # running it after the scope filter meant a mutation naming a target the
    # makefile does not declare could be filtered away before the check that
    # reports it, which the filter then grew a clause to prevent. Hoisted, the
    # filter is one membership test and "--list" gets validated too.
    #
    # A mutation must name its target's own source. Naming an included header
    # instead silently analyzes the wrong file: the run still produces a
    # verdict, and the verdict means nothing.
    sources = target_sources()
    mutable = target_mutable_files()
    misdirected = {
        f"verify-{target}: mutates {src}, but VERIFY_{target.upper()}_SRC is "
        f"{sources.get(target, '<unknown>')}"
        for target, src, *_rest in selected
        if src not in mutable.get(target, set())
    }
    if misdirected:
        print(
            "  mutations naming a file their target does not analyze:", file=sys.stderr
        )
        for line in sorted(misdirected):
            print(f"    {line}", file=sys.stderr)
        return 2

    if args.changed_since:
        # The mutation question, not the proof one: a diff that only moves
        # the machinery deciding which targets run cannot change whether a
        # target rejects a broken source. Passing it explicitly keeps a local
        # MUTANT_SINCE run answering what CI's mutation matrix answers.
        scope = proof_scope.targets_changed_since(
            cc, args.changed_since, proof_scope.MUTATION_HARNESS_FILES
        )
        if scope is not None:
            kept = [(i, m) for i, m in selected_pairs if m[0] in scope]
            skipped = len(selected_pairs) - len(kept)
            if skipped:
                print(
                    f"  skipping {skipped} mutation(s): target source unchanged "
                    f"since {args.changed_since}"
                )
            selected_pairs, selected = kept, [m for _i, m in kept]
            if not selected:
                print("  no proved source changed; nothing to re-verify")
                return 0
    if not selected:
        print(f"no mutations for target {args.target!r}", file=sys.stderr)
        return 2

    if args.list:
        for target, _src, function, desc, _old, _new in selected:
            print(f"  verify-{target:<9} {function:<28} {desc}")
        return 0

    shutil.rmtree(BUILD, ignore_errors=True)
    # Clear the logs too, not just the copies: CI uploads this directory as the
    # artifact a human reads to see WHY something was caught, and a survivor
    # from an earlier run is indistinguishable from this run's output.
    shutil.rmtree(LOGS, ignore_errors=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    # Control first, and through the same executor the mutations use: a false
    # "caught" caused by concurrency would otherwise slip past a serial
    # baseline.
    targets = sorted({m[0] for m in selected})
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        oks = list(pool.map(check_baseline, targets, [sources[t] for t in targets]))
    broken = [t for t, ok in zip(targets, oks) if not ok]
    if broken:
        print(
            "  SETUP FAILED: unmutated sources do not prove for: "
            + ", ".join(f"verify-{t}" for t in broken),
            file=sys.stderr,
        )
        print(
            "  Mutation results would be meaningless; fix the harness first.",
            file=sys.stderr,
        )
        return 2

    # map hands back results in table order however the mutations interleave,
    # so a run stays diffable against the previous one.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(
            pool.map(run_mutation, [i for i, _m in selected_pairs], selected)
        )

    # INFRA means the run produced no verdict, and by far its most common cause
    # is prover starvation: several Frama-C processes, each with its own
    # alt-ergo and z3, oversubscribe the machine and enough goals hit
    # FRAMAC_TIMEOUT that the target exits without naming a reason. That is
    # indistinguishable here from a genuinely broken mutation, and re-running
    # the same mutation alone has resolved every occurrence seen so far.
    #
    # So re-run them once with the pool drained, one at a time. A load artifact
    # turns into the verdict it should have had; a real failure stays INFRA and
    # is reported. The retry is announced either way, because a gate that
    # quietly re-rolls a failure until it passes is worse than one that flakes.
    retried = [i for i, (status, _d) in enumerate(results) if status == "INFRA"]
    if retried:
        print(
            f"  {len(retried)} mutation(s) returned no verdict; re-running "
            "them serially before scoring"
        )
        for i in retried:
            idx = selected_pairs[i][0]
            before = results[i]
            results[i] = run_mutation(idx, selected[i])
            target, _src, function = selected[i][:3]
            if results[i][0] != before[0]:
                print(
                    f"    verify-{target}:{function}: {before[0]} under load, "
                    f"{results[i][0]} alone"
                )

    failures = []
    for mutation, (status, detail) in zip(selected, results):
        target, _src, function, desc = mutation[:4]
        suffix = f"  ({detail})" if detail else ""
        print(f"  {status:<7} verify-{target:<9} {function:<28} {desc}{suffix}")
        if status != "caught":
            failures.append((target, function, desc, status, detail))

    # Coverage: which proved functions have no mutation at all. Reported rather
    # than enforced, so the gap is visible instead of assumed closed.
    covered = {(m[0], m[2]) for m in MUTATIONS}
    uncovered = [
        f"verify-{target}:{function}"
        for target, fcts in sorted(proved_functions().items())
        for function in sorted(set(fcts))
        if (target, function) not in covered
    ]

    print(f"\n  {len(selected)} mutations, {len(selected) - len(failures)} caught")
    if uncovered:
        print(f"  {len(uncovered)} proved function(s) with no mutation yet:")
        for name in uncovered:
            print(f"    {name}")

    if failures:
        print("\n  NOT CAUGHT:", file=sys.stderr)
        for target, function, desc, status, detail in failures:
            print(
                f"    verify-{target} {function}: {desc} [{status}] {detail}",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
