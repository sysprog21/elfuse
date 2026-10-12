/*
 * Linux initial-stack layout arithmetic: the parts a proof can reach
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * build_linux_stack lays out argc/argv/envp/auxv exactly as fs/binfmt_elf.c
 * does, and two things there are easy to get wrong and hard to see wrong. The
 * string region walks down from stack_top by a guest-controlled number of
 * guest-controlled lengths, and the structured area must leave SP 16-byte
 * aligned AND pointing directly at argc, with no gap. A libc that finds either
 * wrong does not fail cleanly; it reads argv from the wrong offset.
 *
 * Split out of stack.c because stack.c cannot be given to Frama-C: it includes
 * core/guest.h and syscall/proc.h, which pull in Hypervisor.framework. This
 * header needs nothing but stdint.h, so make verify-stack proves it directly.
 *
 * The descent is already contained today: sys_execve (src/syscall/exec.c) caps
 * the argv/envp bytes and their pointers together at LINUX_ARG_BYTES_CEILING, 6
 * MiB, and the entry count at ELFUSE_MAX_ARG_STRINGS, against an 8 MiB stack
 * window. Routing every step through stack_take makes that containment
 * structural, held by a postcondition here rather than by two caps in another
 * file staying smaller than the stack.
 */

#pragma once

#include <stdint.h>

/* The Linux initial stack is 16-byte aligned and built from 8-byte words.
 *
 * The proofs below are parameterized over these, so changing either would still
 * prove while silently breaking the layout and the push_u64 SP identity. Pin
 * them: the values are ABI, not tuning.
 */
#define STACK_ALIGN 16ULL
#define STACK_WORD 8ULL

_Static_assert(STACK_ALIGN == 16ULL,
               "AAPCS64 requires 16-byte stack alignment");
_Static_assert(STACK_WORD == sizeof(uint64_t),
               "the initial stack is built from 64-bit words");

/* Ceiling on the structured area, in words. build_linux_stack computes
 * auxv.nwords + 3 + argc + envc, with auxv.nwords bounded by
 * LINUX_STACK_AUXV_WORDS_MAX (48) and argc, envc each capped at
 * ELFUSE_MAX_ARG_STRINGS (131072) by read_string_array, so the true maximum is
 * 262195. Rounded up to a power of two: the value only has to keep words *
 * STACK_WORD far from overflow, and a loose bound is easier to keep true as the
 * auxv set changes.
 */
#define STACK_MAX_WORDS (1ULL << 20)

/* Move a downward-growing stack pointer by bytes, or refuse if that would cross
 * floor.
 *
 * Refusing leaves the pointer untouched: a partial move would leave the caller
 * with a pointer it believes is live and a region it has already overrun.
 */
/*@
  requires \valid(ptr);
  requires *ptr >= floor;
  assigns *ptr;
  ensures \result == 0 || \result == 1;
  ensures \result != 0 <==> bytes <= \old(*ptr) - floor;
  ensures \result != 0 ==> *ptr == \old(*ptr) - bytes;
  ensures \result != 0 ==> *ptr >= floor;
  ensures \result == 0 ==> *ptr == \old(*ptr);
 */
static inline int stack_take(uint64_t *ptr, uint64_t floor, uint64_t bytes)
{
    if (bytes > *ptr - floor)
        return 0;

    *ptr -= bytes;
    return 1;
}

/* Align a stack pointer down to STACK_ALIGN.
 *
 * Written as subtract-the-remainder rather than "& ~15": the compiler emits the
 * same instruction, and the prover reasons about the arithmetic form without
 * first establishing that the mask is one less than a power of two. Same reason
 * src/proved/gva.h uses "% granule".
 */
/*@
  assigns \nothing;
  ensures \result <= sp;
  ensures \result % STACK_ALIGN == 0;
  ensures sp - \result < STACK_ALIGN;
 */
static inline uint64_t stack_align_down(uint64_t sp)
{
    return sp - sp % STACK_ALIGN;
}

/* Words the structured area actually pushes, including the one word of padding
 * that an odd entry count needs.
 *
 * The padding goes here, above the structured area, and not after pushing argc.
 * Masking SP down at the end instead would open a gap between SP and argc, and
 * the Linux ABI requires SP to point AT argc.
 */
/*@
  requires entries <= STACK_MAX_WORDS;
  assigns \nothing;
  ensures \result == entries || \result == entries + 1;
  ensures \result % 2 == 0;
 */
static inline uint64_t stack_pushed_words(uint64_t entries)
{
    return entries + entries % 2;
}

/* Where SP lands after pushing words 8-byte words below a 16-aligned base, or 0
 * if the structured area would not fit above floor.
 *
 * The alignment postcondition is the point: base is 16-aligned and words is
 * even, so the result is 16-aligned, which is what the caller's final SP must
 * be. Callers compute this before pushing and compare it against the SP they
 * actually reach, which is what ties the hand-maintained entry count in
 * build_linux_stack to the pushes it performs.
 */
/*@
  requires base % STACK_ALIGN == 0;
  requires words % 2 == 0;
  requires words <= STACK_MAX_WORDS;
  requires base >= floor;
  requires \valid(sp);
  assigns *sp;
  ensures \result == 0 || \result == 1;
  ensures \result != 0 <==> words * STACK_WORD <= base - floor;
  ensures \result != 0 ==> *sp == base - words * STACK_WORD;
  ensures \result != 0 ==> *sp % STACK_ALIGN == 0;
  ensures \result != 0 ==> *sp >= floor;
  ensures \result == 0 ==> *sp == \old(*sp);
 */
static inline int stack_final_sp(uint64_t base,
                                 uint64_t floor,
                                 uint64_t words,
                                 uint64_t *sp)
{
    uint64_t bytes = words * STACK_WORD;
    if (bytes > base - floor)
        return 0;

    *sp = base - bytes;
    return 1;
}
