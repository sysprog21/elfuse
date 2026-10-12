/*
 * Linux initial stack builder
 *
 * Copyright 2026 elfuse contributors
 * Copyright 2025 Moritz Angermann, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Constructs the initial stack layout that the Linux ABI requires at process
 * startup. The stack is built at the top of the guest stack region and grows
 * downward: string data at the top, then the structured area (auxv, envp, argv,
 * argc) below.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proved/stack.h"
#include "core/stack.h"
#include "debug/log.h"
#include "syscall/proc.h"
#include "linux-limits.h"

/* Linux aarch64 HWCAP bits (from asm/hwcap.h). Only the bits the VZ-sanitized
 * ID registers actually advertise are listed here; HWCAP bits left out (e.g.,
 * HWCAP_EVTSTRM, HWCAP_SSBS, HWCAP_SM3, HWCAP_SM4) correspond to features that
 * the host's ID-register overrides leave at zero and guest must not observe.
 */
#define HWCAP_FP (1ULL << 0)
#define HWCAP_ASIMD (1ULL << 1)
#define HWCAP_AES (1ULL << 3)
#define HWCAP_PMULL (1ULL << 4)
#define HWCAP_SHA1 (1ULL << 5)
#define HWCAP_SHA2 (1ULL << 6)
#define HWCAP_CRC32 (1ULL << 7)
#define HWCAP_ATOMICS (1ULL << 8)  /* LSE atomics */
#define HWCAP_FPHP (1ULL << 9)     /* FP16 */
#define HWCAP_ASIMDHP (1ULL << 10) /* ASIMD FP16 */
#define HWCAP_ASIMDRDM (1ULL << 12)
#define HWCAP_JSCVT (1ULL << 13)
#define HWCAP_FCMA (1ULL << 14)
#define HWCAP_LRCPC (1ULL << 15)
#define HWCAP_DCPOP (1ULL << 16)
#define HWCAP_SHA3 (1ULL << 17)
#define HWCAP_ASIMDDP (1ULL << 20) /* Dot product */
#define HWCAP_SHA512 (1ULL << 21)
#define HWCAP_FHM (1ULL << 23)
#define HWCAP_DIT (1ULL << 24)
#define HWCAP_ILRCPC (1ULL << 26)
#define HWCAP_FLAGM (1ULL << 27)
#define HWCAP_CPUID (1ULL << 11) /* MRS emulation of ID registers from EL0 */
#define HWCAP_SB (1ULL << 29)
#define HWCAP_PACA (1ULL << 30)
#define HWCAP_PACG (1ULL << 31)

/* Linux aarch64 HWCAP2 bits (from asm/hwcap.h). */
#define HWCAP2_DCPODP (1ULL << 0)
#define HWCAP2_FLAGM2 (1ULL << 7)
#define HWCAP2_FRINT (1ULL << 8)
#define HWCAP2_BF16 (1ULL << 14)

/* Build AT_HWCAP value matching VZ-sanitized ID register values.
 *
 * These must be consistent with the VZ-sanitized ID register overrides in
 * syscall/proc.c (MRS trap handler). The Linux kernel derives HWCAP from ID
 * registers, so HWCAP and ID register values must agree.
 *
 * Derived from:
 *   ID_AA64ISAR0_EL1 = 0x0021100110212120
 *   ID_AA64ISAR1_EL1 = 0x0000101110211402
 *   ID_AA64PFR0_EL1  = 0x0001000000110011
 *   ID_AA64PFR1_EL1  = 0x0000000000000000
 *   ID_AA64MMFR2_EL1 = 0x0000000000000000
 */
static uint64_t query_hwcap(void)
{
    uint64_t hwcap = HWCAP_FP | HWCAP_ASIMD |     /* PFR0.FP/AdvSIMD != 0xF */
                     HWCAP_AES | HWCAP_PMULL |    /* ISAR0.AES = 2 */
                     HWCAP_SHA1 |                 /* ISAR0.SHA1 = 1 */
                     HWCAP_SHA2 | HWCAP_SHA512 |  /* ISAR0.SHA2 = 2 */
                     HWCAP_CRC32 |                /* ISAR0.CRC32 = 1 */
                     HWCAP_ATOMICS |              /* ISAR0.Atomic = 2 */
                     HWCAP_FPHP | HWCAP_ASIMDHP | /* PFR0.FP/AdvSIMD >= 1 */
                     HWCAP_CPUID |    /* always (kernel emulates MRS) */
                     HWCAP_ASIMDRDM | /* ISAR0.RDM = 1 */
                     HWCAP_JSCVT |    /* ISAR1.JSCVT = 1 */
                     HWCAP_FCMA |     /* ISAR1.FCMA = 1 */
                     HWCAP_LRCPC | HWCAP_ILRCPC | /* ISAR1.LRCPC = 2 */
                     HWCAP_DCPOP |                /* ISAR1.DPB = 2 */
                     HWCAP_SHA3 |                 /* ISAR0.SHA3 = 1 */
                     HWCAP_ASIMDDP |              /* ISAR0.DP = 1 */
                     HWCAP_FHM |                  /* ISAR0.FHM = 1 */
                     HWCAP_DIT |                  /* PFR0.DIT = 1 */
                     HWCAP_FLAGM |                /* ISAR0.TS = 2 */
                     HWCAP_SB |                   /* ISAR1.SB = 1 */
                     HWCAP_PACA |                 /* ISAR1.API = 4 */
                     HWCAP_PACG;                  /* ISAR1.GPI = 1 */
    /* HWCAP_SSBS, HWCAP_EVTSTRM, HWCAP_SVE, HWCAP_SM3, HWCAP_SM4, HWCAP_USCAT
     * are intentionally not set: the corresponding ID-register fields are zero
     * under VZ sanitization or there is no host emulation (no generic timer).
     */
    return hwcap;
}

/* Build AT_HWCAP2 value matching VZ-sanitized ID register values. */
static uint64_t query_hwcap2(void)
{
    return HWCAP2_DCPODP | /* ISAR1.DPB = 2 */
           HWCAP2_FLAGM2 | /* ISAR0.TS = 2 */
           HWCAP2_FRINT |  /* ISAR1.FRINTTS = 1 */
           HWCAP2_BF16;    /* ISAR1.BF16 = 1 */
}

/* Push a uint64_t onto the stack (growing downward).
 * Returns 0 on success, -1 if the write failed.
 */
static int push_u64(guest_t *g, uint64_t *sp, uint64_t val)
{
    *sp -= 8;
    return guest_write_small(g, *sp, &val, sizeof(val));
}

/* Write a string to guest memory at the given address.
 * Returns 0 on success, -1 on failure.
 */
static int write_str(guest_t *g, uint64_t gva, const char *s)
{
    size_t len = strlen(s) + 1;
    return guest_write(g, gva, s, len);
}

uint64_t build_linux_stack(guest_t *g,
                           uint64_t stack_top,
                           int argc,
                           const char **argv,
                           const char **envp,
                           const elf_info_t *elf_info,
                           uint64_t elf_load_base,
                           uint64_t interp_base,
                           uint64_t vdso_base,
                           int execfd,
                           const char *execfn,
                           linux_stack_auxv_t *auxv_out)
{
    /* Linux initial stack layout (growing from high to low):
     *   [ 16 random bytes for AT_RANDOM ]
     *   [ "aarch64\0" for AT_PLATFORM ]
     *   [ environment strings ]
     *   [ argument strings ]
     *   [ padding to 16-byte alignment ]
     *   [ AT_NULL (0, 0) ]
     *   [ auxv entries (key, value) pairs ]
     *   [ NULL (end of envp) ]
     *   [ envp[0], envp[1], ... ]
     *   [ NULL (end of argv) ]
     *   [ argv[argc-1] ... argv[0] ]
     *   [ argc ]                    <-- SP points here
     */

    /* Count environment entries */
    int envc = 0;
    if (envp) {
        while (envp[envc])
            envc++;
    }


    /* argc is bounded below as well as above, and the lower bound is the one
     * that matters here: a negative argc makes the (uint64_t) total_entries
     * cast below about 2^64, which violates the entries <= STACK_MAX_WORDS
     * precondition of stack_pushed_words and stack_final_sp. Past that the word
     * count wraps and stack_final_sp can report success with a garbage
     * expect_sp. No caller passes a negative argc today; this makes the code
     * discharge the precondition instead of leaving it as an argument about
     * other files.
     */
    if (argc < 0 || argc > ELFUSE_MAX_ARG_STRINGS ||
        envc > ELFUSE_MAX_ARG_STRINGS)
        return 0; /* Caller treats 0 as failure */

    /* Phase 1: Write strings and random data at the top of the stack. stack
     * setup works downward from stack_top.
     */
    uint64_t str_ptr = stack_top;

    /* Floor for the whole descent: every step below goes through stack_take,
     * whose postcondition is that the pointer never crosses this.
     *
     * The image is built inside the default stack window, [stack_base,
     * stack_top), which is mapped whole until mem_stack_init_extent cuts it
     * down. The lowest page of the window is kept out of the build, so the
     * stack a new image starts on always has a page left to grow into.
     */
    const uint64_t stack_floor = g->stack_base + STACK_GUARD_SIZE;
    if (str_ptr < stack_floor)
        return 0;

    /* AT_RANDOM: 16 random bytes */
    if (!stack_take(&str_ptr, stack_floor, 16))
        return 0;
    uint64_t random_ptr = str_ptr;

    /* glibc and musl derive the stack canary and the pointer guard from these
     * 16 bytes, so they must never be predictable. arc4random_buf returns void
     * and cannot fail, which leaves no error path to substitute a constant on.
     * sys.c serves getrandom(2) from it for the same reason.
     */
    uint8_t random_bytes[16];
    arc4random_buf(random_bytes, sizeof(random_bytes));
    int str_err = 0;
    str_err |=
        guest_write_small(g, random_ptr, random_bytes, sizeof(random_bytes));

    /* AT_PLATFORM: "aarch64\0" */
    if (!stack_take(&str_ptr, stack_floor, 8)) /* strlen("aarch64") + 1 */
        return 0;
    uint64_t platform_ptr = str_ptr;
    str_err |= write_str(g, platform_ptr, "aarch64");

    /* AT_EXECFN: the filename handed to execve, copied onto the stack as its
     * own string exactly as fs/binfmt_elf.c does.
     *
     * The kernel takes this from bprm->filename, not from argv[0], and the two
     * diverge in two ways elfuse reproduces: execve(path, "altname", ...)
     * reports path, and under binfmt_misc the interpreter rosetta.c prepends to
     * argv is not the program the guest asked to run. Taking the string from
     * the caller rather than from an argv index keeps that contract out of the
     * argv layout, which differs between the native and rosetta forms and is
     * free to change again (see the preserving-form note in rosetta.c).
     *
     * Guests that identify themselves through auxv rather than argv[0] depend
     * on getting this right: rust-coreutils dispatches its multi-call applet
     * from AT_EXECFN, so a leaked interpreter path makes every applet abort
     * with "unknown program 'rosetta'".
     */
    uint64_t execfn_ptr = 0;
    if (execfn) {
        size_t execfn_len = strlen(execfn) + 1;
        if (!stack_take(&str_ptr, stack_floor, execfn_len))
            return 0;
        execfn_ptr = str_ptr;
        str_err |= write_str(g, execfn_ptr, execfn);
    }

    /* Dynamically allocate pointer arrays to avoid stack buffer overflow with
     * large argument or environment lists. calloc(0, ...) is
     * implementation-defined, so always allocate at least one slot. The extra
     * slot when envc/argc is zero is wasted but keeps the pointers non-NULL,
     * which simplifies subsequent code and avoids tripping static analyzers
     * that cannot correlate the empty-loop case with the NULL pointer.
     */
    uint64_t ret = 0; /* every exit from here on runs the cleanup at out: */
    uint64_t *env_ptrs =
        calloc((size_t) (envc > 0 ? envc : 1), sizeof(uint64_t));
    uint64_t *arg_ptrs =
        calloc((size_t) (argc > 0 ? argc : 1), sizeof(uint64_t));
    if (!env_ptrs || !arg_ptrs)
        goto out;

    /* Environment strings */
    for (int i = envc - 1; i >= 0; i--) {
        size_t len = strlen(envp[i]) + 1;
        if (!stack_take(&str_ptr, stack_floor, len))
            goto out;
        env_ptrs[i] = str_ptr;
        str_err |= write_str(g, str_ptr, envp[i]);
    }

    /* Argument strings (written backward so argv[0] is at lowest addr) */
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        if (!stack_take(&str_ptr, stack_floor, len))
            goto out;
        arg_ptrs[i] = str_ptr;
        str_err |= write_str(g, str_ptr, argv[i]);
    }

    /* Callers with no filename to report keep the historical argv[0] spelling
     * rather than an AT_EXECFN of 0, which no Linux process ever sees.
     */
    if (!execfn_ptr && argc > 0)
        execfn_ptr = arg_ptrs[0];

    /* Phase 2: Build the structured part of the stack. Align str_ptr down to 16
     * bytes first.
     */
    str_ptr = stack_align_down(str_ptr);
    uint64_t sp = str_ptr;

    /* Serialize auxv once here, before the word count is taken, and push it in
     * reverse below so guest memory and /proc/self/auxv expose the same bytes.
     * The count is read off auxv.nwords rather than tallied beside this list,
     * so adding an entry cannot leave the two disagreeing.
     *
     * The bound is what keeps an added entry inside words[].
     */
    linux_stack_auxv_t auxv = {.nwords = 0};
#define AUX(k, v)                                         \
    do {                                                  \
        if (auxv.nwords + 2 > LINUX_STACK_AUXV_WORDS_MAX) \
            goto out;                                     \
        auxv.words[auxv.nwords++] = (k);                  \
        auxv.words[auxv.nwords++] = (v);                  \
    } while (0)
    if (execfd >= 0)
        AUX(AT_EXECFD, (uint64_t) execfd);
    AUX(AT_BASE, interp_base);
    if (vdso_base != 0)
        AUX(AT_SYSINFO_EHDR, vdso_base);
    AUX(AT_PAGESZ, 4096);

    /* phdr_valid is false when no PT_LOAD covers the program header table, so
     * there is no guest address to report and Linux passes AT_PHDR 0. Testing
     * phdr_gpa itself would be wrong: an ET_DYN image whose covering segment
     * sits at p_vaddr 0 has a legitimate phdr_gpa of 0 and must still be
     * relocated by elf_load_base.
     */
    AUX(AT_PHDR, elf_info->phdr_valid ? elf_info->phdr_gpa + elf_load_base : 0);
    AUX(AT_PHENT, elf_info->phentsize);
    AUX(AT_PHNUM, elf_info->phnum);
    AUX(AT_ENTRY, elf_info->entry + elf_load_base);
    AUX(AT_UID, proc_get_uid());
    AUX(AT_EUID, proc_get_euid());
    AUX(AT_GID, proc_get_gid());
    AUX(AT_EGID, proc_get_egid());

    /* Bionic's __libc_init_AT_SECURE aborts when AT_SECURE is absent. elfuse
     * never elevates privileges, so AT_SECURE is always 0.
     */
    AUX(AT_SECURE, 0);
    AUX(AT_HWCAP2, query_hwcap2());
    AUX(AT_HWCAP, query_hwcap());
    AUX(AT_CLKTCK, 100);

    /* glibc 2.34+ sizes SIGSTKSZ and MINSIGSTKSZ from this rather than from a
     * compile-time constant. The frame elfuse pushes needs less, but reporting
     * that would hand the guest a number its own sigaltstack then refuses:
     * sys_sigaltstack rejects anything below LINUX_MINSIGSTKSZ.
     */
    AUX(AT_MINSIGSTKSZ, LINUX_MINSIGSTKSZ);
    AUX(AT_RANDOM, random_ptr);
    AUX(AT_EXECFN, execfn_ptr);
    AUX(AT_PLATFORM, platform_ptr);
    AUX(AT_NULL, 0);
#undef AUX

    /* Three more words than the auxv: the two NULL terminators and argc. */
    int total_entries = (int) auxv.nwords + 3 + argc + envc;

    /* Where SP must land, computed before a single word is pushed. A push the
     * count does not know about would leave SP misaligned or short of argc, and
     * nothing would say so: the guest would just read argv from the wrong
     * offset. Comparing against this at the end turns that into a clean
     * failure. stack_final_sp proves the value is 16-byte aligned and inside
     * the region, given a 16-aligned base and an even word count.
     */
    uint64_t pushed_words = stack_pushed_words((uint64_t) total_entries);
    uint64_t expect_sp = 0;
    if (!stack_final_sp(str_ptr, stack_floor, pushed_words, &expect_sp))
        goto out;

    /* Track cumulative write errors. Any failure means the stack is incomplete.
     *
     * Return 0 so the caller sees the failure.
     */
    int stack_err = str_err;

    if (pushed_words != (uint64_t) total_entries)
        stack_err |= push_u64(g, &sp, 0); /* alignment padding */

#define PUSH(val)                             \
    do {                                      \
        stack_err |= push_u64(g, &sp, (val)); \
    } while (0)


    for (size_t i = auxv.nwords; i > 0; i--)
        PUSH(auxv.words[i - 1]);

    if (auxv_out)
        *auxv_out = auxv;

    /* envp: environment variable pointers + NULL terminator */
    PUSH(0); /* NULL terminator */
    for (int i = envc - 1; i >= 0; i--)
        PUSH(env_ptrs[i]);

    /* argv: NULL terminator, then pointers in reverse order */
    PUSH(0); /* NULL terminator */
    for (int i = argc - 1; i >= 0; i--)
        PUSH(arg_ptrs[i]);

    /* argc: SP now points here, 16-byte aligned */
    PUSH((uint64_t) argc);
#undef PUSH

    /* The pushes must have landed exactly where the count said they would. A
     * mismatch means total_entries no longer describes the code below it.
     */
    if (sp != expect_sp) {
        log_error(
            "build_linux_stack: pushed to 0x%llx, entry count says 0x%llx "
            "(total_entries=%d is out of sync with the pushes)",
            (unsigned long long) sp, (unsigned long long) expect_sp,
            total_entries);
        goto out;
    }

    ret = stack_err ? 0 : sp;

out:
    free(env_ptrs);
    free(arg_ptrs);
    return ret;
}
