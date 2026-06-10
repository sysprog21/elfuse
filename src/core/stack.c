/* Linux initial stack builder
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
#include <sys/random.h>

#include "core/stack.h"
#include "syscall/proc.h"

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

/* Bounds-check: Linux returns E2BIG for oversized argument/environment. ARG_MAX
 * on Linux is typically 2MiB; stack setup caps at reasonable stack limits.
 */
#define MAX_ARGS 131072
#define MAX_ENVS 131072
    if (argc > MAX_ARGS || envc > MAX_ENVS)
        return 0; /* Caller treats 0 as failure */

    /* Phase 1: Write strings and random data at the top of the stack. stack
     * setup works downward from stack_top.
     */
    uint64_t str_ptr = stack_top;

    /* AT_RANDOM: 16 random bytes */
    str_ptr -= 16;
    uint64_t random_ptr = str_ptr;
    uint8_t random_bytes[16];
    if (getentropy(random_bytes, 16) != 0)
        memset(random_bytes, 0x42, 16); /* Fallback: deterministic fill */
    int str_err = 0;
    str_err |=
        guest_write_small(g, random_ptr, random_bytes, sizeof(random_bytes));

    /* AT_PLATFORM: "aarch64\0" */
    str_ptr -= 8; /* strlen("aarch64") + 1 */
    uint64_t platform_ptr = str_ptr;
    str_err |= write_str(g, platform_ptr, "aarch64");

    /* Dynamically allocate pointer arrays to avoid stack buffer overflow with
     * large argument or environment lists. calloc(0, ...) is
     * implementation-defined, so always allocate at least one slot. The extra
     * slot when envc/argc is zero is wasted but keeps the pointers non-NULL,
     * which simplifies subsequent code and avoids tripping static analyzers
     * that cannot correlate the empty-loop case with the NULL pointer.
     */
    uint64_t *env_ptrs =
        calloc((size_t) (envc > 0 ? envc : 1), sizeof(uint64_t));
    uint64_t *arg_ptrs =
        calloc((size_t) (argc > 0 ? argc : 1), sizeof(uint64_t));
    if (!env_ptrs || !arg_ptrs) {
        free(env_ptrs);
        free(arg_ptrs);
        return 0;
    }

    /* Environment strings */
    for (int i = envc - 1; i >= 0; i--) {
        size_t len = strlen(envp[i]) + 1;
        str_ptr -= len;
        env_ptrs[i] = str_ptr;
        str_err |= write_str(g, str_ptr, envp[i]);
    }

    /* Argument strings (written backward so argv[0] is at lowest addr) */
    for (int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        str_ptr -= len;
        arg_ptrs[i] = str_ptr;
        str_err |= write_str(g, str_ptr, argv[i]);
    }

    /* AT_EXECFN: pointer to argv[0] string (write it near the top) */
    uint64_t execfn_ptr = (argc > 0) ? arg_ptrs[0] : 0;

    /* Phase 2: Build the structured part of the stack. Align str_ptr down to 16
     * bytes first.
     */
    str_ptr &= ~15ULL;
    uint64_t sp = str_ptr;

    /* Count auxv entries: base 15 (always) + AT_EXECFN (always) + AT_BASE
     * (always, matching Linux kernel; see commit ba0b177) + optional
     * AT_SYSINFO_EHDR + optional AT_EXECFD. Each auxv entry = 2 words. Plus
     * AT_NULL = 2 words. Total words from auxv = (num_auxv_entries + 1) * 2.
     * Plus envp_null(1) + envp_ptrs(envc) + argv_null(1) + argv_ptrs(argc) +
     * argc(1).
     *
     * Base auxv: 15 entries = 30 words, AT_NULL = 2 words = 32. Always:
     * AT_EXECFN = +2, AT_BASE = +2. Optional: AT_SYSINFO_EHDR (if vdso_base !=
     * 0) = +2,
     *           AT_EXECFD (if execfd >= 0) = +2.
     * Plus envp_null(1) + envp(envc) + argv_null(1) + argv(argc) + argc(1) = 3.
     * Total = 32 + extra + 3 + envc + argc = 35 + extra + envc + argc. For
     * 16-byte alignment: total must be even.
     */
    int extra = 2 + 2; /* AT_EXECFN + AT_BASE (both always present) */
    if (vdso_base != 0)
        extra += 2; /* AT_SYSINFO_EHDR */
    if (execfd >= 0)
        extra += 2; /* AT_EXECFD (binfmt_misc binary fd) */
    int total_entries = 35 + extra + argc + envc;

    /* Track cumulative write errors. Any failure means the stack is incomplete.
     *
     * Return 0 so the caller sees the failure.
     */
    int stack_err = str_err;

    if (total_entries & 1)
        stack_err |= push_u64(g, &sp, 0); /* alignment padding */

#define PUSH(val)                             \
    do {                                      \
        stack_err |= push_u64(g, &sp, (val)); \
    } while (0)
    /* Serialize auxv once, then push it in reverse so guest memory and
     * /proc/self/auxv expose the same bytes.
     */
    linux_stack_auxv_t auxv = {.nwords = 0};
#define AUX(k, v)                        \
    do {                                 \
        auxv.words[auxv.nwords++] = (k); \
        auxv.words[auxv.nwords++] = (v); \
    } while (0)
    if (execfd >= 0)
        AUX(AT_EXECFD, (uint64_t) execfd);
    AUX(AT_BASE, interp_base);
    if (vdso_base != 0)
        AUX(AT_SYSINFO_EHDR, vdso_base);
    AUX(AT_PAGESZ, 4096);
    AUX(AT_PHDR, elf_info->phdr_gpa + elf_load_base);
    AUX(AT_PHENT, elf_info->phentsize);
    AUX(AT_PHNUM, elf_info->phnum);
    AUX(AT_ENTRY, elf_info->entry + elf_load_base);
    AUX(AT_UID, proc_get_uid());
    AUX(AT_EUID, proc_get_euid());
    AUX(AT_GID, proc_get_gid());
    AUX(AT_EGID, proc_get_egid());
    /* Bionic's __libc_init_AT_SECURE aborts when AT_SECURE is absent.
     * elfuse never elevates privileges, so AT_SECURE is always 0.
     */
    AUX(AT_SECURE, 0);
    AUX(AT_HWCAP2, query_hwcap2());
    AUX(AT_HWCAP, query_hwcap());
    AUX(AT_CLKTCK, 100);
    AUX(AT_RANDOM, random_ptr);
    AUX(AT_EXECFN, execfn_ptr);
    AUX(AT_PLATFORM, platform_ptr);
    AUX(AT_NULL, 0);
#undef AUX

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

    free(env_ptrs);
    free(arg_ptrs);
    return stack_err ? 0 : sp;
}
