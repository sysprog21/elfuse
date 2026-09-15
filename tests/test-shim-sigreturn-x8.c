/*
 * test-shim-sigreturn-x8.c -- rt_sigreturn hands EL0 the X8 the frame records.
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * A signal handler rewrites its own ucontext so the return lands on a stub that
 * reads X8 and then issues an SVC with it. The kernel contract is that
 * rt_sigreturn restores all 31 GPRs from the frame, so the stub must see the X8
 * the handler wrote and the SVC must run as that syscall.
 *
 * elfuse has one more thing to get right there. Its EL1 shim is told to drop
 * the exception frame it is holding by a marker the host writes into X8, and
 * the tail that consumes the marker restores no register, so the marker itself
 * used to reach EL0 in place of the restored X8. A guest whose resumed PC sat
 * on an SVC then issued it as syscall 2 and got ENOSYS out of a call it had
 * made as something else, which is what tests/test-shim-futex-toctou caught by
 * racing. This reaches the same window without a race: the handler puts the
 * resume PC on the stub, so every round runs with a live X8 across the return.
 *
 * Rounds alternate, because the marker reaches the resumed SVC by two routes.
 * Plain: the rt_sigreturn itself hands X8 to EL0. Nested: a second signal,
 * raised inside the first handler and blocked until rt_sigreturn unblocks it,
 * is delivered on the way out, and the frame that delivery builds is the one
 * that records X8 for the return that follows.
 *
 * The nested route needs the host to remember, across the rt_sigreturn, what X8
 * the guest is owed, and a third phase holds that memory to its window. It
 * returns to a stub, lets the guest run, and then faults on the same PC with a
 * different X8 live. The fault is an ordinary delivery, not a continuation of
 * the rt_sigreturn, so what the SIGSEGV handler sees has to be the register the
 * guest faulted with and not anything the earlier return left parked.
 *
 * A fourth phase leaves the syscall route entirely. The same drop tail is
 * branched to from the two W^X permission-fault handlers, where the host
 * answers a flip request with the marker because the region never had the
 * permission and the fault is a real SIGSEGV. Nothing publishes an X8 there, so
 * the reload hands back the value the exception was taken with, and the two
 * rounds assert that the handler enters with the guest's X8 rather than the
 * marker.
 *
 * A fifth phase does the same for BRK, which carries the marker out of its own
 * tail rather than exec_drop_frame's. JIT translators use BRK as a trampoline
 * and read X8 in the SIGTRAP handler, so both halves are asserted: the X8 the
 * handler enters with, and the X8 the resumed guest carries once its
 * rt_sigreturn has run.
 *
 * Plain Linux signal ABI throughout, so the reference kernel adjudicates it and
 * the test is registered in tests/test-matrix.sh rather than exempted from it.
 */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

/* aarch64 __NR_getpid. Spelled out rather than taken from a header because the
 * stub below has to load the same number into X8 from assembly.
 */
#define NR_GETPID 172

#define ROUNDS 32

/* aarch64 __NR_mprotect, and the two X8 values the stale-park phase tells
 * apart. Spelled out because stale_stub below loads all three from assembly.
 */
#define NR_MPROTECT 226
#define STALE_PARKED 0x55
#define STALE_LIVE 0x99

/* Written by the stub, read by main. Not static: the stub addresses them by
 * name through adrp/add.
 */
volatile uint64_t resumed_x8;
volatile int64_t resumed_rc;

static sigjmp_buf resume;
static int failures;
static volatile sig_atomic_t nest;   /* raise the second signal in handler */
static volatile sig_atomic_t nested; /* the second handler ran */

void sigreturn_finish(void);
void sigreturn_stub(void);

/* Runs at EL0 with the register state rt_sigreturn restored. Records X8, then
 * issues the SVC that X8 names without touching it, so a corrupted X8 shows up
 * twice: in the recorded value and in the syscall that ran.
 */
__asm__(
    ".text\n"
    ".globl sigreturn_stub\n"
    ".type sigreturn_stub, %function\n"
    "sigreturn_stub:\n"
    "    adrp x9, resumed_x8\n"
    "    add  x9, x9, :lo12:resumed_x8\n"
    "    str  x8, [x9]\n"
    "    svc  #0\n"
    "    adrp x9, resumed_rc\n"
    "    add  x9, x9, :lo12:resumed_rc\n"
    "    str  x0, [x9]\n"
    "    b    sigreturn_finish\n"
    ".size sigreturn_stub, .-sigreturn_stub\n");

void sigreturn_finish(void)
{
    siglongjmp(resume, 1);
}

static void handler(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    ucontext_t *uc = ctx;

    /* Resume on the stub with getpid live in X8. Everything else the frame
     * holds is left alone, including the stack pointer, so the stub returns
     * through siglongjmp on the interrupted thread's own stack.
     */
    uc->uc_mcontext.pc = (uint64_t) (uintptr_t) sigreturn_stub;
    uc->uc_mcontext.regs[8] = NR_GETPID;

    /* SIGUSR2 is in this handler's sa_mask, so it stays pending until
     * rt_sigreturn restores the mask and is then delivered on the way out, with
     * the resume PC and X8 already set above.
     */
    if (nest)
        raise(SIGUSR2);
}

static void nested_handler(int sig)
{
    (void) sig;
    nested = 1;
}

/* Reached twice at the same PC, with X19 holding a writable page.
 *
 * First pass: rt_sigreturn resumes here with X8 = STALE_PARKED, the load
 * succeeds, and the guest runs on. Second pass: the page has been made
 * unreadable and X8 is STALE_LIVE, so the load faults with the fault PC equal
 * to the PC the earlier return came back to.
 */
void stale_stub(void);

__asm__(
    ".text\n"
    ".globl stale_stub\n"
    ".type stale_stub, %function\n"
    "stale_stub:\n"
    "    ldr  x1, [x19]\n"
    "    mov  x0, x19\n"
    "    mov  x1, #4096\n"
    "    mov  x2, #0\n"
    "    mov  x8, #226\n" /* NR_MPROTECT: PROT_NONE over the page */
    "    svc  #0\n"
    "    mov  x8, #0x99\n" /* STALE_LIVE */
    "    b    stale_stub\n"
    ".size stale_stub, .-stale_stub\n");

static uint8_t *stale_page;
static sigjmp_buf stale_back;
static volatile uint64_t stale_x8;
static volatile uint64_t stale_pc;
static volatile sig_atomic_t stale_faulted;

static void stale_redirect(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    ucontext_t *uc = ctx;
    uc->uc_mcontext.pc = (uint64_t) (uintptr_t) stale_stub;
    uc->uc_mcontext.regs[8] = STALE_PARKED;
    uc->uc_mcontext.regs[19] = (uint64_t) (uintptr_t) stale_page;
}

static void stale_fault(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    ucontext_t *uc = ctx;
    stale_faulted = 1;
    stale_x8 = uc->uc_mcontext.regs[8];
    stale_pc = uc->uc_mcontext.pc;
    siglongjmp(stale_back, 1);
}

static int check_stale_park(void)
{
    static char altbuf[SIGSTKSZ * 4];
    struct sigaction sa;
    stack_t ss;
    int failures = 0;

    stale_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stale_page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* The fault is taken on stale_stub, which runs on the interrupted thread's
     * own stack; an alternate stack keeps the handler off it.
     */
    ss.ss_sp = altbuf;
    ss.ss_size = sizeof(altbuf);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) < 0) {
        perror("sigaltstack");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = stale_redirect;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("sigaction SIGUSR1");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = stale_fault;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction SIGSEGV");
        return 1;
    }

    if (sigsetjmp(stale_back, 1) == 0)
        raise(SIGUSR1);

    if (!stale_faulted) {
        fprintf(stderr, "FAIL stale park: the second pass never faulted\n");
        return 1;
    }
    if (stale_pc != (uint64_t) (uintptr_t) stale_stub) {
        fprintf(stderr,
                "FAIL stale park: faulted at 0x%llx, want the stub at "
                "0x%llx\n",
                (unsigned long long) stale_pc,
                (unsigned long long) (uintptr_t) stale_stub);
        failures++;
    }
    if (stale_x8 != STALE_LIVE) {
        fprintf(stderr,
                "FAIL stale park: the fault reports X8 = 0x%llx, want the live "
                "0x%x; 0x%x is the value the earlier rt_sigreturn returned "
                "with\n",
                (unsigned long long) stale_x8, STALE_LIVE, STALE_PARKED);
        failures++;
    }
    return failures;
}

/* The same drop tail is reached from the W^X permission faults, not only from a
 * syscall: the shim asks the host to flip a page and branches to the tail when
 * the host answers with the marker, which it does when the region never had the
 * permission and the fault is a real SIGSEGV. Nothing publishes an X8 on that
 * route, so what the tail reloads is the value the exception was taken with,
 * and that reload is the last write to X8 before EL0: signal delivery installs
 * the handler's PC, SP, LR and argument registers, and X8 is none of those. X8
 * at handler entry is therefore the guest's own on both routes, which is what
 * these two rounds assert; before the reload existed they both entered with the
 * marker.
 *
 * Recorded in assembly at the handler's first instruction. The ucontext cannot
 * answer this: the frame the host builds for these two deliveries records the
 * shim's HVC arguments in X0 and X1 rather than the guest's, so reading X8 out
 * of it would be reading a snapshot taken on the same terms.
 *
 * The value is spelled twice, here and in the two stubs below, which load it
 * from assembly the way stale_stub does.
 */
#define WX_X8 0xa5

/* Written by the handler stub, read by the checker. Not static: the stub
 * addresses it by name through adrp/add.
 */
volatile uint64_t wx_entry_x8;

void wx_entry(int sig, siginfo_t *info, void *ctx);
void wx_entry_c(int sig, siginfo_t *info, void *ctx);
void wx_exec(uint64_t page);
void wx_write(uint64_t page);

__asm__(
    ".text\n"
    ".globl wx_entry\n"
    ".type wx_entry, %function\n"
    "wx_entry:\n"
    "    adrp x9, wx_entry_x8\n"
    "    add  x9, x9, :lo12:wx_entry_x8\n"
    "    str  x8, [x9]\n"
    "    b    wx_entry_c\n"
    ".size wx_entry, .-wx_entry\n"
    ".globl wx_exec\n"
    ".type wx_exec, %function\n"
    "wx_exec:\n"
    "    mov  x8, #0xa5\n"
    "    br   x0\n"
    ".size wx_exec, .-wx_exec\n"
    ".globl wx_write\n"
    ".type wx_write, %function\n"
    "wx_write:\n"
    "    mov  x8, #0xa5\n"
    "    str  xzr, [x0]\n"
    "    ret\n"
    ".size wx_write, .-wx_write\n");

static sigjmp_buf wx_back;

void wx_entry_c(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    (void) ctx;
    siglongjmp(wx_back, 1);
}

/* The X8 the handler entered with, through *taken. A stub that returns instead
 * of faulting leaves it false, which is a host that granted the permission the
 * page was not mapped with rather than an X8 worth reporting.
 */
static uint64_t wx_take_fault(void *page, int write, int *taken)
{
    wx_entry_x8 = 0;
    *taken = 1;
    if (sigsetjmp(wx_back, 1) == 0) {
        if (write)
            wx_write((uint64_t) (uintptr_t) page);
        else
            wx_exec((uint64_t) (uintptr_t) page);
        *taken = 0;
        return 0;
    }
    return wx_entry_x8;
}

static int check_wx_tails(void)
{
    struct sigaction sa;
    int failures = 0;
    uint32_t ret_insn = 0xd65f03c0; /* ret, so a page that is executable runs */

    /* A page with no PROT_EXEC, branched to: an instruction permission fault. A
     * page with no PROT_WRITE, stored to: a write permission fault.
     */
    uint8_t *noexec = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *nowrite = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (noexec == MAP_FAILED || nowrite == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memcpy(noexec, &ret_insn, sizeof(ret_insn));

    /* Both faults are taken outside any handler and neither faulting stub has
     * touched the stack, so the handler runs on the interrupted stack and needs
     * no alternate one. check_stale_park, which does need one, runs after this
     * and installs it then.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = wx_entry;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) < 0) {
        perror("sigaction SIGSEGV");
        return 1;
    }

    int taken = 0;
    uint64_t got = wx_take_fault(noexec, 0, &taken);
    if (!taken) {
        fprintf(stderr,
                "FAIL W^X exec tail: branching to a page with no PROT_EXEC "
                "did not fault\n");
        failures++;
    } else if (got != WX_X8) {
        fprintf(stderr,
                "FAIL W^X exec tail: the handler entered with X8 = 0x%llx, "
                "want the guest's 0x%x\n",
                (unsigned long long) got, WX_X8);
        failures++;
    }

    got = wx_take_fault(nowrite, 1, &taken);
    if (!taken) {
        fprintf(stderr,
                "FAIL W^X write tail: storing to a page with no PROT_WRITE "
                "did not fault\n");
        failures++;
    } else if (got != WX_X8) {
        fprintf(stderr,
                "FAIL W^X write tail: the handler entered with X8 = 0x%llx, "
                "want the guest's 0x%x\n",
                (unsigned long long) got, WX_X8);
        failures++;
    }
    return failures;
}

/* BRK reaches EL0 through a tail of its own, not exec_drop_frame's, and has the
 * same problem to solve there. The host delivers SIGTRAP out of HVC #10 and
 * leaves the drop-frame marker in X8 as it does on every other delivery, so
 * without a reload the handler enters with 2 in place of the guest's X8. A JIT
 * translator patching through BRK trampolines is precisely the caller that
 * reads that register, which is why the tail loads it back from the frame's own
 * X8 slot before dropping the frame.
 *
 * Both halves are asserted. Handler entry is recorded in assembly, for the
 * reason the W^X phase gives: the ucontext is a snapshot the host took on its
 * own terms. The resumed value is read after the handler steps the saved PC
 * past the BRK and returns, which covers the rt_sigreturn out of a BRK-
 * delivered signal, a different tail from the one the entry tests.
 *
 * The value is spelled twice, here and in brk_fire below, which loads it from
 * assembly the way the W^X stubs do.
 */
#define BRK_X8 0xc3

/* Written by the handler stub and by brk_fire, read by the checker. Not static:
 * both address them by name through adrp/add.
 */
volatile uint64_t brk_entry_x8;
volatile uint64_t brk_resumed_x8;

void brk_entry(int sig, siginfo_t *info, void *ctx);
void brk_entry_c(int sig, siginfo_t *info, void *ctx);
void brk_fire(void);

__asm__(
    ".text\n"
    ".globl brk_entry\n"
    ".type brk_entry, %function\n"
    "brk_entry:\n"
    "    adrp x9, brk_entry_x8\n"
    "    add  x9, x9, :lo12:brk_entry_x8\n"
    "    str  x8, [x9]\n"
    "    b    brk_entry_c\n"
    ".size brk_entry, .-brk_entry\n"
    ".globl brk_fire\n"
    ".type brk_fire, %function\n"
    "brk_fire:\n"
    "    mov  x8, #0xc3\n"
    "    brk  #0\n"
    "    adrp x9, brk_resumed_x8\n"
    "    add  x9, x9, :lo12:brk_resumed_x8\n"
    "    str  x8, [x9]\n"
    "    ret\n"
    ".size brk_fire, .-brk_fire\n");

void brk_entry_c(int sig, siginfo_t *info, void *ctx)
{
    (void) sig;
    (void) info;
    ucontext_t *uc = ctx;

    /* Step the saved PC past the BRK so the return lands on the store below it
     * rather than re-executing the trap. Nothing else in the frame is touched,
     * so the X8 the return delivers is the one the frame recorded.
     */
    uc->uc_mcontext.pc += 4;
}

static int check_brk_tail(void)
{
    struct sigaction sa;
    int failures = 0;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = brk_entry;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, NULL) < 0) {
        perror("sigaction SIGTRAP");
        return 1;
    }

    brk_entry_x8 = 0;
    brk_resumed_x8 = 0;
    brk_fire();

    if (brk_entry_x8 != BRK_X8) {
        fprintf(stderr,
                "FAIL BRK tail: the handler entered with X8 = 0x%llx, want "
                "the guest's 0x%x\n",
                (unsigned long long) brk_entry_x8, BRK_X8);
        failures++;
    }
    if (brk_resumed_x8 != BRK_X8) {
        fprintf(stderr,
                "FAIL BRK tail: the resumed guest carries X8 = 0x%llx, want "
                "the guest's 0x%x\n",
                (unsigned long long) brk_resumed_x8, BRK_X8);
        failures++;
    }
    return failures;
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("sigaction SIGUSR1");
        return 1;
    }

    struct sigaction sa2;
    memset(&sa2, 0, sizeof(sa2));
    sa2.sa_handler = nested_handler;
    sigemptyset(&sa2.sa_mask);
    if (sigaction(SIGUSR2, &sa2, NULL) < 0) {
        perror("sigaction SIGUSR2");
        return 1;
    }

    int64_t want_pid = (int64_t) getpid();

    for (int round = 0; round < ROUNDS * 2; round++) {
        resumed_x8 = 0;
        resumed_rc = 0;
        nest = round & 1;
        nested = 0;

        if (sigsetjmp(resume, 1) == 0) {
            raise(SIGUSR1);
            fprintf(stderr, "FAIL round %d: handler did not redirect\n", round);
            failures++;
            continue;
        }

        if (resumed_x8 != NR_GETPID) {
            fprintf(stderr,
                    "FAIL round %d: X8 after rt_sigreturn is %llu, "
                    "want %d\n",
                    round, (unsigned long long) resumed_x8, NR_GETPID);
            failures++;
        }
        if (resumed_rc != want_pid) {
            fprintf(stderr,
                    "FAIL round %d: the resumed SVC returned %lld, "
                    "want the pid %lld\n",
                    round, (long long) resumed_rc, (long long) want_pid);
            failures++;
        }
        if (nest && !nested) {
            fprintf(stderr, "FAIL round %d: the nested signal never ran\n",
                    round);
            failures++;
        }
    }

    failures += check_wx_tails();
    failures += check_brk_tail();
    failures += check_stale_park();

    if (!failures)
        printf(
            "PASS: %d rt_sigreturn rounds kept X8, a later fault on the same "
            "PC saw its own, and the W^X and BRK tails handed theirs to the "
            "handler\n",
            ROUNDS * 2);
    printf("%d failed\n", failures);
    return failures ? 1 : 0;
}
