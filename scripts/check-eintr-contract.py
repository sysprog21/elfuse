"""Fail when a syscall path can hand the guest EINTR without saying whether the
dispatcher may restart it.

The dispatcher restarts an interrupted SVC when the only thing that broke the
wait was an execve handed to the thread group leader (see syscall_restart_arm
in src/syscall/proc.h). Restarting re-executes the syscall with the guest's
original arguments, which is right for a wait that consumed nothing and wrong
for one that did: a relative timeout starts again from zero, and a request
already on the wire is sent twice. Both failure modes were shipped and then
found by review rather than by a test, twice, which is why this is a gate
rather than a convention.

Nothing in C makes that decision visible. A new interruptible wait is
restartable by default simply because the epilogue arms on any EINTR, so the
author of the next one has to know a rule that is not written down anywhere the
compiler can see. This script writes it down: every function that can hand the
guest EINTR is classified here, and the classification is checked against the
source rather than trusted.

Three classifications:

  forbids     The function calls syscall_restart_forbid(). Verified against the
              body, so the claim cannot go stale while the call is deleted.
  restartable Re-executing the syscall is harmless: the wait reports EINTR
              before transferring anything, consuming a deadline, or leaving
              host state behind. Needs a reason.
  not-a-wait  The EINTR does not come from a blocking wait at all (a teardown
              refusal, or handoff bookkeeping). Needs a reason.

Adding an interruptible wait therefore fails the build until its restart
behaviour is stated. Deleting one fails it too, so the inventory cannot rot
into a list of functions that no longer exist.

The unit is the function that decides, not the syscall that returns. A handler
forwarding a wait helper's result carries no EINTR expression of its own and is
not listed; the helper it called is, because that is where the wait happens and
where the decision belongs. Moving the annotation to syscall entry points would
name hundreds of forwarders and put the classification a long way from the code
it describes.

What this does not do is check every branch. It asks whether a function makes
a restart decision, not whether each of its EINTR exits makes the right one, so
a function with several exits that loses the call on one of them still passes.
Catching that needs the reasoning a reviewer does; this only guarantees that
the reasoning happened once and is written down.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"

# Sites that hand EINTR to the guest, keyed by "path::function".
#
# Keyed by function rather than by line so ordinary edits above a site do not
# churn this table. The value is (classification, reason).
INVENTORY = {
    # Waits that consumed a guest-supplied deadline, or sent something.
    "syscall/time.c::interruptible_sleep_ns": (
        "forbids",
        "Relative sleeps have spent part of the interval; TIMER_ABSTIME "
        "re-derives the same instant and stays restartable.",
    ),
    "syscall/poll.c::sys_ppoll": (
        "forbids",
        "A finite poll has spent part of the guest's timeout.",
    ),
    "syscall/poll.c::sys_pselect6": (
        "forbids",
        "A finite select has spent part of the guest's timeout.",
    ),
    "syscall/poll.c::sys_epoll_pwait": (
        "forbids",
        "A finite epoll wait has spent part of the guest's timeout, and ready "
        "events outrank leader work because kqueue consumes the edge.",
    ),
    "runtime/futex.c::futex_wait_inner": (
        "forbids",
        "Relative FUTEX_WAIT has spent part of its timeout; FUTEX_WAIT_BITSET "
        "is absolute and stays restartable.",
    ),
    "syscall/signal.c::signal_rt_sigtimedwait": (
        "forbids",
        "The timeout is spent in 1 ms chunks before this reports EINTR.",
    ),
    "syscall/io.c::tty_drain_interruptible": (
        "forbids",
        "The kernel returns a plain -EINTR from the TCSBRK/TCSBRKP/TIOCSBRK "
        "drain (tty_io.c, no ERESTARTSYS), and part of the output has already "
        "drained, so a restart would wait the interval again.",
    ),
    "syscall/io.c::copy_fd_range": (
        "forbids",
        "sendfile and copy_file_range read a chunk before waiting to write it; "
        "a pipe input cannot be rewound, so a restart would re-run the call "
        "over an input missing that chunk.",
    ),
    "syscall/io.c::splice_drain_chunk": (
        "forbids",
        "Same shape as copy_fd_range, and a pipe is the usual splice input. "
        "This is the drain sys_splice runs per chunk; the forbid lives here "
        "because only this loop knows how much of the chunk never left.",
    ),
    "syscall/fuse.c::fuse_request_locked": (
        "forbids",
        "FUSE_INTERRUPT is on the wire and the request is detached, so a "
        "restart would re-issue the operation under a fresh unique.",
    ),
    "syscall/usbdev.c::ioret_neg_errno": (
        "forbids",
        "kIOReturnAborted means a sync transfer already handed to IOKit was "
        "aborted mid-flight; a restart would send the request twice. The "
        "event thread also maps statuses through here, where the "
        "thread-local flag is dead state.",
    ),
    "syscall/usbdev.c::usbdev_do_reap": (
        "forbids",
        "REAPURB blocks on the completion pipe for URBs an earlier SUBMITURB "
        "already handed to IOKit; proc_reapurb returns -EINTR with no restart "
        "(devio.c:2116-2117), so the dispatcher must not re-enter the wait "
        "as if the guest had asked again.",
    ),
    # Waits that report EINTR before doing anything the guest can observe.
    "syscall/io.c::io_retry_backoff": (
        "restartable",
        "Polled retry helper; reports before the operation it guards runs.",
    ),
    "syscall/io.c::io_wait_fd_or_interrupted": (
        "restartable",
        "Reports readiness or EINTR without transferring anything itself. It "
        "no longer follows that its callers have not: io_xfer waits again "
        "after a partial write, and copy_fd_range and splice_drain_chunk wait "
        "to write a chunk they have already read. Those decide for themselves "
        "and are listed above.",
    ),
    "syscall/io.c::io_wait_fd_timed_or_interrupted": (
        "restartable",
        "The bounded spelling of the wait above, and restartable for the same "
        "reason: it transfers nothing. The deadline is the caller's, not its "
        "own, so the caller that supplied one -- today only the SO_RCVTIMEO "
        "receive in nl_wait_readable_locked -- is the one that must forbid "
        "the restart.",
    ),
    "syscall/fs.c::open_nonblocking_writer": (
        "restartable",
        "FIFO open retry; nothing is opened until it succeeds.",
    ),
    "syscall/fd.c::eventfd_read": (
        "restartable",
        "The wait precedes the read of the counter pipe, so an interrupted "
        "wait has not drained anything and the counter still holds what the "
        "guest came for.",
    ),
    "syscall/fd.c::signalfd_read": (
        "restartable",
        "The wait precedes the dequeue; the pending mask is untouched when it "
        "returns EINTR.",
    ),
    "syscall/fd.c::timerfd_read": (
        "restartable",
        "The wait precedes the zero-timeout kevent that collects the "
        "expirations, so an interrupted wait leaves the count with the timer. "
        "Restarting re-collects the same expirations.",
    ),
    "syscall/io.c::io_xfer": (
        "restartable",
        "EINTR reaches the guest only on the total == 0 exit. Once any byte "
        "has moved the short count is returned instead, which is what Linux "
        "does and what makes the restart safe: there is nothing to redo.",
    ),
    "syscall/net.c::net_wait_or_interrupted": (
        "restartable",
        "A wait, nothing more. Its callers own the question of what they had "
        "already consumed before reaching it.",
    ),
    "syscall/net.c::net_recv_zero_payload_gate": (
        "restartable",
        "Waits for readability before any recv runs, so no datagram has been "
        "taken off the socket.",
    ),
    "syscall/net.c::connect_nonblock_wait": (
        "restartable",
        "The SYN is already out, which is exactly why the restart needs its "
        "precondition rather than a ban: sys_connect treats EALREADY as "
        "in-flight always and EISCONN as in-flight only under "
        "syscall_is_restarted(), so the retry waits the same connection out "
        "instead of starting a second one.",
    ),
    "syscall/net.c::connect_or_interrupted": (
        "restartable",
        "Flips the socket nonblocking, forwards connect_nonblock_wait, and "
        "restores the guest's flags. It consumes nothing of its own; the SYN "
        "the wait below it already sent is sys_connect's problem, not this "
        "one's.",
    ),
    "syscall/net.c::sys_connect": (
        "restartable",
        "The one caller whose restart needs a precondition rather than a ban: "
        "the SYN is out, so it treats EALREADY as in-flight always and EISCONN "
        "as in-flight only under syscall_is_restarted(), and the retry waits "
        "the same connection out instead of opening a second one.",
    ),
    "syscall/net.c::sys_sendto": (
        "restartable",
        "POLLOUT wait, then send. An interrupted wait has sent nothing, and a "
        "send that moved bytes returns the count.",
    ),
    "syscall/net.c::do_accept": (
        "restartable",
        "The readiness wait precedes accept, so an interrupted wait has not "
        "removed a connection from the listen queue.",
    ),
    "syscall/net.c::sys_recvfrom": (
        "restartable",
        "The first wait precedes recvfrom, and later interrupted waits return "
        "the accumulated count instead of EINTR.",
    ),
    "syscall/net-msg.c::sys_sendmsg": (
        "restartable",
        "The wait sits before its send in the EAGAIN retry loop, so EINTR "
        "means nothing left the socket.",
    ),
    "syscall/net-msg.c::net_send_single_iov": (
        "restartable",
        "Same shape, for the single-iovec fast path both sendmsg and sendmmsg "
        "take: the wait precedes the send, so EINTR means nothing left the "
        "socket. sys_sendmmsg forwards this result and carries no wait of its "
        "own, so it is not listed; its loop reports the delivered count rather "
        "than the error once a message has gone out.",
    ),
    "syscall/net-msg.c::sys_recvmsg": (
        "restartable",
        "The first wait precedes recvmsg, and later interrupted waits return "
        "the accumulated count instead of EINTR.",
    ),
    "syscall/net-msg.c::sys_recvmmsg": (
        "forbids",
        "The finite initial poll consumes part of the guest's relative timeout, "
        "so every exit past it refuses the restart that would start the timeout "
        "over. The vlen==1 fast path runs only when no timeout was supplied and "
        "never reaches the poll, so its EINTR stays restartable.",
    ),
    "syscall/fs.c::fcntl_flock_wait": (
        "restartable",
        "The nonblocking flock probe changes nothing before the backoff waits.",
    ),
    "syscall/io.c::sys_read": (
        "restartable",
        "io_xfer returns EINTR only before it has transferred a byte.",
    ),
    "syscall/io.c::sys_readv": (
        "restartable",
        "io_xfer returns EINTR only before it has transferred a byte.",
    ),
    "syscall/io.c::sys_write": (
        "restartable",
        "io_xfer returns EINTR only before it has transferred a byte.",
    ),
    "syscall/io.c::sys_writev": (
        "restartable",
        "io_xfer returns EINTR only before it has transferred a byte.",
    ),
    "syscall/io.c::sys_splice": (
        "restartable",
        "Adds no hazard of its own: the input-side io_xfer reports before the "
        "first byte, and the one exit that has consumed something -- a chunk "
        "read but not written -- is forbidden by splice_drain_chunk, which is "
        "the only frame that knows how much never left.",
    ),
    "syscall/io.c::sys_vmsplice": (
        "restartable",
        "A partial transfer returns its count; EINTR reaches the guest only "
        "before the first byte.",
    ),
    "syscall/proc.c::proc_wait_autoreap_children": (
        "forbids",
        "The loop can reap an exited child before its backoff reports EINTR, "
        "so re-execution would observe different process state.",
    ),
    "syscall/syscall.c::sc_flock": (
        "restartable",
        "The nonblocking flock probe changes nothing before the backoff waits.",
    ),
    "syscall/sysvipc.c::sys_semop": (
        "restartable",
        "A failed IPC_NOWAIT probe applies none of the semaphore operations "
        "before the backoff waits.",
    ),
    "syscall/netlink.c::nl_wait_readable_locked": (
        "forbids",
        "Conditionally, and that condition is sock_intr_errno()'s: a receive "
        "with no SO_RCVTIMEO consumed nothing and stays restartable (Linux "
        "reports ERESTARTSYS there), but one with a finite timeout has spent "
        "part of it, and a restart would hand the guest the whole timeout a "
        "second time, so that branch forbids like every other spent deadline "
        "in this table. Narrowed once more to the guest-visible half of the "
        "EINTR: the dispatcher's leader-only execve handoff also reports "
        "EINTR here, carries no signal, and is restarted by design, so the "
        "forbid is gated on !thread_stop_is_leader_work_only() and the "
        "restarted attempt resumes the deadline rather than taking a fresh "
        "one -- restart_block's job.",
    ),
    "syscall/inotify.c::inotify_read": (
        "restartable",
        "Reached only when kevent returned no event, so nothing is consumed.",
    ),
    "syscall/fuse.c::fuse_dev_read": (
        "restartable",
        "The queue is empty by the loop condition; no request is dequeued.",
    ),
    "syscall/proc.c::sys_wait4": (
        "restartable",
        "Every reapable outcome returns earlier; no child is removed and no "
        "status or rusage is written.",
    ),
    "syscall/proc.c::sys_waitid": (
        "restartable",
        "Same shape as sys_wait4: the reap and WNOHANG answers precede this.",
    ),
    "runtime/futex.c::futex_lock_pi_inner": (
        "restartable",
        "The deadline is absolute and futex_unlock_pi zeroes the word rather "
        "than transferring ownership, so a restart re-CASes.",
    ),
    "runtime/futex.c::sys_futex_waitv": (
        "restartable",
        "The deadline is converted to an absolute instant at entry, so a "
        "restart re-derives the same one.",
    ),
    # Not blocking waits.
    "syscall/signal.c::signal_rt_sigsuspend": (
        "not-a-wait",
        "Returns the EINTR sigsuspend is defined to return; the mask is "
        "restored on the way out.",
    ),
    "syscall/exec.c::exec_handoff_to_leader": (
        "not-a-wait",
        "Handoff bookkeeping: the requester is being reaped, or the slot never "
        "reported back.",
    ),
    "syscall/mem.c::hvf_apply_file_overlay": (
        "not-a-wait",
        "Refuses the overlay because an execve is reaping this thread.",
    ),
    "syscall/mem.c::hvf_remove_file_overlay": (
        "not-a-wait",
        "Refuses the unmap window because an execve is reaping this thread.",
    ),
    "syscall/mem.c::sys_mmap_high_va": (
        "not-a-wait",
        "Refuses the overlay because an execve is reaping this thread.",
    ),
    "runtime/forkipc.c::sys_clone": (
        "not-a-wait",
        "Refuses the fork because an execve is reaping this thread.",
    ),
    "syscall/syscall.c::syscall_dispatch": (
        "not-a-wait",
        "Tests a handler's EINTR result to decide the restart; produces none "
        "of its own.",
    ),
}

# Anything on these lines is the mechanism itself, not a site that reports to a
# guest.
SELF = {"syscall/syscall.c::syscall_restart_forbid"}

EINTR_RE = re.compile(r"(return\s+-LINUX_EINTR|=\s*-LINUX_EINTR|errno\s*=\s*EINTR)\b")

# A function can also decide the restart question without naming EINTR itself:
# it forwards a wait helper's errno and calls syscall_restart_forbid() over the
# top. Those are deciders by the definition above and have to be classified, or
# the one class of caller the helper's own entry cannot describe -- the caller
# that consumed something before the wait -- stays invisible to this gate.
FORBID_MARKER = "syscall_restart_forbid()"

# A wait routed through a shared helper reports the helper's EINTR without ever
# naming it. That is precisely the refactor this tree keeps making -- four
# synthetic readers moved onto io_wait_fd_or_interrupted, and each one silently
# left this gate's view the moment it stopped writing the literal. Treat calling
# one of these as reporting EINTR, so the classification survives the cleanup
# that hides the constant.
#
# Listed by hand. Membership is a property of the code, that this helper hands
# EINTR to its caller, and no spelling rule tracks it: connect_or_interrupted
# and net_recv_zero_payload_gate sit on opposite sides of any suffix convention
# and both report EINTR upward. Deriving the list from INVENTORY would also make
# deleting an entry shrink the regex, which is the gate getting weaker at the
# moment it should be complaining.
#
# A caller of a helper is still free to be 'restartable': the entry states the
# decision, it does not presume one.
EINTR_HELPERS = (
    "io_wait_fd_or_interrupted",
    "io_wait_fd_timed_or_interrupted",
    "net_wait_or_interrupted",
    "net_recv_zero_payload_gate",
    "connect_nonblock_wait",
    "connect_or_interrupted",
    "io_retry_backoff",
    "io_xfer",
)

# Both directions the pair can drift. A helper missing from INVENTORY is one the
# gate demands a classification of without carrying one itself; an empty tuple
# builds the regex '\b()\s*\(', which matches every call in the tree and buries
# the real answer under a thousand unclassified functions.
assert EINTR_HELPERS, "EINTR_HELPERS must not be empty"
for _helper in EINTR_HELPERS:
    assert any(
        key.endswith("::" + _helper) for key in INVENTORY
    ), f"EINTR helper {_helper} is not classified in INVENTORY"

HELPER_RE = re.compile(r"\b(" + "|".join(EINTR_HELPERS) + r")\s*\(")

FUNC_START_RE = re.compile(r"^(\w[\w \t\*]*?)\b(\w+)\s*\([^;]*$")


CODE_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|//[^\n]*', re.S)


def code_only(body):
    """The body with comments and string literals blanked out.

    Every marker this gate looks for is a call, and a call is code. Matching
    the raw text instead lets a function that merely *mentions*
    io_wait_fd_or_interrupted in a comment read as one that calls it, which is
    a gate that answers questions about prose. Newlines are preserved so line
    numbers in any future diagnostic still line up.
    """

    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))

    return CODE_TOKEN_RE.sub(blank, body)


def functions(path):
    """Yield (name, first_line, last_line) for each top-level function."""
    lines = path.read_text(errors="ignore").split("\n")
    name = None
    pending = None
    depth = 0
    start = None
    for i, line in enumerate(lines, 1):
        if start is None:
            m = FUNC_START_RE.match(line)
            if m and not line.lstrip().startswith(
                ("if", "for", "while", "switch", "return", "#", "}")
            ):
                pending = m.group(2)
            if line.startswith("{") and pending:
                name, start, depth = pending, i, 1
                continue
            if line.rstrip().endswith("{") and pending and not line.startswith(" "):
                name, start, depth = pending, i, line.count("{") - line.count("}")
                continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                yield name, start, i
                name, start, pending = None, None, None


def scan():
    """Return {key: has_forbid} for every function that can report EINTR."""
    found = {}
    for path in sorted(SRC.rglob("*.c")):
        rel = path.relative_to(SRC).as_posix()
        text = path.read_text(errors="ignore").split("\n")
        for name, first, last in functions(path):
            body = code_only("\n".join(text[first - 1 : last]))
            forbids = FORBID_MARKER in body
            if not EINTR_RE.search(body) and not forbids and not HELPER_RE.search(body):
                continue
            found[f"{rel}::{name}"] = forbids
    return found


def main():
    found = scan()
    for key in SELF:
        found.pop(key, None)

    problems = []

    for key, has_forbid in sorted(found.items()):
        entry = INVENTORY.get(key)
        if entry is None:
            problems.append(
                f"unclassified: {key} can report EINTR to the guest.\n"
                f"    Decide whether the dispatcher may restart it and add it to\n"
                f"    INVENTORY in {pathlib.Path(__file__).name}. A wait that has\n"
                f"    consumed a relative timeout, transferred data, or sent a\n"
                f"    request must call syscall_restart_forbid() and be recorded\n"
                f"    as 'forbids'."
            )
            continue
        kind, reason = entry
        if kind == "forbids" and not has_forbid:
            problems.append(
                f"stale claim: {key} is recorded as 'forbids' but its body has\n"
                f"    no syscall_restart_forbid() call."
            )
        if kind != "forbids" and has_forbid:
            problems.append(
                f"stale claim: {key} calls syscall_restart_forbid() but is\n"
                f"    recorded as '{kind}'."
            )
        if not reason.strip():
            problems.append(f"missing reason: {key}")

    for key in sorted(set(INVENTORY) - set(found)):
        problems.append(
            f"stale entry: {key} is in INVENTORY but no longer reports EINTR.\n"
            f"    Remove it."
        )

    if problems:
        print("EINTR restart contract check failed:\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        return 1

    forbids = sum(1 for k in INVENTORY if INVENTORY[k][0] == "forbids")
    print(
        f"  {len(found)} function(s) can report EINTR; all classified "
        f"({forbids} forbid the SVC restart)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
