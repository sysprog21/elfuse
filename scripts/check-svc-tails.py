#!/usr/bin/env python3
"""Hold every HVC #5 return tail to the X7 ptrace test, and the X8 tails to X8.

The host encodes a ptrace-stop request in X7 on the HVC #5 return and the shim
reads it in svc_hvc_restore_eret. A tail that reaches EL0 without passing
through that label drops a stop the host has already consumed, and the tracer
waits out its wait4 forever. Nothing in the compiler or the assembler notices,
because every spelling assembles.

Two live bugs had this exact shape, which is why this is a gate and not a
comment:

  exec_drop_frame never tested X7. That one is now deliberate (the host leaves
  X7 alone on the X8 == 2 tail, whose live registers are the final EL0 state
  except for X8, which holds the marker and is reloaded from the frame by the
  second rule below) and is the single allowed exception below.

  tlbi_selective's defensive zero-count exit was "cbz x10, 1f", and 1f resolved
  to a numeric label sitting inside svc_restore_eret, past the test. A numeric
  local label is invisible to review in a way a named one is not, which is the
  second thing this checks.

The gate reads the dispatch region only: from the HVC #5 itself to the start of
svc_restore_eret. Every tail the host can select lives there. Numeric labels
inside that region are fine, and the selective-TLBI loop uses one; what is not
fine is a reference that resolves past the end of it.

The same tail carries a second rule, for the same reason: it restores nothing,
so whatever is in a register when it runs reaches EL0. X8 is where the marker
that selected the tail arrived, so the host publishes the guest's X8 in the
frame's own X8 slot and exec_drop_frame reloads it from there before the pop.
Deleting that one load is invisible in review and turns an SVC the guest has
not executed yet into syscall 2 (sysprog21/elfuse#379), so the offset is
checked here against the C side that writes it rather than left to match by
eye.

handle_brk is held to the same rule and checked the same way. It is not an
HVC #5 tail, but it ends the same: the host delivers a signal out of HVC #10
and leaves the marker in X8, and the tail reloads the guest's value from the
frame slot before dropping the frame. A SIGTRAP handler reading X8 is the
ordinary case there, since JIT translators use BRK as a trampoline.

The host half of the same hand-off is checked too. A signal delivered after an
rt_sigreturn but before the vCPU is resumed cannot read the guest's X8 out of
the register either, so rt_sigreturn parks it and that delivery takes the parked
value. The park is correct only for that one epilogue, and what keeps it from
reaching an unrelated later delivery is that the run loop forgets it before
every resume. A resume added later somewhere else would not forget, and no test
driving the resume that exists today can see that, which is why the call sites
are enumerated here.

What that check establishes is textual and narrower than the rule it stands for:
a call to signal_forget_sigreturn_x8() is written above every hv_vcpu_run().
It does not establish that the call runs. Narrowing it in place, by wrapping the
existing call in a condition, leaves this gate at rc=0 with its summary line
unchanged while the record outlives the resume. Only
tests/test-shim-sigreturn-x8 answers that, and it does: its stale phase fails on
a narrowed forget, reporting the X8 the earlier rt_sigreturn returned with.
Read this gate as the answer to a resume added without a forget, and the test as
the answer to a forget that does not run.
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHIM = ROOT / "src" / "core" / "shim.S"

REGION_START = re.compile(r"^\s*hvc\s+#5\b")
REGION_END = re.compile(r"^svc_restore_eret:")

LABEL = re.compile(r"^([A-Za-z_.][A-Za-z_0-9.]*):")
NUM_LABEL = re.compile(r"^(\d+):")
BRANCH = re.compile(r"^\s*(?:b|bl|b\.[a-z]+|cbz|cbnz|tbz|tbnz)\s+(.*)$")

# Transfers this script cannot follow: a register branch, and "ret", which
# leaves through X30 rather than through the tail. The shim has none today;
# one added here needs a different argument than "the branch targets look
# right".
INDIRECT = re.compile(r"^\s*(?:br|blr|ret)\b")

# Control leaves a tail only through one of these. Anything else as the last
# instruction before svc_restore_eret means the tail falls through into it,
# which reaches EL0 having skipped the X7 test just as surely as a branch would.
#
# "ret" is deliberately absent. It leaves through X30, which in this dispatch
# is a guest register restored from the saved frame, so it is neither a tail
# this gate can follow nor one that reaches the test.
TERMINAL = re.compile(r"^\s*(?:b|br|eret)\b(?!\.)")

# The gate label earns its name only while it still tests X7.
X7_TEST = re.compile(r"^\s*(?:cbz|cbnz)\s+x7\b")

GATE = "svc_hvc_restore_eret"
FORBIDDEN = "svc_restore_eret"
DROP_TAIL = "exec_drop_frame"
BRK_TAIL = "handle_brk"

# Each X8-reloading tail's one restore, and the pop it has to precede.
DROP_RELOAD = re.compile(r"^\s*ldr\s+x8,\s*\[sp,\s*#(\d+)\]")
DROP_POP = re.compile(r"^\s*add\s+sp,\s*sp,\s*#(\d+)\b")
ERET = re.compile(r"^\s*eret\b")

# The C side of the same frame slot.
SIGNAL_C = ROOT / "src" / "syscall" / "signal.c"
C_DEFINE = re.compile(r"^#define\s+(SHIM_FRAME_OFF_X8|SHIM_FRAME_BYTES)\s+(\d+)\s*$")

# The host side of the hand-off: the resume, and the call that has to precede
# it. RESUME_LOOKBACK is generous on purpose -- a forget separated from its
# resume by a few lines of bookkeeping is the shape the run loop already has,
# and demanding the line above would reject it. What the window buys is
# tolerance, not proof: see the module docstring for what this does not answer.
SRC = ROOT / "src"
RESUME = re.compile(r"\bhv_vcpu_run\s*\(")
FORGET = re.compile(r"\bsignal_forget_sigreturn_x8\s*\(\s*\)")
COMMENT = re.compile(r"^\s*(?:/\*|\*|//)")
RESUME_LOOKBACK = 12

# The one tail allowed to skip the test, and why. Keep the reason with the name:
# an exception added later without one is the bug this gate exists to stop.
ALLOWED_SKIP = {
    "exec_drop_frame": "X8 == 2; the host takes that stop inline, never writes X7",
}


def branch_target(operands):
    """The label of a branch is its last comma-separated operand."""
    tail = operands.split(",")[-1].strip()
    return tail.split()[0] if tail else ""


def frame_constants(lines, path):
    """The C-side SHIM_FRAME_* values, or a problem list."""
    found = {}
    for line in lines:
        if m := C_DEFINE.match(line):
            found[m.group(1)] = int(m.group(2))
    missing = {"SHIM_FRAME_OFF_X8", "SHIM_FRAME_BYTES"} - set(found)
    if missing:
        return None, [
            f"{path}: no #define for {', '.join(sorted(missing))}; the host no "
            f"longer names the frame slot the drop tail reloads X8 from"
        ]
    return found, []


def check_reload_tail(lines, path, tail, gone, leaks, frame=None):
    """A frame-dropping tail must put the frame's X8 back before it pops it.

    @tail is the label, @gone what a missing label means, and @leaks what EL0
    is handed when the load is not there. Both callers below restore no other
    register, so the load is the whole of what stands between the host's X8 and
    the guest's.
    """
    at = next(
        (i for i, l in enumerate(lines) if LABEL.match(l) and l.startswith(tail + ":")),
        None,
    )
    if at is None:
        return [f"{path}: no '{tail}:' label; {gone}"]

    reload_at = reload_off = pop_at = pop_size = None
    for i in range(at + 1, len(lines)):
        if reload_at is None and (m := DROP_RELOAD.match(lines[i])):
            reload_at, reload_off = i, int(m.group(1))
        if pop_at is None and (m := DROP_POP.match(lines[i])):
            pop_at, pop_size = i, int(m.group(1))
        if ERET.match(lines[i]):
            break

    problems = []
    if reload_at is None:
        problems.append(
            f"{path}:{at + 1}: '{tail}' does not reload X8 from the frame. "
            f"It restores no register, so {leaks}"
        )
    elif pop_at is not None and reload_at > pop_at:
        problems.append(
            f"{path}:{reload_at + 1}: the X8 reload is below the pop, so it "
            f"reads past the frame it was meant to read."
        )
    if pop_at is None:
        problems.append(
            f"{path}:{at + 1}: '{tail}' ERETs without popping the frame "
            f"it was told to drop. SAVE_GPRS subtracted those bytes from "
            f"SP_EL1 and nothing else gives them back, so the exception stack "
            f"walks down one frame per drop until it leaves the shim block."
        )
    if frame:
        if reload_off is not None and reload_off != frame["SHIM_FRAME_OFF_X8"]:
            problems.append(
                f"{path}:{reload_at + 1}: reloads X8 from [sp, #{reload_off}], "
                f"but the host publishes it at "
                f"{frame['SHIM_FRAME_OFF_X8']} (SHIM_FRAME_OFF_X8)."
            )
        if pop_size is not None and pop_size != frame["SHIM_FRAME_BYTES"]:
            problems.append(
                f"{path}:{pop_at + 1}: pops {pop_size} bytes, but the host "
                f"bounds-checks a {frame['SHIM_FRAME_BYTES']}-byte frame "
                f"(SHIM_FRAME_BYTES)."
            )
    return problems


def check_resume_barrier(lines, path):
    """Every vCPU resume must have a forget written above it.

    Textual, and deliberately reported as such: this finds a resume that no
    forget precedes, which is the way the call goes missing when a resume is
    added elsewhere. A forget that is present but does not run reads the same
    here; tests/test-shim-sigreturn-x8 is what catches that.
    """
    problems = []
    sites = 0
    for i, line in enumerate(lines):
        if COMMENT.match(line) or not RESUME.search(line):
            continue
        sites += 1
        lo = max(0, i - RESUME_LOOKBACK)
        covered = False
        for j in range(i - 1, lo - 1, -1):
            # Prose is not code on either side of this walk. A commented-out
            # forget is exactly the deletion this rule exists to catch, and
            # counting it as coverage would hide it.
            if COMMENT.match(lines[j]):
                continue
            # A second resume between the two is the one that is uncovered:
            # the forget above it belongs to the first.
            if RESUME.search(lines[j]):
                break
            if FORGET.search(lines[j]):
                covered = True
                break
        if covered:
            continue
        problems.append(
            f"{path}:{i + 1}: resumes the vCPU without calling "
            f"signal_forget_sigreturn_x8() first. The X8 an rt_sigreturn "
            f"parked for a delivery in its own epilogue then outlives the "
            f"guest running, and a later delivery that lands on the same PC "
            f"is handed it in place of the live register."
        )
    return problems, sites


def check(lines, path, counted=None, frame=None):
    """Return a list of problem strings. Empty means the tails are sound.

    @counted, when a list, receives the number of tails reaching the test, so
    the caller does not walk the file again just to report it.
    """
    start = end = None
    for i, line in enumerate(lines):
        if start is None and REGION_START.match(line):
            start = i
        elif start is not None and REGION_END.match(line):
            end = i
            break
    if start is None:
        return [f"{path}: no 'hvc #5' found; the dispatch moved or was renamed"]
    if end is None:
        return [f"{path}: no '{FORBIDDEN}:' after the HVC #5; the tail moved"]

    problems_drop = check_reload_tail(
        lines,
        path,
        DROP_TAIL,
        "the X8 == 2 tail is gone",
        "the drop-frame marker itself reaches EL0 in X8, and a frame whose "
        "saved PC is on an SVC issues that SVC as syscall 2.",
        frame,
    )
    problems_drop += check_reload_tail(
        lines,
        path,
        BRK_TAIL,
        "the BRK tail is gone",
        "the marker a SIGTRAP delivery leaves behind reaches the handler in "
        "X8, in place of the X8 the guest hit the BRK with.",
        frame,
    )

    named = {m.group(1): i for i, l in enumerate(lines) if (m := LABEL.match(l))}
    numeric = [
        (int(m.group(1)), i) for i, l in enumerate(lines) if (m := NUM_LABEL.match(l))
    ]

    problems = list(problems_drop)

    # The whole gate rests on this label testing X7. Renaming or emptying it
    # would leave every tail branching somewhere that no longer checks.
    gate_at = named.get(GATE)
    if gate_at is None:
        problems.append(f"{path}: no '{GATE}:' label; the X7 tail is gone")
    elif not any(
        X7_TEST.match(lines[k])
        for k in range(gate_at + 1, min(gate_at + 6, len(lines)))
    ):
        problems.append(
            f"{path}:{gate_at + 1}: '{GATE}' no longer tests X7, so every tail "
            f"branching to it reaches EL0 unchecked"
        )

    # Fallthrough. The tail physically above svc_restore_eret reaches it with no
    # branch at all if its last instruction is not a transfer, and a branch walk
    # alone says nothing about that. Deleting one 'b svc_hvc_restore_eret' is the
    # whole of the mistake.
    last = None
    for i in range(start, end):
        body = LABEL.sub("", NUM_LABEL.sub("", lines[i])).strip()
        if not body or body.startswith(("/*", "*", "//", ".")):
            continue
        last, last_body = i, body
    if last is None:
        problems.append(f"{path}: the HVC #5 dispatch has no instructions")
    elif not TERMINAL.match(" " + last_body) and not INDIRECT.match(
        " " + last_body
    ):
        problems.append(
            f"{path}:{last + 1}: the last instruction of the HVC #5 dispatch is "
            f"'{last_body}', so control falls through into "
            f"{FORBIDDEN} without the X7 test. End the tail with an explicit "
            f"'b {GATE}'."
        )

    for i in range(start, end):
        if INDIRECT.match(lines[i]):
            problems.append(
                f"{path}:{i + 1}: register branch in the HVC #5 dispatch; this "
                f"gate cannot follow it, so the X7 test cannot be shown to be "
                f"reached."
            )

    # A numeric label on svc_restore_eret is what let a stray "1f" land past the
    # test. Numeric labels inside the dispatch are fine; the branch walk below
    # proves each reference resolves in the region rather than assuming it.
    for value, at in numeric:
        if at == end + 1:
            problems.append(
                f"{path}:{at + 1}: numeric label '{value}:' on {FORBIDDEN}. A "
                f"'{value}f' anywhere in the tail above resolves here and skips "
                f"the X7 test, which is how one live bug got in. Leave this "
                f"label named."
            )

    for i in range(start, end):
        m = BRANCH.match(lines[i])
        if not m:
            continue
        target = branch_target(m.group(1))
        if not target:
            continue
        where = f"{path}:{i + 1}"

        if target == FORBIDDEN:
            problems.append(
                f"{where}: branches to {FORBIDDEN}, skipping the X7 ptrace "
                f"test. Branch to {GATE} instead; it tests X7 and falls through "
                f"to {FORBIDDEN}."
            )
            continue

        if target == GATE:
            continue

        if target in ALLOWED_SKIP:
            # Only the X8 == 2 edge is exempt, not the label. An unconditional
            # branch here, or one not guarded by that compare, reaches a tail
            # that never restores the frame from a path where the host did
            # write X7.
            guarded = lines[i].strip().startswith("b.eq") and any(
                re.match(r"\s*cmp\s+x8,\s*#2\b", lines[j])
                for j in range(max(start, i - 4), i)
            )
            if not guarded:
                problems.append(
                    f"{where}: reaches '{target}' other than through the "
                    f"'cmp x8, #2' / 'b.eq' edge. That tail never restores the "
                    f"frame, so a path where the host wrote X7 must not get "
                    f"there."
                )
            continue

        if num := re.fullmatch(r"(\d+)([fb])", target):
            value, direction = int(num.group(1)), num.group(2)
            candidates = [at for v, at in numeric if v == value]
            if direction == "f":
                dest = min((at for at in candidates if at > i), default=None)
            else:
                dest = max((at for at in candidates if at < i), default=None)
            if dest is None:
                problems.append(f"{where}: '{target}' resolves to nothing")
            elif not start <= dest < end:
                problems.append(
                    f"{where}: '{target}' resolves to line {dest + 1}, outside "
                    f"the HVC #5 dispatch, so it leaves EL1 without the X7 "
                    f"test. Branch to {GATE} or to a named label in the tail."
                )
            continue

        at = named.get(target)
        if at is None:
            problems.append(f"{where}: unknown branch target '{target}'")
        elif not start <= at < end:
            problems.append(
                f"{where}: branches out of the HVC #5 dispatch to '{target}', "
                f"which does not test X7. Every tail must reach {GATE}; add "
                f"'{target}' to ALLOWED_SKIP in this script, with the reason, "
                f"if it is genuinely exempt."
            )

    if counted is not None:
        counted.append(
            sum(
                1
                for i in range(start, end)
                if (m := BRANCH.match(lines[i]))
                and branch_target(m.group(1)) == GATE
            )
        )

    return problems


# A sound BRK tail, and a sound drop tail. Both are appended to every fixture
# below: each rule runs against the whole file, so a fixture aimed at one of
# them has to keep the other intact or every case inherits its failure.
GOOD_BRK = [
    "handle_brk:",
    "    LOAD_GPRS",
    "    hvc #10",
    "    ldr x8, [sp, #64]",
    "    add sp, sp, #256",
    "    eret",
]
GOOD_DROP = [
    "exec_drop_frame:",
    "    ldr x8, [sp, #64]",
    "    add sp, sp, #256",
    "    eret",
]


def _shim(tail, brk=None):
    """Wrap a dispatch tail in the minimum surrounding shape.

    The drop tail goes last so a case aiming at it can slice its body off with
    [:-3] and write its own.
    """
    return (
        ["handle_svc_0:", "    hvc #5", "    cbz x8, svc_hvc_restore_eret"]
        + tail
        + [
            "svc_restore_eret:",
            "    RESTORE_GPRS_KEEP_X0",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    b svc_restore_eret",
        ]
        + (GOOD_BRK if brk is None else brk)
        + GOOD_DROP
    )


CASES = [
    ("clean dispatch", _shim(["tlbi_full:", "    b svc_hvc_restore_eret"]), 0),
    (
        "tail branching straight to the restore",
        _shim(["tlbi_full:", "    b svc_restore_eret"]),
        1,
    ),
    (
        "numeric forward reference escaping the region",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x10, 1f",
            "    b svc_hvc_restore_eret",
            "svc_restore_eret:",
            "1:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    eret",
        ]
        + GOOD_BRK
        + GOOD_DROP,
        2,
    ),
    (
        "in-region loop label is not a finding",
        _shim(
            [
                "tlbi_selective:",
                "    cbz x10, svc_hvc_restore_eret",
                "3:  tlbi vae1is, x11",
                "    b.ne 3b",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "documented exception is allowed",
        _shim(
            [
                "tlbi_full:",
                "    cmp x8, #2",
                "    b.eq exec_drop_frame",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "tail falling through into the restore",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x8, svc_hvc_restore_eret",
            "tlbi_full:",
            "    isb",
            "svc_restore_eret:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    cbz x7, svc_restore_eret",
            "    eret",
        ]
        + GOOD_BRK
        + GOOD_DROP,
        1,
    ),
    (
        "register branch cannot be cleared",
        _shim(["tlbi_full:", "    br x16"]),
        1,
    ),
    (
        "branch out to an unrelated handler",
        _shim(["tlbi_full:", "    b handle_unrelated"])
        + ["handle_unrelated:", "    eret"],
        1,
    ),
    ("no dispatch at all", ["_start:", "    ret"], 1),
    (
        "tail leaving through ret",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret", "other:", "    ret"]),
        1,
    ),
    (
        "unconditional branch to the exempt tail",
        _shim(["tlbi_full:", "    b exec_drop_frame"]),
        1,
    ),
    (
        "the X8 == 2 edge is still allowed",
        _shim(
            [
                "tlbi_full:",
                "    cmp x8, #2",
                "    b.eq exec_drop_frame",
                "    b svc_hvc_restore_eret",
            ]
        ),
        0,
    ),
    (
        "gate label emptied of its X7 test",
        [
            "handle_svc_0:",
            "    hvc #5",
            "    cbz x8, svc_hvc_restore_eret",
            "    b svc_hvc_restore_eret",
            "svc_restore_eret:",
            "    eret",
            "svc_hvc_restore_eret:",
            "    b svc_restore_eret",
        ]
        + GOOD_BRK
        + GOOD_DROP,
        1,
    ),
    (
        "drop tail no longer reloads X8",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret"])[:-3]
        + ["    add sp, sp, #256", "    eret"],
        1,
    ),
    (
        "drop tail reloads X8 after the pop",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret"])[:-3]
        + ["    add sp, sp, #256", "    ldr x8, [sp, #64]", "    eret"],
        1,
    ),
    (
        "drop tail reloads X8 from the wrong slot",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret"])[:-3]
        + ["    ldr x8, [sp, #72]", "    add sp, sp, #256", "    eret"],
        1,
    ),
    (
        "drop tail no longer pops the frame",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret"])[:-3]
        + ["    ldr x8, [sp, #64]", "    eret"],
        1,
    ),
    (
        "BRK tail no longer reloads X8",
        _shim(
            ["tlbi_full:", "    b svc_hvc_restore_eret"],
            brk=["handle_brk:", "    LOAD_GPRS", "    hvc #10",
                 "    add sp, sp, #256", "    eret"],
        ),
        1,
    ),
    (
        "BRK tail reloads X8 after the pop",
        _shim(
            ["tlbi_full:", "    b svc_hvc_restore_eret"],
            brk=["handle_brk:", "    LOAD_GPRS", "    hvc #10",
                 "    add sp, sp, #256", "    ldr x8, [sp, #64]", "    eret"],
        ),
        1,
    ),
    (
        "BRK tail reloads X8 from the wrong slot",
        _shim(
            ["tlbi_full:", "    b svc_hvc_restore_eret"],
            brk=["handle_brk:", "    LOAD_GPRS", "    hvc #10",
                 "    ldr x8, [sp, #72]", "    add sp, sp, #256", "    eret"],
        ),
        1,
    ),
    (
        "BRK tail popped its frame before the HVC again",
        _shim(
            ["tlbi_full:", "    b svc_hvc_restore_eret"],
            brk=["handle_brk:", "    RESTORE_GPRS", "    hvc #10", "    eret"],
        ),
        2,
    ),
    (
        "BRK tail gone",
        _shim(["tlbi_full:", "    b svc_hvc_restore_eret"], brk=[]),
        1,
    ),
]


SELF_TEST_FRAME = {"SHIM_FRAME_OFF_X8": 64, "SHIM_FRAME_BYTES": 256}

RESUME_CASES = [
    (
        "resume behind the forget",
        [
            "        signal_forget_sigreturn_x8();",
            "",
            "        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);",
        ],
        1,
        0,
    ),
    (
        "forget deleted",
        ["        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);"],
        1,
        1,
    ),
    (
        "forget moved below the resume",
        [
            "        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);",
            "        signal_forget_sigreturn_x8();",
        ],
        1,
        1,
    ),
    (
        "a second resume added without one",
        [
            "        signal_forget_sigreturn_x8();",
            "        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);",
            "        if (retry)",
            "            hv_vcpu_run(vcpu);",
        ],
        2,
        1,
    ),
    (
        "prose naming the resume is not a call site",
        [
            "    /* kick the vCPUs out of hv_vcpu_run() before the unmap */",
            "     * ordered by the first hv_vcpu_run and the release here",
        ],
        0,
        0,
    ),
    (
        "forget commented out above the resume",
        [
            "        // signal_forget_sigreturn_x8();",
            "        HV_CHECK_CTX(hv_vcpu_run(vcpu), vcpu, g);",
        ],
        1,
        1,
    ),
]


def self_test():
    print("  SVCTAIL self-test", flush=True)
    failures = 0
    for name, lines, expected in CASES:
        got = len(check(lines, "<case>", frame=SELF_TEST_FRAME))
        if got != expected:
            print(f"  FAIL {name}: expected {expected} problem(s), got {got}")
            failures += 1
    for name, lines, want_sites, expected in RESUME_CASES:
        got, sites = check_resume_barrier(lines, "<case>")
        if len(got) != expected or sites != want_sites:
            print(
                f"  FAIL {name}: expected {expected} problem(s) over "
                f"{want_sites} site(s), got {len(got)} over {sites}"
            )
            failures += 1
    total = len(CASES) + len(RESUME_CASES)
    if failures:
        print(f"  self-test: {failures} of {total} cases failed")
        return 1
    print(f"  self-test: {total} cases, all pass")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--self-test", action="store_true", help="run the checker's own cases"
    )
    if parser.parse_args().self_test:
        return self_test()

    counted = []
    frame, problems = frame_constants(
        SIGNAL_C.read_text().splitlines(), str(SIGNAL_C)
    )
    problems += check(SHIM.read_text().splitlines(), str(SHIM), counted, frame)

    resumes = 0
    for src in sorted(SRC.rglob("*.c")):
        found, sites = check_resume_barrier(
            src.read_text().splitlines(), str(src.relative_to(ROOT))
        )
        problems += found
        resumes += sites
    if not resumes:
        problems.append(
            "src: no hv_vcpu_run() call site found; the vCPU resume moved, and "
            "with it the point the parked X8 has to be forgotten at"
        )

    print(f"  SVCTAIL {SHIM.relative_to(ROOT)}", flush=True)
    if problems:
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        print(
            f"\n  {len(problems)} problem(s): a tail that can reach EL0 without "
            f"the X7 ptrace test, a frame-dropping tail that hands EL0 the "
            f"marker instead of the guest's X8 or leaves the frame it was told "
            f"to drop, or a resume with no forget written above it.",
            file=sys.stderr,
        )
        return 1

    print(
        f"  {counted[0]} HVC #5 tail(s) reach the X7 test, "
        f"{len(ALLOWED_SKIP)} documented exception; {DROP_TAIL} and {BRK_TAIL} "
        f"both reload X8 from [sp, #{frame['SHIM_FRAME_OFF_X8']}] before the "
        f"pop; {resumes} vCPU resume(s) have a forget written above them"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
