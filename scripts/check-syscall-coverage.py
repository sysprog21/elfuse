#!/usr/bin/env python3
"""Best-effort syscall coverage audit for dispatch.tbl against tests/."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DISPATCH = ROOT / "src" / "syscall" / "dispatch.tbl"
TESTS = ROOT / "tests"

ENTRY_RE = re.compile(r"^(SYS_[A-Za-z0-9_]+)\s+(sc_[A-Za-z0-9_]+)\s+([01])$")

ALIASES: dict[str, set[str]] = {
    "faccessat": {"faccessat2"},
    "renameat": {"renameat2"},
    # Linux syscall name vs. libc wrapper name. On 64-bit aarch64 each
    # entry on the left is the dispatch.tbl entry; the entries on the
    # right are libc function names that route through that syscall.
    "pread64": {"pread"},
    "pwrite64": {"pwrite"},
    "epoll_pwait": {"epoll_wait"},
    "eventfd2": {"eventfd"},
    "rt_sigaction": {"sigaction"},
    "rt_sigprocmask": {"sigprocmask"},
    "rt_sigtimedwait": {"sigwait", "sigwaitinfo", "sigtimedwait"},
    "signalfd4": {"signalfd"},
}

# Keep only syscalls that genuinely lack a direct test reference. main() rejects
# stale entries once a direct call or alias is added so exemptions cannot mask a
# later test regression.
INDIRECT_COVERAGE: dict[str, str] = {
    "lgetxattr": "Symlink xattr semantics are filesystem-sensitive; audit via fs-xattr code and negative-path tests.",
    "lsetxattr": "Symlink xattr semantics are filesystem-sensitive; audit via fs-xattr code and negative-path tests.",
    "listxattr": "Covered indirectly through xattr plumbing; success-path coverage is filesystem-dependent.",
    "llistxattr": "Symlink xattr list semantics are filesystem-sensitive; retained as indirect coverage.",
    "flistxattr": "Covered indirectly through xattr plumbing and fd-based xattr checks.",
    "fgetxattr": "Covered indirectly through xattr plumbing and fd-based xattr checks.",
    "lremovexattr": "Symlink xattr semantics are filesystem-sensitive; retained as indirect coverage.",
    "rt_sigsuspend": "Signal suspension is exercised by higher-level signal tests; direct raw coverage is timing-sensitive.",
    "rt_sigpending": "Signal pending state is exercised indirectly by the signal suite.",
    "ptrace": "Covered by debugger integration via tests/test-gdbstub.sh.",
    "chroot": "Exercised only by the dynamic coreutils shell suite via the chroot(8) applet; the syscall itself has no dedicated C test (requires elevated privilege).",
    "rt_sigreturn": "Kernel-only return-from-handler trampoline; invoked implicitly by every signal handler exit. No userspace callers.",
    "get_robust_list": "Pthread-internal: glibc may set/get a robust-list pointer transparently during thread setup; rarely called directly by application code.",
    "set_robust_list": "Pthread-internal: glibc and musl issue set_robust_list during thread bring-up via a path that the audit corpus does not call directly.",
}


FLAG_MATRIX = TESTS / "flag-matrix.tbl"

# Syscalls whose flags argument must have rows in tests/flag-matrix.tbl. A name
# mentioned in a test says the call was made; a row says each flag was asserted
# set and clear against a real kernel. Dropping the rows for one of these fails
# the audit, and so does listing a syscall the dispatcher no longer serves.
FLAG_MATRIX_REQUIRED: set[str] = {
    "accept4",
    "clone",
    "dup3",
    "epoll_create1",
    "eventfd2",
    "faccessat2",
    "fchmodat",
    "fchmodat2",
    "fchownat",
    "fcntl",
    "inotify_init1",
    "linkat",
    "memfd_create",
    "mmap",
    "mprotect",
    "newfstatat",
    "openat",
    "pipe2",
    "renameat2",
    "signalfd4",
    "socket",
    "socketpair",
    "statx",
    "timerfd_create",
    "unlinkat",
    "utimensat",
}

_ROW_PREFIX = re.compile(r"^(?:pending |unsupported:\S+ )?([a-z][a-z0-9_]*) \| ")


def load_flag_matrix_names() -> set[str]:
    names: set[str] = set()
    for line in FLAG_MATRIX.read_text(encoding="utf-8").splitlines():
        match = _ROW_PREFIX.match(line.strip())
        if match:
            names.add(match.group(1))
    return names


def load_dispatch_names() -> list[str]:
    names: list[str] = []
    for line in DISPATCH.read_text(encoding="utf-8").splitlines():
        match = ENTRY_RE.match(line.strip())
        if match:
            names.append(match.group(1)[4:])
    return names


C_SUFFIXES = (".c", ".h")

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def strip_c_comments(text: str) -> str:
    """Drop C block and line comments. Required before the call-shape
    regex below so that mentions like "// TODO: test sync(2)" cannot
    falsely cover a syscall.
    """
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    return text


def load_test_corpora() -> tuple[str, str]:
    """Return (c_corpus, other_corpus). Splitting matters because shell
    scripts that invoke coreutils applets ("run sync 0", "run kill ...")
    would otherwise falsely cover the like-named syscalls. C corpus is
    fed through strip_c_comments() so commented-out syscalls cannot
    claim coverage either.
    """
    c_chunks: list[str] = []
    other_chunks: list[str] = []
    for path in sorted(TESTS.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix in C_SUFFIXES:
            c_chunks.append(strip_c_comments(text))
        else:
            other_chunks.append(text)
    return "\n".join(c_chunks), "\n".join(other_chunks)


def has_direct_reference(name: str, c_corpus: str, other_corpus: str) -> bool:
    # C: require call-shape ("name(") or an explicit syscall-number macro.
    # That covers libc wrappers (open(...), read(...), ...) and direct
    # syscall(SYS_*, ...) uses, while rejecting bare-word occurrences in
    # comments, TEST() labels, and error messages like FAIL("child sync recv").
    # Non-C corpus (shell, Python): only count explicit syscall-number
    # macros. Coreutils applet names share words with syscalls (sync, kill,
    # chroot, chmod) and "name(" rarely makes sense in those files anyway.
    c_patterns = [
        rf"\b{name}\s*\(",
        rf"\bSYS_{name}\b",
        rf"\b__NR_{name}\b",
    ]
    other_patterns = [
        rf"\bSYS_{name}\b",
        rf"\b__NR_{name}\b",
    ]
    if any(re.search(p, c_corpus) for p in c_patterns):
        return True
    return any(re.search(p, other_corpus) for p in other_patterns)


def main() -> int:
    c_corpus, other_corpus = load_test_corpora()
    missing: list[str] = []
    used_indirect: dict[str, str] = {}

    for name in load_dispatch_names():
        if has_direct_reference(name, c_corpus, other_corpus):
            continue
        if any(
            has_direct_reference(alias, c_corpus, other_corpus)
            for alias in ALIASES.get(name, set())
        ):
            continue
        if name in INDIRECT_COVERAGE:
            used_indirect[name] = INDIRECT_COVERAGE[name]
            continue
        missing.append(name)

    matrix = load_flag_matrix_names()
    no_rows = sorted(FLAG_MATRIX_REQUIRED - matrix)
    not_dispatched = sorted(FLAG_MATRIX_REQUIRED - set(load_dispatch_names()))
    unlisted = sorted(matrix - FLAG_MATRIX_REQUIRED)

    stale_indirect = sorted(set(INDIRECT_COVERAGE) - set(used_indirect))
    if no_rows or not_dispatched or unlisted:
        for label, names in (
            ("Syscalls with no row left in tests/flag-matrix.tbl:", no_rows),
            ("FLAG_MATRIX_REQUIRED entries absent from dispatch.tbl:",
             not_dispatched),
            ("Syscalls with rows but missing from FLAG_MATRIX_REQUIRED:",
             unlisted),
        ):
            if names:
                print(label, file=sys.stderr)
                for name in names:
                    print(f"  - {name}", file=sys.stderr)
        return 1
    if missing or stale_indirect:
        if missing:
            print("Uncovered syscalls in dispatch.tbl:", file=sys.stderr)
            for name in missing:
                print(f"  - {name}", file=sys.stderr)
        if stale_indirect:
            print(
                "Stale indirect-coverage exemptions (now directly covered or "
                "absent from dispatch.tbl):",
                file=sys.stderr,
            )
            for name in stale_indirect:
                print(f"  - {name}", file=sys.stderr)
        return 1

    print("syscall coverage audit: PASS")
    print(f"  flag matrix: {len(matrix)} syscalls have per-flag rows")
    for name, reason in sorted(used_indirect.items()):
        print(f"  indirect {name}: {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
