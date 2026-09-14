#!/usr/bin/env bash

# Exercise the commit-message rules against messages that must pass and must
# fail. Every case below is a regression that was live at some point: a hook
# that rejects a merge aborts the merge halfway, and one that lints the diff
# "git commit -v" appends rejects a message that is fine.
#
# Runs the hook under /bin/bash as well when that shell is older than 4.4,
# because a stock macOS resolves "/usr/bin/env bash" there and empty arrays
# under set -u behave differently.
#
# Messages go in through "-", the same door the pre-push hook and the CI
# commit-log gate use, and not through /dev/stdin. That path exists precisely
# because a minimal container need not carry that device, so a test written
# against it exercises the branch nothing else takes and breaks where the branch
# it skipped was written to work.

set -uo pipefail

script_dir=$(cd -P "$(dirname "$0")" && pwd)
hook="$script_dir/git-commit-msg.sh"
failures=0
checks=0

# expect_ok <name> <message>
expect_ok()
{
    checks=$((checks + 1))
    local out
    if ! out=$(printf '%s' "$2" | "$hook" - 2>&1); then
        printf 'FAIL (rejected, should pass): %s\n      %s\n' "$1" "$out" >&2
        failures=$((failures + 1))
    fi
}

# expect_fail <name> <message> <expected diagnostic substring>
expect_fail()
{
    checks=$((checks + 1))
    local out
    if out=$(printf '%s' "$2" | "$hook" - 2>&1); then
        printf 'FAIL (accepted, should reject): %s\n' "$1" >&2
        failures=$((failures + 1))
    elif [ "${out#*"$3"}" = "$out" ]; then
        printf 'FAIL (wrong reason): %s\n      wanted %s, got %s\n' "$1" "$3" "$out" >&2
        failures=$((failures + 1))
    fi
}

expect_ok 'plain subject' 'Add a syscall'
expect_ok 'subject and body' 'Add a syscall

Explain the problem this solves.
'
expect_ok 'exactly 50 characters' 'Reject a syscall that outlives its own page tables'
expect_ok 'one parenthesized group' 'Route main() error paths through one label'
expect_ok 'pull-request reference' 'Implement times syscall (#199)'
expect_ok 'verb absent from the mood list' 'Wire the epoll wakeup pipe'

# git composes these itself; rejecting a merge subject aborts the merge.
expect_ok 'merge subject over 50' 'Merge pull request #311 from sysprog21/contributing'
expect_ok 'revert subject' 'Revert "Gate comment width in make and CI"

This reverts commit 047b59c.
'
expect_ok 'fixup subject' 'fixup! Add a syscall'

# "Merge " also starts an ordinary imperative subject, so the exemption names
# the forms git writes rather than the word they share.
expect_fail 'hand-written merge subject' 'Merge the free lists into one.' \
    'end with a period'

# "git commit -v" puts the diff below a scissors line, uncommented. Linting it
# fails on width, on ASCII, and on whatever else the diff happens to contain.
expect_ok 'verbose commit diff is ignored' 'Add a syscall

Short body.
# ------------------------ >8 ------------------------
# Do not modify or remove the line above.
diff --git a/src/big.c b/src/big.c
+an added line considerably wider than seventy two characters, as diffs are
'

# The subject, second line and body are split with parameter expansion rather
# than three sed calls, so the shapes that expansion gets wrong are worth
# pinning: no trailing newline, no body at all, and a blank line that is the
# whole body.
expect_ok 'no trailing newline' 'Add a syscall'
expect_ok 'trailing blank line only' 'Add a syscall

'
expect_ok 'body line exactly 72' 'Add a syscall

123456789012345678901234567890123456789012345678901234567890123456789012
'
expect_fail 'tab inside the subject' 'Add	a	syscall' 'printable ASCII'

expect_fail 'empty' '' 'descriptive subject'
expect_fail 'body line 73' 'Add a syscall

1234567890123456789012345678901234567890123456789012345678901234567890123
' 'exceed 72'
expect_fail 'single word' 'Fix' 'more than one word'
expect_fail '51 characters' 'Reject a syscall that outlives its own page tables!' 'exceeds 50'
expect_fail 'lowercase start' 'add a syscall' 'capital letter'

# Rule 3 decides the case of the first letter with a glob range, and a range
# follows LC_COLLATE rather than ASCII. Only a locale that interleaves the cases
# puts a capital inside [a-z], and a UTF-8 charmap alone does not say that: a
# C.UTF-8 keeps the C collation and takes the same branch the C locale does. Ask
# each candidate whether "A" falls in the range, put the accepted subject to the
# ones that say yes, and say so when no candidate does.
locale_legs=0
for locale_name in $(locale -a 2>/dev/null | grep -i 'utf-*8$'); do
    (
        export LC_ALL="$locale_name"
        # The constant subject is the point: ask where this locale sorts "A".
        # shellcheck disable=SC2194
        case A in [a-z]) exit 0 ;; esac
        exit 1
    ) || continue
    checks=$((checks + 1))
    locale_legs=$((locale_legs + 1))
    if ! locale_out=$(printf 'Add a syscall' | LC_ALL="$locale_name" "$hook" - 2>&1); then
        printf 'FAIL (rejected under %s): %s\n' "$locale_name" "$locale_out" >&2
        failures=$((failures + 1))
    fi
    [ "$locale_legs" -lt 8 ] || break
done
if [ "$locale_legs" -eq 0 ]; then
    echo 'note: no UTF-8 locale here collates a capital into [a-z]' >&2
fi
expect_fail 'trailing period' 'Add a syscall.' 'end with a period'
expect_fail 'past tense' 'Added a syscall' 'imperative mood'
expect_fail 'gerund' 'Adding a syscall' 'imperative mood'
expect_fail 'conventional commit' 'fs: skip procfs symlinks' 'conventional-commit'
# The backticks below are the input under test, not a substitution.
# shellcheck disable=SC2016
expect_fail 'backtick' 'Add `sys_mmap` handling' 'backticks'
expect_fail 'excessive parentheses' 'Add mmap(2) and mprotect(2) here' 'overuses parentheses'
expect_fail 'non-ASCII' 'Add a syscall and an em dash '$'—''here' 'printable ASCII'
expect_fail 'no blank line' 'Add a syscall
Body on the second line.
' 'blank line'
expect_fail 'body over 72' 'Add a syscall

This body line is quite deliberately wider than the seventy-two column limit.
' 'exceed 72'
for scheme in http https ftp git s3; do
    expect_ok "$scheme URL on a line of its own" "Add a syscall

$scheme://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
"
done
expect_ok 'normal message with a URL reference' 'Add a syscall

The guest calls it during startup and stops when it gets ENOSYS back,
so every program built against a newer libc exits before reaching main.

See https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
'
expect_ok 'URL in parentheses ending a wide line' 'Add a syscall

See the thread (https://github.com/sysprog21/elfuse/issues/187#issuecomment-12345678).
'
expect_ok 'URL starting at column 73' 'Add a syscall

12345678901234567890123456789012345678901234567890123456789012345678901 https://x.y/z
'
expect_fail 'prose through column 72 before a URL' 'Add a syscall

123456789012345678901234567890123456789012345678901234567890123456789012 https://x.y/z
' 'exceed 72'
expect_fail 'prose after a wide URL' 'Add a syscall

See https://github.com/sysprog21/elfuse/issues/187#issuecomment-1234567890 here
' 'exceed 72'
expect_fail 'wide prose after a URL line' 'Add a syscall

https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
This body line is quite deliberately wider than the seventy-two column limit.
' 'exceed 72'
expect_fail 'wide path without a scheme' 'Add a syscall

www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes
' 'exceed 72'
expect_fail 'body describes how' 'Add a syscall

How: it calls into the dispatch table.
' 'what and why'

# The pre-commit hook must survive a commit that stages no C at all. What breaks
# is an unguarded empty-array expansion under set -u, which only bash 3.2
# rejects, and only a stock macOS still resolves "/usr/bin/env bash" to one. On
# a Linux runner both names below are the same bash 5 binary, so running them
# both is a duplicate rather than the coverage it resembles. Dedupe by resolved
# path: one pass reported honestly beats two that are the same pass counted
# twice.
seen_shells=
for shell in /bin/bash bash; do
    resolved=$(command -v "$shell" 2> /dev/null) || continue
    resolved=$(cd -P "$(dirname "$resolved")" 2> /dev/null && printf '%s/%s' "$(pwd)" "${resolved##*/}")
    case " $seen_shells " in
        *" $resolved "*) continue ;;
    esac
    seen_shells="$seen_shells $resolved"
    checks=$((checks + 1))
    tmp=$(mktemp -d) || exit 1
    if ! (
        cd "$tmp" || exit 1
        git init -q . && git config user.email t@t && git config user.name T
        cp "$script_dir/../.clang-format" . 2> /dev/null
        echo doc > README.md
        git add README.md
        "$shell" "$script_dir/git-pre-commit.sh" > /dev/null
    ); then
        printf 'FAIL: pre-commit on a docs-only change under %s (%s)\n' \
            "$shell" "$("$shell" --version | head -1)" >&2
        failures=$((failures + 1))
    fi
    rm -rf "$tmp"
done

# Pushing a branch to a remote that has no tracking refs yet, which is what a
# freshly added fork looks like. The boundary "everything not already published"
# excludes nothing there, so the walk reaches the root commit: the hook must not
# judge a history it was handed rather than one the author wrote.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q --bare origin.git
    git init -q --bare fork.git
    git init -q work && cd work || exit 1
    git config user.email t@t && git config user.name T
    git remote add origin ../origin.git
    git remote add fork ../fork.git
    cp -R "$script_dir/../scripts" .

    # Published history the author did not write, and would not be able to fix.
    git commit -q --allow-empty -m "Added a thing badly." --no-verify
    git push -q origin HEAD:refs/heads/main
    git fetch -q origin

    # One clean commit of their own, pushed to a fork that has seen nothing.
    git commit -q --allow-empty -m "Add a clean thing" --no-verify
    ./scripts/install-git-hooks.sh --quiet
    git push -q fork HEAD:refs/heads/topic
) > /dev/null 2>&1; then
    echo 'FAIL: pushing to a fresh remote judges history the author did not write' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# A force-push can advertise a remote tip the local repository has never
# fetched. Reject the push instead of treating a failed revision walk as an
# empty range.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q --bare remote.git
    git init -q work && cd work || exit 1
    git config user.email t@t && git config user.name T
    git remote add origin ../remote.git
    cp -R "$script_dir/../scripts" . && cp "$script_dir/../.clang-format" .
    ./scripts/install-git-hooks.sh --quiet

    git commit -q --allow-empty -m "Add base"
    git push -q origin HEAD:refs/heads/main
    git branch stale
    git clone -q ../remote.git writer && cd writer || exit 1
    git config user.email t@t && git config user.name T
    git checkout -q -b main origin/main

    # The setup has to succeed, or the force-push below is rejected for its
    # message and this check passes without the unavailable tip ever existing.
    git commit -q --allow-empty -m "Add remote change" || exit 1
    git push -q origin HEAD:refs/heads/main || exit 1

    # "$tmp", not "..": the clone above put writer inside work, so a single
    # level up is still work and every "git -C work" below would fail with
    # "cannot change to work". Negated, that failure reads as the push having
    # been rejected, and the check passes without the hook running at all.
    cd "$tmp" && git -C work checkout -q stale
    git -C work commit -q --allow-empty -m "Added an invalid message" --no-verify
    ! git -C work push -q --force origin HEAD:refs/heads/main
) > /dev/null 2>&1; then
    echo 'FAIL: force-push with an unavailable remote tip bypasses pre-push' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# An unpinned clang-format on PATH must not block a commit. The hook delegates
# the version gate to .ci/check-format.sh, so the two answers it can get back,
# "this file is wrong" and "I could not run", have to stay distinguishable; a
# hook that conflates them rejects a correctly formatted file over a formatter
# the author happens to have.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1

    # An isolated PATH, not a prefix. A runner with the pinned formatter in
    # /usr/bin has check-format.sh select that one before ever reaching the
    # fake, and the case under test never runs. Everything else the hook needs
    # is linked in; only clang-format is withheld.
    mkdir -p fakebin
    for dir in /usr/bin /bin /usr/local/bin /opt/homebrew/bin; do
        [ -d "$dir" ] || continue
        for tool in "$dir"/*; do
            case "${tool##*/}" in
                clang-format*) continue ;;
            esac
            [ -x "$tool" ] || continue
            ln -sf "$tool" "fakebin/${tool##*/}" 2> /dev/null
        done
    done
    printf '#!/bin/sh\necho "clang-format version 18.1.0"\n' > fakebin/clang-format
    chmod +x fakebin/clang-format

    git init -q . && git config user.email t@t && git config user.name T
    mkdir -p src .ci scripts
    cp "$script_dir/../.ci/check-format.sh" "$script_dir/../.ci/check-security.sh" .ci/
    cp "$script_dir/git-pre-commit.sh" scripts/
    cp "$script_dir/../.clang-format" .
    printf 'int main(void)\n{\n    return 0;\n}\n' > src/ok.c
    git add src/ok.c
    # The isolation is the whole fixture, so assert it rather than assume it.
    ! PATH="$tmp/fakebin" command -v clang-format-22 > /dev/null 2>&1 || exit 1
    PATH="$tmp/fakebin" bash scripts/git-pre-commit.sh
) > /dev/null 2>&1; then
    echo 'FAIL: an unpinned clang-format blocks the commit' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# Through the installed symlinks, not by calling the scripts where they live.
# The two shapes differ: installed, $0 is the link under .git/hooks, so a hook
# resolving a sibling script from "dirname $0" looks in the wrong directory and
# only fails once someone actually commits. Direct invocation never sees it.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q --bare remote.git
    git init -q work && cd work || exit 1
    git config user.email t@t && git config user.name T
    git remote add origin ../remote.git
    cp -R "$script_dir/../scripts" . && cp "$script_dir/../.clang-format" .
    ./scripts/install-git-hooks.sh --quiet

    echo doc > README.md && git add README.md
    # Rejected by commit-msg, so nothing lands.
    git commit -q -m "Added a doc." > /dev/null 2>&1 && exit 1
    git commit -q -m "Add a doc" > /dev/null 2>&1 || exit 1

    # Pre-push has to find check-commit-log.sh from the installed symlink.
    git commit -q --allow-empty -m "Add another doc" > /dev/null 2>&1 || exit 1
    git push -q origin HEAD:refs/heads/probe > /dev/null 2>&1 || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: hooks do not work through the installed symlinks' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# Hooks installed from the primary worktree run when an older linked worktree
# lacks the checker. The link must resolve the helper beside its own source.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q --bare remote.git
    git init -q primary && cd primary || exit 1
    git config user.email t@t && git config user.name T
    echo base > README.md && git add README.md
    git commit -q -m "Add base"
    git branch old
    cp -R "$script_dir/../scripts" . && cp "$script_dir/../.clang-format" .
    ./scripts/install-git-hooks.sh --quiet
    git worktree add -q ../linked old
    cd ../linked || exit 1
    git remote add origin ../remote.git

    echo doc > linked.md && git add linked.md
    git commit -q -m "Add linked doc" > /dev/null 2>&1 || exit 1

    # A clean push succeeds whether or not a hook ran, so the assertion is the
    # rejection: this commit reaches the remote only if pre-push failed to
    # resolve check-commit-log.sh beside the script the symlink points at.
    git commit -q --allow-empty -m "Added a bad subject" --no-verify
    ! git push -q origin HEAD:refs/heads/old > /dev/null 2>&1 || exit 1
    git reset -q --hard HEAD~1
    git push -q origin HEAD:refs/heads/old > /dev/null 2>&1 || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: pre-push cannot use the primary worktree checker' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# A linked worktree can carry these scripts before the primary worktree does.
# Its installation still has to enumerate its own scripts and run pre-push.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q --bare remote.git
    git init -q primary && cd primary || exit 1
    git config user.email t@t && git config user.name T
    echo base > README.md && git add README.md
    git commit -q -m "Add base"
    git branch old
    git worktree add -q ../linked
    cd ../linked || exit 1
    git remote add origin ../remote.git
    cp -R "$script_dir/../scripts" . && mkdir mk
    cp "$script_dir/../mk/common.mk" mk/

    make -sn -f mk/common.mk BUILD_DIR=build build/.hooks-installed > /dev/null
    [ ! -e build/.hooks-installed ] || exit 1
    [ ! -e "$(git rev-parse --git-path hooks)/pre-push" ] || exit 1
    ! make -sq -f mk/common.mk BUILD_DIR=build build/.hooks-installed
    [ ! -e build/.hooks-installed ] || exit 1
    [ ! -e "$(git rev-parse --git-path hooks)/pre-push" ] || exit 1
    make -s -f mk/common.mk BUILD_DIR=build build/.hooks-installed
    [ -e build/.hooks-installed ] || exit 1
    [ -L "$(git rev-parse --git-path hooks)/commit-msg" ] || exit 1

    # The stamp only says the target ran. What has to be true is that the hooks
    # it linked are live in this worktree, and a commit that must be refused is
    # the only thing that shows it.
    echo doc > linked.md && git add linked.md
    ! git commit -q -m "Added a bad subject" > /dev/null 2>&1 || exit 1
    git commit -q -m "Add linked doc" > /dev/null 2>&1 || exit 1
    git push -q origin HEAD:refs/heads/linked > /dev/null 2>&1 || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: hooks do not install from a linked worktree' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# git strips comments with core.commentChar, not with "#". Written with the
# wrong one, the guidance survives into the message and becomes the subject.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q . && git config user.email t@t && git config user.name T
    git config core.commentChar ";"
    : > msg
    "$script_dir/git-prepare-commit-msg.sh" msg
    [ -z "$(git stripspace --strip-comments < msg)" ] || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: the message template ignores core.commentChar' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# "git commit -v" has appended the diff by the time prepare-commit-msg runs. The
# rules still have to reach the buffer, and above the scissors line, since git
# drops everything below it along with the diff.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q . && git config user.email t@t && git config user.name T
    {
        printf '\n# Please enter the commit message.\n'
        printf '# ------------------------ >8 ------------------------\n'
        printf 'diff --git a/a b/a\n+a line the message must not be judged on\n'
    } > msg
    "$script_dir/git-prepare-commit-msg.sh" msg
    grep -q 'Commit rules' msg || exit 1
    [ "$(grep -n 'Commit rules' msg | sed -n '1s/:.*//p')" \
        -lt "$(grep -n '>8' msg | sed -n '1s/:.*//p')" ] || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: the rules never reach a "git commit -v" buffer' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# The format gate separates "this file is wrong" from "I could not read it", or
# the pre-commit hook blocks a commit over a path it failed to extract.
checks=$((checks + 1))
status=0
"$script_dir/../.ci/check-format.sh" no-such-file.c > /dev/null 2>&1 || status=$?
if [ "$status" -ne 2 ]; then
    printf 'FAIL: the format check reports %d, not 2, on a path it cannot read\n' \
        "$status" >&2
    failures=$((failures + 1))
fi

# A staged shell script reaches the same gates CI runs it through. Before, an
# all-shell commit staged nothing the hook looked at.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    command -v shellcheck > /dev/null 2>&1 || exit 0
    git init -q . && git config user.email t@t && git config user.name T
    mkdir -p scripts .ci
    cp "$script_dir/git-pre-commit.sh" scripts/
    cp "$script_dir/../.ci/check-format.sh" "$script_dir/../.ci/check-security.sh" .ci/
    printf '#!/bin/sh\nunused_variable=2\n' > scripts/thing.sh
    git add scripts/thing.sh
    ! bash scripts/git-pre-commit.sh > /dev/null 2>&1 || exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: a staged shell script bypasses the pre-commit checks' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# A path with a space in it, and a hook whose script a branch later removes. The
# first truncated the worktree path; the second stranded the link, because the
# name was only ever read from the script that had gone.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    mkdir -p "$tmp/with space" && cd "$tmp/with space" || exit 1
    git init -q repo && cd repo || exit 1
    git config user.email t@t && git config user.name T
    mkdir scripts && cp "$script_dir"/git-*.sh "$script_dir/install-git-hooks.sh" scripts/
    ./scripts/install-git-hooks.sh --quiet
    hooks=$(git rev-parse --path-format=absolute --git-path hooks)

    # pwd -P: mktemp hands back a /var path that resolves to /private/var on
    # macOS, and the installer records the resolved one.
    here=$(pwd -P)
    [ "$(readlink "$hooks/pre-push")" = "$here/scripts/git-pre-push.sh" ] || exit 1

    # Installing from a linked worktree is where the primary path has to survive
    # intact. With it truncated at the space the link still lands somewhere
    # plausible, because the missing source falls back to the invoking worktree,
    # so only this arrangement tells the two apart.
    git commit -q --allow-empty -m "Add base" --no-verify
    git worktree add -q ../linked -b linked
    cp -R scripts "../linked/scripts"

    # Uninstall first, or the install below reports KEEP for links the primary
    # already made and the assertion passes without the linked path deciding
    # anything.
    ./scripts/install-git-hooks.sh --uninstall > /dev/null
    (cd ../linked && ./scripts/install-git-hooks.sh --quiet)
    [ "$(readlink "$hooks/pre-push")" = "$here/scripts/git-pre-push.sh" ] || exit 1
    ./scripts/install-git-hooks.sh --uninstall > /dev/null
    rm -rf ../linked
    git worktree prune
    ./scripts/install-git-hooks.sh --quiet

    rm scripts/git-prepare-commit-msg.sh
    ./scripts/install-git-hooks.sh --uninstall > /dev/null
    for left in "$hooks"/commit-msg "$hooks"/pre-commit "$hooks"/pre-push \
        "$hooks"/prepare-commit-msg; do
        [ ! -e "$left" ] && [ ! -L "$left" ] || exit 1
    done
) > /dev/null 2>&1; then
    echo 'FAIL: install or uninstall mishandles spaces or a removed script' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

# A security gate that cannot read what it was asked to scan must not report
# that the scan was clean.
checks=$((checks + 1))
if "$script_dir/../.ci/check-security.sh" no-such-file.c > /dev/null 2>&1; then
    echo 'FAIL: the security check passes on a path it cannot read' >&2
    failures=$((failures + 1))
fi

# A hook that cannot reach the .ci checkers must say so. Skipping them quietly
# and then reporting that the staged checks passed is the one failure this hook
# exists to prevent, and the author has no way to see it.
checks=$((checks + 1))
tmp=$(mktemp -d) || exit 1
if ! (
    cd "$tmp" || exit 1
    git init -q . && git config user.email t@t && git config user.name T
    mkdir -p scripts src
    cp "$script_dir/git-pre-commit.sh" scripts/
    cp "$script_dir/../.clang-format" .
    printf '#include <string.h>\nvoid f(char *d, const char *s)\n{\n    strcpy(d, s);\n}\n' \
        > src/bad.c
    git add src/bad.c

    # Captured, not piped into "grep -q": under pipefail an early grep exit
    # leaves the hook writing into a closed pipe, and the 141 that comes back
    # would fail this check on the run where the note was actually printed.
    out=$(bash scripts/git-pre-commit.sh 2>&1)

    # Ending the subshell on the case, rather than on a plain command, is what
    # shfmt 3.13 mis-prints: it drops the ";" before "then" and leaves a script
    # that no longer parses. Spelling the verdict out keeps the reformat stable.
    case "$out" in
        *"format and API checks skipped"*) exit 0 ;;
    esac
    exit 1
) > /dev/null 2>&1; then
    echo 'FAIL: unreachable .ci checkers are skipped without a word' >&2
    failures=$((failures + 1))
fi
rm -rf "$tmp"

if [ "$failures" -ne 0 ]; then
    printf '%d of %d hook checks failed.\n' "$failures" "$checks" >&2
    exit 1
fi

printf 'All %d hook checks passed.\n' "$checks"
