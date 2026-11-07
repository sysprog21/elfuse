#!/usr/bin/env bash

# Reject staged defects that are cheap to find before CI.
#
# Everything here reads the staged content, not the working tree, so a partial
# "git add -p" is judged on what would actually be committed.
#
# A missing local formatter warns rather than blocks. A tool this machine does
# not have is not a defect in the change, and CI enforces both formatters
# regardless; turning that into a failed commit only teaches contributors to
# pass --no-verify, which costs the checks that do work.

set -uo pipefail

repo_root=$(git rev-parse --show-toplevel) || exit 1
cd "$repo_root" || exit 1

# The checkers come from beside the installed script, not from the worktree
# being committed to. Installed, $0 is the symlink under .git/hooks; a linked
# worktree on a branch that predates .ci/ would otherwise resolve them to paths
# that do not exist there and lose the checks without saying so.
hook_path=$0
while [ -L "$hook_path" ]; do
    hook_dir=$(cd -P "$(dirname "$hook_path")" && pwd)
    hook_path=$(readlink "$hook_path")
    case "$hook_path" in
        /*) ;;
        *) hook_path="$hook_dir/$hook_path" ;;
    esac
done
ci_dir=$(cd -P "$(dirname "$hook_path")/../.ci" 2> /dev/null && pwd)

if git diff --cached --quiet; then
    exit 0
fi

failed=0
staged_dir=
trap '[ -n "$staged_dir" ] && rm -rf "$staged_dir"' EXIT

# Bash 3.2 is what /usr/bin/env bash resolves to on a stock macOS, and there
# "${array[@]}" of an empty array is an unbound variable under set -u, while
# "${#array[@]}" is not. Every expansion below therefore sits behind a count
# test; a docs-only commit otherwise aborts on the first empty one.
#
# One pass, four sets, matching what each CI gate reads. Two of those gates read
# more than C: a commit touching only a shell script would otherwise stage
# nothing this hook looks at and reach CI unchecked, which is the opposite of
# the parity it advertises.
c_files=()
src_files=()
flow_files=()
sh_files=()
staged=()
while IFS= read -r -d '' file; do
    case "$file" in
        # Fixed benchmark input: formatting it would invalidate the baseline.
        tests/bench-corpus/*) continue ;;
        src/*.c | src/*.h)
            c_files+=("$file")
            src_files+=("$file")
            flow_files+=("$file")
            ;;
        tests/*.c | tests/*.h)
            c_files+=("$file")
            flow_files+=("$file")
            ;;

        # Reflowed by .ci/check-commentflow.sh but not formatted by
        # .ci/check-format.sh, so these reach one gate and not the other.
        frama-c-stubs/*.h) flow_files+=("$file") ;;
        *.s | *.S | *.sh | *.bash) flow_files+=("$file") ;;
    esac
    case "$file" in
        .ci/*.sh | scripts/*.sh) sh_files+=("$file") ;;
    esac
done < <(git diff --cached --name-only -z --diff-filter=ACMR)

staged+=("${c_files[@]+"${c_files[@]}"}")
staged+=("${flow_files[@]+"${flow_files[@]}"}")
staged+=("${sh_files[@]+"${sh_files[@]}"}")

if [ "${#staged[@]}" -gt 0 ]; then
    staged_dir=$(mktemp -d) || exit 1

    # .clang-format comes out of the index too. Staged alongside a C change, the
    # working-tree copy is a different style than the one being committed, and
    # the hook would judge the change against a rule the commit does not carry.
    if ! printf '%s\0' "${staged[@]}" \
        | git checkout-index --stdin -z -f --prefix="$staged_dir/"; then
        echo "Cannot read the staged content." >&2
        exit 1
    fi

    # Tracked, it comes out of the index like everything else. Untracked, the
    # worktree copy is all there is, and a repository that does not carry one at
    # all is not an error here: clang-format falls back to its own default and
    # CI is the authority either way.
    if git ls-files --error-unmatch .clang-format > /dev/null 2>&1; then
        printf '%s\0' .clang-format \
            | git checkout-index --stdin -z -f --prefix="$staged_dir/"
    elif [ -e .clang-format ]; then
        cp .clang-format "$staged_dir/"
    fi

    # The version gate, the patterns and the diff all live in .ci/, and this
    # runs them there rather than carrying a second copy that drifts. Each is
    # given the extracted index so it sees staged content, from a working
    # directory that keeps its diagnostics naming src/foo.c and not a temp path.
    #
    # Both checkers separate "these files are wrong" from "this check could not
    # run", so which clang-format counts stays check-format.sh's answer alone.
    # Asking again here is the duplication being removed, and asking only
    # whether some clang-format exists gets the version case wrong: an unpinned
    # one on PATH would block every C commit over a formatter the author does
    # not have rather than over anything they wrote. Absent .ci, both checks
    # below are unreachable. Say so: skipping quietly and then printing that the
    # staged checks passed is the failure mode this hook exists to prevent, and
    # it is the one an author cannot see.
    if [ -z "$ci_dir" ] && [ "${#c_files[@]}" -gt 0 ]; then
        echo "note: no .ci beside $hook_path; format and API checks skipped." >&2
    fi

    if [ "${#c_files[@]}" -gt 0 ] && [ -n "$ci_dir" ]; then
        status=0
        (cd "$staged_dir" && "$ci_dir/check-format.sh" "${c_files[@]}") \
            || status=$?
        if [ "$status" -eq 1 ]; then
            failed=1
        elif [ "$status" -ne 0 ]; then
            echo "note: format check skipped, commit not blocked; CI runs it." >&2
        fi
    fi

    if [ "${#src_files[@]}" -gt 0 ] && [ -n "$ci_dir" ]; then
        if ! (cd "$staged_dir" \
            && "$ci_dir/check-security.sh" "${src_files[@]}"); then
            failed=1
        fi
    fi

    if [ "${#sh_files[@]}" -gt 0 ]; then
        if ! command -v shellcheck > /dev/null 2>&1; then
            echo "note: shellcheck not found, skipping shell check." >&2
        elif ! (cd "$staged_dir" \
            && shellcheck --severity=warning "${sh_files[@]}"); then
            failed=1
        fi
    fi

    # Exit 1 is "these files would change"; anything else is the tool failing to
    # read them, which .ci/check-commentflow.sh is careful never to report as a
    # style violation. Same discipline here: a parse error that reads as bad
    # style sends the author to reformat code that was already fine.
    commentflow=${COMMENTFLOW:-commentflow}
    if [ "${#flow_files[@]}" -eq 0 ]; then
        :
    elif ! command -v "$commentflow" > /dev/null 2>&1; then
        echo "note: commentflow not found, skipping comment reflow check." >&2
    else
        status=0
        "$commentflow" --check "${flow_files[@]/#/$staged_dir/}" || status=$?
        if [ "$status" -eq 1 ]; then
            echo "Staged comments need reflowing; run 'make indent'." >&2
            failed=1
        elif [ "$status" -ne 0 ]; then
            echo "note: $commentflow exited $status (I/O or parse error)." >&2
        fi
    fi
fi

# Covers trailing whitespace, space-before-tab, and leftover conflict markers,
# each reported as file:line. A hand-rolled conflict-marker grep only repeats
# this, and repeating it through a pipe into "grep -q" under pipefail makes it
# fail open: grep exits at the first match, git takes SIGPIPE, the pipeline
# reports 141, and the caller reads that as "clean" on exactly the large diffs
# worth checking.
if ! git diff --cached --check; then
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "Staged checks passed. Commit-message rules run next; use the body for what and why."
