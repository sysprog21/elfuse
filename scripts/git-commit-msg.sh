#!/usr/bin/env bash

# Enforce the commit-message rules CONTRIBUTING.md states, so a message is
# rejected while it is still cheap to rewrite.
#
# Every check below traces to a numbered rule in the "Git Commit Style" section.
# A rule that cannot be decided mechanically is not guessed at: the
# imperative-mood and what-and-why checks look for the forms that are wrong
# beyond argument and let everything else through. Both were calibrated against
# 400 commits of this repository's history and rejected none of them.
#
# The expensive failure here is a false rejection, not a missed one. CI runs the
# same script over a pull request's commits, so a message that slips past a
# contributor without hooks installed is still caught before it merges.

set -uo pipefail

# Every rule below is defined over printable ASCII, and a glob range or a
# bracket expression follows LC_COLLATE instead. Decide them all in C.
export LC_ALL=C

message_file=$1

# "-" reads standard input. The hook itself is always handed a real path, but
# the commit-log gate feeds whole messages through this script, and routing
# those through /dev/stdin assumes a device that a minimal container need not
# have. Where it is missing the read yields nothing and every commit is rejected
# for want of a subject, which is a failure mode a check must not have.
if [ "$message_file" = "-" ]; then
    message_file=$(mktemp) || exit 1
    trap 'rm -f "$message_file"' EXIT
    cat > "$message_file"
fi

# "git commit -v" appends the diff below a scissors line, and those lines are
# not comment-prefixed. git strips them itself, but only after this hook has
# run, so without cutting them here every verbose commit gets linted against its
# own diff and fails on line width.
message=$(sed '/-\{8,\}[[:space:]]*>8[[:space:]]*-\{8,\}/,$d' "$message_file" \
    | git stripspace --strip-comments)
subject=${message%%$'\n'*}
body=
second=
if [ "$message" != "$subject" ]; then
    body=${message#*$'\n'}
    second=${body%%$'\n'*}
fi
failed=0

error()
{
    printf 'Commit message: %s\n' "$1" >&2
    failed=1
}

# Messages git composes itself. A merge subject names the branch and routinely
# runs past 50 characters, and rejecting one aborts the merge halfway; the fixup
# and squash forms are consumed by rebase and never reach history.
#
# The merge forms are spelled out rather than matched as "Merge ", which is also
# how an ordinary imperative subject starts: "Merge the free lists into one" is
# a sentence this gate has to read, and under the looser pattern it skipped
# every rule below, in the hook and in CI alike.
case "$subject" in
    fixup!\ * | squash!\ *) exit 0 ;;
    Merge\ branch\ * | Merge\ branches\ * | Merge\ tag\ * | Merge\ commit\ * | \
        Merge\ pull\ request\ * | Merge\ remote-tracking\ branch\ *) exit 0 ;;
esac

# Rule 2, plus the additional rule against single-word commits.
if [ -z "$subject" ]; then
    error "a descriptive subject is required"
elif [ "${#subject}" -gt 50 ]; then
    error "subject exceeds 50 characters"
else
    case "$subject" in
        *[[:space:]]*) ;;
        *) error "subject must contain more than one word" ;;
    esac
fi

# The range is printable ASCII, so this catches a tab and a stray control byte
# as well as anything above 0x7f. Saying "ASCII" alone would misname the first
# two, which are ASCII and still unwanted.
if LC_ALL=C grep -q '[^ -~]' <<< "$message"; then
    error "message must be printable ASCII, with no tabs or control characters"
fi

# Rule 3.
case "$subject" in
    [[:space:]]*) error "subject must not start with whitespace" ;;
    [a-z]*) error "subject must start with a capital letter" ;;
esac

# Rule 4.
case "$subject" in
    *.) error "subject must not end with a period" ;;
esac

# Rule 5. Only the past-tense, third-person and gerund forms are listed. A verb
# absent from this list is accepted, which is the safe direction to be wrong in.
first_word=$(printf '%s' "${subject%%[[:space:]]*}" | tr '[:upper:]' '[:lower:]')
case "$first_word" in
    added | adds | adding | adjusted | adjusts | adjusting | amended | amends | \
        amending | avoided | avoids | avoiding | bumped | bumps | bumping | \
        changed | changes | changing | checked | checks | checking | committed | \
        commits | committing | copied | copies | copying | corrected | corrects | \
        correcting | created | creates | creating | decreased | decreases | \
        decreasing | deleted | deletes | deleting | disabled | disables | disabling | \
        dropped | drops | dropping | duplicated | duplicates | duplicating | \
        enabled | enables | enabling | excluded | excludes | excluding | fixed | \
        fixes | fixing | handled | handles | handling | implemented | implements | \
        implementing | improved | improves | improving | included | includes | \
        including | increased | increases | increasing | installed | installs | \
        installing | introduced | introduces | introducing | merged | merges | \
        merging | moved | moves | moving | pruned | prunes | pruning | refactored | \
        refactors | refactoring | released | releases | releasing | removed | \
        removes | removing | renamed | renames | renaming | replaced | replaces | \
        replacing | resolved | resolves | resolving | reverted | reverts | \
        reverting | showed | shows | showing | tested | tests | testing | tidied | \
        tidies | tidying | updated | updates | updating | used | uses | using)
        error "subject must use the imperative mood"
        ;;
esac

# A scope prefix hides the real subject behind a tag, which defeats rules 3 and
# 5 for the words that matter. The four commits in history using this form all
# predate the current style.
if [[ $subject =~ ^[[:alpha:]]+(\!|\([^\)]*\))?:[[:space:]] ]]; then
    error "subject must not use conventional-commit syntax"
fi

# Backticks are confusable with single quotes on some terminals, so they are
# refused outright. Parentheses are not: CONTRIBUTING objects to excessive use,
# and a subject naming main() or times(2) or a pull-request number carries one
# pair for a reason. Two pairs is where a subject starts reading as clutter.
case "$subject" in
    *\`*) error "subject must not contain backticks" ;;
esac

opens=${subject//[^(]/}
if [ "${#opens}" -gt 1 ]; then
    error "subject overuses parentheses"
fi

# Rule 1. An empty second line is what separates them, so a non-empty one with
# anything following is a run-together subject and body.
if [ -n "$body" ] && [ -n "$second" ]; then
    error "separate the subject from the body with a blank line"
fi

# Rule 6, except where everything past column 72 is part of one word containing
# a URL. Only the first 72 characters are searched for where that word begins,
# because ##*[[:space:]] over the whole line is quadratic in its length.
while IFS= read -r line; do
    [ "${#line}" -gt 72 ] || continue
    head=${line:0:72}
    case "${head##*[[:space:]]}${line:72}" in
        *[[:space:]]*) ;;
        *[[:alnum:]]://?*) continue ;;
    esac
    error "body lines must not exceed 72 characters"
    break
done <<< "$body"

# Rule 7, in the one form that can be decided by looking: a body that opens a
# section announcing it is about to describe the mechanism. A regex, where the
# checks above are globs, because this one is genuinely alternation over words
# and spelling that out as a case is less legible than the pattern it replaces.
if grep -qiE '^(how|implementation( (details|notes|steps))?|steps?)[[:space:]]*:' <<< "$body"; then
    error "body must explain what and why, not how"
fi

exit "$failed"
