#!/usr/bin/env bash
# elfuse oci run compatibility / end-to-end smoke tests
#
# Default mode (always runs):
#   - CLI surface smokes (--help, missing IMAGE, no-pin ref)
#   - Fixture-builder integration: assemble a tiny store from a single
#     uncompressed-tar layer, verify the resulting blob count and that
#     elfuse oci inspect can render the runtime block
#
# Heavy mode (OCI_COMPAT_TEST=1):
#   - alpine-shaped, busybox-shaped, two-layer-whiteout fixtures,
#     each driven end-to-end through elfuse oci run.
#     Requires a case-sensitive APFS sysroot volume; the suite skips
#     the actual launch unless OCI_COMPAT_TEST=1 is set in the
#     environment to gate the hdiutil-attach + run path.
#
# Online mode (OCI_FETCH_ONLINE=1):
#   - Pulls docker.io/library/alpine:3 (a multi-arch tag pinning to an
#     OCI image index) from the real registry into a scratch store,
#     runs `elfuse oci run alpine:3 /bin/busybox echo elfuse-online-ok`,
#     asserts rc=0 and the verbatim stdout line. Regression anchor for
#     the oci_run index-walk fix. Not in `make check` (requires
#     network access).
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${ROOT}/build"
ELFUSE="${BUILD}/elfuse"
BUILDER="${BUILD}/oci-fixture-builder"

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
RESET=$'\033[0m'

PASS=0
FAIL=0

ok()   { printf "  ${GREEN}OK${RESET}   %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  ${RED}FAIL${RESET} %s: %s\n" "$1" "$2"; FAIL=$((FAIL+1)); }
skip() { printf "  ${YELLOW}SKIP${RESET} %s: %s\n" "$1" "$2"; }

if [ ! -x "${ELFUSE}" ]; then
    echo "error: ${ELFUSE} not built; run 'make elfuse' first" >&2
    exit 1
fi
if [ ! -x "${BUILDER}" ]; then
    echo "error: ${BUILDER} not built; run 'make oci-fixture-builder' first" >&2
    exit 1
fi

SCRATCH=$(mktemp -d /tmp/elfuse-compat-XXXXXX)
# Track the heavy-mode hdiutil mountpoint so the EXIT trap can detach
# the sparsebundle before the SCRATCH rm. Empty when heavy mode is not
# active or the attach failed; the trap is a no-op in that case.
HEAVY_MOUNT=""
compat_cleanup() {
    if [ -n "${HEAVY_MOUNT}" ] && [ -d "${HEAVY_MOUNT}" ]; then
        # -force releases the volume even when a child process kept a
        # file open inside the mount. The scratch sparsebundle is
        # throwaway, so the safer plain detach is not worth retrying.
        hdiutil detach -force "${HEAVY_MOUNT}" >/dev/null 2>&1 || true
    fi
    rm -rf "${SCRATCH}"
}
trap compat_cleanup EXIT

# ── CLI surface smokes ───────────────────────────────────────────────

# --help renders the run usage block and exits 0.
out=$("${ELFUSE}" oci run --help 2>&1)
rc=$?
case "${out}" in
    *"usage: elfuse oci run"*)
        if [ "${rc}" = 0 ]; then
            ok "cli: --help prints usage and exits 0"
        else
            bad "cli: --help" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "cli: --help" "no usage text"
        ;;
esac

# BusyBox-style multicall: a symlink named elfuse-container dispatches
# straight into the OCI CLI on argv[0], and usage text is branded with
# the invoked alias instead of the "elfuse oci" spelling.
ln -s "${ELFUSE}" "${SCRATCH}/elfuse-container"
mc_help=$("${SCRATCH}/elfuse-container" help 2>&1)
rc=$?
case "${mc_help}" in
    *"usage: elfuse-container <subcommand>"*)
        if [ "${rc}" = 0 ]; then
            ok "multicall: help brands usage with alias and exits 0"
        else
            bad "multicall: help" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "multicall: help" "usage not branded: ${mc_help%%$'\n'*}"
        ;;
esac

mc_run=$("${SCRATCH}/elfuse-container" run --help 2>&1)
rc=$?
case "${mc_run}" in
    *"usage: elfuse-container run"*)
        if [ "${rc}" = 0 ]; then
            ok "multicall: run --help brands sub-usage with alias"
        else
            bad "multicall: run --help" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "multicall: run --help" "usage not branded: ${mc_run%%$'\n'*}"
        ;;
esac

# Bare invocation prints usage to stderr and exits 2, like `elfuse oci`.
"${SCRATCH}/elfuse-container" >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "multicall: bare invocation returns rc=2"
else
    bad "multicall: bare invocation" "rc=${rc} (want 2)"
fi

# The build tree ships the alias next to the binary (Makefile LN step).
if [ -L "${BUILD}/elfuse-container" ]; then
    ok "multicall: build tree ships elfuse-container symlink"
else
    bad "multicall: build symlink" "${BUILD}/elfuse-container missing"
fi

# `oci pull --help` documents the skopeo transfer and the --arch flag.
pull_help=$("${ELFUSE}" oci pull --help 2>&1)
case "${pull_help}" in
    *"skopeo"*)
        ok "pull-smoke: --help documents skopeo transfer"
        ;;
    *)
        bad "pull-smoke: skopeo usage" "${pull_help}"
        ;;
esac

case "${pull_help}" in
    *"--arch"*)
        ok "pull-smoke: --help advertises --arch"
        ;;
    *)
        bad "pull-smoke: --help lacks --arch" "${pull_help}"
        ;;
esac

# Missing IMAGE returns rc=2.
"${ELFUSE}" oci run --keep >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: missing IMAGE returns rc=2"
else
    bad "cli: missing IMAGE" "rc=${rc} (want 2)"
fi

# Unknown option returns rc=2.
"${ELFUSE}" oci run --nope alpine >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: unknown option returns rc=2"
else
    bad "cli: unknown option" "rc=${rc} (want 2)"
fi

# -e without a value returns rc=2.
"${ELFUSE}" oci run -e >/dev/null 2>&1
rc=$?
if [ "${rc}" = 2 ]; then
    ok "cli: -e without value returns rc=2"
else
    bad "cli: -e w/o value" "rc=${rc} (want 2)"
fi

# ── Fixture builder integration ──────────────────────────────────────

STORE="${SCRATCH}/store"
mkdir -p "${STORE}"

# Hand-build a one-file uncompressed tar layer. tar(1) is portable; the
# OCI manifest descriptor uses mediaType=...tar (uncompressed) so no
# gzip step is needed.
mkdir -p "${SCRATCH}/layer-src"
cp "${BUILD}/test-hello" "${SCRATCH}/layer-src/hello"
chmod 0755 "${SCRATCH}/layer-src/hello"
(cd "${SCRATCH}/layer-src" && tar cf "${SCRATCH}/layer.tar" hello)

if "${BUILDER}" \
        --store "${STORE}" \
        --ref "local/scratch:v1" \
        --entrypoint "/hello" \
        --env "GREETING=fixture" \
        --workdir "/" \
        --user "1234:5678" \
        --layer "${SCRATCH}/layer.tar" \
        >"${SCRATCH}/manifest-digest.txt" 2>"${SCRATCH}/builder.err"; then
    ok "fixture: oci-fixture-builder exits 0"
else
    bad "fixture: oci-fixture-builder" "$(cat "${SCRATCH}/builder.err")"
fi

# Pin must appear as a manifests[] entry in index.json. Use grep over the
# raw bytes so the test stays portable (jq is not on the macOS default
# install). The canonical ref-name annotation is what oci_store_put_ref
# emits for local/scratch:v1.
if [ -f "${STORE}/index.json" ] &&
   grep -q '"org.opencontainers.image.ref.name"' "${STORE}/index.json" &&
   grep -q 'docker.io/local/scratch:v1' "${STORE}/index.json"; then
    ok "fixture: ref pin written to index.json"
else
    bad "fixture: ref pin" "no matching ref.name annotation in index.json"
fi

# Blob count: layer + config + manifest = 3.
blob_count=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_count}" = 3 ]; then
    ok "fixture: 3 blobs (layer + config + manifest)"
else
    bad "fixture: blob count" "got ${blob_count} (want 3)"
fi

# elfuse oci inspect on the fresh fixture must render the runtime block.
# This proves the manifest -> config blob -> image-config-parser ->
# inspect renderer chain still composes end to end.
inspect_out=$("${ELFUSE}" oci inspect --store "${STORE}" local/scratch:v1 2>&1)
case "${inspect_out}" in
    *"runtime:"*"entrypoint:"*"/hello"*)
        ok "fixture: oci inspect renders runtime block"
        ;;
    *)
        bad "fixture: oci inspect runtime" "no runtime+entrypoint match in output"
        ;;
esac

# Runtime block must echo Env / User / WorkingDir verbatim so the
# operator can read the launch contract before invoking oci run.
case "${inspect_out}" in
    *"GREETING=fixture"*) ok "fixture: inspect shows Env line" ;;
    *) bad "fixture: inspect Env" "no GREETING=fixture" ;;
esac
case "${inspect_out}" in
    *"1234:5678"*) ok "fixture: inspect shows User line" ;;
    *) bad "fixture: inspect User" "no 1234:5678" ;;
esac

# ── Prune CLI smoke ──────────────────────────────────────────────────

# The fixture above produced 3 reachable blobs (layer + config + manifest).
# Drop two extra dangling blobs into blobs/sha256/ via dd + sha256sum
# substitutes; this proves the end-to-end CLI dispatch (parser, store
# open, mark, sweep, output formatter) runs without any C-level
# unit-test scaffolding.
mkdir -p "${SCRATCH}/danglings"
echo "compat-dangling-one" > "${SCRATCH}/danglings/a"
echo "compat-dangling-two" > "${SCRATCH}/danglings/b"
for f in "${SCRATCH}/danglings/a" "${SCRATCH}/danglings/b"; do
    if command -v shasum >/dev/null 2>&1; then
        hex=$(shasum -a 256 "$f" | awk '{print $1}')
    else
        hex=$(sha256sum "$f" | awk '{print $1}')
    fi
    cp "$f" "${STORE}/blobs/sha256/${hex}"
done

blob_before_prune=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_before_prune}" = 5 ]; then
    ok "prune-smoke: 5 blobs before prune (3 reachable + 2 dangling)"
else
    bad "prune-smoke: pre-state" "got ${blob_before_prune} (want 5)"
fi

# Dry-run must not touch disk and must report 2 reclaimable blobs.
dry_out=$("${ELFUSE}" oci prune --store "${STORE}" 2>&1)
rc=$?
case "${dry_out}" in
    *"reclaimable: 2 blobs"*"kept:"*"3 blobs"*"dry-run"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: dry-run reports 2 reclaimable, 3 kept"
        else
            bad "prune-smoke: dry-run" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: dry-run output" "${dry_out}"
        ;;
esac

blob_after_dry=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_after_dry}" = 5 ]; then
    ok "prune-smoke: dry-run did not touch disk"
else
    bad "prune-smoke: dry-run disk" "got ${blob_after_dry} (want 5)"
fi

# Commit reclaims the two dangling blobs.
commit_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit 2>&1)
rc=$?
case "${commit_out}" in
    *"reclaimed: 2 blobs"*"kept:"*"3 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --commit reclaims 2 blobs"
        else
            bad "prune-smoke: --commit" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --commit output" "${commit_out}"
        ;;
esac

blob_after_commit=$(find "${STORE}/blobs/sha256" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${blob_after_commit}" = 3 ]; then
    ok "prune-smoke: --commit unlinked dangling blobs"
else
    bad "prune-smoke: --commit disk" "got ${blob_after_commit} (want 3)"
fi

# ── filter smoke (--older-than / --keep-bytes) ──────────────────

# Stage two fresh dangling blobs and backdate one so --older-than 1d
# distinguishes them. The fresh one must survive; the backdated one
# must be reclaimed and counted in the skipped line that only renders
# when at least one candidate was spared.
mkdir -p "${SCRATCH}/c14"
echo "filter-fresh" > "${SCRATCH}/c14/fresh"
echo "filter-stale" > "${SCRATCH}/c14/stale"
for f in "${SCRATCH}/c14/fresh" "${SCRATCH}/c14/stale"; do
    if command -v shasum >/dev/null 2>&1; then
        hex=$(shasum -a 256 "$f" | awk '{print $1}')
    else
        hex=$(sha256sum "$f" | awk '{print $1}')
    fi
    cp "$f" "${STORE}/blobs/sha256/${hex}"
    case "${f}" in
        *stale)
            stale_hex="${hex}"
            ;;
        *fresh)
            fresh_hex="${hex}"
            ;;
    esac
done
# touch -t accepts [[CC]YY]MMDDhhmm[.SS]; pick 1970-01-02 so the blob
# is unambiguously older than any 1-day cutoff regardless of TZ.
touch -t 197001020000 "${STORE}/blobs/sha256/${stale_hex}"

older_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit --older-than 1d 2>&1)
rc=$?
case "${older_out}" in
    *"reclaimed: 1 blobs"*"skipped:"*"1 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --older-than reclaims stale, skips fresh"
        else
            bad "prune-smoke: --older-than" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --older-than output" "${older_out}"
        ;;
esac

if [ ! -e "${STORE}/blobs/sha256/${stale_hex}" ] \
   && [ -e "${STORE}/blobs/sha256/${fresh_hex}" ]; then
    ok "prune-smoke: --older-than only the stale blob was unlinked"
else
    bad "prune-smoke: --older-than disk state" \
        "stale=${stale_hex} fresh=${fresh_hex}"
fi

# --keep-bytes 0 must behave as no filter: the fresh blob that
# survived the previous step is dangling and gets reclaimed.
keep_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit --keep-bytes 0 2>&1)
rc=$?
case "${keep_out}" in
    *"reclaimed: 1 blobs"*)
        if [ "${rc}" = 0 ]; then
            ok "prune-smoke: --keep-bytes 0 disables the budget filter"
        else
            bad "prune-smoke: --keep-bytes 0" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "prune-smoke: --keep-bytes 0 output" "${keep_out}"
        ;;
esac

# Invalid duration -> non-zero exit, stderr describes the failure.
bad_dur_out=$("${ELFUSE}" oci prune --store "${STORE}" --older-than foo 2>&1)
rc=$?
case "${bad_dur_out}" in
    *"invalid duration"*)
        if [ "${rc}" != 0 ]; then
            ok "prune-smoke: invalid --older-than rejected"
        else
            bad "prune-smoke: invalid duration" "rc=${rc} (want non-zero)"
        fi
        ;;
    *)
        bad "prune-smoke: invalid duration message" "${bad_dur_out}"
        ;;
esac

bad_size_out=$("${ELFUSE}" oci prune --store "${STORE}" --keep-bytes foo 2>&1)
rc=$?
case "${bad_size_out}" in
    *"invalid byte size"*)
        if [ "${rc}" != 0 ]; then
            ok "prune-smoke: invalid --keep-bytes rejected"
        else
            bad "prune-smoke: invalid byte size" "rc=${rc} (want non-zero)"
        fi
        ;;
    *)
        bad "prune-smoke: invalid byte size message" "${bad_size_out}"
        ;;
esac

# ── Rebuild-cache CLI smoke ───────────────────────────────────

# A volume without any unpacked trees still parses cleanly and reports
# scanned=0. The store under SCRATCH/store has no images/, so the walker
# treats it as the empty case and rc must be 0.
rebuild_out=$("${ELFUSE}" oci rebuild-cache --store "${STORE}" \
                                            --volume "${SCRATCH}" 2>&1)
rc=$?
case "${rebuild_out}" in
    *"rebuild-cache (dry-run):"*"scanned:"*"0 unpacked trees"*"dry-run; pass --commit to write"*)
        if [ "${rc}" = 0 ]; then
            ok "rebuild-cache-smoke: dry-run on empty volume reports scanned=0"
        else
            bad "rebuild-cache-smoke: dry-run rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "rebuild-cache-smoke: dry-run output" "${rebuild_out}"
        ;;
esac

# ── layer + stack prune sweep smoke ───────────────────────────

# After the prune-smoke section above the store holds 3 reachable blobs
# (manifest + config + layer for the dry/commit fixture pin). Drop one
# dangling layer dir and one dangling stack dir into the store and verify
# the CLI render now mentions layers and stacks alongside blobs, that the
# directories are unlinked on --commit, and that the existing blob lines
# still match the expected output shape.
mkdir -p "${SCRATCH}/c33d"
echo "dangling-layer" > "${SCRATCH}/c33d/layer"
echo "dangling-stack" > "${SCRATCH}/c33d/stack"
if command -v shasum >/dev/null 2>&1; then
    layer_hex=$(shasum -a 256 "${SCRATCH}/c33d/layer" | awk '{print $1}')
    stack_hex=$(shasum -a 256 "${SCRATCH}/c33d/stack" | awk '{print $1}')
else
    layer_hex=$(sha256sum "${SCRATCH}/c33d/layer" | awk '{print $1}')
    stack_hex=$(sha256sum "${SCRATCH}/c33d/stack" | awk '{print $1}')
fi
mkdir -p "${STORE}/layers/sha256/${layer_hex}"
mkdir -p "${STORE}/layers/stacks/sha256/${stack_hex}"
echo "filler" > "${STORE}/layers/sha256/${layer_hex}/payload"

c33d_out=$("${ELFUSE}" oci prune --store "${STORE}" --commit 2>&1)
rc=$?
case "${c33d_out}" in
    *"layers:"*"reclaimed"*"stacks:"*"reclaimed"*)
        if [ "${rc}" = 0 ]; then
            ok "c33d-smoke: --commit renders layers + stacks lines"
        else
            bad "c33d-smoke: --commit rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "c33d-smoke: --commit output" "${c33d_out}"
        ;;
esac

if [ ! -e "${STORE}/layers/sha256/${layer_hex}" ] \
   && [ ! -e "${STORE}/layers/stacks/sha256/${stack_hex}" ]; then
    ok "c33d-smoke: dangling layer and stack dirs were unlinked"
else
    bad "c33d-smoke: disk state" \
        "layer=${layer_hex} stack=${stack_hex} still present"
fi

# ── store-wide status smoke ─────────────────────────────────────

# Default human render exposes the three sections so an operator running
# `elfuse oci status` after prune still gets a coherent snapshot of the
# remaining store state.
status_out=$("${ELFUSE}" oci status --store "${STORE}" 2>&1)
rc=$?
case "${status_out}" in
    *"PINS ("*"STORE TOTALS:"*"blobs:"*)
        if [ "${rc}" = 0 ]; then
            ok "status-smoke: human render shows PINS and STORE TOTALS"
        else
            bad "status-smoke: human rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "status-smoke: human render" "${status_out}"
        ;;
esac

# Structured output for jq-style consumers. Substring matches keep the
# check portable across jq / no-jq installs; the schema is enforced via
# the test-oci-status unit suite.
json_out=$("${ELFUSE}" oci status --store "${STORE}" --json 2>&1)
rc=$?
case "${json_out}" in
    *'"schemaVersion":1'*'"pins":'*'"totals":'*'"blob_count":'*)
        if [ "${rc}" = 0 ]; then
            ok "status-smoke: --json schemaVersion 1 with pins/totals"
        else
            bad "status-smoke: --json rc" "rc=${rc} (want 0)"
        fi
        ;;
    *)
        bad "status-smoke: --json render" "${json_out}"
        ;;
esac

# --no-disk-usage zeroes the size fields but counters still populate.
nodu_out=$("${ELFUSE}" oci status --store "${STORE}" --json --no-disk-usage 2>&1)
case "${nodu_out}" in
    *'"blob_bytes":0'*'"disk_usage_skipped":true'*)
        ok "status-smoke: --no-disk-usage zeroes byte totals"
        ;;
    *)
        bad "status-smoke: --no-disk-usage" "${nodu_out}"
        ;;
esac

# ── Heavy mode (full E2E launches) ───────────────────────────────────
#
# OCI_COMPAT_TEST=1 provisions a scratch case-sensitive APFS sparsebundle
# at ${SCRATCH}/scratch.sparsebundle, attaches it under HEAVY_MOUNT, and
# drives each fixture end-to-end through `elfuse oci run`.
# The volume is detached and the SCRATCH dir is wiped on EXIT. The
# default ${HOME}/Library/Application Support/elfuse/ volume is never
# touched so the test cannot pollute a developer's working store.

if [ -n "${OCI_COMPAT_TEST:-}" ]; then
    heavy_busybox="${GUEST_BUSYBOX:-${ROOT}/externals/test-fixtures/aarch64-musl/staticbin/bin/busybox}"
    if [ ! -x "${heavy_busybox}" ]; then
        skip "heavy: static busybox missing" \
             "${heavy_busybox} not found; run tests/fetch-fixtures.sh first"
    else
        HEAVY_IMAGE="${SCRATCH}/scratch.sparsebundle"
        HEAVY_MOUNT_DEST="${SCRATCH}/scratch-mount"
        # hdiutil refuses to create over an existing path and refuses to
        # attach onto a mountpoint dir that does not exist yet; the create
        # call writes the sparsebundle to disk, mkdir provisions the
        # mountpoint, attach binds them. -nobrowse keeps Finder from
        # registering the volume on developer laptops.
        if hdiutil create -size 256m \
                          -fs "Case-sensitive APFS" \
                          -volname "elfuse-compat" \
                          -type SPARSEBUNDLE \
                          -quiet "${HEAVY_IMAGE}" \
            && mkdir -p "${HEAVY_MOUNT_DEST}" \
            && hdiutil attach -mountpoint "${HEAVY_MOUNT_DEST}" \
                              -nobrowse -quiet "${HEAVY_IMAGE}"; then
            HEAVY_MOUNT="${HEAVY_MOUNT_DEST}"
            ok "heavy: scratch sparsebundle attached at ${HEAVY_MOUNT}"
        else
            bad "heavy: sparsebundle setup" "hdiutil create+attach failed"
        fi

        if [ -n "${HEAVY_MOUNT}" ]; then
            HEAVY_STORE="${SCRATCH}/heavy-store"
            mkdir -p "${HEAVY_STORE}"

            # ── Fixture A: alpine-shaped ────────────────────────────────
            #
            # Minimal single-layer image with a static busybox at
            # /bin/busybox and a small /etc/os-release. Exercises the
            # baseline unpack -> clone-rootfs -> guest-launch chain on a
            # freshly attached sparsebundle volume without any hardlink
            # or whiteout surface in the layer tar.
            FIX_A_SRC="${SCRATCH}/fix-a-src"
            mkdir -p "${FIX_A_SRC}/bin" "${FIX_A_SRC}/etc"
            cp "${heavy_busybox}" "${FIX_A_SRC}/bin/busybox"
            chmod 0755 "${FIX_A_SRC}/bin/busybox"
            cat > "${FIX_A_SRC}/etc/os-release" <<'EOF'
NAME="elfuse-compat-A"
ID=alpine-shaped
EOF
            (cd "${FIX_A_SRC}" && tar cf "${SCRATCH}/fix-a.tar" bin etc)

            if "${BUILDER}" \
                    --store "${HEAVY_STORE}" \
                    --ref "compat/alpine-shaped:v1" \
                    --entrypoint "/bin/busybox" \
                    --workdir "/" \
                    --layer "${SCRATCH}/fix-a.tar" \
                    >/dev/null 2>"${SCRATCH}/fix-a-build.err"; then
                ok "heavy/A: alpine-shaped fixture built"
            else
                bad "heavy/A: fixture build" \
                    "$(cat "${SCRATCH}/fix-a-build.err")"
            fi

            # busybox dispatches on argv[1] when argv[0] is the busybox
            # binary itself, so passing "echo elfuse-..." as the CLI tail
            # selects the echo applet.
            run_log="${SCRATCH}/fix-a-run.log"
            "${ELFUSE}" oci run \
                --store "${HEAVY_STORE}" \
                --volume "${HEAVY_MOUNT}" \
                compat/alpine-shaped:v1 \
                echo "elfuse-alpine-shaped-ok" \
                >"${run_log}" 2>&1
            run_rc=$?
            if [ "${run_rc}" = 0 ] \
               && grep -q "^elfuse-alpine-shaped-ok$" "${run_log}"; then
                ok "heavy/A: oci run alpine-shaped prints expected line"
            else
                bad "heavy/A: oci run alpine-shaped" \
                    "rc=${run_rc} log=$(tail -n 5 "${run_log}")"
            fi

            # ── Fixture B: busybox-shaped ───────────────────────────────
            #
            # Single layer that hardlinks /bin/echo (the entrypoint) at
            # /bin/busybox so the layer tar carries a typeflag '1' record
            # the apply_hardlink path must rebuild. busybox dispatches on
            # argv[0] when the program name is one of its applets, so
            # launching via the hardlink (entrypoint /bin/echo) routes
            # straight into the echo applet without an extra argv shuffle.
            # BSD tar detects shared inodes on disk and emits the hardlink
            # entry automatically, so the layout below produces a "regular
            # file then hardlink" pair without any tar flag fiddling.
            FIX_B_SRC="${SCRATCH}/fix-b-src"
            mkdir -p "${FIX_B_SRC}/bin"
            cp "${heavy_busybox}" "${FIX_B_SRC}/bin/busybox"
            chmod 0755 "${FIX_B_SRC}/bin/busybox"
            ln "${FIX_B_SRC}/bin/busybox" "${FIX_B_SRC}/bin/echo"
            ln "${FIX_B_SRC}/bin/busybox" "${FIX_B_SRC}/bin/cat"
            (cd "${FIX_B_SRC}" && tar cf "${SCRATCH}/fix-b.tar" bin)

            # Sanity-check that tar wrote at least one hardlink entry, so
            # a future change to the build host's tar that silently turns
            # hardlinks into duplicates does not turn this fixture into a
            # busybox-only smoke test. BSD tar prints "h<perm-bits>..."
            # in the leading column for typeflag '1' records, distinct
            # from "-<perm>" (regular file) and "l<perm>" (symlink).
            hardlink_count=$(tar -tvf "${SCRATCH}/fix-b.tar" 2>/dev/null \
                             | grep -c "^h")
            if [ "${hardlink_count}" -ge 1 ]; then
                ok "heavy/B: layer tar carries hardlink records (${hardlink_count})"
            else
                bad "heavy/B: layer tar hardlinks" \
                    "tar emitted ${hardlink_count} hardlink rows (want >=1)"
            fi

            if "${BUILDER}" \
                    --store "${HEAVY_STORE}" \
                    --ref "compat/busybox-shaped:v1" \
                    --entrypoint "/bin/echo" \
                    --workdir "/" \
                    --layer "${SCRATCH}/fix-b.tar" \
                    >/dev/null 2>"${SCRATCH}/fix-b-build.err"; then
                ok "heavy/B: busybox-shaped fixture built"
            else
                bad "heavy/B: fixture build" \
                    "$(cat "${SCRATCH}/fix-b-build.err")"
            fi

            run_log="${SCRATCH}/fix-b-run.log"
            "${ELFUSE}" oci run \
                --store "${HEAVY_STORE}" \
                --volume "${HEAVY_MOUNT}" \
                compat/busybox-shaped:v1 \
                "elfuse-busybox-shaped-ok" \
                >"${run_log}" 2>&1
            run_rc=$?
            if [ "${run_rc}" = 0 ] \
               && grep -q "^elfuse-busybox-shaped-ok$" "${run_log}"; then
                ok "heavy/B: oci run via /bin/echo hardlink prints line"
            else
                bad "heavy/B: oci run busybox-shaped" \
                    "rc=${run_rc} log=$(tail -n 5 "${run_log}")"
            fi

            # ── Fixture C: two-layer-whiteout ───────────────────────────
            #
            # Layer 1 stages /bin/busybox + /bin/ls hardlink + a /data
            # directory with two files (keep.txt, remove.txt). Layer 2
            # whites out /data/remove.txt via the OCI ".wh.<name>" marker.
            # After layer apply the unpacked rootfs must contain only
            # /data/keep.txt under /data/ - never the whiteout marker
            # itself and never the removed entry. The launch uses /bin/ls
            # against /data (cmd = [/data]) so the proof is the exact
            # stdout shape.
            FIX_C_SRC1="${SCRATCH}/fix-c-l1"
            FIX_C_SRC2="${SCRATCH}/fix-c-l2"
            mkdir -p "${FIX_C_SRC1}/bin" "${FIX_C_SRC1}/data"
            mkdir -p "${FIX_C_SRC2}/data"
            cp "${heavy_busybox}" "${FIX_C_SRC1}/bin/busybox"
            chmod 0755 "${FIX_C_SRC1}/bin/busybox"
            ln "${FIX_C_SRC1}/bin/busybox" "${FIX_C_SRC1}/bin/ls"
            printf "keep\n" > "${FIX_C_SRC1}/data/keep.txt"
            printf "remove\n" > "${FIX_C_SRC1}/data/remove.txt"
            # OCI spec: whiteout file is an empty regular file at the
            # parent dir with name ".wh.<base>". Its presence alone tells
            # the apply path to delete the matching entry from the lower
            # layer.
            : > "${FIX_C_SRC2}/data/.wh.remove.txt"
            (cd "${FIX_C_SRC1}" && tar cf "${SCRATCH}/fix-c-l1.tar" bin data)
            (cd "${FIX_C_SRC2}" && tar cf "${SCRATCH}/fix-c-l2.tar" data)

            if "${BUILDER}" \
                    --store "${HEAVY_STORE}" \
                    --ref "compat/two-layer-whiteout:v1" \
                    --entrypoint "/bin/ls" \
                    --cmd "/data" \
                    --workdir "/" \
                    --layer "${SCRATCH}/fix-c-l1.tar" \
                    --layer "${SCRATCH}/fix-c-l2.tar" \
                    >/dev/null 2>"${SCRATCH}/fix-c-build.err"; then
                ok "heavy/C: two-layer-whiteout fixture built"
            else
                bad "heavy/C: fixture build" \
                    "$(cat "${SCRATCH}/fix-c-build.err")"
            fi

            run_log="${SCRATCH}/fix-c-run.log"
            "${ELFUSE}" oci run \
                --store "${HEAVY_STORE}" \
                --volume "${HEAVY_MOUNT}" \
                compat/two-layer-whiteout:v1 \
                >"${run_log}" 2>&1
            run_rc=$?
            if [ "${run_rc}" != 0 ]; then
                bad "heavy/C: oci run two-layer-whiteout" \
                    "rc=${run_rc} log=$(tail -n 5 "${run_log}")"
            elif grep -q "^keep.txt$" "${run_log}" \
                 && ! grep -q "^remove.txt$" "${run_log}"; then
                ok "heavy/C: whiteout dropped remove.txt, keep.txt survived"
            else
                bad "heavy/C: whiteout output shape" \
                    "log=$(tr '\n' '|' < "${run_log}")"
            fi
            # The OCI image-spec is explicit that the ".wh.<name>" marker
            # must never appear in the final filesystem. A regression that
            # forwards the marker as a real file breaks layered tooling
            # downstream, so the test asserts on the unpacked image tree
            # in addition to the runtime stdout shape.
            unpacked_data=$(find "${HEAVY_MOUNT}/images" -type d -name data \
                                 2>/dev/null | head -n 1)
            if [ -n "${unpacked_data}" ] \
               && [ -e "${unpacked_data}/keep.txt" ] \
               && [ ! -e "${unpacked_data}/remove.txt" ] \
               && [ ! -e "${unpacked_data}/.wh.remove.txt" ]; then
                ok "heavy/C: unpacked /data tree has only keep.txt"
            else
                bad "heavy/C: unpacked /data tree" \
                    "data=${unpacked_data:-unset} keep=$(test -e ${unpacked_data}/keep.txt 2>/dev/null && echo y || echo n) remove=$(test -e ${unpacked_data}/remove.txt 2>/dev/null && echo y || echo n) wh=$(test -e ${unpacked_data}/.wh.remove.txt 2>/dev/null && echo y || echo n)"
            fi
        fi
    fi
else
    skip "alpine-shaped / busybox-shaped / two-layer-whiteout E2E" \
         "OCI_COMPAT_TEST=1 gates the hdiutil-backed pipeline"
fi

# ── Online mode (gated) ──────────────────────────────────────────────
#
# When OCI_FETCH_ONLINE=1 is set, pull docker.io/library/alpine:3 (a
# multi-arch image whose tag pins to an OCI image index by design) and
# run it. This is the regression anchor for the index-walk bug in
# oci_run: before the fix the run-side parser fed the index blob into
# oci_manifest_parse and died with "manifest config descriptor
# missing"; after the fix oci_run drills into the linux/arm64 leaf
# manifest transparently. Uses an isolated scratch store under
# ${SCRATCH} so the test cannot collide with the user's default
# ${HOME}/Library/Application Support/elfuse/store/ . The default
# sparsebundle volume is reused (the unpacked image content is
# content-addressed, so re-running the test is idempotent on disk).

if [ -n "${OCI_FETCH_ONLINE:-}" ]; then
    ONLINE_STORE="${SCRATCH}/online-store"
    mkdir -p "${ONLINE_STORE}"

    pull_log="${SCRATCH}/online-pull.log"
    if "${ELFUSE}" oci pull --store "${ONLINE_STORE}" alpine:3 \
            >"${pull_log}" 2>&1; then
        ok "online: oci pull alpine:3 succeeded"
    else
        bad "online: oci pull alpine:3" "$(tail -n 5 "${pull_log}")"
    fi

    # Multi-arch tags pin to the image index digest. After the
    # index-walk fix in src/oci/run.c, oci_run resolves the leaf
    # manifest before unpack instead of failing at parse. The
    # canonical proof: stdout from busybox echo matches verbatim.
    run_log="${SCRATCH}/online-run.log"
    "${ELFUSE}" oci run --store "${ONLINE_STORE}" alpine:3 \
        /bin/busybox echo "elfuse-online-ok" \
        >"${run_log}" 2>&1
    run_rc=$?
    if [ "${run_rc}" = 0 ] && grep -q "^elfuse-online-ok$" "${run_log}"; then
        ok "online: oci run alpine:3 prints expected line"
    elif grep -q "manifest config descriptor missing" "${run_log}"; then
        bad "online: oci run alpine:3" \
            "regressed to pre-fix index-walk error: $(tail -n 3 "${run_log}")"
    else
        bad "online: oci run alpine:3" \
            "rc=${run_rc} log=$(tail -n 3 "${run_log}")"
    fi
else
    skip "alpine:3 online pull + run" \
         "OCI_FETCH_ONLINE=1 gates docker.io network access"
fi

TOTAL=$((PASS + FAIL))
echo ""
echo "Results: ${PASS}/${TOTAL} passed"
[ "${FAIL}" = 0 ]
