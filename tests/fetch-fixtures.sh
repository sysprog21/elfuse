#!/usr/bin/env bash

# fetch-fixtures.sh -- Download Alpine packages and assemble a qemu/elfuse test
# fixture tree under externals/test-fixtures/.
#
# Idempotent: re-runs are no-ops once everything is in place. Re-execute with
# FORCE=1 to rebuild from scratch.
#
# Layout:
#   externals/test-fixtures/
#     cache/                       # downloaded .apk + .tar.gz
#     cache/x86_64/                # x86_64 .apk + .tar.gz (when enabled)
#     kernel/vmlinuz-virt          # extracted aarch64 kernel image
#     rootfs/                      # extracted aarch64 minirootfs + overlays
#     initramfs.cpio.gz            # built from rootfs/ (qemu boot image)
#     keys/{ssh_key,ssh_key.pub}   # generated ssh keypair
#     aarch64-musl/
#       staticbin/bin/             # busybox-static + applet symlinks
#       dyn-bin/                   # relative symlinks into rootfs
#     x86_64-musl/                 # only when INCLUDE_X86_64=1
#       rootfs/                    # x86_64 minirootfs + apk overlays
#       staticbin/bin/             # x86_64 busybox-static + applets
#       dyn-bin/                   # x86_64 dyn-bin aggregate
#
# Environment:
#   FORCE=1            Rebuild every stage from scratch.
#   KERNEL_ALPINE_VERSION=<rel>
#                      Alpine release the oracle kernel comes from, default
#                      3.23 (Linux 6.18 LTS). Userland stays on
#                      ALPINE_VERSION.
#   INCLUDE_X86_64=1   Also fetch x86_64 userspace for the elfuse-x86_64
#                      test-matrix mode. Default off; adds ~80 MiB of
#                      downloads but reuses the same Alpine version pin
#                      so the package set stays aligned across arches.
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# shellcheck source=tests/lib/bash-compat.sh
. "$(dirname "$0")/lib/bash-compat.sh"

ALPINE_VERSION="${ALPINE_VERSION:-3.21}"

# The oracle kernel resolves from its own Alpine release: 3.23 ships linux-virt
# 6.18, the LTS line elfuse reports to the guest, while the userland pins stay
# on ALPINE_VERSION. The linux-virt apk carries the kernel and its lib/modules
# tree, so both move together.
KERNEL_ALPINE_VERSION="${KERNEL_ALPINE_VERSION:-3.23}"

# Empty by default -- the exact point release is resolved from the live releases
# listing at fetch time (see resolve_minirootfs), then written back here so the
# x86_64 path reuses the same patch. Set explicitly to pin one.
ALPINE_PATCH="${ALPINE_PATCH:-}"
ALPINE_ARCH="${ALPINE_ARCH:-aarch64}"

CDN_BASE="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}"
RELEASES="${CDN_BASE}/releases/${ALPINE_ARCH}"
MAIN_REPO="${CDN_BASE}/main/${ALPINE_ARCH}"
COMMUNITY_REPO="${CDN_BASE}/community/${ALPINE_ARCH}"
KERNEL_REPO="https://dl-cdn.alpinelinux.org/alpine/v${KERNEL_ALPINE_VERSION}/main/${ALPINE_ARCH}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURES="${REPO_ROOT}/externals/test-fixtures"
CACHE="${FIXTURES}/cache"
ROOTFS="${FIXTURES}/rootfs"
KERNEL_DIR="${FIXTURES}/kernel"
KEYS_DIR="${FIXTURES}/keys"
STATICBIN="${FIXTURES}/aarch64-musl/staticbin/bin"
INITRAMFS="${FIXTURES}/initramfs.cpio.gz"

# Required packages as "repo:name". Versions are NOT pinned here: Alpine's
# mirror keeps only the latest build of each package, so any hard-coded version
# 404s once a newer build supersedes it. resolve_versions() reads each repo's
# live APKINDEX and fills PKG_RESOLVED with "repo:name:version" tuples; the rest
# of the script and pkg_version go through that.
#
# Tuples (not associative arrays) keep this working on bash 3.2 hosts (stock
# macOS /bin/bash) -- see tests/lib/bash-compat.sh.
PKGS=(
    "kernel:linux-virt"
    "main:busybox-static"
    "main:dropbear"
    "main:zlib"
    "main:utmps-libs"
    "main:skalibs-libs"
    "main:musl"
    "main:musl-dev"
    "main:musl-utils"
    "main:libgcc"
    "main:libcrypto3"
    "main:acl-libs"
    "main:libattr"
    "main:pcre2"
    "main:coreutils"
    "main:coreutils-env"
    "main:coreutils-fmt"
    "main:coreutils-sha512sum"
    "main:bash"
    "main:dash"
    "main:findutils"
    "main:diffutils"
    "main:grep"
    "main:sed"
    "main:gawk"
    "main:gmp"
    "main:readline"
    "main:libncursesw"
    "main:ncurses-terminfo-base"
    "main:lua5.4"
    "main:lua5.4-libs"
    "main:luajit"
    "main:jq"
    "main:oniguruma"
    "main:sqlite"
    "main:sqlite-libs"
    "main:tree"
)

# "repo:name:version" tuples, populated by resolve_versions() from live APKINDEX
# data. Same shape the staging loops and pkg_version expect.
PKG_RESOLVED=()

# Set to 1 by main() when the resolved version set differs from versions.lock,
# forcing a rebuild of the staged tree even without FORCE. Global so the x86_64
# path can honor it too.
REBUILD=0

# Look up a resolved package version by its "repo:name" prefix.
#
# Returns the version on stdout and rc=0 on hit, rc=1 (silently) on miss so the
# old ${PKGS[key]:-} fallback callers keep working.
pkg_version()
{
    local target="$1:"
    local entry
    for entry in ${PKG_RESOLVED[@]+"${PKG_RESOLVED[@]}"}; do
        case "$entry" in
            "$target"*)
                printf '%s\n' "${entry#"$target"}"
                return 0
                ;;
        esac
    done
    return 1
}

# Subset whose binaries are exposed as standalone "static-bins" suite paths.
# Most are dynamic but link only against musl/zlib/etc., already in rootfs/.
# Applet list (hardcoded -- busybox 1.37 inventory). Busybox does not have b2sum
# / numfmt / base32; those tests fall through to the dynamic-coreutils suite
# where the real coreutils binary is available.
STATIC_APPLETS=(
    echo cat head tail wc sort tr seq expr factor base64 md5sum sha256sum
    cp touch ls stat basename dirname realpath df du
    uname date id printenv nproc
    true false sleep env nice nohup timeout
    sha1sum sha512sum cksum
    chmod chown ln rm mkdir rmdir mv pwd
    cmp diff find sed grep awk
)

# Resolved by resolve_minirootfs() before staging.
MINIROOTFS_TGZ=""

c_blue()
{
    printf '\033[0;34m%s\033[0m' "$*"
}
c_green()
{
    printf '\033[0;32m%s\033[0m' "$*"
}
c_yellow()
{
    printf '\033[1;33m%s\033[0m' "$*"
}

log()
{
    printf '%s %s\n' "$(c_blue ' fixtures:')" "$*"
}
ok()
{
    printf '%s %s\n' "$(c_green '       ok:')" "$*"
}

fetch()
{
    local url="$1" dest="$2"
    if [ -s "$dest" ] && [ "${FORCE:-0}" != "1" ]; then
        return 0
    fi
    log "fetch $(basename "$dest")"
    curl -fsSL --retry 3 -o "$dest.partial" "$url"
    mv "$dest.partial" "$dest"
}

apk_url()
{
    local repo="$1" name="$2" version="$3"
    case "$repo" in
        main) echo "${MAIN_REPO}/${name}-${version}.apk" ;;
        community) echo "${COMMUNITY_REPO}/${name}-${version}.apk" ;;
        kernel) echo "${KERNEL_REPO}/${name}-${version}.apk" ;;
        *)
            echo "unknown repo: $repo" >&2
            return 1
            ;;
    esac
}

apk_path()
{
    local name="$1" version="$2"
    echo "${CACHE}/${name}-${version}.apk"
}

repo_url()
{
    case "$1" in
        main) echo "$MAIN_REPO" ;;
        community) echo "$COMMUNITY_REPO" ;;
        kernel) echo "$KERNEL_REPO" ;;
        *)
            echo "unknown repo: $1" >&2
            return 1
            ;;
    esac
}

# Resolve the current version of every package in PKGS by parsing each
# referenced repo's APKINDEX, populating PKG_RESOLVED with "repo:name:version"
# tuples. Alpine prunes superseded builds from the mirror, so reading the live
# index is the only reliable way to keep the fixture build from 404-ing on a
# stale pin. Flattened "name version" indexes are cached so warm re-runs work
# offline.
resolve_versions()
{
    # Unique set of repos referenced by PKGS (no associative arrays: track a
    # space-padded string for membership tests).
    local entry repo repos=""
    for entry in "${PKGS[@]}"; do
        repo="${entry%%:*}"
        case " $repos " in
            *" $repo "*) ;;
            *) repos="$repos $repo" ;;
        esac
    done

    local base idxtgz idxfile
    for repo in $repos; do
        base="$(repo_url "$repo")"
        idxtgz="${CACHE}/APKINDEX-${repo}.tar.gz"
        idxfile="${CACHE}/APKINDEX-${repo}.versions"
        log "resolve versions ($repo)"

        # Always try to refresh the index -- tracking the live mirror is the
        # point -- but fall back to a cached copy so warm re-runs work offline.
        # APKINDEX records are blank-line separated; P: is the package name, V:
        # its version. Flatten to "name version" lines.
        if curl -fsSL --retry 3 -o "${idxtgz}.partial" "${base}/APKINDEX.tar.gz"; then
            mv "${idxtgz}.partial" "$idxtgz"
            tar xzOf "$idxtgz" APKINDEX 2> /dev/null | awk '
                /^P:/ { name = substr($0, 3) }
                /^V:/ { ver  = substr($0, 3) }
                /^$/  { if (name != "") print name, ver; name = ""; ver = "" }
                END   { if (name != "") print name, ver }
            ' > "${idxfile}.partial"
            mv "${idxfile}.partial" "$idxfile"
        else
            rm -f "${idxtgz}.partial"
            [ -s "$idxfile" ] || {
                echo "error: cannot fetch APKINDEX for $repo (mirror unreachable, no cache)" >&2
                exit 1
            }
            log "offline: reusing cached APKINDEX ($repo)"
        fi
    done

    # Resolve each package against its repo's flattened index.
    local name version missing=0
    PKG_RESOLVED=()
    for entry in "${PKGS[@]}"; do
        repo="${entry%%:*}"
        name="${entry#*:}"
        idxfile="${CACHE}/APKINDEX-${repo}.versions"
        version="$(awk -v n="$name" '$1 == n { print $2; exit }' "$idxfile")"
        if [ -z "$version" ]; then
            echo "error: package ${repo}:${name} not present in APKINDEX" >&2
            missing=1
            continue
        fi
        PKG_RESOLVED+=("${repo}:${name}:${version}")
    done
    [ "$missing" = 0 ] || exit 1
}

# Resolve the minirootfs point release. Alpine keeps only a handful of recent
# releases under releases/, so honor an explicit ALPINE_PATCH but otherwise pick
# the newest the mirror advertises and write it back to ALPINE_PATCH so the
# x86_64 path reuses the same patch. Sets MINIROOTFS_TGZ.
resolve_minirootfs()
{
    if [ -z "$ALPINE_PATCH" ]; then
        log "resolve minirootfs"
        local listing=""
        listing="$(curl -fsSL --retry 3 "${RELEASES}/" 2> /dev/null || true)"
        ALPINE_PATCH="$(printf '%s\n' "$listing" \
            | grep -oE "alpine-minirootfs-[0-9.]+-${ALPINE_ARCH}\.tar\.gz" \
            | sed -E "s/^alpine-minirootfs-([0-9.]+)-${ALPINE_ARCH}\.tar\.gz/\1/" \
            | sort -uV | tail -1 || true)"
        if [ -z "$ALPINE_PATCH" ]; then
            # Offline fallback: newest minirootfs already in the cache.
            ALPINE_PATCH="$(ls "${CACHE}"/alpine-minirootfs-*-"${ALPINE_ARCH}".tar.gz \
                2> /dev/null \
                | sed -E "s#.*/alpine-minirootfs-([0-9.]+)-${ALPINE_ARCH}\.tar\.gz#\1#" \
                | sort -V | tail -1 || true)"
        fi
        if [ -z "$ALPINE_PATCH" ]; then
            echo "error: no minirootfs tarball found (mirror unreachable, cache empty)" >&2
            exit 1
        fi
    fi
    MINIROOTFS_TGZ="alpine-minirootfs-${ALPINE_PATCH}-${ALPINE_ARCH}.tar.gz"
}

# Strip Alpine apk metadata (.PKGINFO, .SIGN.*, .pre-install, etc.) when
# extracting into a target tree. These are not real files and pollute the
# rootfs.
extract_apk_to()
{
    local apk="$1" dest="$2"
    mkdir -p "$dest"
    tar xzf "$apk" -C "$dest" \
        --exclude='.PKGINFO' \
        --exclude='.SIGN.*' \
        --exclude='.pre-install' \
        --exclude='.post-install' \
        --exclude='.pre-upgrade' \
        --exclude='.post-upgrade' \
        --exclude='.pre-deinstall' \
        --exclude='.post-deinstall' \
        --exclude='.trigger' 2> /dev/null || true
}

main()
{
    mkdir -p "$CACHE" "$KERNEL_DIR" "$KEYS_DIR" "$STATICBIN" "$ROOTFS"

    # Resolve all package versions and the minirootfs name from the live mirror
    # before downloading anything.
    resolve_versions
    resolve_minirootfs

    # If the resolved version set changed since the last run, the staged
    # rootfs/kernel/initramfs are built from stale apks and must be rebuilt even
    # without an explicit FORCE.
    local entry manifest lockfile
    manifest="$({
        for entry in "${PKG_RESOLVED[@]}"; do
            printf '%s\n' "$entry"
        done | LC_ALL=C sort
        printf 'minirootfs=%s\n' "$MINIROOTFS_TGZ"
    })"
    lockfile="${FIXTURES}/versions.lock"
    if [ ! -f "$lockfile" ] || [ "$manifest" != "$(cat "$lockfile")" ]; then
        REBUILD=1
    fi

    # Download all required apk packages.
    local entry repo name version
    for entry in "${PKG_RESOLVED[@]}"; do
        repo="${entry%%:*}"
        name="${entry#*:}"
        name="${name%:*}"
        version="${entry##*:}"
        fetch "$(apk_url "$repo" "$name" "$version")" "$(apk_path "$name" "$version")"
    done

    fetch "${RELEASES}/${MINIROOTFS_TGZ}" "${CACHE}/${MINIROOTFS_TGZ}"

    # Stage the rootfs.
    if [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ] || [ ! -e "${ROOTFS}/.staged" ]; then
        log "stage rootfs"
        rm -rf "$ROOTFS"
        mkdir -p "$ROOTFS"
        tar xzf "${CACHE}/${MINIROOTFS_TGZ}" -C "$ROOTFS" 2> /dev/null

        # Overlay every cached apk except linux-virt (kernel goes elsewhere).
        # The kernel apk's lib/modules/ tree IS overlayed (needed for modprobe).
        local entry name version
        for entry in "${PKG_RESOLVED[@]}"; do
            name="${entry#*:}"
            name="${name%:*}"
            version="${entry##*:}"
            [ "$name" = "linux-virt" ] && continue
            extract_apk_to "$(apk_path "$name" "$version")" "$ROOTFS"
        done

        # Extract just the kernel-modules subtree from linux-virt.
        local modstage linux_virt_ver
        linux_virt_ver="$(pkg_version "kernel:linux-virt")"
        modstage="$(mktemp -d)"
        tar xzf "$(apk_path linux-virt "$linux_virt_ver")" \
            -C "$modstage" 'lib/modules' 2> /dev/null
        cp -R "$modstage/lib/modules" "$ROOTFS/lib/" 2> /dev/null
        rm -rf "$modstage"

        # /init (custom -- no openrc, just bring up minimum services for ssh).
        cat > "${ROOTFS}/init" << 'EOF'
#!/bin/sh
# Custom init -- sets up enough for dropbear ssh + 9p shared mounts.
set +e
exec </dev/console >/dev/console 2>&1

mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts -o gid=5,mode=620 devpts /dev/pts
mount -t tmpfs tmpfs /dev/shm
mount -t tmpfs tmpfs /run

# Load kernel modules for virtio-net + 9p shared filesystem.  Order matters:
# bus/transport modules first, then class drivers.
for mod in failover net_failover virtio_net netfs 9pnet 9pnet_virtio 9p; do
    modprobe "$mod" 2>/dev/null || true
done

# Shared filesystem from the host (qemu -virtfs).
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 host /mnt/host \
    || echo "qemu-runner: 9p mount failed"

# Networking: qemu user-mode places guest at 10.0.2.15, host at 10.0.2.2.
ifconfig lo 127.0.0.1 up
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up || echo "qemu-runner: eth0 up failed"
route add default gw 10.0.2.2 2>/dev/null

# Dropbear -- pre-baked host keys, pubkey auth only (passwords disabled).
mkdir -p /etc/dropbear /var/empty /var/log
chmod 700 /root /root/.ssh
chown -R 0:0 /root
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || \
    /usr/bin/dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null 2>&1
[ -f /etc/dropbear/dropbear_rsa_host_key ] || \
    /usr/bin/dropbearkey -t rsa -s 2048 -f /etc/dropbear/dropbear_rsa_host_key >/dev/null 2>&1

echo "qemu-runner: ready"
# -s: disable password auth (pubkey only); -F: foreground; -E: stderr logs.
exec /usr/sbin/dropbear -F -E -s -p 22 \
    -r /etc/dropbear/dropbear_rsa_host_key \
    -r /etc/dropbear/dropbear_ed25519_host_key
EOF
        chmod 755 "${ROOTFS}/init"

        # Hostname & basic config
        echo "elfuse-qemu" > "${ROOTFS}/etc/hostname"
        cat > "${ROOTFS}/etc/hosts" << 'EOF'
127.0.0.1 localhost elfuse-qemu
10.0.2.15 elfuse-qemu
EOF

        # Need a tty entry for dropbear's PAM-equivalent path.
        grep -q '^root:' "${ROOTFS}/etc/passwd" \
            || echo 'root:x:0:0:root:/root:/bin/sh' >> "${ROOTFS}/etc/passwd"

        touch "${ROOTFS}/.staged"
    fi
    ok "rootfs ready ($(du -sh "$ROOTFS" | cut -f1))"

    # Generate the SSH keypair if needed.
    if [ ! -s "${KEYS_DIR}/ssh_key" ]; then
        log "generate ssh keypair"
        ssh-keygen -t ed25519 -N '' -C 'elfuse-qemu-runner' \
            -f "${KEYS_DIR}/ssh_key" > /dev/null
    fi

    # Install pubkey into rootfs/root/.ssh/authorized_keys
    mkdir -p "${ROOTFS}/root/.ssh"
    cp "${KEYS_DIR}/ssh_key.pub" "${ROOTFS}/root/.ssh/authorized_keys"
    chmod 700 "${ROOTFS}/root/.ssh"
    chmod 600 "${ROOTFS}/root/.ssh/authorized_keys"
    ok "ssh keypair installed"

    # Extract the kernel from linux-virt.
    if [ ! -s "${KERNEL_DIR}/vmlinuz-virt" ] || [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ]; then
        log "extract kernel"
        local linux_virt_ver
        linux_virt_ver="$(pkg_version "kernel:linux-virt")"
        rm -rf "${KERNEL_DIR}/work"
        mkdir -p "${KERNEL_DIR}/work"
        tar xzf "$(apk_path linux-virt "$linux_virt_ver")" \
            -C "${KERNEL_DIR}/work" boot/vmlinuz-virt 2> /dev/null
        mv "${KERNEL_DIR}/work/boot/vmlinuz-virt" "${KERNEL_DIR}/vmlinuz-virt"
        rm -rf "${KERNEL_DIR}/work"
    fi
    ok "kernel: ${KERNEL_DIR}/vmlinuz-virt"

    # Build the initramfs archive.
    if [ ! -s "$INITRAMFS" ] || [ "$REBUILD" = 1 ] || [ "$ROOTFS/.staged" -nt "$INITRAMFS" ]; then
        log "build initramfs"
        (cd "$ROOTFS" && find . -print0 | LC_ALL=C sort -z \
            | cpio --quiet --null -o -H newc 2> /dev/null | gzip -9) > "$INITRAMFS"
    fi
    ok "initramfs: $(du -h "$INITRAMFS" | cut -f1)"

    # Stage the dynamic-bin aggregate directory. Single flat directory of
    # *relative* symlinks pointing into the rootfs. Relative paths matter: this
    # same tree is consumed by elfuse on macOS AND by qemu's guest kernel after
    # a 9p mount, where any absolute host path would no longer resolve.
    local dynbin="${FIXTURES}/aarch64-musl/dyn-bin"
    if [ ! -d "$dynbin" ] || [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ]; then
        log "stage dyn-bin aggregate"
        rm -rf "$dynbin"
        mkdir -p "$dynbin"

        # ${dynbin} is at <fixtures>/aarch64-musl/dyn-bin; rootfs is at
        # <fixtures>/rootfs. The relative path back is "../../rootfs/...".
        for sub in bin usr/bin; do
            [ -d "${ROOTFS}/${sub}" ] || continue
            for src in "${ROOTFS}/${sub}"/*; do
                [ -e "$src" ] || continue
                local name
                name="$(basename "$src")"
                [ -e "${dynbin}/${name}" ] && continue
                ln -sfn "../../rootfs/${sub}/${name}" "${dynbin}/${name}"
            done
        done
    fi
    ok "dyn-bin: $(find "$dynbin" -maxdepth 1 -type l 2> /dev/null | wc -l | tr -d ' ') entries"

    # Stage the static-bin tree.
    if [ ! -s "${STATICBIN}/busybox" ] || [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ]; then
        log "stage static-bin tree"
        local busybox_ver
        busybox_ver="$(pkg_version "main:busybox-static")"
        rm -rf "${STATICBIN}"
        mkdir -p "${STATICBIN}"
        local stage
        stage="$(mktemp -d)"
        tar xzf "$(apk_path busybox-static "$busybox_ver")" -C "$stage" 2> /dev/null
        mv "${stage}/bin/busybox.static" "${STATICBIN}/busybox"
        chmod 755 "${STATICBIN}/busybox"
        rm -rf "$stage"
        for applet in "${STATIC_APPLETS[@]}"; do
            ln -sfn busybox "${STATICBIN}/${applet}"
        done
    fi
    ok "static-bin: ${STATICBIN}/busybox + ${#STATIC_APPLETS[@]} applets"

    if [ "${INCLUDE_X86_64:-0}" = "1" ]; then
        fetch_x86_64_userspace "$manifest"
    fi

    # Record the resolved version set so the next run can detect a mirror bump
    # and rebuild the staged tree instead of silently reusing stale apks.
    printf '%s\n' "$manifest" > "$lockfile"

    printf '\n%s\n' "$(c_yellow 'Fixtures ready.')"
    printf 'rootfs/sysroot:  %s\n' "$ROOTFS"
    printf 'kernel:          %s\n' "${KERNEL_DIR}/vmlinuz-virt"
    printf 'initramfs:       %s\n' "$INITRAMFS"
    printf 'ssh key:         %s\n' "${KEYS_DIR}/ssh_key"
    printf 'static bin tree: %s\n' "$STATICBIN"
    if [ "${INCLUDE_X86_64:-0}" = "1" ]; then
        printf 'x86_64 rootfs:   %s\n' "${FIXTURES}/x86_64-musl/rootfs"
        printf 'x86_64 staticbin:%s\n' "${FIXTURES}/x86_64-musl/staticbin/bin"
    fi
}

# Fetch just enough Alpine x86_64 packages to drive the elfuse-x86_64 test
# matrix mode through rosetta. Userspace only: no kernel or initramfs is built
# because elfuse runs x86_64 binaries directly. Pinned to the same Alpine
# release as the aarch64 corpus so busybox / coreutils versions match and the
# per-mode expected-count table stays consistent.
fetch_x86_64_userspace()
{
    local manifest="$1"
    local x86_cache="${FIXTURES}/cache/x86_64"
    local x86_rootfs="${FIXTURES}/x86_64-musl/rootfs"
    local x86_staticbin="${FIXTURES}/x86_64-musl/staticbin/bin"
    local x86_dynbin="${FIXTURES}/x86_64-musl/dyn-bin"
    mkdir -p "$x86_cache" "$x86_rootfs" "$x86_staticbin" "$x86_dynbin"

    # The shared versions.lock is rewritten by ARM-only runs too, so the x86_64
    # tree keeps its own lock: a stale tree must rebuild even when the shared
    # lock already matches the mirror.
    local x86_lock="${FIXTURES}/x86_64-musl/versions.lock"
    if [ ! -f "$x86_lock" ] || [ "$manifest" != "$(cat "$x86_lock")" ]; then
        REBUILD=1
    fi
    # Drop it before touching the tree so a failed rebuild leaves no lock.
    rm -f "$x86_lock"

    local x86_main="${CDN_BASE}/main/x86_64"
    local x86_releases="${CDN_BASE}/releases/x86_64"
    local x86_minirootfs="alpine-minirootfs-${ALPINE_PATCH}-x86_64.tar.gz"

    log "x86_64: fetch packages"
    local entry repo name version x86_url x86_dest
    for entry in "${PKG_RESOLVED[@]}"; do
        repo="${entry%%:*}"
        name="${entry#*:}"
        name="${name%:*}"
        version="${entry##*:}"
        [ "$repo" = "main" ] || continue
        x86_url="${x86_main}/${name}-${version}.apk"
        x86_dest="${x86_cache}/${name}-${version}.apk"
        fetch "$x86_url" "$x86_dest"
    done
    fetch "${x86_releases}/${x86_minirootfs}" "${x86_cache}/${x86_minirootfs}"

    if [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ] || [ ! -e "${x86_rootfs}/.staged" ]; then
        log "x86_64: stage rootfs"
        rm -rf "$x86_rootfs"
        mkdir -p "$x86_rootfs"
        tar xzf "${x86_cache}/${x86_minirootfs}" -C "$x86_rootfs" 2> /dev/null
        local stage_entry stage_repo stage_name stage_version
        for stage_entry in "${PKG_RESOLVED[@]}"; do
            stage_repo="${stage_entry%%:*}"
            stage_name="${stage_entry#*:}"
            stage_name="${stage_name%:*}"
            stage_version="${stage_entry##*:}"
            [ "$stage_repo" = "main" ] || continue
            [ "$stage_name" = "linux-virt" ] && continue
            extract_apk_to "${x86_cache}/${stage_name}-${stage_version}.apk" "$x86_rootfs"
        done
        touch "${x86_rootfs}/.staged"
    fi
    ok "x86_64 rootfs ($(du -sh "$x86_rootfs" 2> /dev/null | cut -f1))"

    if [ ! -s "${x86_staticbin}/busybox" ] || [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ]; then
        log "x86_64: stage static-bin tree"
        local busybox_ver
        busybox_ver="$(pkg_version "main:busybox-static")"
        rm -rf "$x86_staticbin"
        mkdir -p "$x86_staticbin"
        local stage
        stage="$(mktemp -d)"
        tar xzf "${x86_cache}/busybox-static-${busybox_ver}.apk" \
            -C "$stage" 2> /dev/null
        mv "${stage}/bin/busybox.static" "${x86_staticbin}/busybox"
        chmod 755 "${x86_staticbin}/busybox"
        rm -rf "$stage"
        for applet in "${STATIC_APPLETS[@]}"; do
            ln -sfn busybox "${x86_staticbin}/${applet}"
        done
    fi
    ok "x86_64 static-bin: ${x86_staticbin}/busybox + ${#STATIC_APPLETS[@]} applets"

    if [ ! -d "$x86_dynbin" ] || [ -z "$(ls -A "$x86_dynbin" 2> /dev/null)" ] \
        || [ "${FORCE:-0}" = "1" ] || [ "$REBUILD" = 1 ]; then
        log "x86_64: stage dyn-bin aggregate"
        rm -rf "$x86_dynbin"
        mkdir -p "$x86_dynbin"
        for sub in bin usr/bin; do
            [ -d "${x86_rootfs}/${sub}" ] || continue
            for src in "${x86_rootfs}/${sub}"/*; do
                [ -e "$src" ] || continue
                local name
                name="$(basename "$src")"
                [ -e "${x86_dynbin}/${name}" ] && continue
                ln -sfn "../rootfs/${sub}/${name}" "${x86_dynbin}/${name}"
            done
        done
    fi
    ok "x86_64 dyn-bin: $(find "$x86_dynbin" -maxdepth 1 -type l 2> /dev/null \
        | wc -l | tr -d ' ') entries"

    printf '%s\n' "$manifest" > "$x86_lock"
}

main "$@"
