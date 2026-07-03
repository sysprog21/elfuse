/* OCI per-run /etc host-truth injection
 *
 * Copyright 2026 elfuse contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Overlays /etc/resolv.conf, /etc/hosts, and /etc/hostname on the
 * per-run clone-rootfs so guest libc lookups (getaddrinfo,
 * gethostname, /etc/hosts walks) see values matching the macOS host
 * rather than the image's containerd defaults. The entry point is
 * invoked from src/oci/run.c
 * after oci_clone_rootfs and before the manifest parse.
 */

#ifndef ELFUSE_OCI_RUNTIME_FILES_H
#define ELFUSE_OCI_RUNTIME_FILES_H

#ifdef __cplusplus
extern "C" {
#endif

/* Write /etc/{resolv.conf,hosts,hostname} into <run_dir>/etc/.
 *
 * Creates the /etc/ directory at mode 0755 if it is missing.
 * Overwrites any pre-existing file or symlink at the three target
 * paths (image distros often ship /etc/resolv.conf as a symlink to
 * /run/systemd/resolve/stub-resolv.conf, which would otherwise
 * dangle inside the guest).
 *
 * /etc/resolv.conf is built from "nameserver <ip>" entries reported
 * by scutil --dns; on any scutil failure or zero hits the helper
 * falls back to 8.8.8.8 / 1.1.1.1. /etc/hosts is a fixed five-line
 * block with localhost, ip6-loopback aliases, link-local multicast
 * names, and host.elfuse.internal. /etc/hostname is the literal
 * string "elfuse\n".
 *
 * Returns 0 on success, -1 on the first irrecoverable error with
 * *err pointing at a static diagnostic. errno is preserved on the
 * failing syscall.
 */
int oci_runtime_files_inject(const char *run_dir, const char **err);

#ifdef __cplusplus
}
#endif

#endif /* ELFUSE_OCI_RUNTIME_FILES_H */
