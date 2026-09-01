# Shared ssh argv for the qemu test VM.
#
# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# timeout(1) cannot wrap a shell function, so what the callers share is the
# argv: qemu_ssh_opts fills QEMU_SSH_OPTS from QEMU_SSH_KEY and QEMU_PORT at
# call time, and each caller builds its own ssh command line around it. The
# conformance backend spells the same list in tests/conformance/backends/ssh.py.

# shellcheck disable=SC2034  # Consumed by the sourcing script.
qemu_ssh_opts()
{
    QEMU_SSH_OPTS=(
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR
        -o BatchMode=yes
        -o ConnectTimeout=10
        -o ServerAliveInterval=10
        -o ServerAliveCountMax=6
        -i "$QEMU_SSH_KEY"
        -p "$QEMU_PORT"
    )
}
