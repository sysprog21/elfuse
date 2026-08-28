# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

from conformance.backends.base import Backend, BackendError

def make(name: str, repo_root: Path, **options: Any) -> Backend:
    if name == "elfuse":
        from conformance.backends.elfuse import ElfuseBackend

        return ElfuseBackend(repo_root, **options)
    if name == "qemu":
        from conformance.backends.qemu import QemuBackend

        return QemuBackend(repo_root, **options)
    if name == "host":
        from conformance.backends.host import HostBackend

        if options:
            raise BackendError("host backend takes no options, got %s" % sorted(options))
        return HostBackend(repo_root)
    raise BackendError("unknown backend %r" % (name,))
