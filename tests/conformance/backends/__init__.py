# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

from conformance.backends.base import Backend, BackendError

def make(name: str, repo_root: Path, **options: Any) -> Backend:
    if name == "elfuse":
        from conformance.backends.elfuse import ElfuseBackend as cls
    elif name == "qemu":
        from conformance.backends.qemu import QemuBackend as cls
    else:
        raise BackendError("unknown backend %r" % (name,))
    return cls(repo_root, **options)
