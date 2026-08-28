# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Dict

from conformance.providers.base import Provider, ProviderError

REGISTRY: Dict[str, str] = {
    "fake": "conformance.providers.fake:FakeProvider",
}


def make(name: str, repo_root: Path) -> Provider:
    if name not in REGISTRY:
        raise ProviderError("unknown suite %r; registered: %s" % (name, ", ".join(sorted(REGISTRY))))
    module, _, cls = REGISTRY[name].partition(":")
    return getattr(importlib.import_module(module), cls)(repo_root)
