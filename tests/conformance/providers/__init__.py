# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Dict, Type, Union

from conformance.providers.base import Provider, ProviderError

REGISTRY: Dict[str, Union[str, Type[Provider]]] = {}


def make(name: str, repo_root: Path) -> Provider:
    if name not in REGISTRY:
        raise ProviderError(
            "unknown suite %r; registered: %s"
            % (name, ", ".join(sorted(REGISTRY)) or "none")
        )
    target = REGISTRY[name]
    if isinstance(target, str):
        module, _, cls = target.partition(":")
        target = getattr(importlib.import_module(module), cls)
    if target.name != name:
        # A blank name would collapse suite_dir and payload_root onto the
        # shared parents.
        raise ProviderError("provider for %r declares name %r" % (name, target.name))
    return target(repo_root)
