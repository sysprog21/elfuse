# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional

from conformance import payload

EXIT_CURRENT, EXIT_ERROR, EXIT_DRIFT = 0, 2, 3


class UpdateError(RuntimeError):
    pass


def diff(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    out = []
    for section in sorted(set(old) | set(new)):
        a, b = old.get(section), new.get(section)
        if not isinstance(a, dict) or not isinstance(b, dict):
            if a != b:
                out.append("%s: %r -> %r" % (section, a, b))
            continue
        for key in sorted(set(a) | set(b)):
            if a.get(key) != b.get(key):
                out.append("%s.%s: %r -> %r" % (section, key, a.get(key), b.get(key)))
    return out


def refresh(provider: Any, ref: Optional[str] = None, check: bool = False,
            out: Callable[[str], None] = print) -> int:
    """Refresh pins through the provider schema and latest_pin hook."""
    try:
        current = payload.load_pins(provider.pins_path, provider.pins_schema)
        fresh = provider.latest_pin(copy.deepcopy(current), ref)
        payload.check_pins(fresh, provider.pins_schema)
    except (payload.PinError, UpdateError, OSError) as e:
        # Network failures from latest_pin are update errors.
        out("conformance: %s" % e)
        return EXIT_ERROR
    changes = diff(current, fresh)
    if not changes:
        out("%s: pins are current" % provider.pins_path)
        return EXIT_CURRENT
    for line in changes:
        out("  " + line)
    if check:
        out("%s: upstream has moved; run without --check to rewrite" % provider.pins_path)
        return EXIT_DRIFT
    try:
        payload.write_pins(provider.pins_path, fresh, provider.pins_schema)
    except OSError as e:
        out("conformance: %s" % e)
        return EXIT_ERROR
    out("%s: rewritten" % provider.pins_path)
    for step in provider.update_next_steps():
        out("  next: " + step)
    return EXIT_CURRENT
