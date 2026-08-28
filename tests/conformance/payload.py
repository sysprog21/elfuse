# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

MANIFEST = "manifest.json"
_HEX = {"hex40": re.compile(r"^[0-9a-f]{40}$"), "hex64": re.compile(r"^[0-9a-f]{64}$")}


class PayloadError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class PinError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fingerprint(pin_section: Dict[str, Any], files: Iterable[Path], flavor: str = "") -> str:
    h = hashlib.sha256()
    h.update(json.dumps(pin_section, sort_keys=True).encode())
    for path in files:
        h.update(path.name.encode() + b"\0")
        h.update(sha256_file(path).encode() + b"\0")
    h.update(flavor.encode())
    return h.hexdigest()


def _walk(root: Path) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in list(dirnames):
            path = Path(dirpath) / name
            if path.is_symlink():
                out[path.relative_to(root).as_posix()] = {"link": os.readlink(path)}
                dirnames.remove(name)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if rel == MANIFEST:
                continue
            if path.is_symlink():
                out[rel] = {"link": os.readlink(path)}
            else:
                st = path.stat()
                out[rel] = {"sha256": sha256_file(path), "size": st.st_size,
                            "mode": "%o" % (st.st_mode & 0o777)}
    return out


def write_manifest(root: Path, fp: str, extra: Optional[Dict[str, Any]] = None,
                   volatile: Iterable[str] = ()) -> Dict[str, Any]:
    """Permit new files below volatile prefixes during verification."""
    doc = {"schema_version": 1, "fingerprint": fp, "files": _walk(root), "extra": extra or {},
           "volatile": sorted(volatile)}
    atomic_write(root / MANIFEST, json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return doc


def read_manifest(root: Path) -> Dict[str, Any]:
    path = root / MANIFEST
    if not path.is_file():
        raise PayloadError("missing", "no %s under %s" % (MANIFEST, root))
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        raise PayloadError("corrupt", "%s: %s" % (path, e)) from None
    volatile = doc.get("volatile", []) if isinstance(doc, dict) else []
    if (not isinstance(doc, dict) or doc.get("schema_version") != 1
            or not isinstance(doc.get("files"), dict)
            or not isinstance(volatile, list) or not all(isinstance(v, str) for v in volatile)):
        raise PayloadError("corrupt", "%s: unexpected shape" % path)
    return doc


def verify(root: Path, expected_fp: Optional[str] = None) -> Dict[str, Any]:
    doc = read_manifest(root)
    if expected_fp is not None and doc.get("fingerprint") != expected_fp:
        raise PayloadError(
            "stale",
            "%s was built for fingerprint %s, the tree wants %s"
            % (root, str(doc.get("fingerprint"))[:12], expected_fp[:12]),
        )
    actual = _walk(root)
    want = doc["files"]
    # A trailing slash, so a volatile "tmp" does not also absorb "tmplog/".
    volatile = tuple(v.rstrip("/") + "/" for v in doc.get("volatile", []))
    missing = sorted(set(want) - set(actual))
    extra = sorted(k for k in set(actual) - set(want) if not k.startswith(volatile))
    changed = sorted(k for k in set(want) & set(actual) if want[k] != actual[k])
    if missing or extra or changed:
        parts = []
        for label, items in (("missing", missing), ("extra", extra), ("changed", changed)):
            if items:
                parts.append("%s: %s" % (label, ", ".join(items[:5]) + (" ..." if len(items) > 5 else "")))
        raise PayloadError("corrupt", "%s does not match its manifest (%s)" % (root, "; ".join(parts)))
    return doc


def status(root: Path, expected_fp: str) -> str:
    try:
        doc = read_manifest(root)
    except PayloadError as e:
        return e.kind
    return "ok" if doc.get("fingerprint") == expected_fp else "stale"


def absent_message(suite: str, root: Path, state: str, build_hint: str) -> str:
    return ("conformance: %s payload %s (%s); run: %s, see docs/conformance.md"
            % (suite, state, root, build_hint))


def atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        os.fchmod(fd, 0o644)  # generated files should not retain mkstemp's 0600
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def check_pins(doc: Any, schema: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise PinError("pins: schema_version must be 1")
    for section, fields in schema.items():
        body = doc.get(section)
        if not isinstance(body, dict):
            raise PinError("pins: missing section %r" % section)
        for name, kind in fields.items():
            value = body.get(name)
            where = "pins: %s.%s" % (section, name)
            if kind == "int":
                if not isinstance(value, int) or isinstance(value, bool):
                    raise PinError("%s must be an integer" % where)
            elif not isinstance(value, str) or not value:
                raise PinError("%s must be a non-empty string" % where)
            elif kind in _HEX and not _HEX[kind].match(value):
                raise PinError("%s is not a %s digest" % (where, kind))
            elif kind == "url" and not value.startswith("https://"):
                raise PinError("%s must be an https URL" % where)
    return doc


def load_pins(path: Path, schema: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise PinError("%s: %s" % (path, e)) from None
    return check_pins(doc, schema)


def write_pins(path: Path, doc: Dict[str, Any], schema: Dict[str, Dict[str, str]]) -> None:
    check_pins(doc, schema)
    atomic_write(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")
