# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsoncError(ValueError):
    pass


def strip(text: str) -> str:
    out = []
    comma = None
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            comma = None
            i = j + 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise JsoncError("unterminated block comment")
            # Preserve token separation when a block comment is removed.
            out.append(" " + "\n" * text.count("\n", i, j))
            i = j + 2
        else:
            if c == ",":
                comma = len(out)
            elif c in "]}" and comma is not None:
                out[comma] = ""
                comma = None
            elif not c.isspace():
                comma = None
            out.append(c)
            i += 1
    return "".join(out)


def _reject(literal: str) -> Any:
    raise JsoncError("%s is not JSON" % literal)


def loads(text: str) -> Any:
    try:
        return json.loads(strip(text), parse_constant=_reject)
    except json.JSONDecodeError as e:
        raise JsoncError("line %d: %s" % (e.lineno, e.msg)) from None


def load(path: Path) -> Any:
    try:
        return loads(path.read_text())
    except (JsoncError, OSError, UnicodeDecodeError) as e:
        raise JsoncError("%s: %s" % (path, e)) from None
