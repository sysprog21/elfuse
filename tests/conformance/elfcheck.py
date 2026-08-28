# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

EM_AARCH64 = 183
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5


class ElfError(ValueError):
    pass


@dataclass
class DynamicInfo:
    machine: int
    interp: Optional[str] = None
    needed: List[str] = field(default_factory=list)
    has_load: bool = False


def _headers(data: bytes, path: Path) -> Tuple[int, list]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("%s: not an ELF file" % path)
    if data[4] != 2 or data[5] != 1:
        raise ElfError("%s: not ELF64 little-endian" % path)
    machine = struct.unpack_from("<H", data, 18)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or phoff + phnum * 56 > len(data):
        raise ElfError("%s: program header table out of range" % path)
    phdrs = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56) for i in range(phnum)]
    return machine, phdrs


def _vaddr_to_offset(phdrs: list, vaddr: int) -> Optional[int]:
    for p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ in phdrs:
        if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def _cstring(data: bytes, offset: int, path: Path) -> str:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ElfError("%s: string out of range" % path)
    return data[offset:end].decode("ascii", "replace")


def read_dynamic(path: Path) -> DynamicInfo:
    data = path.read_bytes()
    machine, phdrs = _headers(data, path)
    info = DynamicInfo(machine)
    for p_type, _, p_offset, _, _, p_filesz, _, _ in phdrs:
        if p_type == PT_LOAD:
            info.has_load = True
        elif p_type == PT_INTERP:
            info.interp = _cstring(data, p_offset, path)
        elif p_type == PT_DYNAMIC:
            if p_offset + p_filesz > len(data):
                raise ElfError("%s: dynamic segment out of range" % path)
            entries = [struct.unpack_from("<qQ", data, p_offset + i * 16) for i in range(p_filesz // 16)]
            strtab = next((v for t, v in entries if t == DT_STRTAB), None)
            needed = [v for t, v in entries if t == DT_NEEDED]
            if needed:
                if strtab is None:
                    raise ElfError("%s: DT_NEEDED without DT_STRTAB" % path)
                base = _vaddr_to_offset(phdrs, strtab)
                if base is None:
                    raise ElfError("%s: DT_STRTAB outside any PT_LOAD" % path)
                info.needed = [_cstring(data, base + off, path) for off in needed]
    return info


def validate_static_aarch64(path: Path) -> None:
    info = read_dynamic(path)
    if info.machine != EM_AARCH64:
        raise ElfError("%s: machine %d is not AArch64" % (path, info.machine))
    if not info.has_load:
        raise ElfError("%s: no PT_LOAD segment" % path)
    if info.interp is not None:
        raise ElfError("%s: has PT_INTERP %s, not static" % (path, info.interp))
    if info.needed:
        raise ElfError("%s: needs %s, not static" % (path, ", ".join(info.needed)))
