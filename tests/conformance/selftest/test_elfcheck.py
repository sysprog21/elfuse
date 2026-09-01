# Copyright 2026 elfuse contributors
# SPDX-License-Identifier: Apache-2.0

import struct
import unittest
from pathlib import Path

from conformance import elfcheck
from conformance.selftest.fixture import TempDirTest


def elf(machine=elfcheck.EM_AARCH64, interp=None, needed=(), load=True):
    phdrs = []
    body = bytearray()
    strtab = b"\0" + b"\0".join(n.encode() for n in needed) + b"\0"
    offsets, pos = [], 1
    for n in needed:
        offsets.append(pos)
        pos += len(n) + 1
    interp_bytes = (interp.encode() + b"\0") if interp else b""
    dyn = b"".join(struct.pack("<qQ", elfcheck.DT_NEEDED, o) for o in offsets)
    if needed:
        dyn += struct.pack("<qQ", elfcheck.DT_STRTAB, 0x10000)
    dyn += struct.pack("<qQ", elfcheck.DT_NULL, 0)
    body += strtab
    interp_off = len(body)
    body += interp_bytes
    dyn_off = len(body)
    body += dyn
    count = 1 + (1 if interp else 0) + (1 if needed else 0)
    if not load:
        count -= 1
    data_off = 64 + 56 * count
    if load:
        phdrs.append((elfcheck.PT_LOAD, 5, data_off, 0x10000, 0x10000, len(body), len(body), 0x1000))
    if interp:
        phdrs.append((elfcheck.PT_INTERP, 4, data_off + interp_off, 0, 0, len(interp_bytes), len(interp_bytes), 1))
    if needed:
        phdrs.append((elfcheck.PT_DYNAMIC, 6, data_off + dyn_off, 0, 0, len(dyn), len(dyn), 8))
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<H", header, 18, machine)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, len(phdrs))
    return bytes(header) + b"".join(struct.pack("<IIQQQQQQ", *p) for p in phdrs) + bytes(body)


class ElfcheckTest(TempDirTest):
    def setUp(self):
        super().setUp()
        self.path = self.dir / "bin"

    def check(self, image):
        self.path.write_bytes(image)
        elfcheck.validate_static_aarch64(self.path)

    def test_static(self):
        self.check(elf())

    def test_rejections(self):
        for image, fragment in (
            (elf(machine=62), "not AArch64"),
            (elf(interp="/lib/ld-linux-aarch64.so.1"), "PT_INTERP"),
            (elf(needed=("libc.so.6",)), "needs libc.so.6"),
            (b"not an elf", "not an ELF"),
            (elf(load=False), "PT_LOAD"),
        ):
            self.path.write_bytes(image)
            with self.assertRaises(elfcheck.ElfError) as cm:
                elfcheck.validate_static_aarch64(self.path)
            self.assertIn(fragment, str(cm.exception))

    def test_truncated_dynamic_is_an_elf_error(self):
        image = elf(needed=("libc.so.6",))
        self.path.write_bytes(image[:-8])
        with self.assertRaises(elfcheck.ElfError) as cm:
            elfcheck.read_dynamic(self.path)
        self.assertIn("dynamic segment out of range", str(cm.exception))

    def test_read_dynamic(self):
        self.path.write_bytes(elf(interp="/lib/ld.so", needed=("libc.so.6", "libm.so.6")))
        info = elfcheck.read_dynamic(self.path)
        self.assertEqual(info.interp, "/lib/ld.so")
        self.assertEqual(info.needed, ["libc.so.6", "libm.so.6"])


if __name__ == "__main__":
    unittest.main()
