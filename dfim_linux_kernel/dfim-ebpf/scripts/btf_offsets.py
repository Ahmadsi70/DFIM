#!/usr/bin/env python3
"""Extract CO-RE field byte offsets from /sys/kernel/btf/vmlinux."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

BTF_MAGIC = 0xEB9F
TARGET_FIELDS = {
    "linux_binprm": "file",
    "file": "f_inode",
    "inode": "i_ino",
}


def read_cstr(data: bytes, base: int, off: int) -> str:
    if off == 0:
        return ""
    start = base + off
    if start >= len(data):
        raise ValueError(f"string offset out of range: {off}")
    end = data.index(0, start)
    return data[start:end].decode()


def member_byte_offset(raw_offset: int) -> int:
    return (raw_offset & 0xFFFFFF) // 8


def type_info_size(kind: int, vlen: int) -> int:
    if kind in (4, 5):
        return 12 + vlen * 12
    if kind == 1:
        return 16
    if kind == 3:
        return 24
    if kind == 6:
        return 12 + vlen * 8
    if kind == 19:
        return 12 + vlen * 12
    if kind == 12:  # func — vlen is linkage, not member count
        return 12
    if kind == 13:  # func_proto
        return 12 + vlen * 8
    if kind == 14:
        return 16
    if kind == 15:
        return 12 + vlen * 16
    if kind in (16, 17):
        return 16
    return 12


def parse_offsets(path: Path) -> dict[str, int]:
    data = path.read_bytes()
    magic, _ver, _flags, hdr_len, type_off, type_len, str_off, _str_len = struct.unpack_from(
        "<HBBIIIII", data, 0
    )
    if magic != BTF_MAGIC:
        raise ValueError(f"invalid BTF magic: {magic:#x}")

    str_base = hdr_len + str_off
    type_base = hdr_len + type_off
    found: dict[str, int] = {}

    off = 0
    while off < type_len:
        name_off, info = struct.unpack_from("<II", data, type_base + off)
        kind = info >> 24
        vlen = info & 0xFFFF
        name = read_cstr(data, str_base, name_off)

        if kind in (4, 5) and name in TARGET_FIELDS:
            pos = type_base + off + 12
            want = TARGET_FIELDS[name]
            for i in range(vlen):
                mname_off, _mtype, moff = struct.unpack_from("<III", data, pos + i * 12)
                member = read_cstr(data, str_base, mname_off)
                if member == want:
                    found[name] = member_byte_offset(moff)
                    break

        off += type_info_size(kind, vlen)

    missing = set(TARGET_FIELDS) - set(found)
    if missing:
        raise KeyError(f"missing offsets for: {sorted(missing)}")

    return found


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "/sys/kernel/btf/vmlinux")
    offsets = parse_offsets(path)
    for struct_name, field in TARGET_FIELDS.items():
        print(f"{struct_name.upper()}_{field.upper()}={offsets[struct_name]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
