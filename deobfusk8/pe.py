from __future__ import annotations
from typing import Any, Dict, Iterable, List, Optional
import pefile

Addr = int


class PEImage:
    def __init__(self, path: str):
        self.path = path
        self.pe = pefile.PE(path)
        self.base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        with open(path, "rb") as f:
            self.raw = f.read()
        self.sections: List[Dict[str, Any]] = []
        for s in self.pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="replace")
            self.sections.append(
                {
                    "name": name,
                    "va": self.base + int(s.VirtualAddress),
                    "vsize": int(s.Misc_VirtualSize),
                    "raw_offset": int(s.PointerToRawData),
                    "raw_size": int(s.SizeOfRawData),
                    "data": s.get_data(),
                }
            )

    def section_for_va(self, va: Addr) -> Optional[Dict[str, Any]]:
        for s in self.sections:
            if s["va"] <= va < s["va"] + max(s["vsize"], s["raw_size"]):
                return s
        return None

    def va_to_offset(self, va: Addr) -> Optional[int]:
        s = self.section_for_va(va)
        if not s:
            return None
        return s["raw_offset"] + (va - s["va"])

    def read_va(self, va: Addr, size: int) -> Optional[bytes]:
        off = self.va_to_offset(va)
        if off is None or off < 0 or off >= len(self.raw):
            return None
        return self.raw[off : off + size]

    def read_c_string(self, va: Addr, max_len: int = 4096) -> bytes:
        data = self.read_va(va, max_len) or b""
        return data.split(b"\x00", 1)[0]

    def find_pattern(
        self, pattern: bytes, sections: Optional[Iterable[str]] = None
    ) -> List[Addr]:
        names = set(sections) if sections else None
        out: List[Addr] = []
        for s in self.sections:
            if names and s["name"] not in names:
                continue
            data = s["data"]
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx < 0:
                    break
                out.append(s["va"] + idx)
                idx += 1
        return out

    @property
    def text(self) -> Optional[Dict[str, Any]]:
        for s in self.sections:
            if s["name"] == ".text" or s["va"] == self.base + 4096:
                return s
        return None
