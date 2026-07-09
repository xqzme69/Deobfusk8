from __future__ import annotations

from typing import List, Optional, Tuple

from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, Cs
from capstone.x86 import X86_REG_RIP

from .pe import PEImage, Addr


def make_cs() -> Cs:
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True
    return cs


def find_functions_referencing(pe: PEImage, cs: Cs, target_va: Addr) -> List[Addr]:
    refs: List[Addr] = []
    text = pe.text
    if not text:
        return refs
    data = text["data"]
    base = text["va"]
    for insn in cs.disasm(data, base):
        if insn.mnemonic == "lea" and len(insn.operands) == 2:
            op = insn.operands[1]
            if op.type == CS_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    addr = insn.address + insn.size + op.mem.disp
                    if addr == target_va:
                        refs.append(insn.address)
    return refs


def find_function_boundaries(
    pe: PEImage, cs: Cs, addr_in_func: Addr
) -> Tuple[Optional[Addr], Optional[Addr]]:
    text = pe.section_for_va(addr_in_func)
    if not text:
        return (None, None)
    data = text["data"]
    base = text["va"]
    prologues = [
        b"H\x83\xec",
        b"H\x81\xec",
        b"H\x89\\$",
        b"@S",
        b"@U",
        b"@V",
        b"@W",
        b"U",
        b"S",
        b"V",
        b"W",
        b"AT",
        b"AU",
        b"AV",
        b"AW",
    ]
    offset = addr_in_func - base
    search_start = max(0, offset - 8192)
    best_start = None
    for off in range(offset - 1, search_start, -1):
        for p in prologues:
            if data[off : off + len(p)] == p:
                if off > 0 and data[off - 1] in (195, 204, 194, 144):
                    best_start = base + off
                    break
                if (base + off) % 16 == 0:
                    best_start = base + off
                    break
        if best_start:
            break
    if not best_start:
        for off in range(offset - 1, search_start, -1):
            if data[off] in (195, 204) and off + 1 < len(data):
                best_start = base + off + 1
                while pe.read_va(best_start, 1) in (b"\x90", b"\xcc"):
                    best_start += 1
                break
    if not best_start:
        return (None, None)
    func_end = None
    for insn in cs.disasm(data[best_start - base :], best_start):
        if insn.address > addr_in_func + 4096:
            break
        if insn.mnemonic == "ret" and insn.address > addr_in_func:
            func_end = insn.address + insn.size
            break
    return (best_start, func_end)
