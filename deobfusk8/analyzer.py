from __future__ import annotations
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import time
import json
import re
import struct
from dataclasses import asdict
from .aes import INV_SBOX, decrypt_aes_ecb
from capstone.x86 import X86_REG_RIP
from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from .pe import PEImage, Addr
from .disasm import make_cs, find_function_boundaries
from .hash import fnv1a_32, u32
from .result import (
    CallSiteResult,
    UniversalResult,
    Evidence,
    StrategyTrace,
    KeyTemplateResult,
    KSCandidate,
    UNKNOWN,
)
from .interpreter import (
    LocalConcreteInterpreter,
    CopyingLocalInterpreter,
    ConcreteState,
)
from .key import (
    KeyMixerTemplate,
    Obfusk8AES8TwoPassKeyMixer,
    Obfusk8CompilerFoldedInitTemplate,
    MBASimplifier,
)
from .resolve8 import Resolve8HashResolver, COMMON_APIS
from .k8_syscall import (
    K8SyscallAnalyzer,
    InlineDecryptDiscovery,
    RuntimeKeyBackwardSlicer,
)


class Analyzer:
    def __init__(self, path: str, verbose: bool = False):
        self.pe = PEImage(path)
        self.cs = make_cs()
        self.verbose = verbose
        self._func_const_cache: Dict[Addr, Optional[int]] = {}
        self._func_source_cache: Dict[Addr, Optional[Addr]] = {}
        self._func_raw_chunks_cache: Dict[Addr, Tuple[Optional[int], Optional[int]]] = (
            {}
        )
        self._text_insns_cache: Optional[List[Any]] = None
        self._bounds_cache: Dict[Addr, Tuple[Optional[Addr], Optional[Addr]]] = {}
        self.fnv_func: Optional[Addr] = None
        self.build_hash: Optional[int] = None
        self.build_hash_inputs: List[str] = []

    def reg_name(self, reg: int) -> str:
        return self.cs.reg_name(reg) or ""

    def canon_reg(self, reg: int) -> str:
        n = self.reg_name(reg)
        return {
            "al": "rax",
            "ah": "rax",
            "ax": "rax",
            "eax": "rax",
            "bl": "rbx",
            "bh": "rbx",
            "bx": "rbx",
            "ebx": "rbx",
            "cl": "rcx",
            "ch": "rcx",
            "cx": "rcx",
            "ecx": "rcx",
            "dl": "rdx",
            "dh": "rdx",
            "dx": "rdx",
            "edx": "rdx",
            "sil": "rsi",
            "si": "rsi",
            "esi": "rsi",
            "dil": "rdi",
            "di": "rdi",
            "edi": "rdi",
            "bp": "rbp",
            "ebp": "rbp",
            "sp": "rsp",
            "esp": "rsp",
            "r8b": "r8",
            "r8w": "r8",
            "r8d": "r8",
            "r9b": "r9",
            "r9w": "r9",
            "r9d": "r9",
            "r10b": "r10",
            "r10w": "r10",
            "r10d": "r10",
            "r11b": "r11",
            "r11w": "r11",
            "r11d": "r11",
            "r12b": "r12",
            "r12w": "r12",
            "r12d": "r12",
            "r13b": "r13",
            "r13w": "r13",
            "r13d": "r13",
            "r14b": "r14",
            "r14w": "r14",
            "r14d": "r14",
            "r15b": "r15",
            "r15w": "r15",
            "r15d": "r15",
        }.get(n, n)

    @staticmethod
    def is_printable_blob(data: bytes) -> bool:
        if not data:
            return False
        good = 0
        for b in data:
            if b in (9, 10, 13) or 32 <= b < 127:
                good += 1
        return good / max(1, len(data)) >= 0.85

    def rip_target(self, insn: Any, mem_op: Any) -> Addr:
        return int(insn.address + insn.size + mem_op.mem.disp)

    def disasm_range(self, start: Addr, size: int) -> List[Any]:
        data = self.pe.read_va(start, size) or b""
        return list(self.cs.disasm(data, start))

    def text_insns(self) -> List[Any]:
        if self._text_insns_cache is None:
            text = self.pe.text
            self._text_insns_cache = (
                list(self.cs.disasm(text["data"][:131072], text["va"])) if text else []
            )
        return self._text_insns_cache

    def context_insns(
        self, center: Addr, before: int = 6144, after: int = 64
    ) -> List[Any]:
        sec = self.pe.section_for_va(center)
        sec_start = sec["va"] if sec else max(0, center - before)
        base0 = max(sec_start, center - before)
        size0 = max(0, center - base0 + after)
        best: List[Any] = []
        for delta in range(0, 16):
            start = base0 + delta
            if start >= center:
                break
            ins = self.disasm_range(start, max(0, size0 - delta))
            if len(ins) > len(best):
                best = ins
            if any((x.address == center for x in ins)):
                return ins
        fstart, _ = self.find_function_boundaries(center)
        if (
            fstart is not None
            and fstart < center
            and (center - fstart <= max(before, 12288))
        ):
            return self.disasm_range(fstart, center - fstart + after)
        return best

    def find_insn_index(self, insns: List[Any], addr: Addr) -> int:
        return next((i for i, x in enumerate(insns) if x.address == addr), -1)

    def find_rsbox(self) -> Optional[Addr]:
        sig = bytes(INV_SBOX[:16])
        locs = self.pe.find_pattern(sig)
        if not locs:
            return None
        for va in locs:
            data = self.pe.read_va(va, 256)
            if data and list(data) == INV_SBOX:
                return va
        return locs[0]

    def find_functions_referencing(self, target_va: Addr) -> List[Addr]:
        text = self.pe.text
        if not text:
            return []
        refs: List[Addr] = []
        for insn in self.cs.disasm(text["data"], text["va"]):
            if insn.mnemonic == "lea" and len(insn.operands) == 2:
                dst, src = insn.operands
                if src.type == CS_OP_MEM and src.mem.base == X86_REG_RIP:
                    if self.rip_target(insn, src) == target_va:
                        refs.append(insn.address)
        return refs

    def find_function_boundaries(
        self, addr_in_func: Addr
    ) -> Tuple[Optional[Addr], Optional[Addr]]:
        if addr_in_func in self._bounds_cache:
            return self._bounds_cache[addr_in_func]
        sec = self.pe.section_for_va(addr_in_func)
        if not sec:
            self._bounds_cache[addr_in_func] = (None, None)
            return (None, None)
        data = sec["data"]
        base = sec["va"]
        off = addr_in_func - base
        search_start = max(0, off - 12288)
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
        best = None
        for i in range(off - 1, search_start, -1):
            for p in prologues:
                if data[i : i + len(p)] == p:
                    va = base + i
                    if va % 16 == 0 or (i > 0 and data[i - 1] in (195, 194, 204, 144)):
                        best = va
                        break
            if best:
                break
        if not best:
            for i in range(off - 1, search_start, -1):
                if data[i] in (195, 194, 204):
                    best = base + i + 1
                    while self.pe.read_va(best, 1) in (b"\x90", b"\xcc"):
                        best += 1
                    break
        if not best:
            self._bounds_cache[addr_in_func] = (None, None)
            return (None, None)
        end = None
        for insn in self.cs.disasm(data[best - base :], best):
            if insn.address > addr_in_func + 8192:
                break
            if insn.mnemonic == "ret" and insn.address > addr_in_func:
                end = insn.address + insn.size
                break
        self._bounds_cache[addr_in_func] = (best, end)
        return (best, end)

    def build_xrefs(self) -> Dict[Addr, List[Addr]]:
        out: Dict[Addr, List[Addr]] = {}
        text = self.pe.text
        if not text:
            return out
        for insn in self.cs.disasm(text["data"], text["va"]):
            if (
                insn.mnemonic == "call"
                and len(insn.operands) == 1
                and (insn.operands[0].type == CS_OP_IMM)
            ):
                out.setdefault(int(insn.operands[0].imm), []).append(insn.address)
        return out

    def find_decrypt_calls(self) -> Tuple[List[Addr], List[Tuple[Addr, Addr]]]:
        rsbox = self.find_rsbox()
        if rsbox is None:
            return ([], [])
        if self.verbose:
            print(f"[+] rsbox: 0x{rsbox:X}")
        refs = self.find_functions_referencing(rsbox)
        if not refs:
            return ([], [])
        subbytes_func, _ = self.find_function_boundaries(refs[0])
        if not subbytes_func:
            return ([], [])
        xrefs = self.build_xrefs()
        decrypt_block_funcs = set()
        for call_addr in xrefs.get(subbytes_func, []):
            f, _ = self.find_function_boundaries(call_addr)
            if f:
                decrypt_block_funcs.add(f)
        decrypt_funcs = set()
        for db in decrypt_block_funcs:
            for call_addr in xrefs.get(db, []):
                f, _ = self.find_function_boundaries(call_addr)
                if f:
                    decrypt_funcs.add(f)
        user_calls: List[Tuple[Addr, Addr]] = []
        for df in decrypt_funcs:
            for call_addr in xrefs.get(df, []):
                user_calls.append((call_addr, df))
        return (sorted(decrypt_funcs), sorted(user_calls))

    def resolve_reg_backwards(
        self, insns: List[Any], idx: int, reg: int, depth: int = 0
    ) -> Optional[Value]:
        if depth > 8:
            return None
        want = self.canon_reg(reg)
        for j in range(idx - 1, -1, -1):
            insn = insns[j]
            if not insn.operands:
                continue
            dst = insn.operands[0]
            if dst.type != CS_OP_REG or self.canon_reg(dst.reg) != want:
                continue
            if insn.mnemonic == "mov" and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == CS_OP_IMM:
                    return int(src.imm)
                if src.type == CS_OP_REG:
                    return self.resolve_reg_backwards(insns, j, src.reg, depth + 1)
                if src.type == CS_OP_MEM and src.mem.base == X86_REG_RIP:
                    data = self.pe.read_va(self.rip_target(insn, src), 8)
                    return int.from_bytes(data or b"\x00" * 8, "little")
                return None
            if insn.mnemonic == "lea" and len(insn.operands) >= 2:
                src = insn.operands[1]
                if src.type == CS_OP_MEM:
                    if src.mem.base == X86_REG_RIP:
                        return self.rip_target(insn, src)
                    base = self.reg_name(src.mem.base)
                    if base in ("rbp", "rsp") and src.mem.index == 0:
                        return (base, int(src.mem.disp))
                return None
            if (
                insn.mnemonic == "call"
                and len(insn.operands) == 1
                and (insn.operands[0].type == CS_OP_IMM)
            ):
                return self.summarize_const_return(int(insn.operands[0].imm))
            if insn.mnemonic == "xor" and len(insn.operands) == 2:
                s = insn.operands[1]
                if s.type == CS_OP_REG and self.canon_reg(s.reg) == want:
                    return 0
            return None
        return None

    def summarize_const_return(self, addr: Addr) -> Optional[int]:
        if addr in self._func_const_cache:
            return self._func_const_cache[addr]
        val: Optional[int] = None
        try:
            insns = self.disasm_range(addr, 288)
            regs: Dict[str, int] = {}
            for insn in insns:
                m = insn.mnemonic
                ops = insn.operands
                if m == "mov" and len(ops) == 2 and (ops[0].type == CS_OP_REG):
                    dst = self.canon_reg(ops[0].reg)
                    if dst == "rax":
                        if ops[1].type == CS_OP_IMM:
                            regs["rax"] = int(ops[1].imm) & 18446744073709551615
                        elif (
                            ops[1].type == CS_OP_REG
                            and self.canon_reg(ops[1].reg) in regs
                        ):
                            regs["rax"] = regs[self.canon_reg(ops[1].reg)]
                        else:
                            regs.pop("rax", None)
                elif m == "call" and len(ops) == 1 and (ops[0].type == CS_OP_IMM):
                    sub = self.summarize_const_return(int(ops[0].imm))
                    if sub is None:
                        regs.pop("rax", None)
                    else:
                        regs["rax"] = sub
                elif (
                    m == "add"
                    and len(ops) == 2
                    and (ops[0].type == CS_OP_REG)
                    and (self.canon_reg(ops[0].reg) == "rax")
                    and (ops[1].type == CS_OP_IMM)
                ):
                    regs["rax"] = (
                        regs.get("rax", 0) + int(ops[1].imm) & 18446744073709551615
                    )
                elif (
                    m == "shr"
                    and len(ops) == 2
                    and (ops[0].type == CS_OP_REG)
                    and (self.canon_reg(ops[0].reg) == "rax")
                    and (ops[1].type == CS_OP_IMM)
                ):
                    regs["rax"] = regs.get("rax", 0) >> int(ops[1].imm)
                elif m == "ret":
                    val = regs.get("rax")
                    break
        except Exception:
            val = None
        self._func_const_cache[addr] = val
        return val

    def summarize_source_pointer(self, addr: Addr) -> Optional[Addr]:
        if addr in self._func_source_cache:
            return self._func_source_cache[addr]
        src: Optional[Addr] = None
        try:
            insns = self.disasm_range(addr, 352)
            for insn in insns:
                if insn.mnemonic == "lea" and len(insn.operands) == 2:
                    dst, mem = insn.operands
                    if (
                        dst.type == CS_OP_REG
                        and self.canon_reg(dst.reg) == "rdx"
                        and (mem.type == CS_OP_MEM)
                        and (mem.mem.base == X86_REG_RIP)
                    ):
                        src = self.rip_target(insn, mem)
                        break
                if insn.mnemonic == "ret":
                    break
        except Exception:
            src = None
        self._func_source_cache[addr] = src
        return src

    def summarize_helper_raw_chunks(
        self, addr: Addr
    ) -> Tuple[Optional[int], Optional[int]]:
        if addr in self._func_raw_chunks_cache:
            return self._func_raw_chunks_cache[addr]
        raw: Optional[int] = None
        chunks: Optional[int] = None
        first_call: Optional[int] = None
        call_count = 0
        try:
            insns = self.disasm_range(addr, 864)
            for insn in insns:
                if (
                    insn.mnemonic == "call"
                    and len(insn.operands) == 1
                    and (insn.operands[0].type == CS_OP_IMM)
                ):
                    call_count += 1
                    if first_call is None:
                        first_call = int(insn.operands[0].imm)
                if insn.mnemonic == "mov" and len(insn.operands) == 2:
                    dst, src = insn.operands
                    if (
                        dst.type == CS_OP_MEM
                        and self.reg_name(dst.mem.base) == "rsp"
                        and (dst.mem.disp == 104)
                        and (src.type == CS_OP_IMM)
                    ):
                        chunks = int(src.imm)
                if insn.mnemonic == "cmp" and len(insn.operands) == 2:
                    a, b = insn.operands
                    if (
                        a.type == CS_OP_MEM
                        and self.reg_name(a.mem.base) == "rsp"
                        and (a.mem.disp == 88)
                        and (b.type == CS_OP_IMM)
                    ):
                        raw = int(b.imm)
                if raw is not None and chunks is not None:
                    break
                if insn.mnemonic == "ret":
                    break
            if (
                (raw is None or chunks is None)
                and first_call is not None
                and (call_count <= 2)
            ):
                sub_raw, sub_chunks = self.summarize_helper_raw_chunks(first_call)
                raw = raw if raw is not None else sub_raw
                chunks = chunks if chunks is not None else sub_chunks
        except Exception:
            raw, chunks = (None, None)
        self._func_raw_chunks_cache[addr] = (raw, chunks)
        return (raw, chunks)

    def detect_build_hash(self) -> Optional[int]:
        text = self.pe.text
        if not text:
            return None
        for insn in self.cs.disasm(text["data"], text["va"]):
            if (
                insn.mnemonic == "mov"
                and len(insn.operands) == 2
                and (insn.operands[1].type == CS_OP_IMM)
                and (int(insn.operands[1].imm) == 2166136261)
            ):
                fstart, _ = self.find_function_boundaries(insn.address)
                if not fstart:
                    fstart = max(text["va"], insn.address - 48)
                fins = self.disasm_range(fstart, 288)
                strings: List[bytes] = []
                for fi in fins:
                    if fi.mnemonic == "lea" and len(fi.operands) == 2:
                        dst, src = fi.operands
                        if (
                            dst.type == CS_OP_REG
                            and self.canon_reg(dst.reg) == "rax"
                            and (src.type == CS_OP_MEM)
                            and (src.mem.base == X86_REG_RIP)
                        ):
                            s = self.pe.read_c_string(self.rip_target(fi, src), 128)
                            if s and self.is_printable_blob(s):
                                strings.append(s)
                    if fi.mnemonic == "ret":
                        break
                if len(strings) >= 2:
                    self.fnv_func = fstart
                    self.build_hash_inputs = [
                        x.decode("utf-8", errors="replace") for x in strings[:2]
                    ]
                    self.build_hash = fnv1a_32(strings[0], strings[1])
                    return self.build_hash
        return None

    def recover_source_from_context(
        self, insns: List[Any], call_idx: int
    ) -> Tuple[Optional[Addr], Optional[Addr], str]:
        for j in range(call_idx - 1, -1, -1):
            insn = insns[j]
            if (
                insn.mnemonic != "call"
                or len(insn.operands) != 1
                or insn.operands[0].type != CS_OP_IMM
            ):
                continue
            target = int(insn.operands[0].imm)
            if self.fnv_func and target == self.fnv_func:
                continue
            src: Optional[Addr] = None
            for k in range(j - 1, -1, -1):
                x = insns[k]
                if not x.operands:
                    continue
                dst = x.operands[0]
                if dst.type == CS_OP_REG and self.canon_reg(dst.reg) == "rdx":
                    if (
                        x.mnemonic == "lea"
                        and len(x.operands) == 2
                        and (x.operands[1].type == CS_OP_MEM)
                        and (x.operands[1].mem.base == X86_REG_RIP)
                    ):
                        src = self.rip_target(x, x.operands[1])
                    elif (
                        x.mnemonic == "mov"
                        and len(x.operands) == 2
                        and (x.operands[1].type == CS_OP_IMM)
                    ):
                        src = int(x.operands[1].imm)
                    break
            if src is not None and self.pe.section_for_va(src):
                return (src, target, "caller_rdx")
            src = self.summarize_source_pointer(target)
            if src is not None and self.pe.section_for_va(src):
                return (src, target, "callee_lea")
        return (None, None, "none")

    def recover_args_from_context(
        self,
        insns: List[Any],
        call_idx: int,
        helper: Optional[Addr],
        source_va: Optional[Addr],
    ) -> Tuple[Optional[int], Optional[int]]:
        chunks: Optional[int] = None
        raw_size: Optional[int] = None
        for k in range(call_idx - 1, -1, -1):
            insn = insns[k]
            if not insn.operands:
                continue
            dst = insn.operands[0]
            if (
                dst.type == CS_OP_REG
                and self.canon_reg(dst.reg) == "r8"
                and (chunks is None)
            ):
                val = self._value_from_writer(insns, k)
                if isinstance(val, int):
                    chunks = val
            if (
                dst.type == CS_OP_REG
                and self.canon_reg(dst.reg) == "r9"
                and (raw_size is None)
            ):
                val = self._value_from_writer(insns, k)
                if isinstance(val, int):
                    raw_size = val
            if chunks is not None and raw_size is not None:
                break
        if helper is not None:
            h_raw, h_chunks = self.summarize_helper_raw_chunks(helper)
            if chunks is None or chunks <= 0 or chunks > 40:
                chunks = h_chunks
            if raw_size is None or raw_size <= 0 or raw_size > 640:
                raw_size = h_raw
        if raw_size is None and source_va is not None:
            s = self.pe.read_c_string(source_va, 4096)
            if s:
                raw_size = len(s) + 1
        if chunks is None and raw_size is not None:
            chunks = (raw_size + 15) // 16
        return (chunks, raw_size)

    def _value_from_writer(self, insns: List[Any], idx: int) -> Optional[Value]:
        insn = insns[idx]
        if len(insn.operands) < 2:
            if (
                insn.mnemonic == "call"
                and len(insn.operands) == 1
                and (insn.operands[0].type == CS_OP_IMM)
            ):
                return self.summarize_const_return(int(insn.operands[0].imm))
            return None
        src = insn.operands[1]
        if insn.mnemonic == "mov":
            if src.type == CS_OP_IMM:
                return int(src.imm)
            if src.type == CS_OP_REG:
                return self.resolve_reg_backwards(insns, idx, src.reg)
        if insn.mnemonic == "lea" and src.type == CS_OP_MEM:
            if src.mem.base == X86_REG_RIP:
                return self.rip_target(insn, src)
            base = self.reg_name(src.mem.base)
            if base in ("rbp", "rsp") and src.mem.index == 0:
                return (base, int(src.mem.disp))
        return None

    def recover_runtime_key(
        self, call_addr: Addr
    ) -> Tuple[Optional[bytes], Dict[str, Any]]:
        meta: Dict[str, Any] = {}
        build_hash = (
            self.build_hash if self.build_hash is not None else self.detect_build_hash()
        )
        if build_hash is None:
            meta["error"] = "build_hash_not_found"
            return (None, meta)
        insns = self.context_insns(call_addr, before=6144, after=32)
        candidates: List[Tuple[int, str, int]] = []
        for i, insn in enumerate(insns):
            if insn.address >= call_addr:
                break
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                dst, src = insn.operands
                if (
                    dst.type == CS_OP_MEM
                    and src.type == CS_OP_REG
                    and (self.reg_name(src.reg) == "al")
                ):
                    base = self.reg_name(dst.mem.base)
                    if base in ("rbp", "rsp"):
                        candidates.append((i, base, int(dst.mem.disp)))
        last_error = "no_key_init_candidate"
        for i0, base, keyoff in reversed(candidates):
            key, info, err = self._try_recover_key_from_candidate(
                insns, i0, base, keyoff, build_hash
            )
            if key is not None:
                meta.update(info)
                return (key, meta)
            last_error = err
        meta["error"] = last_error
        return (None, meta)

    def _try_recover_key_from_candidate(
        self, insns: List[Any], i0: int, base: str, keyoff: int, build_hash: int
    ) -> Tuple[Optional[bytes], Dict[str, Any], str]:
        word = None
        b3 = None
        orimm = None
        for insn in insns[i0 + 1 : min(len(insns), i0 + 45)]:
            if (
                insn.mnemonic == "mov"
                and len(insn.operands) == 2
                and (insn.operands[0].type == CS_OP_MEM)
                and (self.reg_name(insn.operands[0].mem.base) == base)
                and (insn.operands[1].type == CS_OP_IMM)
            ):
                disp = int(insn.operands[0].mem.disp)
                if disp == keyoff + 1:
                    word = int(insn.operands[1].imm) & 65535
                elif disp == keyoff + 3:
                    b3 = int(insn.operands[1].imm) & 255
            if (
                insn.mnemonic == "or"
                and len(insn.operands) == 2
                and (insn.operands[0].type == CS_OP_REG)
                and (self.canon_reg(insn.operands[0].reg) == "rax")
                and (insn.operands[1].type == CS_OP_IMM)
            ):
                orimm = int(insn.operands[1].imm) & 255
        if word is None or b3 is None or orimm is None:
            return (None, {}, "key_init_constants_missing")
        ks_bytes = None
        ks_off = None
        ks_src = None
        for j in range(i0 - 1, max(-1, i0 - 160), -1):
            insn = insns[j]
            if (
                insn.mnemonic not in ("movaps", "movups", "movdqa", "movdqu")
                or len(insn.operands) != 2
            ):
                continue
            dst, src = insn.operands
            if (
                dst.type == CS_OP_MEM
                and self.reg_name(dst.mem.base) == base
                and (src.type == CS_OP_REG)
            ):
                ks_off = int(dst.mem.disp)
                xmm = self.reg_name(src.reg)
                for k in range(j - 1, max(-1, j - 32), -1):
                    prev = insns[k]
                    if (
                        prev.mnemonic in ("movaps", "movups", "movdqa", "movdqu")
                        and len(prev.operands) == 2
                    ):
                        pdst, psrc = prev.operands
                        if (
                            pdst.type == CS_OP_REG
                            and self.reg_name(pdst.reg) == xmm
                            and (psrc.type == CS_OP_MEM)
                            and (psrc.mem.base == X86_REG_RIP)
                        ):
                            ks_src = self.rip_target(prev, psrc)
                            ks_bytes = self.pe.read_va(ks_src, 16)
                            break
                break
        if not ks_bytes or len(ks_bytes) < 16:
            return (None, {}, "ks_xmm_source_missing")
        key = self._obfusk8_key_from_pattern(build_hash, ks_bytes, word, b3, orimm)
        info = {
            "key_base": base,
            "key_offset": keyoff,
            "ks_offset": ks_off,
            "ks_source_va": ks_src,
            "ks_initial": ks_bytes.hex(),
            "init_word": word,
            "init_byte3": b3,
            "or_imm": orimm,
        }
        return (key, info, "ok")

    @staticmethod
    def _obfusk8_key_from_pattern(
        build_hash: int, ks_bytes: bytes, word: int, byte3: int, or_imm: int
    ) -> bytes:
        words = [int.from_bytes(ks_bytes[i : i + 4], "little") for i in range(0, 16, 4)]
        key = bytearray(16)
        key[0] = build_hash & 255
        key[1:3] = int(word).to_bytes(2, "little")
        key[3] = byte3 & 255

        def idx_first(i: int, edx_ctr: int) -> int:
            if i < 8:
                return edx_ctr
            if i <= 11:
                return i - 8 >> 1
            return (i - 12 >> 1) + 2

        def idx_second(i: int) -> int:
            if i <= 3:
                return i
            if i <= 7:
                return 7 - i
            if i <= 11:
                return i - 8 >> 1
            return (i - 12 >> 1) + 2

        eax = u32(build_hash & 4294967040 | or_imm & 255)
        edx_ctr = 3
        for i in range(4, 16):
            r = words[idx_first(i, edx_ctr)]
            tmp = u32(eax ^ r)
            v = u32(tmp ^ i)
            corr = u32(~tmp & i)
            v = u32(v - u32(corr + corr))
            out = u32(r ^ v)
            key[i] = out & 255
            eax = u32(out & 255 ^ v)
            edx_ctr -= 1
        eax = build_hash
        for i in range(16):
            r = words[idx_second(i)]
            tmp = u32(eax ^ r)
            v = u32(tmp ^ i)
            corr = u32(~tmp & i)
            v = u32(v - u32(corr + corr))
            key[i] ^= v & 255
            eax = u32(v & 4294967040 ^ r)
        return bytes(key)

    def decode_text(
        self, data: bytes, raw_size: Optional[int] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        if raw_size is not None and raw_size > 0:
            data = data[:raw_size]
        if not data:
            return (None, None)
        if (
            len(data) >= 2
            and data[1] == 0
            and any((data[i] != 0 for i in range(0, min(len(data), 16), 2)))
        ):
            text = data.decode("utf-16le", errors="ignore").rstrip("\x00")
            return (text, "wchar")
        text = data.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
        return (text, "char")

    def analyze(self) -> List[CallSiteResult]:
        if self.build_hash is None:
            self.detect_build_hash()
        decrypt_funcs, calls = self.find_decrypt_calls()
        if self.verbose:
            print(
                f"[+] decrypt funcs: {', '.join((hex(x) for x in decrypt_funcs)) or 'none'}"
            )
            print(f"[+] decrypt calls: {len(calls)}")
            if self.build_hash is not None:
                print(
                    f"[+] build hash: 0x{self.build_hash:08X} inputs={self.build_hash_inputs}"
                )
        out: List[CallSiteResult] = []
        if not calls:
            return out
        text_base = self.pe.text["va"] if self.pe.text else self.pe.base
        for call_addr, decrypt_func in calls:
            insns = self.context_insns(call_addr, before=6144, after=64)
            call_idx = self.find_insn_index(insns, call_addr)
            if call_idx < 0:
                out.append(
                    CallSiteResult(
                        hex(call_addr),
                        hex(decrypt_func),
                        "none",
                        "low",
                        reason="call_not_in_disassembly",
                    )
                )
                continue
            source_va, helper, source_kind = self.recover_source_from_context(
                insns, call_idx
            )
            chunks, raw_size = self.recover_args_from_context(
                insns, call_idx, helper, source_va
            )
            key, key_meta = self.recover_runtime_key(call_addr)
            text = None
            text_type = None
            confidence = "low"
            source = source_kind
            reason = None
            if source_va is not None and raw_size is not None:
                blob = self.pe.read_va(source_va, raw_size) or b""
                if blob:
                    t, tt = self.decode_text(blob, raw_size)
                    if t and self.is_printable_blob(t.encode("utf-8", errors="ignore")):
                        text, text_type = (t, tt)
                        confidence = "high"
                        source = f"static_source:{source_kind}"
                    else:
                        reason = "source_blob_not_printable"
                else:
                    reason = "source_blob_unreadable"
            elif source_va is None:
                reason = "source_va_not_found"
            else:
                reason = "raw_size_not_found"
            out.append(
                CallSiteResult(
                    call_addr=hex(call_addr),
                    decrypt_func=hex(decrypt_func),
                    source=source,
                    confidence=confidence,
                    text=text,
                    text_type=text_type,
                    raw_size=raw_size,
                    chunks=chunks,
                    source_va=hex(source_va) if source_va is not None else None,
                    helper_func=hex(helper) if helper is not None else None,
                    runtime_key=key.hex() if key else None,
                    key_base=key_meta.get("key_base"),
                    key_offset=(
                        hex(key_meta["key_offset"])
                        if "key_offset" in key_meta
                        else None
                    ),
                    ks_offset=(
                        hex(key_meta["ks_offset"])
                        if key_meta.get("ks_offset") is not None
                        else None
                    ),
                    reason=reason or key_meta.get("error"),
                )
            )
        return out


_REG_ID_RAX = None


def _init_reg_ids(an: Analyzer) -> None:
    global _REG_ID_RAX
    if _REG_ID_RAX is None:
        insn = next(an.cs.disasm(b"H\x89\xc0", 4096))
        _REG_ID_RAX = insn.operands[0].reg


class UniversalAnalyzer(Analyzer):
    def __init__(self, path: str, verbose: bool = False, use_pro_fallback: bool = True):
        super().__init__(path, verbose=verbose)
        _init_reg_ids(self)
        self.use_pro_fallback = use_pro_fallback
        self.traces_by_call: Dict[int, List[StrategyTrace]] = {}

    def add_trace(self, call_addr: int, tr: StrategyTrace) -> None:
        self.traces_by_call.setdefault(call_addr, []).append(tr)

    def find_decrypt_calls(self) -> Tuple[List[int], List[Tuple[int, int]]]:
        funcs, calls = super().find_decrypt_calls()
        if calls:
            return (funcs, calls)
        pfuncs, pcalls = self.find_decrypt_calls_by_prototype()
        return (pfuncs, pcalls)

    def find_decrypt_calls_by_prototype(
        self,
    ) -> Tuple[List[int], List[Tuple[int, int]]]:
        text = self.pe.text
        if not text:
            return ([], [])
        target_counts: Dict[int, int] = {}
        callsites: List[Tuple[int, int]] = []
        for insn in self.cs.disasm(text["data"], text["va"]):
            if (
                insn.mnemonic != "call"
                or len(insn.operands) != 1
                or insn.operands[0].type != CS_OP_IMM
            ):
                continue
            call_addr = int(insn.address)
            target = int(insn.operands[0].imm)
            ctx = self.context_insns(call_addr, before=288, after=16)
            idx = self.find_insn_index(ctx, call_addr)
            if idx < 0:
                continue
            saw_r8_small = False
            saw_r9_small = False
            saw_stack_key = False
            saw_stack_ks = False
            for x in ctx[max(0, idx - 30) : idx]:
                if not x.operands:
                    continue
                if x.mnemonic == "mov" and len(x.operands) == 2:
                    d, s = x.operands
                    if (
                        d.type == CS_OP_REG
                        and self.canon_reg(d.reg) == "r8"
                        and (s.type == CS_OP_IMM)
                        and (1 <= int(s.imm) <= 40)
                    ):
                        saw_r8_small = True
                    if (
                        d.type == CS_OP_REG
                        and self.canon_reg(d.reg) == "r9"
                        and (s.type == CS_OP_IMM)
                        and (1 <= int(s.imm) <= 640)
                    ):
                        saw_r9_small = True
                    if (
                        d.type == CS_OP_MEM
                        and self.reg_name(d.mem.base) == "rsp"
                        and (d.mem.disp == 32)
                    ):
                        saw_stack_key = True
                    if (
                        d.type == CS_OP_MEM
                        and self.reg_name(d.mem.base) == "rsp"
                        and (d.mem.disp == 40)
                    ):
                        saw_stack_ks = True
            if saw_r8_small and saw_r9_small and saw_stack_key:
                callsites.append((call_addr, target))
                target_counts[target] = target_counts.get(target, 0) + 1
        keep = {t for t, c in target_counts.items() if c >= 2}
        if not keep and target_counts:
            keep = set(target_counts)
        out = [(c, t) for c, t in callsites if t in keep]
        return (sorted(keep), sorted(out))

    def find_key_candidate_and_start(
        self, call_addr: int
    ) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[int], str]:
        insns = self.context_insns(call_addr, before=8704, after=32)
        call_idx = self.find_insn_index(insns, call_addr)
        if call_idx < 0:
            return (None, None, None, None, "call_not_in_context")
        candidates: List[Tuple[int, str, int]] = []
        for i, insn in enumerate(insns[:call_idx]):
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                dst, src = insn.operands
                if (
                    dst.type == CS_OP_MEM
                    and src.type == CS_OP_REG
                    and (self.reg_name(src.reg) == "al")
                ):
                    base = self.reg_name(dst.mem.base)
                    if base in ("rbp", "rsp"):
                        candidates.append((i, base, int(dst.mem.disp)))
        if not candidates:
            return (None, None, None, None, "no_byte_al_store_candidate")
        for i0, base, keyoff in reversed(candidates):
            start = None
            for j in range(i0 - 1, max(-1, i0 - 220), -1):
                x = insns[j]
                if (
                    x.mnemonic in ("movaps", "movups", "movdqa", "movdqu")
                    and len(x.operands) == 2
                ):
                    d, s = x.operands
                    if d.type == CS_OP_MEM and self.reg_name(d.mem.base) == base:
                        start = x.address
                        if s.type == CS_OP_REG:
                            xmm = self.reg_name(s.reg)
                            for k in range(j - 1, max(-1, j - 40), -1):
                                y = insns[k]
                                if (
                                    y.mnemonic
                                    in ("movaps", "movups", "movdqa", "movdqu")
                                    and len(y.operands) == 2
                                ):
                                    yd, ys = y.operands
                                    if (
                                        yd.type == CS_OP_REG
                                        and self.reg_name(yd.reg) == xmm
                                    ):
                                        start = y.address
                                        break
                        break
            if start is not None:
                return (start, base, keyoff, i0, "ok")
        return (None, None, None, None, "no_xmm_ks_initializer_before_candidate")

    def recover_runtime_key_by_local_interpreter(
        self, call_addr: int
    ) -> Tuple[Optional[bytes], Dict[str, Any]]:
        meta: Dict[str, Any] = {"method": "local_concrete_interpreter"}
        build_hash = (
            self.build_hash if self.build_hash is not None else self.detect_build_hash()
        )
        if build_hash is None:
            meta["error"] = "build_hash_not_found"
            return (None, meta)
        start, base, keyoff, cand_idx, reason = self.find_key_candidate_and_start(
            call_addr
        )
        if start is None or base is None or keyoff is None:
            meta["error"] = reason
            return (None, meta)
        summaries: Dict[int, int] = {}
        if self.fnv_func is not None:
            summaries[self.fnv_func] = build_hash
        interp = LocalConcreteInterpreter(
            self, summaries=summaries, verbose=self.verbose
        )
        try:
            st = interp.run(start, call_addr)
        except Exception as e:
            meta["error"] = f"local_interpreter_exception:{e}"
            return (None, meta)
        base_addr = st.regs.get(base, UNKNOWN)
        if base_addr is UNKNOWN:
            meta["error"] = f"{base}_unknown"
            meta["logs"] = st.logs[-20:]
            return (None, meta)
        key_addr = int(base_addr) + int(keyoff)
        key = st.read_bytes(key_addr, 16)
        if not key or len(key) != 16:
            meta["error"] = "key_unreadable_after_interpretation"
            meta["logs"] = st.logs[-20:]
            return (None, meta)
        if key == b"\x00" * 16:
            meta["error"] = "key_all_zero_rejected"
            meta["logs"] = st.logs[-20:]
            return (None, meta)
        meta.update(
            {
                "start": hex(start),
                "key_base": base,
                "key_offset": keyoff,
                "key_addr_model": hex(key_addr),
                "logs": st.logs[-20:],
            }
        )
        return (key, meta)

    def recover_runtime_key(
        self, call_addr: int
    ) -> Tuple[Optional[bytes], Dict[str, Any]]:
        key, meta = self.recover_runtime_key_by_local_interpreter(call_addr)
        if key is not None:
            self.add_trace(
                call_addr,
                StrategyTrace(
                    strategy="key.local_concrete_interpreter",
                    ok=True,
                    detail=f"key recovered from {meta.get('start')} base={meta.get('key_base')} off={hex(meta.get('key_offset', 0))}",
                    evidence=[
                        Evidence(
                            "runtime_key",
                            95,
                            "local slice executed concretely",
                            value=key.hex(),
                        )
                    ],
                ),
            )
            return (key, meta)
        self.add_trace(
            call_addr,
            StrategyTrace(
                strategy="key.local_concrete_interpreter",
                ok=False,
                detail=meta.get("error", "unknown"),
                evidence=[],
            ),
        )
        if self.use_pro_fallback:
            key2, meta2 = super().recover_runtime_key(call_addr)
            if key2 is not None:
                meta2 = dict(meta2)
                meta2["method"] = "source_pattern_fallback"
                self.add_trace(
                    call_addr,
                    StrategyTrace(
                        strategy="key.source_pattern_fallback",
                        ok=True,
                        detail="key recovered by Obfusk8 source-template pattern",
                        evidence=[
                            Evidence(
                                "runtime_key",
                                80,
                                "source-template fallback",
                                value=key2.hex(),
                            )
                        ],
                    ),
                )
                return (key2, meta2)
            self.add_trace(
                call_addr,
                StrategyTrace(
                    strategy="key.source_pattern_fallback",
                    ok=False,
                    detail=meta2.get("error", "unknown"),
                    evidence=[],
                ),
            )
            return (
                None,
                {"method": "failed", "error": meta.get("error") or meta2.get("error")},
            )
        return (None, meta)

    def score_result(
        self,
        text: Optional[str],
        source_va: Optional[int],
        key: Optional[bytes],
        raw_size: Optional[int],
        chunks: Optional[int],
        reason: Optional[str],
    ) -> str:
        if (
            text
            and key
            and raw_size
            and chunks
            and (1 <= chunks <= 40)
            and (1 <= raw_size <= 640)
        ):
            return "high"
        if text and raw_size:
            return "medium"
        if text:
            return "low"
        return "failed"

    def analyze_universal(self) -> List[UniversalResult]:
        if self.build_hash is None:
            self.detect_build_hash()
        decrypt_funcs, calls = self.find_decrypt_calls()
        if self.verbose:
            print(
                f"[+] decrypt funcs: {', '.join((hex(x) for x in decrypt_funcs)) or 'none'}"
            )
            print(f"[+] decrypt calls: {len(calls)}")
            if self.build_hash is not None:
                print(
                    f"[+] build hash: 0x{self.build_hash:08X} inputs={self.build_hash_inputs}"
                )
        out: List[UniversalResult] = []
        for call_addr, decrypt_func in calls:
            insns = self.context_insns(call_addr, before=8704, after=64)
            call_idx = self.find_insn_index(insns, call_addr)
            if call_idx < 0:
                out.append(
                    UniversalResult(
                        hex(call_addr),
                        hex(decrypt_func),
                        "failed",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        "none",
                        "call_not_in_disassembly",
                    )
                )
                continue
            source_va, helper, source_kind = self.recover_source_from_context(
                insns, call_idx
            )
            if source_va is not None:
                self.add_trace(
                    call_addr,
                    StrategyTrace(
                        strategy="source.recover_from_context",
                        ok=True,
                        detail=f"{source_kind} -> {hex(source_va)}",
                        evidence=[
                            Evidence(
                                "source_va", 90, source_kind, address=hex(source_va)
                            )
                        ],
                    ),
                )
            else:
                self.add_trace(
                    call_addr,
                    StrategyTrace(
                        "source.recover_from_context", False, "source pointer not found"
                    ),
                )
            chunks, raw_size = self.recover_args_from_context(
                insns, call_idx, helper, source_va
            )
            if chunks and raw_size:
                self.add_trace(
                    call_addr,
                    StrategyTrace(
                        strategy="args.prototype_or_helper_summary",
                        ok=True,
                        detail=f"chunks={chunks} raw_size={raw_size}",
                        evidence=[
                            Evidence(
                                "chunks",
                                85,
                                "small immediate/helper summary",
                                value=chunks,
                            ),
                            Evidence(
                                "raw_size",
                                85,
                                "small immediate/helper summary",
                                value=raw_size,
                            ),
                        ],
                    ),
                )
            else:
                self.add_trace(
                    call_addr,
                    StrategyTrace(
                        "args.prototype_or_helper_summary",
                        False,
                        f"chunks={chunks} raw_size={raw_size}",
                    ),
                )
            key, key_meta = self.recover_runtime_key(call_addr)
            text = None
            text_type = None
            reason = None
            source = source_kind
            if source_va is not None and raw_size is not None:
                blob = self.pe.read_va(source_va, raw_size) or b""
                t, tt = self.decode_text(blob, raw_size) if blob else (None, None)
                if t and self.is_printable_blob(t.encode("utf-8", errors="ignore")):
                    text, text_type = (t, tt)
                    source = f"static_source:{source_kind}"
                    self.add_trace(
                        call_addr,
                        StrategyTrace(
                            strategy="plaintext.static_source_shortcut",
                            ok=True,
                            detail=f"decoded {len(t)} chars",
                            evidence=[
                                Evidence(
                                    "plaintext",
                                    95,
                                    "source literal recovered from Obfusk8 helper",
                                    value=t,
                                )
                            ],
                        ),
                    )
                else:
                    reason = "source_blob_not_printable"
                    self.add_trace(
                        call_addr,
                        StrategyTrace(
                            "plaintext.static_source_shortcut", False, reason
                        ),
                    )
            else:
                reason = "source_or_raw_size_missing"
                self.add_trace(
                    call_addr,
                    StrategyTrace("plaintext.static_source_shortcut", False, reason),
                )
            confidence = self.score_result(
                text, source_va, key, raw_size, chunks, reason
            )
            key_source = key_meta.get("method") if key_meta else None
            out.append(
                UniversalResult(
                    call_addr=hex(call_addr),
                    decrypt_func=hex(decrypt_func),
                    confidence=confidence,
                    text=text,
                    text_type=text_type,
                    raw_size=raw_size,
                    chunks=chunks,
                    source_va=hex(source_va) if source_va is not None else None,
                    helper_func=hex(helper) if helper is not None else None,
                    runtime_key=key.hex() if key else None,
                    key_source=key_source,
                    source=source,
                    reason=reason or (key_meta or {}).get("error"),
                    traces=self.traces_by_call.get(call_addr, []),
                )
            )
        return out


class FastUniversalAnalyzer(UniversalAnalyzer):
    def __init__(self, path: str, verbose: bool = False, use_pro_fallback: bool = True):
        super().__init__(path, verbose=verbose, use_pro_fallback=use_pro_fallback)
        self._fast_xrefs_cache: Optional[Dict[int, List[int]]] = None
        self._pdata_funcs: Optional[List[Tuple[int, int]]] = None
        self._decrypt_calls_cache: Optional[Tuple[List[int], List[Tuple[int, int]]]] = None

    def find_decrypt_calls(self) -> Tuple[List[int], List[Tuple[int, int]]]:
        if self._decrypt_calls_cache is not None:
            return self._decrypt_calls_cache
        result = super().find_decrypt_calls()
        self._decrypt_calls_cache = result
        return result

    def pdata_funcs(self) -> List[Tuple[int, int]]:
        if self._pdata_funcs is not None:
            return self._pdata_funcs
        out: List[Tuple[int, int]] = []
        try:
            for e in getattr(self.pe.pe, "DIRECTORY_ENTRY_EXCEPTION", []):
                start = self.pe.base + int(e.struct.BeginAddress)
                end = self.pe.base + int(e.struct.EndAddress)
                if start < end:
                    out.append((start, end))
        except Exception:
            pass
        out.sort()
        self._pdata_funcs = out
        return out

    def find_function_boundaries(
        self, addr_in_func: int
    ) -> Tuple[Optional[int], Optional[int]]:
        if addr_in_func in self._bounds_cache:
            return self._bounds_cache[addr_in_func]
        funcs = self.pdata_funcs()
        lo, hi = (0, len(funcs) - 1)
        while lo <= hi:
            mid = (lo + hi) // 2
            start, end = funcs[mid]
            if addr_in_func < start:
                hi = mid - 1
            elif addr_in_func >= end:
                lo = mid + 1
            else:
                self._bounds_cache[addr_in_func] = (start, end)
                return (start, end)
        return super().find_function_boundaries(addr_in_func)

    def find_functions_referencing(self, target_va: int) -> List[int]:
        text = self.pe.text
        if not text:
            return []
        data = text["data"]
        base = text["va"]
        refs: List[int] = []
        i = 0
        n = len(data)
        while i < n - 6:
            b = data[i]
            if 64 <= b <= 79 and i + 7 <= n and (data[i + 1] == 141):
                modrm = data[i + 2]
                if modrm & 199 == 5:
                    disp = struct.unpack_from("<i", data, i + 3)[0]
                    if base + i + 7 + disp == target_va:
                        refs.append(base + i)
                        i += 7
                        continue
            if b == 141 and (not (i > 0 and 64 <= data[i - 1] <= 79)):
                modrm = data[i + 1]
                if modrm & 199 == 5:
                    disp = struct.unpack_from("<i", data, i + 2)[0]
                    if base + i + 6 + disp == target_va:
                        refs.append(base + i)
                        i += 6
                        continue
            i += 1
        return sorted(set(refs))

    def build_xrefs(self) -> Dict[int, List[int]]:
        if self._fast_xrefs_cache is not None:
            return self._fast_xrefs_cache
        out: Dict[int, List[int]] = {}
        text = self.pe.text
        if not text:
            self._fast_xrefs_cache = out
            return out
        data = text["data"]
        base = text["va"]
        text_start = base
        text_end = base + max(text["vsize"], text["raw_size"])
        for i, b in enumerate(data[:-4]):
            if b != 232:
                continue
            disp = struct.unpack_from("<i", data, i + 1)[0]
            call = base + i
            target = call + 5 + disp
            if text_start <= target < text_end:
                out.setdefault(target, []).append(call)
        self._fast_xrefs_cache = out
        return out

    def detect_build_hash(self) -> Optional[int]:
        if self.build_hash is not None:
            return self.build_hash
        text = self.pe.text
        if not text:
            return None
        sig = struct.pack("<I", 2166136261)
        data = text["data"]
        base = text["va"]
        idx = 0
        while True:
            idx = data.find(sig, idx)
            if idx < 0:
                break
            hit = base + idx
            fstart, fend = self.find_function_boundaries(hit)
            if not fstart:
                idx += 1
                continue
            size = min(max(0, (fend or fstart + 768) - fstart), 1280)
            fins = self.disasm_range(fstart, size)
            strings: List[bytes] = []
            for insn in fins:
                if insn.mnemonic == "lea" and len(insn.operands) == 2:
                    dst, src = insn.operands
                    if (
                        dst.type == 1
                        and self.canon_reg(dst.reg) == "rax"
                        and (src.type == 3)
                    ):
                        if self.reg_name(src.mem.base) == "rip":
                            s = self.pe.read_c_string(self.rip_target(insn, src), 128)
                            if s and self.is_printable_blob(s):
                                if s not in strings:
                                    strings.append(s)
                if insn.mnemonic == "ret":
                    break
            if len(strings) >= 2:
                self.fnv_func = fstart
                self.build_hash_inputs = [
                    x.decode("utf-8", errors="replace") for x in strings[:2]
                ]
                self.build_hash = fnv1a_32(strings[0], strings[1])
                return self.build_hash
            idx += 1
        return None

    def find_decrypt_calls_by_prototype(
        self,
    ) -> Tuple[List[int], List[Tuple[int, int]]]:
        xrefs = self.build_xrefs()
        callsites: List[Tuple[int, int]] = []
        target_counts: Dict[int, int] = {}
        for target, calls in xrefs.items():
            for call_addr in calls:
                ctx = self.context_insns(call_addr, before=352, after=16)
                idx = self.find_insn_index(ctx, call_addr)
                if idx < 0:
                    continue
                saw_r8_small = False
                saw_r9_small = False
                saw_stack_key = False
                for x in ctx[max(0, idx - 40) : idx]:
                    if x.mnemonic != "mov" or len(x.operands) != 2:
                        continue
                    d, s = x.operands
                    if (
                        d.type == 1
                        and self.canon_reg(d.reg) == "r8"
                        and (s.type == 2)
                        and (1 <= int(s.imm) <= 40)
                    ):
                        saw_r8_small = True
                    if (
                        d.type == 1
                        and self.canon_reg(d.reg) == "r9"
                        and (s.type == 2)
                        and (1 <= int(s.imm) <= 640)
                    ):
                        saw_r9_small = True
                    if (
                        d.type == 3
                        and self.reg_name(d.mem.base) == "rsp"
                        and (d.mem.disp == 32)
                    ):
                        saw_stack_key = True
                if saw_r8_small and saw_r9_small and saw_stack_key:
                    callsites.append((call_addr, target))
                    target_counts[target] = target_counts.get(target, 0) + 1
        keep = {t for t, c in target_counts.items() if c >= 2}
        if not keep and target_counts:
            keep = set(target_counts)
        return (sorted(keep), sorted(((c, t) for c, t in callsites if t in keep)))


class BaseAnalyzer(FastUniversalAnalyzer):
    def is_text_bytes(self, data: bytes, min_ratio: float = 0.8) -> bool:
        if not data:
            return False
        stripped = data.rstrip(b"\x00")
        if not stripped:
            return False
        good = sum((1 for b in stripped if b in (9, 10, 13) or 32 <= b < 127))
        if good >= max(1, int(len(stripped) * min_ratio)):
            return True
        if (
            len(data) >= 4
            and len(data) % 2 == 0
            and (data[1] == 0)
            and (data[-2:] == b"\x00\x00")
            and any((data[i] != 0 for i in range(0, min(len(data), 32), 2)))
        ):
            try:
                text = data.decode("utf-16le", errors="ignore").rstrip("\x00")
            except Exception:
                return False
            if not text:
                return False
            good_chars = sum((1 for ch in text if ch.isprintable() or ch in "\t\n\r"))
            return good_chars >= max(1, int(len(text) * min_ratio))
        return False

    def local_call_state(
        self, call_addr: int
    ) -> Tuple[Optional[ConcreteState], Dict[str, Any]]:
        meta: Dict[str, Any] = {"method": "function_entry_local_concrete"}
        build_hash = (
            self.build_hash if self.build_hash is not None else self.detect_build_hash()
        )
        fstart, fend = self.find_function_boundaries(call_addr)
        if fstart is None:
            meta["error"] = "function_boundary_not_found"
            return (None, meta)
        summaries: Dict[int, int] = {}
        if build_hash is not None and self.fnv_func is not None:
            summaries[self.fnv_func] = build_hash
        interp = CopyingLocalInterpreter(
            self, summaries=summaries, verbose=self.verbose
        )
        max_steps = int(getattr(self, "local_max_steps", 80000))
        try:
            st = interp.run(fstart, call_addr, max_steps=max_steps)
        except Exception as e:
            meta["error"] = f"local_interpreter_exception:{e}"
            return (None, meta)
        meta.update(
            {
                "start": hex(fstart),
                "end": hex(fend or 0),
                "max_steps": max_steps,
                "logs": st.logs[-40:],
            }
        )
        return (st, meta)

    def recover_from_local_state(self, call_addr: int) -> Dict[str, Any]:
        st, meta = self.local_call_state(call_addr)
        out: Dict[str, Any] = {"ok": False, "meta": meta}
        if st is None:
            return out
        rsp = st.regs.get("rsp", UNKNOWN)
        rcx = st.regs.get("rcx", UNKNOWN)
        rdx = st.regs.get("rdx", UNKNOWN)
        chunks = st.regs.get("r8", UNKNOWN)
        raw_size = st.regs.get("r9", UNKNOWN)
        if rsp is UNKNOWN:
            out["reason"] = "rsp_unknown"
            return out
        key_ptr = st.read_int(int(rsp) + 32, 8)
        ks_ptr = st.read_int(int(rsp) + 40, 8)
        if chunks is UNKNOWN or raw_size is UNKNOWN:
            out["reason"] = "chunks_or_raw_unknown"
            return out
        chunks = int(chunks) & 4294967295
        raw_size = int(raw_size) & 4294967295
        if not (1 <= chunks <= 40 and 1 <= raw_size <= 640):
            out["reason"] = f"bad_args chunks={chunks} raw={raw_size}"
            return out
        key = None
        key_status = "missing"
        key_reason = None
        if key_ptr is not UNKNOWN:
            raw_key = st.read_bytes(int(key_ptr), 16)
            if raw_key and len(raw_key) == 16:
                if raw_key == b"\x00" * 16:
                    key_status = "rejected_zero"
                    key_reason = "zero_key_rejected"
                else:
                    key = raw_key
                    key_status = "recovered"
            else:
                key_reason = "key_unreadable"
        else:
            key_reason = "key_ptr_unknown"
        local_src = None
        if isinstance(rdx, int):
            local_src = st.read_bytes(int(rdx), raw_size)
        enc = None
        if isinstance(rdx, int):
            enc = st.read_bytes(int(rdx), chunks * 16)
        out.update(
            {
                "ok": True,
                "state": st,
                "rcx": rcx,
                "rdx": rdx,
                "chunks": chunks,
                "raw_size": raw_size,
                "key_ptr": key_ptr,
                "ks_ptr": ks_ptr,
                "runtime_key": key,
                "key_status": key_status,
                "key_reason": key_reason,
                "local_src": local_src,
                "enc_data": enc,
                "logs": st.logs[-40:],
            }
        )
        return out

    def analyze_universal(self) -> List[UniversalResult]:
        if self.build_hash is None:
            self.detect_build_hash()
        decrypt_funcs, calls = self.find_decrypt_calls()
        if self.verbose:
            print(
                f"[+] decrypt funcs: {', '.join((hex(x) for x in decrypt_funcs)) or 'none'}"
            )
            print(f"[+] decrypt calls: {len(calls)}")
            if self.build_hash is not None:
                print(
                    f"[+] build hash: 0x{self.build_hash:08X} inputs={self.build_hash_inputs}"
                )
        out: List[UniversalResult] = []
        for call_addr, decrypt_func in calls:
            traces: List[StrategyTrace] = []
            local = self.recover_from_local_state(call_addr)
            text: Optional[str] = None
            text_type: Optional[str] = None
            source = "none"
            reason: Optional[str] = None
            raw_size: Optional[int] = None
            chunks: Optional[int] = None
            runtime_key: Optional[bytes] = None
            source_va: Optional[int] = None
            helper: Optional[int] = None
            if local.get("ok"):
                raw_size = int(local["raw_size"])
                chunks = int(local["chunks"])
                runtime_key = local.get("runtime_key")
                key_status = local.get("key_status") or (
                    "recovered" if runtime_key else "missing"
                )
                key_evidence = [
                    Evidence(
                        "key_status",
                        80,
                        local.get("key_reason") or key_status,
                        value=key_status,
                    )
                ]
                if runtime_key:
                    key_evidence.append(
                        Evidence(
                            "runtime_key",
                            90,
                            "[rsp+0x20] local state",
                            value=runtime_key.hex(),
                        )
                    )
                traces.append(
                    StrategyTrace(
                        "state.function_entry_local_concrete",
                        True,
                        f"chunks={chunks} raw={raw_size} rdx={(hex(local['rdx']) if isinstance(local.get('rdx'), int) else local.get('rdx'))} key_status={key_status}",
                        key_evidence,
                    )
                )
                local_src = local.get("local_src")
                if isinstance(local_src, (bytes, bytearray)) and self.is_text_bytes(
                    bytes(local_src)
                ):
                    t, tt = self.decode_text(bytes(local_src), raw_size)
                    if t:
                        text, text_type = (t, tt)
                        source = "local_state:rdx_printable_buffer"
                        traces.append(
                            StrategyTrace(
                                "plaintext.local_rdx_buffer",
                                True,
                                f"decoded {len(t)} chars",
                                [
                                    Evidence(
                                        "plaintext",
                                        96,
                                        "printable local RDX buffer",
                                        value=t,
                                    )
                                ],
                            )
                        )
                if text is None and runtime_key and (decrypt_aes_ecb is not None):
                    enc = local.get("enc_data")
                    if isinstance(enc, (bytes, bytearray)) and len(enc) == chunks * 16:
                        try:
                            pt = decrypt_aes_ecb(bytes(enc), runtime_key)[:raw_size]
                            t, tt = self.decode_text(pt, raw_size)
                            if t and self.is_text_bytes(pt):
                                text, text_type = (t, tt)
                                source = "aes_decrypt:local_state"
                                traces.append(
                                    StrategyTrace(
                                        "plaintext.aes_validation",
                                        True,
                                        f"decoded {len(t)} chars",
                                        [
                                            Evidence(
                                                "plaintext",
                                                98,
                                                "AES decrypt validated",
                                                value=t,
                                            )
                                        ],
                                    )
                                )
                            else:
                                traces.append(
                                    StrategyTrace(
                                        "plaintext.aes_validation",
                                        False,
                                        "decrypted bytes not printable",
                                    )
                                )
                        except Exception as e:
                            traces.append(
                                StrategyTrace(
                                    "plaintext.aes_validation", False, f"exception:{e}"
                                )
                            )
                if text is None:
                    reason = local.get("reason") or "local_state_no_plaintext"
            else:
                reason = (
                    local.get("reason")
                    or local.get("meta", {}).get("error")
                    or "local_state_failed"
                )
                traces.append(
                    StrategyTrace("state.function_entry_local_concrete", False, reason)
                )
            insns = self.context_insns(call_addr, before=8704, after=64)
            call_idx = self.find_insn_index(insns, call_addr)
            if call_idx >= 0:
                sva, hp, sk = self.recover_source_from_context(insns, call_idx)
                source_va, helper = (sva, hp)
                c2, r2 = self.recover_args_from_context(insns, call_idx, hp, sva)
                raw_size = raw_size or r2
                chunks = chunks or c2
                if sva is not None and raw_size is not None:
                    blob = self.pe.read_va(sva, raw_size) or b""
                    t, tt = self.decode_text(blob, raw_size) if blob else (None, None)
                    if t and self.is_text_bytes(blob):
                        if text is None or len(t) > len(text):
                            text, text_type = (t, tt)
                            source = f"static_source:{sk}"
                            reason = None
                        traces.append(
                            StrategyTrace(
                                "plaintext.static_source_shortcut",
                                True,
                                f"decoded {len(t)} chars",
                                [
                                    Evidence(
                                        "plaintext", 90, sk, address=hex(sva), value=t
                                    )
                                ],
                            )
                        )
                    else:
                        traces.append(
                            StrategyTrace(
                                "plaintext.static_source_shortcut",
                                False,
                                "source blob not printable",
                            )
                        )
            confidence = "failed"
            if text and runtime_key and raw_size and chunks:
                confidence = "high"
            elif text and raw_size:
                confidence = "medium"
            elif text:
                confidence = "low"
            out.append(
                UniversalResult(
                    call_addr=hex(call_addr),
                    decrypt_func=hex(decrypt_func),
                    confidence=confidence,
                    text=text,
                    text_type=text_type,
                    raw_size=raw_size,
                    chunks=chunks,
                    source_va=hex(source_va) if source_va is not None else None,
                    helper_func=hex(helper) if helper is not None else None,
                    runtime_key=runtime_key.hex() if runtime_key else None,
                    key_source="function_entry_local_concrete" if runtime_key else None,
                    source=source,
                    reason=reason,
                    traces=traces,
                )
            )
        return out


def classify_result(r: UniversalResult) -> str:
    text = r.text or ""
    if any((marker in text for marker in OBFUSK8_RUNTIME_LITERAL_MARKERS)):
        return "obfusk8_runtime_literal"
    return "user_literal"


def is_runtime_literal(r: UniversalResult) -> bool:
    return classify_result(r) == "obfusk8_runtime_literal"


def result_to_dict(r: UniversalResult) -> Dict[str, Any]:
    d = asdict(r)
    d["classification"] = classify_result(r)
    d["filtered_by_default"] = is_runtime_literal(r)
    return d


OBFUSK8_RUNTIME_LITERAL_MARKERS = ("Oh skibiddi oooh", "pojkdkddkeifpojkdkddkeif")


def classify_result_symbolic(r: UniversalResult) -> str:
    text = r.text or ""
    if any((marker in text for marker in OBFUSK8_RUNTIME_LITERAL_MARKERS)):
        return "obfusk8_runtime_literal"
    return classify_result(r)


def is_runtime_literal_symbolic(r: UniversalResult) -> bool:
    return classify_result_symbolic(r) == "obfusk8_runtime_literal"


def result_to_dict_symbolic(r: UniversalResult) -> Dict[str, Any]:
    d = asdict(r)
    d["classification"] = classify_result_symbolic(r)
    d["filtered_by_default"] = is_runtime_literal_symbolic(r)
    return d


class SymbolicAnalyzer(BaseAnalyzer):
    def __init__(
        self,
        path: str,
        verbose: bool = False,
        use_pro_fallback: bool = True,
        enable_symbolic: bool = True,
        full_local_threshold: int = 8,
        local_max_steps: int = 80000,
    ):
        super().__init__(path, verbose=verbose, use_pro_fallback=use_pro_fallback)
        self.enable_symbolic = enable_symbolic
        self.full_local_threshold = full_local_threshold
        self.local_max_steps = int(local_max_steps)
        self.key_templates: List[KeyMixerTemplate] = [Obfusk8AES8TwoPassKeyMixer()]
        self.last_key_template_diag: Dict[int, Dict[str, Any]] = {}

    @staticmethod
    def _ks_words_from_bytes(data: bytes) -> Optional[List[int]]:
        if not data or len(data) < 16:
            return None
        words = [
            int.from_bytes(data[i : i + 4], "little", signed=False)
            for i in range(0, 16, 4)
        ]
        return [u32(x) for x in words]

    def _candidate_score(self, words: Sequence[int]) -> int:
        if len(words) < 4:
            return 0
        byteish = sum((1 for x in words[:4] if 0 <= int(x) <= 255))
        score = 40 + byteish * 12
        if any((int(x) != 0 for x in words[:4])):
            score += 8
        return min(score, 96)

    def recover_ks_from_local(self, local: Dict[str, Any]) -> Optional[KSCandidate]:
        st = local.get("state")
        ks_ptr = local.get("ks_ptr")
        if st is None or ks_ptr is UNKNOWN or ks_ptr is None:
            return None
        try:
            data = st.read_bytes(int(ks_ptr), 16)
        except Exception:
            data = None
        words = self._ks_words_from_bytes(data or b"")
        if not words:
            return None
        return KSCandidate(
            words=words,
            source="local_state:[rsp+0x28]",
            confidence=self._candidate_score(words),
        )

    def recover_ks_candidates_from_context(self, call_addr: int) -> List[KSCandidate]:
        out: List[KSCandidate] = []
        seen: set[Tuple[int, Tuple[int, ...]]] = set()
        insns = self.context_insns(call_addr, before=9728, after=64)
        call_idx = self.find_insn_index(insns, call_addr)
        if call_idx < 0:
            return out
        xmm_sources: Dict[str, Tuple[int, List[int]]] = {}
        for i, insn in enumerate(insns[:call_idx]):
            if (
                insn.mnemonic not in ("movaps", "movups", "movdqa", "movdqu")
                or len(insn.operands) != 2
            ):
                continue
            dst, src = insn.operands
            if (
                dst.type == CS_OP_REG
                and src.type == CS_OP_MEM
                and (src.mem.base == X86_REG_RIP)
            ):
                addr = self.rip_target(insn, src)
                data = self.pe.read_va(addr, 16) or b""
                words = self._ks_words_from_bytes(data)
                if words:
                    xmm_sources[self.reg_name(dst.reg)] = (addr, words)
                    key = (addr, tuple(words))
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            KSCandidate(
                                words=words,
                                source="rip_xmm_load",
                                address=addr,
                                confidence=self._candidate_score(words) - 5,
                            )
                        )
            elif dst.type == CS_OP_MEM and src.type == CS_OP_REG:
                xmm = self.reg_name(src.reg)
                if xmm in xmm_sources:
                    addr, words = xmm_sources[xmm]
                    key = (addr, tuple(words))
                    if key not in seen:
                        seen.add(key)
                        out.append(
                            KSCandidate(
                                words=words,
                                source="rip_xmm_load_then_stack_store",
                                address=addr,
                                confidence=self._candidate_score(words) + 5,
                            )
                        )
        for insn in insns[max(0, call_idx - 180) : call_idx]:
            for op in getattr(insn, "operands", []):
                if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
                    addr = self.rip_target(insn, op)
                    data = self.pe.read_va(addr, 16) or b""
                    words = self._ks_words_from_bytes(data)
                    if words and sum((1 for x in words[:4] if x <= 255)) >= 3:
                        key = (addr, tuple(words))
                        if key not in seen:
                            seen.add(key)
                            out.append(
                                KSCandidate(
                                    words=words,
                                    source="nearby_rip_dword_array",
                                    address=addr,
                                    confidence=self._candidate_score(words) - 10,
                                )
                            )
        return sorted(out, key=lambda c: c.confidence, reverse=True)

    def recover_folded_init_constants(
        self, call_addr: int
    ) -> List[Tuple[int, int, int]]:
        insns = self.context_insns(call_addr, before=8704, after=32)
        call_idx = self.find_insn_index(insns, call_addr)
        if call_idx < 0:
            return []
        out: List[Tuple[int, int, int]] = []
        candidates: List[Tuple[int, str, int]] = []
        for i, insn in enumerate(insns[:call_idx]):
            if insn.mnemonic == "mov" and len(insn.operands) == 2:
                dst, src = insn.operands
                if (
                    dst.type == CS_OP_MEM
                    and src.type == CS_OP_REG
                    and (self.reg_name(src.reg) == "al")
                ):
                    base = self.reg_name(dst.mem.base)
                    if base in ("rbp", "rsp"):
                        candidates.append((i, base, int(dst.mem.disp)))
        for i0, base, keyoff in reversed(candidates[-8:]):
            word = None
            b3 = None
            orimm = None
            for insn in insns[i0 + 1 : min(len(insns), i0 + 55)]:
                if (
                    insn.mnemonic == "mov"
                    and len(insn.operands) == 2
                    and (insn.operands[0].type == CS_OP_MEM)
                    and (self.reg_name(insn.operands[0].mem.base) == base)
                    and (insn.operands[1].type == CS_OP_IMM)
                ):
                    disp = int(insn.operands[0].mem.disp)
                    if disp == keyoff + 1:
                        word = int(insn.operands[1].imm) & 65535
                    elif disp == keyoff + 3:
                        b3 = int(insn.operands[1].imm) & 255
                if (
                    insn.mnemonic == "or"
                    and len(insn.operands) == 2
                    and (insn.operands[0].type == CS_OP_REG)
                    and (self.canon_reg(insn.operands[0].reg) == "rax")
                    and (insn.operands[1].type == CS_OP_IMM)
                ):
                    orimm = int(insn.operands[1].imm) & 255
            if word is not None and b3 is not None and (orimm is not None):
                out.append((word, b3, orimm))
        return out

    def _validate_key_candidate(
        self,
        key: bytes,
        local: Optional[Dict[str, Any]],
        raw_size: Optional[int],
        chunks: Optional[int],
    ) -> Tuple[int, Optional[str], str]:
        if len(key) != 16 or key == b"\x00" * 16:
            return (-100, None, "invalid_key_bytes")
        if not local or not local.get("ok"):
            return (0, None, "no_local_state_for_aes_validation")
        if raw_size is None:
            raw_size = local.get("raw_size")
        if chunks is None:
            chunks = local.get("chunks")
        if (
            not isinstance(raw_size, int)
            or not isinstance(chunks, int)
            or (not (1 <= chunks <= 40 and 1 <= raw_size <= 640))
        ):
            return (-10, None, "bad_args_for_validation")
        enc = local.get("enc_data")
        if not isinstance(enc, (bytes, bytearray)) or len(enc) != chunks * 16:
            return (0, None, "encrypted_data_unavailable")
        try:
            pt = decrypt_aes_ecb(bytes(enc), key)[:raw_size]
        except Exception as e:
            return (-25, None, f"aes_exception:{e}")
        text, _typ = self.decode_text(pt, raw_size)
        if text and self.is_text_bytes(pt):
            return (35, text, "aes_plaintext_validated")
        return (-20, None, "aes_plaintext_not_printable")

    def synthesize_key_from_templates(
        self,
        call_addr: int,
        local: Optional[Dict[str, Any]] = None,
        raw_size: Optional[int] = None,
        chunks: Optional[int] = None,
    ) -> KeyTemplateResult:
        build_hash = (
            self.build_hash if self.build_hash is not None else self.detect_build_hash()
        )
        if build_hash is None:
            return KeyTemplateResult(False, reason="build_hash_not_found")
        ks_candidates: List[KSCandidate] = []
        if local:
            ksl = self.recover_ks_from_local(local)
            if ksl:
                ks_candidates.append(ksl)
        ks_candidates.extend(self.recover_ks_candidates_from_context(call_addr))
        dedup: List[KSCandidate] = []
        seen: set[Tuple[Tuple[int, ...], Optional[int]]] = set()
        for c in ks_candidates:
            k = (tuple(c.words[:4]), c.address)
            if k not in seen:
                seen.add(k)
                dedup.append(c)
        if not dedup:
            return KeyTemplateResult(False, reason="ks_candidates_not_found")
        templates: List[KeyMixerTemplate] = list(self.key_templates)
        for word, b3, orimm in self.recover_folded_init_constants(call_addr):
            templates.append(Obfusk8CompilerFoldedInitTemplate(self, word, b3, orimm))
        best: Optional[KeyTemplateResult] = None
        attempts: List[Dict[str, Any]] = []
        for ks in dedup[:12]:
            for templ in templates:
                try:
                    key = templ.compute(build_hash, ks.words)
                except Exception as e:
                    attempts.append(
                        {
                            "template": templ.name,
                            "ks_source": ks.source,
                            "ok": False,
                            "reason": str(e),
                        }
                    )
                    continue
                val_bump, val_text, val_reason = self._validate_key_candidate(
                    key, local, raw_size, chunks
                )
                score = max(0, min(100, ks.confidence + val_bump))
                attempt = {
                    "template": templ.name,
                    "ks_source": ks.source,
                    "ks_address": hex(ks.address) if ks.address else None,
                    "ks_words": ks.words[:4],
                    "score": score,
                    "validation": val_reason,
                    "validation_text": val_text,
                    "key": key.hex(),
                }
                attempts.append(attempt)
                res = KeyTemplateResult(
                    ok=score >= 55,
                    key=key,
                    template=templ.name,
                    ks_source=ks.source + (f"@{hex(ks.address)}" if ks.address else ""),
                    ks_words=ks.words[:4],
                    confidence=score,
                    reason=val_reason,
                    validation_text=val_text,
                )
                if best is None or res.confidence > best.confidence:
                    best = res
        self.last_key_template_diag[call_addr] = {
            "attempts": attempts[:40],
            "ks_candidate_count": len(dedup),
        }
        if best and best.ok:
            return best
        return best or KeyTemplateResult(False, reason="no_template_matched")

    def analyze_universal(self) -> List[UniversalResult]:
        if self.build_hash is None:
            self.detect_build_hash()
        _funcs, _calls = self.find_decrypt_calls()
        if len(_calls) <= self.full_local_threshold:
            results = super().analyze_universal()
            base_engine = "v4_function_entry_local"
        else:
            results = UniversalAnalyzer.analyze_universal(self)
            base_engine = "fast_static_first"
        if self.verbose:
            print(
                f"[v5] base_engine={base_engine} callsites={len(_calls)} threshold={self.full_local_threshold}"
            )
        enhanced: List[UniversalResult] = []
        for r in results:
            call_addr = int(r.call_addr, 16)
            local: Optional[Dict[str, Any]] = None
            if not r.runtime_key or r.confidence in ("failed", "low", "medium"):
                try:
                    local = self.recover_from_local_state(call_addr)
                except Exception:
                    local = None
                kt = self.synthesize_key_from_templates(
                    call_addr, local=local, raw_size=r.raw_size, chunks=r.chunks
                )
                trace = StrategyTrace(
                    strategy="key.symbolic_template_synthesis",
                    ok=bool(kt.ok),
                    detail=kt.reason or "ok",
                    evidence=[
                        Evidence(
                            "template",
                            kt.confidence,
                            kt.template or "none",
                            value=kt.template,
                        ),
                        Evidence(
                            "ks_source",
                            kt.confidence,
                            kt.ks_source or "none",
                            value=kt.ks_words,
                        ),
                        Evidence(
                            "runtime_key",
                            kt.confidence,
                            "template-computed",
                            value=kt.key.hex() if kt.key else None,
                        ),
                    ],
                )
                r.traces.append(trace)
                if kt.ok and kt.key and (not r.runtime_key):
                    r.runtime_key = kt.key.hex()
                    r.key_source = "symbolic_template_synthesis:" + (
                        kt.template or "unknown"
                    )
                    if r.confidence == "failed" and kt.validation_text:
                        r.text = kt.validation_text
                        r.text_type = "char"
                        r.source = "aes_decrypt:symbolic_template_synthesis"
                        r.reason = None
                        r.confidence = "high" if kt.confidence >= 85 else "medium"
                    elif r.text and r.confidence in ("low", "medium"):
                        r.confidence = "high" if kt.confidence >= 80 else r.confidence
                if call_addr in self.last_key_template_diag:
                    r.traces.append(
                        StrategyTrace(
                            strategy="diagnostic.synthesis_attempts",
                            ok=True,
                            detail=f"attempts={len(self.last_key_template_diag[call_addr].get('attempts', []))}",
                            evidence=[
                                Evidence(
                                    "attempts",
                                    50,
                                    "top template attempts",
                                    value=self.last_key_template_diag[call_addr],
                                )
                            ],
                        )
                    )
            enhanced.append(r)
        return enhanced


class Obfusk8Analyzer(SymbolicAnalyzer):
    _RUNTIME_MARKERS = ("Oh skibiddi oooh", "pojkdkddkeifpojkdkddkeif")

    @staticmethod
    def _looks_like_decode_artifact(text: str) -> bool:
        """Reject short printable blobs produced by source-based false positives.

        Obfusk8 wrappers occasionally expose printable-looking encrypted bytes
        through the static-source shortcut. They are usually short, repetitive,
        low-diversity strings such as ``N88NNN8`` or ``i@PPPP@iii``. Keep normal
        short indicators such as file extensions, DLL names, paths and API names.
        """
        if not text:
            return False
        if any(marker in text for marker in Obfusk8Analyzer._RUNTIME_MARKERS):
            return False
        if len(text) > 16:
            return False
        if any(ch.isspace() for ch in text):
            return False
        if text.startswith((".", "http://", "https://")):
            return False
        lower = text.lower()
        if lower.endswith(".dl") and not lower.endswith(".dll"):
            return True
        if "\\" in text or "/" in text or "." in text:
            return False
        api_like = re.match(r"^(Nt|Zw|Rtl|Ldr|Get|Set|Create|Open|Close|Read|Write|Virtual|Internet|Crypt|Find)[A-Za-z0-9_]+$", text)
        if api_like:
            known = {api for api in COMMON_APIS if re.match(r"^(Nt|Zw|Rtl|Ldr|Get|Set|Create|Open|Close|Read|Write|Virtual|Internet|Crypt|Find)[A-Za-z0-9_]+$", api)}
            if any(api.startswith(text) and api != text for api in known):
                return True
            return False
        unique = len(set(text))
        # Repetitive ASCII patterns with almost no semantic content.
        if len(text) >= 4 and unique <= 2:
            return True
        if len(text) >= 6 and unique <= 3:
            return True
        if len(text) >= 6 and unique <= 4 and not re.search(r"[a-z]{2,}|[A-Z][a-z]", text):
            return True
        return False

    def classify_result(self, r: UniversalResult) -> str:
        text = r.text or ""
        if any(marker in text for marker in self._RUNTIME_MARKERS):
            return "obfusk8_runtime_literal"
        if self._looks_like_decode_artifact(text):
            return "obfusk8_decode_artifact"
        blob = json.dumps(
            [asdict(t) for t in r.traces], ensure_ascii=False, default=str
        ).lower()
        if (
            any((x in blob for x in ("__debugbreak", "anti-debug", "vm_state")))
            and r.confidence != "high"
        ):
            return "obfusk8_runtime_candidate"
        return classify_result_symbolic(r)

    def is_runtime_literal(self, r: UniversalResult) -> bool:
        return self.classify_result(r) in (
            "obfusk8_runtime_literal",
            "obfusk8_runtime_candidate",
            "obfusk8_decode_artifact",
        )

    def _decode_local_source(self, call_addr: int) -> Optional[Tuple[str, str, Dict[str, Any]]]:
        try:
            local = self.recover_from_local_state(call_addr)
        except Exception as exc:
            return None
        if not local.get("ok"):
            return None
        raw_size = local.get("raw_size")
        local_src = local.get("local_src")
        if not isinstance(local_src, (bytes, bytearray)):
            return None
        blob = bytes(local_src)
        if not self.is_text_bytes(blob):
            return None
        text, text_type = self.decode_text(blob, raw_size)
        if not text or self._looks_like_decode_artifact(text):
            return None
        return text, text_type or "char", local

    def _needs_local_source_retry(self, result: UniversalResult) -> bool:
        if not result.text:
            return True
        return self._looks_like_decode_artifact(result.text)

    def _apply_local_source_recovery(self, result: UniversalResult) -> None:
        if not self._needs_local_source_retry(result):
            return
        try:
            call_addr = int(result.call_addr, 16)
        except Exception:
            return
        decoded = self._decode_local_source(call_addr)
        if decoded is None:
            return
        text, text_type, local = decoded
        result.text = text
        result.text_type = text_type
        result.source = "local_state:rdx_printable_buffer"
        result.reason = None
        result.confidence = "medium"
        if result.raw_size is None and local.get("raw_size") is not None:
            result.raw_size = int(local["raw_size"])
        if result.chunks is None and local.get("chunks") is not None:
            result.chunks = int(local["chunks"])
        key = local.get("runtime_key")
        if isinstance(key, (bytes, bytearray)) and len(key) == 16 and key != b"\x00" * 16:
            result.runtime_key = bytes(key).hex()
            result.key_source = "function_entry_local_concrete"
        result.traces.append(
            StrategyTrace(
                strategy="plaintext.local_source_retry",
                ok=True,
                detail=f"decoded {len(text)} chars after static-source retry",
                evidence=[
                    Evidence(
                        "plaintext",
                        92,
                        "local interpreter recovered RDX source buffer",
                        value=text,
                    )
                ],
            )
        )

    def analyze_strings(self) -> List[UniversalResult]:
        results = self.analyze_universal()
        for result in results:
            self._apply_local_source_recovery(result)
        return results

    def analyze_all(
        self, include_unreferenced_hashes: bool = False, slice_limit: int = 0
    ) -> Dict[str, Any]:
        t0 = time.time()
        string_results = self.analyze_strings()
        recovered_strings = [r.text for r in string_results if r.text]
        api = Resolve8HashResolver(self, recovered_strings).run(
            include_unreferenced=include_unreferenced_hashes
        )
        syscall = K8SyscallAnalyzer(self, recovered_strings, api).run()
        inline = InlineDecryptDiscovery(self).run()
        if slice_limit and slice_limit > 0:
            try:
                _funcs, calls = self.find_decrypt_calls()
            except Exception:
                calls = []
            slices = (
                RuntimeKeyBackwardSlicer(self).run(calls, limit=slice_limit)
                if calls
                else {
                    "ok": False,
                    "reason": "slice_limit_nonzero_but_no_decrypt_calls",
                    "reports": [],
                    "complete": 0,
                    "total": 0,
                }
            )
        else:
            slices = {
                "ok": False,
                "reason": "slice_limit_zero",
                "reports": [],
                "complete": 0,
                "total": 0,
            }
        return {
            "binary": self.pe.path,
            "image_base": hex(self.pe.base),
            "elapsed_sec": round(time.time() - t0, 3),
            "build_hash": (
                f"0x{self.build_hash:08X}" if self.build_hash is not None else None
            ),
            "build_hash_inputs": self.build_hash_inputs,
            "strings": {
                "results": [self.result_to_dict(r) for r in string_results],
                "recovered_user_strings": len(
                    [
                        r
                        for r in string_results
                        if r.text and (not self.is_runtime_literal(r))
                    ]
                ),
                "filtered_runtime_literals": len(
                    [r for r in string_results if r.text and self.is_runtime_literal(r)]
                ),
            },
            "resolve8_api_hashes": api,
            "k8_syscalls": syscall,
            "inline_decrypt_discovery": inline,
            "runtime_key_slices": slices,
            "z3_mba_self_test": MBASimplifier.prove_with_z3(),
        }

    @staticmethod
    def _trace_blob_for_result(r: UniversalResult) -> str:
        try:
            return json.dumps(
                [asdict(t) for t in r.traces], ensure_ascii=False, default=str
            ).lower()
        except Exception:
            return ""

    def source_strategy_for_result(self, r: UniversalResult) -> str:
        source = r.source or "none"
        if source.startswith("aes_decrypt"):
            return "aes_decrypt"
        if source.startswith("static_source"):
            return "static_source"
        if source.startswith("local_state:rdx_printable_buffer"):
            return "local_plaintext_buffer"
        if source.startswith("symbolic_template"):
            return "symbolic_template"
        if r.text:
            return source or "unknown_text_source"
        return "unrecovered"

    def key_status_for_result(self, r: UniversalResult) -> str:
        key = (r.runtime_key or "").lower().replace("0x", "")
        if key:
            if len(key) == 32 and set(key) <= {"0"}:
                return "rejected_zero"
            return "recovered"
        blob = self._trace_blob_for_result(r)
        if (
            "zero_key_rejected" in blob
            or "key_all_zero_rejected" in blob
            or "rejected_zero" in blob
        ):
            return "rejected_zero"
        if r.text and r.source and r.source.startswith("static_source"):
            return "not_required_static_source"
        if r.text and r.source == "local_state:rdx_printable_buffer":
            return "not_required_local_plaintext"
        if r.text:
            return "missing"
        return "unavailable"

    def warnings_for_result(self, r: UniversalResult) -> List[str]:
        warnings: List[str] = []
        key_status = self.key_status_for_result(r)
        source_strategy = self.source_strategy_for_result(r)
        classification = self.classify_result(r)
        if key_status == "rejected_zero":
            warnings.append("zero runtime key rejected")
        if classification == "obfusk8_decode_artifact":
            warnings.append("filtered probable decode artifact")
        if (
            r.text
            and key_status in ("missing", "unavailable")
            and (source_strategy != "aes_decrypt")
        ):
            warnings.append("plaintext recovered without runtime key")
        if r.confidence == "medium" and key_status != "recovered":
            warnings.append("medium confidence: source-based recovery")
        return warnings

    def result_to_dict(self, r: UniversalResult) -> Dict[str, Any]:
        d = result_to_dict_symbolic(r)
        key_status = self.key_status_for_result(r)
        if key_status == "rejected_zero":
            d["runtime_key"] = None
            d["key_source"] = None
        d["classification"] = self.classify_result(r)
        d["filtered_by_default"] = self.is_runtime_literal(r)
        d["source_strategy"] = self.source_strategy_for_result(r)
        d["key_status"] = key_status
        d["key_available"] = key_status == "recovered"
        d["warnings"] = self.warnings_for_result(r)
        return d
