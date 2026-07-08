from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import re
from capstone import CS_OP_MEM
from .aes import INV_SBOX
from .resolve8 import COMMON_APIS
from .result import UNKNOWN


def _is_complete_syscall_name(name: str) -> bool:
    if not re.match(r"^(Zw|Nt)[A-Za-z0-9_]+$", name or ""):
        return False
    known = {api for api in COMMON_APIS if re.match(r"^(Zw|Nt)[A-Za-z0-9_]+$", api)}
    if name in known:
        return True
    # Drop truncated prefixes such as "NtAllocateVir" when the full API name is
    # present in the dictionary. Unknown full syscall names are still allowed.
    if any(api.startswith(name) and api != name for api in known):
        return False
    return len(name) >= 14


@dataclass
class SyscallIntent:
    name: str
    source: str
    hash_hex: Optional[str] = None
    locations: List[str] = field(default_factory=list)
    confidence: int = 60


class K8SyscallAnalyzer:
    def __init__(
        self,
        analyzer: SymbolicAnalyzer,
        strings: Iterable[str],
        api_report: Optional[Dict[str, Any]] = None,
    ):
        self.an = analyzer
        self.strings = list(strings)
        self.api_report = api_report or {}

    def run(self) -> Dict[str, Any]:
        intents: Dict[str, SyscallIntent] = {}
        for s in self.strings:
            if _is_complete_syscall_name(s or ""):
                name = s
                intents[name] = SyscallIntent(
                    name=name, source="deobfuscated_string", confidence=80
                )
        for h in (
            self.api_report.get("hits", []) if isinstance(self.api_report, dict) else []
        ):
            name = h.get("name", "")
            if _is_complete_syscall_name(name):
                cur = intents.get(name) or SyscallIntent(
                    name=name, source="resolve8_hash", confidence=70
                )
                cur.hash_hex = h.get("hash_hex")
                cur.locations = h.get("locations", []) or []
                cur.confidence = max(cur.confidence, 85 if cur.locations else 70)
                intents[name] = cur
        features: Dict[str, Any] = {}
        raw = self.an.pe.raw
        features["mentions_ntdll"] = b"ntdll.dll" in raw.lower()
        features["has_allocation_syscall_name"] = any(
            (
                x in intents
                for x in ("NtAllocateVirtualMemory", "ZwAllocateVirtualMemory")
            )
        )
        features["has_query_process_name"] = any(
            (
                x in intents
                for x in ("NtQueryInformationProcess", "ZwQueryInformationProcess")
            )
        )
        features["possible_k8_syscall_engine"] = (
            bool(intents)
            or features["has_allocation_syscall_name"]
            or features["has_query_process_name"]
        )
        return {
            "ok": True,
            "note": "SSNs are not static PE properties; Obfusk8 computes them at runtime from loaded ntdll export order.",
            "features": features,
            "syscall_intents": [
                asdict(v) for v in sorted(intents.values(), key=lambda x: x.name)
            ],
        }


@dataclass
class InlineDecryptCandidate:
    function_start: str
    function_end: Optional[str]
    evidence: List[str]
    rsbox_refs: List[str] = field(default_factory=list)
    confidence: int = 50


@dataclass
class KeySliceReport:
    ok: bool
    call_addr: str
    key_ptr: Optional[str]
    covered_offsets: List[int]
    writers: List[Dict[str, Any]]
    recovered_key: Optional[str] = None
    reason: Optional[str] = None


class InlineDecryptDiscovery:
    def __init__(self, analyzer: SymbolicAnalyzer):
        self.an = analyzer

    def run(self) -> Dict[str, Any]:
        rsbox_sig = bytes(INV_SBOX[:16])
        rsbox_locs = self.an.pe.find_pattern(rsbox_sig)
        cands: Dict[int, InlineDecryptCandidate] = {}
        if not rsbox_locs:
            return {"ok": False, "reason": "rsbox_not_found", "candidates": []}
        for rsbox in rsbox_locs[:4]:
            try:
                refs = self.an.find_functions_referencing(rsbox)
            except Exception:
                refs = []
            for ref in refs:
                fstart, fend = self.an.find_function_boundaries(ref)
                if not fstart:
                    continue
                cand = cands.setdefault(
                    fstart,
                    InlineDecryptCandidate(
                        function_start=hex(fstart),
                        function_end=hex(fend) if fend else None,
                        evidence=["references_AES_rsbox"],
                        rsbox_refs=[],
                        confidence=65,
                    ),
                )
                cand.rsbox_refs.append(hex(ref))
        for cand in cands.values():
            if len(cand.rsbox_refs) > 1:
                cand.confidence += 10
            cand.confidence = min(cand.confidence, 90)
        return {
            "ok": True,
            "rsbox_locations": [hex(x) for x in rsbox_locs],
            "candidates": [
                asdict(c)
                for c in sorted(
                    cands.values(), key=lambda c: c.confidence, reverse=True
                )
            ],
        }


class RuntimeKeyBackwardSlicer:
    def __init__(self, analyzer: SymbolicAnalyzer):
        self.an = analyzer

    def _mem_addr_from_local_base(self, st: Any, mem: Any) -> Optional[int]:
        base_name = self.an.reg_name(mem.base)
        index_name = self.an.reg_name(mem.index) if getattr(mem, "index", 0) else None
        base = st.regs.get(base_name, UNKNOWN) if base_name else 0
        if base is UNKNOWN or base is None:
            try:
                base = st.regs.get(self.an.canon_reg(mem.base), UNKNOWN)
            except Exception:
                base = UNKNOWN
        if base is UNKNOWN or base is None:
            return None
        val = int(base) + int(mem.disp)
        if index_name:
            idx = st.regs.get(index_name, UNKNOWN)
            if idx is UNKNOWN:
                return None
            val += int(idx) * int(mem.scale or 1)
        return val & 18446744073709551615

    def slice_call(self, call_addr: int) -> KeySliceReport:
        try:
            local = self.an.recover_from_local_state(call_addr)
        except Exception as e:
            return KeySliceReport(
                False, hex(call_addr), None, [], [], reason=f"local_state_error:{e}"
            )
        if not local.get("ok"):
            return KeySliceReport(
                False,
                hex(call_addr),
                None,
                [],
                [],
                reason=str(
                    local.get("reason")
                    or local.get("meta", {}).get("error")
                    or "local_state_failed"
                ),
            )
        st = local.get("state")
        key_ptr = local.get("key_ptr")
        key_bytes = local.get("runtime_key")
        if st is None or key_ptr is UNKNOWN or key_ptr is None:
            return KeySliceReport(
                False, hex(call_addr), None, [], [], reason="key_ptr_unknown"
            )
        key_ptr_i = int(key_ptr)
        fstart, _fend = self.an.find_function_boundaries(call_addr)
        if not fstart:
            return KeySliceReport(
                False,
                hex(call_addr),
                hex(key_ptr_i),
                [],
                [],
                reason="function_boundary_not_found",
            )
        insns = self.an.disasm_range(fstart, max(0, call_addr - fstart + 16))
        writers: List[Dict[str, Any]] = []
        covered: set[int] = set()
        for insn in insns:
            if insn.address >= call_addr:
                break
            if not getattr(insn, "operands", None):
                continue
            dst = insn.operands[0]
            if dst.type != CS_OP_MEM:
                continue
            addr = self._mem_addr_from_local_base(st, dst.mem)
            if addr is None:
                continue
            size = max(1, int(getattr(dst, "size", 1) or 1))
            lo = max(addr, key_ptr_i)
            hi = min(addr + size, key_ptr_i + 16)
            if lo < hi:
                off_start = lo - key_ptr_i
                off_end = hi - key_ptr_i
                for o in range(off_start, off_end):
                    covered.add(o)
                writers.append(
                    {
                        "address": hex(insn.address),
                        "mnemonic": f"{insn.mnemonic} {insn.op_str}",
                        "write_addr": hex(addr),
                        "size": size,
                        "key_offsets": list(range(off_start, off_end)),
                    }
                )
        return KeySliceReport(
            ok=bool(key_bytes) and len(covered) == 16,
            call_addr=hex(call_addr),
            key_ptr=hex(key_ptr_i),
            covered_offsets=sorted(covered),
            writers=writers[-80:],
            recovered_key=(
                key_bytes.hex() if isinstance(key_bytes, (bytes, bytearray)) else None
            ),
            reason=(
                None
                if len(covered) == 16
                else f"partial_key_coverage:{len(covered)}/16"
            ),
        )

    def run(self, calls: Sequence[Tuple[int, int]], limit: int = 64) -> Dict[str, Any]:
        reports = [asdict(self.slice_call(c)) for c, _t in list(calls)[:limit]]
        return {
            "ok": True,
            "reports": reports,
            "complete": sum((1 for r in reports if r.get("ok"))),
            "total": len(reports),
        }
