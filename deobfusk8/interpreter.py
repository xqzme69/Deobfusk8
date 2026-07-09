from __future__ import annotations

from typing import Any, Dict, List, Optional

from capstone import CS_OP_IMM, CS_OP_MEM, CS_OP_REG
from capstone.x86 import X86_REG_RIP

from .result import UNKNOWN


class Analyzer:
    pass


class ConcreteState:
    STACK_RBP = 123145302310912
    STACK_RSP = 123145303359488

    def __init__(self, analyzer: Analyzer):
        self.an = analyzer
        self.regs: Dict[str, Any] = {}
        self.xmm: Dict[str, bytes] = {}
        self.mem: Dict[int, int] = {}
        self.flags: Dict[str, Any] = {
            "zf": UNKNOWN,
            "cf": UNKNOWN,
            "sf": UNKNOWN,
            "of": UNKNOWN,
        }
        self.pc: Optional[int] = None
        self.halted = False
        self.logs: List[str] = []
        self.regs.update(
            {
                "rax": 0,
                "rbx": 0,
                "rcx": 0,
                "rdx": 0,
                "rsi": 0,
                "rdi": 0,
                "r8": 0,
                "r9": 0,
                "r10": 0,
                "r11": 0,
                "r12": 0,
                "r13": 0,
                "r14": 0,
                "r15": 0,
                "rbp": self.STACK_RBP,
                "rsp": self.STACK_RSP,
            }
        )

    def copy(self) -> "ConcreteState":
        s = ConcreteState(self.an)
        s.regs = dict(self.regs)
        s.xmm = dict(self.xmm)
        s.mem = dict(self.mem)
        s.flags = dict(self.flags)
        s.pc = self.pc
        s.halted = self.halted
        s.logs = list(self.logs)
        return s

    def log(self, msg: str) -> None:
        self.logs.append(msg)

    def read_bytes(self, addr: int, size: int) -> Optional[bytes]:
        out = []
        for i in range(size):
            a = addr + i
            if a in self.mem:
                out.append(self.mem[a])
            else:
                pe_b = self.an.pe.read_va(a, 1)
                if pe_b is None or len(pe_b) != 1:
                    return None
                out.append(pe_b[0])
        return bytes(out)

    def write_bytes(self, addr: int, data: bytes) -> None:
        for i, b in enumerate(data):
            self.mem[addr + i] = b & 255

    def read_int(self, addr: int, size: int) -> Any:
        b = self.read_bytes(addr, size)
        if b is None or len(b) != size:
            return UNKNOWN
        return int.from_bytes(b, "little", signed=False)

    def write_int(self, addr: int, value: int, size: int) -> None:
        self.write_bytes(
            addr, int(value & (1 << size * 8) - 1).to_bytes(size, "little")
        )


class LocalConcreteInterpreter:
    def __init__(
        self,
        analyzer: Analyzer,
        summaries: Optional[Dict[int, int]] = None,
        verbose: bool = False,
    ):
        self.an = analyzer
        self.summaries = summaries or {}
        self.verbose = verbose

    def reg_name(self, reg: int) -> str:
        return self.an.reg_name(reg)

    def canon(self, reg: int) -> str:
        return self.an.canon_reg(reg)

    def reg_bits(self, reg: int) -> int:
        n = self.reg_name(reg)
        if (
            n in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh")
            or n.endswith("b")
            or n in ("sil", "dil", "bpl", "spl")
        ):
            return 8
        if n.endswith("w") or n in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
            return 16
        if n.startswith("e") or n.endswith("d"):
            return 32
        return 64

    def get_reg(self, st: ConcreteState, reg: int) -> Any:
        n = self.reg_name(reg)
        c = self.canon(reg)
        v = st.regs.get(c, UNKNOWN)
        if v is UNKNOWN:
            return UNKNOWN
        v = int(v) & 18446744073709551615
        if (
            n in ("al", "bl", "cl", "dl")
            or n.endswith("b")
            or n in ("sil", "dil", "bpl", "spl")
        ):
            return v & 255
        if n in ("ah", "bh", "ch", "dh"):
            return v >> 8 & 255
        if n.endswith("w") or n in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
            return v & 65535
        if n.startswith("e") or n.endswith("d"):
            return v & 4294967295
        return v

    def set_reg(self, st: ConcreteState, reg: int, value: Any) -> None:
        c = self.canon(reg)
        n = self.reg_name(reg)
        if value is UNKNOWN:
            st.regs[c] = UNKNOWN
            return
        value = int(value)
        old = st.regs.get(c, 0)
        if old is UNKNOWN:
            old = 0
        old = int(old) & 18446744073709551615
        if (
            n in ("al", "bl", "cl", "dl")
            or n.endswith("b")
            or n in ("sil", "dil", "bpl", "spl")
        ):
            st.regs[c] = old & ~255 | value & 255
        elif n in ("ah", "bh", "ch", "dh"):
            st.regs[c] = old & ~65280 | (value & 255) << 8
        elif n.endswith("w") or n in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
            st.regs[c] = old & ~65535 | value & 65535
        elif n.startswith("e") or n.endswith("d"):
            st.regs[c] = value & 4294967295
        else:
            st.regs[c] = value & 18446744073709551615

    def mem_addr(self, st: ConcreteState, insn: Any, op: Any) -> Any:
        m = op.mem
        if m.base == X86_REG_RIP:
            return int(insn.address + insn.size + m.disp)
        base = 0
        if m.base:
            base = self.get_reg(st, m.base)
            if base is UNKNOWN:
                return UNKNOWN
        idx = 0
        if m.index:
            idx = self.get_reg(st, m.index)
            if idx is UNKNOWN:
                return UNKNOWN
            idx *= m.scale
        return int(base) + int(idx) + int(m.disp) & 18446744073709551615

    def read_op(self, st: ConcreteState, insn: Any, op: Any) -> Any:
        if op.type == CS_OP_IMM:
            return int(op.imm)
        if op.type == CS_OP_REG:
            rn = self.reg_name(op.reg)
            if rn.startswith("xmm"):
                return st.xmm.get(rn, b"\x00" * 16)
            return self.get_reg(st, op.reg)
        if op.type == CS_OP_MEM:
            addr = self.mem_addr(st, insn, op)
            if addr is UNKNOWN:
                return UNKNOWN
            if op.size == 16:
                return st.read_bytes(addr, 16) or UNKNOWN
            return st.read_int(addr, max(1, op.size))
        return UNKNOWN

    def write_op(self, st: ConcreteState, insn: Any, op: Any, value: Any) -> None:
        if op.type == CS_OP_REG:
            rn = self.reg_name(op.reg)
            if rn.startswith("xmm"):
                if isinstance(value, (bytes, bytearray)) and len(value) >= 16:
                    st.xmm[rn] = bytes(value[:16])
                else:
                    st.xmm[rn] = b"\x00" * 16 if value is not UNKNOWN else b"\x00" * 16
            else:
                self.set_reg(st, op.reg, value)
        elif op.type == CS_OP_MEM:
            addr = self.mem_addr(st, insn, op)
            if addr is UNKNOWN:
                return
            if isinstance(value, (bytes, bytearray)):
                st.write_bytes(addr, bytes(value[: op.size or len(value)]))
            elif value is UNKNOWN:
                st.write_bytes(addr, b"\x00" * max(1, op.size))
            else:
                st.write_int(addr, int(value), max(1, op.size))

    @staticmethod
    def mask_for_bits(bits: int) -> int:
        return (1 << bits) - 1

    def set_logic_flags(self, st: ConcreteState, v: Any, bits: int) -> None:
        if v is UNKNOWN:
            st.flags.update({"zf": UNKNOWN, "cf": False, "sf": UNKNOWN, "of": False})
            return
        mask = self.mask_for_bits(bits)
        vv = int(v) & mask
        st.flags["zf"] = vv == 0
        st.flags["sf"] = bool(vv & 1 << bits - 1)
        st.flags["cf"] = False
        st.flags["of"] = False

    def set_cmp_flags(self, st: ConcreteState, a: Any, b: Any, bits: int) -> None:
        if a is UNKNOWN or b is UNKNOWN:
            st.flags.update(
                {"zf": UNKNOWN, "cf": UNKNOWN, "sf": UNKNOWN, "of": UNKNOWN}
            )
            return
        mask = self.mask_for_bits(bits)
        aa, bb = (int(a) & mask, int(b) & mask)
        r = aa - bb & mask
        st.flags["zf"] = r == 0
        st.flags["cf"] = aa < bb
        st.flags["sf"] = bool(r & 1 << bits - 1)
        st.flags["of"] = (aa ^ bb) & (aa ^ r) & 1 << bits - 1 != 0

    def eval_jcc(self, st: ConcreteState, mnemonic: str) -> Any:
        zf, cf, sf, of = (
            st.flags.get("zf", UNKNOWN),
            st.flags.get("cf", UNKNOWN),
            st.flags.get("sf", UNKNOWN),
            st.flags.get("of", UNKNOWN),
        )
        if mnemonic in ("je", "jz"):
            return zf
        if mnemonic in ("jne", "jnz"):
            return UNKNOWN if zf is UNKNOWN else not zf
        if mnemonic in ("ja", "jnbe"):
            return (
                False
                if (cf is False and zf is False) is False
                and (cf is not UNKNOWN and zf is not UNKNOWN)
                else UNKNOWN if cf is UNKNOWN or zf is UNKNOWN else not cf and (not zf)
            )
        if mnemonic in ("jae", "jnb", "jnc"):
            return UNKNOWN if cf is UNKNOWN else not cf
        if mnemonic in ("jb", "jc", "jnae"):
            return cf
        if mnemonic in ("jbe", "jna"):
            return UNKNOWN if cf is UNKNOWN or zf is UNKNOWN else cf or zf
        if mnemonic in ("jg", "jnle"):
            return (
                UNKNOWN
                if zf is UNKNOWN or sf is UNKNOWN or of is UNKNOWN
                else not zf and sf == of
            )
        if mnemonic in ("jge", "jnl"):
            return UNKNOWN if sf is UNKNOWN or of is UNKNOWN else sf == of
        if mnemonic in ("jl", "jnge"):
            return UNKNOWN if sf is UNKNOWN or of is UNKNOWN else sf != of
        if mnemonic in ("jle", "jng"):
            return (
                UNKNOWN
                if zf is UNKNOWN or sf is UNKNOWN or of is UNKNOWN
                else zf or sf != of
            )
        return UNKNOWN

    def execute(self, st: ConcreteState, insn: Any, stop_addr: int) -> None:
        m = insn.mnemonic
        ops = insn.operands
        next_pc = insn.address + insn.size
        try:
            if insn.address == stop_addr:
                st.halted = True
                st.pc = insn.address
                return
            if m in ("nop", "int3"):
                st.pc = next_pc
                return
            if m == "ret":
                st.halted = True
                st.pc = next_pc
                return
            if m == "call" and len(ops) == 1:
                target = None
                if ops[0].type == CS_OP_IMM:
                    target = int(ops[0].imm)
                if target in self.summaries:
                    st.regs["rax"] = self.summaries[target] & 18446744073709551615
                    st.log(
                        f"summary call {hex(target)} -> rax={hex(self.summaries[target])}"
                    )
                else:
                    st.regs["rax"] = 0
                    st.log(f"unknown call {(hex(target) if target else '?')} -> rax=0")
                st.pc = next_pc
                return
            if m == "jmp" and len(ops) == 1 and (ops[0].type == CS_OP_IMM):
                st.pc = int(ops[0].imm)
                return
            if (
                m.startswith("j")
                and m != "jmp"
                and (len(ops) == 1)
                and (ops[0].type == CS_OP_IMM)
            ):
                cond = self.eval_jcc(st, m)
                if cond is True:
                    st.pc = int(ops[0].imm)
                elif cond is False:
                    st.pc = next_pc
                else:
                    st.log(
                        f"unknown branch {m} at {hex(insn.address)}; falling through"
                    )
                    st.pc = next_pc
                return
            if m in ("mov", "movzx", "movsxd") and len(ops) == 2:
                v = self.read_op(st, insn, ops[1])
                if m == "movzx" and v is not UNKNOWN:
                    v = int(v)
                self.write_op(st, insn, ops[0], v)
                st.pc = next_pc
                return
            if m == "lea" and len(ops) == 2:
                addr = self.mem_addr(st, insn, ops[1])
                self.write_op(st, insn, ops[0], addr)
                st.pc = next_pc
                return
            if m in ("movaps", "movups", "movdqa", "movdqu") and len(ops) == 2:
                v = self.read_op(st, insn, ops[1])
                self.write_op(st, insn, ops[0], v)
                st.pc = next_pc
                return
            if m in ("xor", "and", "or", "add", "sub", "imul") and len(ops) >= 2:
                a = self.read_op(st, insn, ops[0])
                b = self.read_op(st, insn, ops[1])
                bits = max(8, ops[0].size * 8)
                mask = self.mask_for_bits(bits)
                if a is UNKNOWN or b is UNKNOWN:
                    r = UNKNOWN
                else:
                    aa, bb = (int(a) & mask, int(b) & mask)
                    if m == "xor":
                        r = aa ^ bb
                    elif m == "and":
                        r = aa & bb
                    elif m == "or":
                        r = aa | bb
                    elif m == "add":
                        r = aa + bb
                    elif m == "sub":
                        r = aa - bb
                    else:
                        r = aa * bb
                    r &= mask
                self.write_op(st, insn, ops[0], r)
                self.set_logic_flags(st, r, bits)
                st.pc = next_pc
                return
            if m in ("shl", "sal", "shr", "sar", "rol", "ror") and len(ops) == 2:
                a = self.read_op(st, insn, ops[0])
                b = self.read_op(st, insn, ops[1])
                bits = max(8, ops[0].size * 8)
                mask = self.mask_for_bits(bits)
                if a is UNKNOWN or b is UNKNOWN:
                    r = UNKNOWN
                else:
                    aa, cnt = (int(a) & mask, int(b) & 63)
                    if m in ("shl", "sal"):
                        r = aa << cnt & mask
                    elif m == "shr":
                        r = aa >> cnt
                    elif m == "sar":
                        sign = 1 << bits - 1
                        signed = aa - (1 << bits) if aa & sign else aa
                        r = signed >> cnt & mask
                    elif m == "rol":
                        cnt %= bits
                        r = (aa << cnt | aa >> bits - cnt) & mask
                    else:
                        cnt %= bits
                        r = (aa >> cnt | aa << bits - cnt) & mask
                self.write_op(st, insn, ops[0], r)
                self.set_logic_flags(st, r, bits)
                st.pc = next_pc
                return
            if m == "not" and len(ops) == 1:
                a = self.read_op(st, insn, ops[0])
                bits = max(8, ops[0].size * 8)
                r = UNKNOWN if a is UNKNOWN else ~int(a) & self.mask_for_bits(bits)
                self.write_op(st, insn, ops[0], r)
                st.pc = next_pc
                return
            if m in ("inc", "dec") and len(ops) == 1:
                a = self.read_op(st, insn, ops[0])
                bits = max(8, ops[0].size * 8)
                if a is UNKNOWN:
                    r = UNKNOWN
                else:
                    r = int(a) + (1 if m == "inc" else -1) & self.mask_for_bits(bits)
                self.write_op(st, insn, ops[0], r)
                self.set_logic_flags(st, r, bits)
                st.pc = next_pc
                return
            if m in ("cmp", "test") and len(ops) == 2:
                a = self.read_op(st, insn, ops[0])
                b = self.read_op(st, insn, ops[1])
                bits = max(8, ops[0].size * 8, ops[1].size * 8)
                if m == "cmp":
                    self.set_cmp_flags(st, a, b, bits)
                else:
                    r = UNKNOWN if a is UNKNOWN or b is UNKNOWN else int(a) & int(b)
                    self.set_logic_flags(st, r, bits)
                st.pc = next_pc
                return
            if m.startswith("cmov") and len(ops) == 2:
                cond_m = "j" + m[4:]
                cond = self.eval_jcc(st, cond_m)
                if cond is True:
                    self.write_op(st, insn, ops[0], self.read_op(st, insn, ops[1]))
                elif cond is UNKNOWN:
                    self.write_op(st, insn, ops[0], UNKNOWN)
                st.pc = next_pc
                return
            if m in ("pxor", "xorps") and len(ops) == 2:
                self.write_op(st, insn, ops[0], b"\x00" * 16)
                st.pc = next_pc
                return
            st.log(f"unsupported {m} {insn.op_str} at {hex(insn.address)}")
            st.pc = next_pc
        except Exception as e:
            st.log(f"exception at {hex(insn.address)} {m} {insn.op_str}: {e}")
            st.halted = True
            st.pc = next_pc

    def run(
        self, start: int, stop: int, window_after: int = 64, max_steps: int = 15000
    ) -> ConcreteState:
        sec = self.an.pe.section_for_va(start)
        if not sec:
            raise ValueError("start address is not in a PE section")
        end = min(sec["va"] + max(sec["vsize"], sec["raw_size"]), stop + window_after)
        data = self.an.pe.read_va(start, end - start) or b""
        insns = list(self.an.cs.disasm(data, start))
        imap = {i.address: i for i in insns}
        st = ConcreteState(self.an)
        st.pc = start
        steps = 0
        while st.pc is not None and (not st.halted) and (steps < max_steps):
            if st.pc == stop:
                st.halted = True
                break
            insn = imap.get(st.pc)
            if insn is None:
                st.log(f"pc {hex(st.pc)} outside local map")
                break
            self.execute(st, insn, stop)
            steps += 1
        if steps >= max_steps:
            st.log(f"max_steps reached: {max_steps}")
        return st


class CopyingLocalInterpreter(LocalConcreteInterpreter):
    def _u64(self, v: int) -> int:
        return int(v) & 18446744073709551615

    def _looks_like_ascii_blob(self, data: bytes) -> bool:
        if not data:
            return False
        body = data.split(b"\x00", 1)[0]
        if len(body) < 3:
            return False
        good = sum((32 <= b < 127 or b in (9, 10, 13) for b in body))
        return good >= max(3, int(len(body) * 0.85))

    def _read_printable_pe_literal(
        self, addr: int, max_len: int = 640
    ) -> Optional[bytes]:
        blob = self.an.pe.read_va(addr, max_len)
        if not blob:
            return None
        if b"\x00" in blob:
            n = blob.index(b"\x00") + 1
            blob = blob[:n]
        if self._looks_like_ascii_blob(blob):
            return blob
        return None

    def execute(self, st: ConcreteState, insn: Any, stop_addr: int) -> None:
        m = insn.mnemonic
        ops = insn.operands
        next_pc = insn.address + insn.size
        if m == "push" and len(ops) == 1:
            v = self.read_op(st, insn, ops[0])
            rsp = st.regs.get("rsp", UNKNOWN)
            if rsp is not UNKNOWN:
                rsp = self._u64(int(rsp) - 8)
                st.regs["rsp"] = rsp
                st.write_int(rsp, 0 if v is UNKNOWN else int(v), 8)
            st.pc = next_pc
            return
        if m == "pop" and len(ops) == 1:
            rsp = st.regs.get("rsp", UNKNOWN)
            if rsp is not UNKNOWN:
                v = st.read_int(int(rsp), 8)
                self.write_op(st, insn, ops[0], v)
                st.regs["rsp"] = self._u64(int(rsp) + 8)
            st.pc = next_pc
            return
        if m == "cdqe":
            eax = st.regs.get("rax", UNKNOWN)
            if eax is not UNKNOWN:
                x = int(eax) & 4294967295
                if x & 2147483648:
                    x -= 4294967296
                st.regs["rax"] = self._u64(x)
            st.pc = next_pc
            return
        if m == "movsx" and len(ops) == 2:
            v = self.read_op(st, insn, ops[1])
            if v is not UNKNOWN:
                bits = max(8, ops[1].size * 8)
                sign = 1 << bits - 1
                vv = int(v) & (1 << bits) - 1
                if vv & sign:
                    vv -= 1 << bits
                v = vv
            self.write_op(st, insn, ops[0], v)
            st.pc = next_pc
            return
        if m.startswith("rep stosb"):
            count = st.regs.get("rcx", UNKNOWN)
            dst = st.regs.get("rdi", UNKNOWN)
            al = st.regs.get("rax", UNKNOWN)
            if (
                count is not UNKNOWN
                and dst is not UNKNOWN
                and (al is not UNKNOWN)
                and (0 <= int(count) <= 8192)
            ):
                st.write_bytes(int(dst), bytes([int(al) & 255]) * int(count))
                st.regs["rdi"] = self._u64(int(dst) + int(count))
                st.regs["rcx"] = 0
            st.pc = next_pc
            return
        if m == "call" and len(ops) == 1:
            target = int(ops[0].imm) if ops[0].type == CS_OP_IMM else None
            if target in self.summaries:
                st.regs["rax"] = self.summaries[target] & 18446744073709551615
                st.log(
                    f"summary call {hex(target)} -> rax={hex(self.summaries[target])}"
                )
                st.pc = next_pc
                return
            rcx = st.regs.get("rcx", UNKNOWN)
            rdx = st.regs.get("rdx", UNKNOWN)
            if isinstance(rcx, int) and isinstance(rdx, int):
                lit = self._read_printable_pe_literal(rdx, 640)
                if lit is not None:
                    st.write_bytes(rcx, lit)
                    st.regs["rax"] = int(rcx) & 18446744073709551615
                    st.log(
                        f"summary printable-copy call {(hex(target) if target else '?')} {hex(rdx)} -> {hex(rcx)} len={len(lit)}"
                    )
                    st.pc = next_pc
                    return
            st.regs["rax"] = 0
            st.log(f"unknown call {(hex(target) if target else '?')} -> rax=0")
            st.pc = next_pc
            return
        return super().execute(st, insn, stop_addr)
