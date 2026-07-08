from __future__ import annotations
from typing import Any, Sequence, Optional, List
from .hash import u32


class MBASimplifier:
    @staticmethod
    def l_xor(a: int, b: int) -> int:
        return u32((u32(a) | u32(b)) - (u32(a) & u32(b)))

    @staticmethod
    def l_sub(a: int, b: int) -> int:
        return u32((u32(a) ^ u32(b)) - u32(2 * (~u32(a) & u32(b))))

    @staticmethod
    def l_or(a: int, b: int) -> int:
        return u32(u32(a) + u32(b) - (u32(a) & u32(b)))

    @staticmethod
    def prove_with_z3() -> Dict[str, Any]:
        try:
            import z3
        except Exception as e:
            return {"available": False, "error": str(e), "proofs": {}}
        x = z3.BitVec("x", 32)
        y = z3.BitVec("y", 32)
        proofs: Dict[str, str] = {}
        checks = {
            "L_XOR == XOR": ((x | y) - (x & y), x ^ y),
            "L_SUB == SUB": ((x ^ y) - z3.BitVecVal(2, 32) * (~x & y), x - y),
            "L_OR == OR": (x + y - (x & y), x | y),
        }
        for name, (a, b) in checks.items():
            s = z3.Solver()
            s.add(a != b)
            proofs[name] = str(s.check())
        return {"available": True, "proofs": proofs}


class KeyMixerTemplate:
    name = "abstract"

    def compute(self, build_hash: int, ks_words: Sequence[int]) -> bytes:
        raise NotImplementedError


class Obfusk8AES8TwoPassKeyMixer(KeyMixerTemplate):
    name = "obfusk8_aes8_twopass_source"

    @staticmethod
    def _m(i: int) -> int:
        if i < 4:
            return i
        if i < 8:
            return 7 - i
        if i < 12:
            return i - 8 >> 1
        return (i - 12 >> 1) + 2

    def compute(self, build_hash: int, ks_words: Sequence[int]) -> bytes:
        if len(ks_words) < 4:
            raise ValueError("need four _ks words")
        ks = [u32(x) for x in ks_words[:4]]
        runtime_key = [0] * 16
        kx = u32(build_hash)
        for i in range(16):
            m = self._m(i)
            kx = MBASimplifier.l_xor(kx, ks[m])
            kx = MBASimplifier.l_sub(kx, i)
            runtime_key[i] = (ks[m] ^ kx & 255) & 255
            kx = u32(kx ^ runtime_key[i])
        kx = u32(build_hash)
        for i in range(16):
            m = self._m(i)
            kx = MBASimplifier.l_xor(kx, ks[m])
            kx = MBASimplifier.l_sub(kx, i)
            runtime_key[i] = (runtime_key[i] ^ kx & 255) & 255
            kx = u32(kx ^ (ks[m] ^ kx & 255))
        return bytes(runtime_key)


class Obfusk8CompilerFoldedInitTemplate(KeyMixerTemplate):
    name = "obfusk8_compiler_folded_init"

    def __init__(self, analyzer: Any, word: int, byte3: int, or_imm: int):
        self.analyzer = analyzer
        self.word = word
        self.byte3 = byte3
        self.or_imm = or_imm

    def compute(self, build_hash: int, ks_words: Sequence[int]) -> bytes:
        ks_bytes = b"".join(
            (int(x).to_bytes(4, "little", signed=False) for x in ks_words[:4])
        )
        return self.analyzer._obfusk8_key_from_pattern(
            build_hash, ks_bytes, self.word, self.byte3, self.or_imm
        )
