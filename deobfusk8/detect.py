from __future__ import annotations
import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

_SBOX = [
    99,
    124,
    119,
    123,
    242,
    107,
    111,
    197,
    48,
    1,
    103,
    43,
    254,
    215,
    171,
    118,
    202,
    130,
    201,
    125,
    250,
    89,
    71,
    240,
    173,
    212,
    162,
    175,
    156,
    164,
    114,
    192,
    183,
    253,
    147,
    38,
    54,
    63,
    247,
    204,
    52,
    165,
    229,
    241,
    113,
    216,
    49,
    21,
    4,
    199,
    35,
    195,
    24,
    150,
    5,
    154,
    7,
    18,
    128,
    226,
    235,
    39,
    178,
    117,
    9,
    131,
    44,
    26,
    27,
    110,
    90,
    160,
    82,
    59,
    214,
    179,
    41,
    227,
    47,
    132,
    83,
    209,
    0,
    237,
    32,
    252,
    177,
    91,
    106,
    203,
    190,
    57,
    74,
    76,
    88,
    207,
    208,
    239,
    170,
    251,
    67,
    77,
    51,
    133,
    69,
    249,
    2,
    127,
    80,
    60,
    159,
    168,
    81,
    163,
    64,
    143,
    146,
    157,
    56,
    245,
    188,
    182,
    218,
    33,
    16,
    255,
    243,
    210,
    205,
    12,
    19,
    236,
    95,
    151,
    68,
    23,
    196,
    167,
    126,
    61,
    100,
    93,
    25,
    115,
    96,
    129,
    79,
    220,
    34,
    42,
    144,
    136,
    70,
    238,
    184,
    20,
    222,
    94,
    11,
    219,
    224,
    50,
    58,
    10,
    73,
    6,
    36,
    92,
    194,
    211,
    172,
    98,
    145,
    149,
    228,
    121,
    231,
    200,
    55,
    109,
    141,
    213,
    78,
    169,
    108,
    86,
    244,
    234,
    101,
    122,
    174,
    8,
    186,
    120,
    37,
    46,
    28,
    166,
    180,
    198,
    232,
    221,
    116,
    31,
    75,
    189,
    139,
    138,
    112,
    62,
    181,
    102,
    72,
    3,
    246,
    14,
    97,
    53,
    87,
    185,
    134,
    193,
    29,
    158,
    225,
    248,
    152,
    17,
    105,
    217,
    142,
    148,
    155,
    30,
    135,
    233,
    206,
    85,
    40,
    223,
    140,
    161,
    137,
    13,
    191,
    230,
    66,
    104,
    65,
    153,
    45,
    15,
    176,
    84,
    187,
    22,
]
_INV_SBOX = [
    82,
    9,
    106,
    213,
    48,
    54,
    165,
    56,
    191,
    64,
    163,
    158,
    129,
    243,
    215,
    251,
    124,
    227,
    57,
    130,
    155,
    47,
    255,
    135,
    52,
    142,
    67,
    68,
    196,
    222,
    233,
    203,
    84,
    123,
    148,
    50,
    166,
    194,
    35,
    61,
    238,
    76,
    149,
    11,
    66,
    250,
    195,
    78,
    8,
    46,
    161,
    102,
    40,
    217,
    36,
    178,
    118,
    91,
    162,
    73,
    109,
    139,
    209,
    37,
    114,
    248,
    246,
    100,
    134,
    104,
    152,
    22,
    212,
    164,
    92,
    204,
    93,
    101,
    182,
    146,
    108,
    112,
    72,
    80,
    253,
    237,
    185,
    218,
    94,
    21,
    70,
    87,
    167,
    141,
    157,
    132,
    144,
    216,
    171,
    0,
    140,
    188,
    211,
    10,
    247,
    228,
    88,
    5,
    184,
    179,
    69,
    6,
    208,
    44,
    30,
    143,
    202,
    63,
    15,
    2,
    193,
    175,
    189,
    3,
    1,
    19,
    138,
    107,
    58,
    145,
    17,
    65,
    79,
    103,
    220,
    234,
    151,
    242,
    207,
    206,
    240,
    180,
    230,
    115,
    150,
    172,
    116,
    34,
    231,
    173,
    53,
    133,
    226,
    249,
    55,
    232,
    28,
    117,
    223,
    110,
    71,
    241,
    26,
    113,
    29,
    41,
    197,
    137,
    111,
    183,
    98,
    14,
    170,
    24,
    190,
    27,
    252,
    86,
    62,
    75,
    198,
    210,
    121,
    32,
    154,
    219,
    192,
    254,
    120,
    205,
    90,
    244,
    31,
    221,
    168,
    51,
    136,
    7,
    199,
    49,
    177,
    18,
    16,
    89,
    39,
    128,
    236,
    95,
    96,
    81,
    127,
    169,
    25,
    181,
    74,
    13,
    45,
    229,
    122,
    159,
    147,
    201,
    156,
    239,
    160,
    224,
    59,
    77,
    174,
    42,
    245,
    176,
    200,
    235,
    187,
    60,
    131,
    83,
    153,
    97,
    23,
    43,
    4,
    126,
    186,
    119,
    214,
    38,
    225,
    105,
    20,
    99,
    85,
    33,
    12,
    125,
]
_SBOX_SIG = bytes(_SBOX[:16])
_INV_SBOX_SIG = bytes(_INV_SBOX[:16])
_FNV_SEED_LE = struct.pack("<I", 2166136261)
_DECOY_SECTIONS = {
    ".themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".enigma1",
    ".enigma2",
    ".enigma3",
    ".aspack",
    ".aPlib",
    ".nsp0",
    ".nsp1",
    ".petite",
    ".svkp",
    ".sforce",
}
_RUNTIME_MARKERS = [b"Oh skibiddi oooh", b"pojkdkddkeifpojkdkddkeif"]
_MIN_OBFUSK8_SECTIONS = 15


@dataclass
class _Finding:
    name: str
    present: bool
    score: int
    detail: str = ""


@dataclass
class FingerprintResult:
    path: str
    confidence: int
    verdict: str
    findings: List[_Finding] = field(default_factory=list)
    section_count: int = 0
    section_names: List[str] = field(default_factory=list)
    decoy_sections: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        flag = {
            "high": "[!!!]",
            "medium": "[ ! ]",
            "low": "[ ? ]",
            "unlikely": "[   ]",
        }.get(self.verdict, "[   ]")
        lines = [
            f"{flag} {self.path}  confidence={self.confidence}%  verdict={self.verdict}"
        ]
        for f in self.findings:
            mark = "+" if f.present else "-"
            pts = f"+{f.score}" if f.present else "   "
            lines.append(f"    {mark} {pts:>4}  {f.name}: {f.detail}")
        if self.decoy_sections:
            lines.append(f"    +      decoy sections: {', '.join(self.decoy_sections)}")
        lines.append(
            f"         PE sections: {self.section_count} ({', '.join(self.section_names[:8])}"
            + (" ..." if len(self.section_names) > 8 else "")
            + ")"
        )
        return "\n".join(lines)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def fingerprint(path: str) -> FingerprintResult:
    raw = Path(path).read_bytes()
    result = FingerprintResult(path=path, confidence=0, verdict="unlikely")
    try:
        import pefile

        pe = pefile.PE(path)
        section_names: List[str] = []
        for s in pe.sections:
            section_names.append(s.Name.rstrip(b"\x00").decode(errors="replace"))
        pe.close()
    except Exception:
        section_names = []
    result.section_count = len(section_names)
    result.section_names = section_names
    result.decoy_sections = [n for n in section_names if n in _DECOY_SECTIONS]
    score = 0
    has_rsbox = _INV_SBOX_SIG in raw
    f1 = _Finding(
        name="AES rsbox (256-byte inverse S-box)",
        present=has_rsbox,
        score=55,
        detail=f"signature {('found' if has_rsbox else 'not found')} ({_INV_SBOX_SIG.hex()[:24]}...)",
    )
    result.findings.append(f1)
    if has_rsbox:
        score += 55
    has_sbox = _SBOX_SIG in raw
    f2 = _Finding(
        name="AES sbox (forward S-box)",
        present=has_sbox,
        score=15,
        detail=f"signature {('found' if has_sbox else 'not found')}",
    )
    result.findings.append(f2)
    if has_sbox:
        score += 15
    has_fnv = _FNV_SEED_LE in raw
    f3 = _Finding(
        name="FNV1a seed 0x811C9DC5 (build-hash subsystem)",
        present=has_fnv,
        score=10,
        detail=f"constant {('found' if has_fnv else 'not found')} in binary",
    )
    result.findings.append(f3)
    if has_fnv:
        score += 10
    has_decoy = bool(result.decoy_sections)
    f4 = _Finding(
        name="Decoy PE section names",
        present=has_decoy,
        score=12,
        detail=(
            f"found: {', '.join(result.decoy_sections)}"
            if has_decoy
            else "none of the known decoy names present"
        ),
    )
    result.findings.append(f4)
    if has_decoy:
        score += 12
    high_sec = result.section_count >= _MIN_OBFUSK8_SECTIONS
    f5 = _Finding(
        name=f"High PE section count (>={_MIN_OBFUSK8_SECTIONS})",
        present=high_sec,
        score=8,
        detail=f"{result.section_count} sections found",
    )
    result.findings.append(f5)
    if high_sec:
        score += 8
    markers_found = [m.decode() for m in _RUNTIME_MARKERS if m in raw]
    has_markers = bool(markers_found)
    f6 = _Finding(
        name="Obfusk8 runtime-literal marker strings",
        present=has_markers,
        score=20,
        detail=(
            f"found: {markers_found}"
            if has_markers
            else "not present (may have been removed or binary differs)"
        ),
    )
    result.findings.append(f6)
    if has_markers:
        score += 20
    result.confidence = min(score, 100)
    if result.confidence >= 70:
        result.verdict = "high"
    elif result.confidence >= 40:
        result.verdict = "medium"
    elif result.confidence >= 20:
        result.verdict = "low"
    else:
        result.verdict = "unlikely"
    return result


def is_obfusk8(path: str, threshold: int = 55) -> bool:
    return fingerprint(path).confidence >= threshold


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deobfusk8 fingerprinter: quickly detect Obfusk8-protected PE files"
    )
    ap.add_argument("binaries", nargs="+", help="One or more PE64 binaries to inspect")
    ap.add_argument(
        "--threshold",
        type=int,
        default=55,
        help="Confidence threshold %% for a positive verdict (default 55)",
    )
    ap.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print results as JSON instead of human-readable text",
    )
    ap.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Only print files that meet the threshold",
    )
    args = ap.parse_args(argv)
    results: List[FingerprintResult] = []
    for path in args.binaries:
        if not os.path.isfile(path):
            print(f"[-] Not found: {path}", file=sys.stderr)
            continue
        r = fingerprint(path)
        results.append(r)
        if not args.json_output:
            if args.quiet and r.confidence < args.threshold:
                continue
            print(r)
            print()
    if args.json_output:
        output = [r.as_dict() for r in results]
        if not args.quiet:
            print(json.dumps(output, indent=2, ensure_ascii=False))
        else:
            print(
                json.dumps(
                    [r.as_dict() for r in results if r.confidence >= args.threshold],
                    indent=2,
                    ensure_ascii=False,
                )
            )
    positives = [r for r in results if r.confidence >= args.threshold]
    if results:
        print(
            f"[*] {len(positives)}/{len(results)} file(s) above {args.threshold}% threshold",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
