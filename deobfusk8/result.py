from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class CallSiteResult:
    call_addr: str
    decrypt_func: str
    source: str
    confidence: str
    text: Optional[str] = None
    text_type: Optional[str] = None
    raw_size: Optional[int] = None
    chunks: Optional[int] = None
    source_va: Optional[str] = None
    helper_func: Optional[str] = None
    runtime_key: Optional[str] = None
    key_base: Optional[str] = None
    key_offset: Optional[str] = None
    ks_offset: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class Evidence:
    kind: str
    confidence: int
    reason: str
    address: Optional[str] = None
    value: Any = None


@dataclass
class StrategyTrace:
    strategy: str
    ok: bool
    detail: str
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class UniversalResult:
    call_addr: str
    decrypt_func: str
    confidence: str
    text: Optional[str]
    text_type: Optional[str]
    raw_size: Optional[int]
    chunks: Optional[int]
    source_va: Optional[str]
    helper_func: Optional[str]
    runtime_key: Optional[str]
    key_source: Optional[str]
    source: str
    reason: Optional[str]
    traces: List[StrategyTrace] = field(default_factory=list)


@dataclass
class KeyTemplateResult:
    ok: bool
    key: Optional[bytes] = None
    template: Optional[str] = None
    ks_source: Optional[str] = None
    ks_words: Optional[List[int]] = None
    confidence: int = 0
    reason: Optional[str] = None
    validation_text: Optional[str] = None


@dataclass
class KSCandidate:
    words: List[int]
    source: str
    address: Optional[int] = None
    confidence: int = 50


UNKNOWN = object()


def sval(v: Any) -> str:
    if v is UNKNOWN:
        return "?"
    return str(v)
