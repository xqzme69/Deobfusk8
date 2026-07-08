from __future__ import annotations


def u32(x: int) -> int:
    return x & 4294967295


def fnv1a_32(*items: bytes) -> int:
    h = 2166136261
    for item in items:
        for b in item:
            h ^= b
            h = h * 16777619 & 4294967295
    return h
