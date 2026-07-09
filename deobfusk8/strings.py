from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .analyzer import Obfusk8Analyzer
from .result import UniversalResult


def analyze_binary(
    binary: str,
    *,
    include_unreferenced_hashes: bool = False,
    slice_limit: int = 0,
    verbose: bool = False,
    no_pro_fallback: bool = False,
    no_symbolic: bool = False,
    full_local_threshold: int = 8,
    local_max_steps: int = 80000,
) -> Dict[str, Any]:
    analyzer = Obfusk8Analyzer(
        binary,
        verbose=verbose,
        use_pro_fallback=not no_pro_fallback,
        enable_symbolic=not no_symbolic,
        full_local_threshold=full_local_threshold,
        local_max_steps=local_max_steps,
    )
    report = analyzer.analyze_all(
        include_unreferenced_hashes=include_unreferenced_hashes, slice_limit=slice_limit
    )
    report["_analyzer"] = analyzer
    return report


def is_runtime_literal(result: Dict[str, Any]) -> bool:
    return bool(result.get("filtered_by_default"))


def user_string_results(
    report: Dict[str, Any], *, include_runtime: bool = False
) -> List[Dict[str, Any]]:
    results = report.get("strings", {}).get("results", [])
    visible_strings: List[Dict[str, Any]] = []
    for string_entry in results:
        if not string_entry.get("text"):
            continue
        if not include_runtime and string_entry.get("filtered_by_default"):
            continue
        visible_strings.append(string_entry)
    return visible_strings


def write_json(report: Dict[str, Any], path: str) -> None:
    public_report = {key: value for key, value in report.items() if key != "_analyzer"}
    Path(path).write_text(
        json.dumps(public_report, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def write_txt(
    report: Dict[str, Any], path: str, *, include_runtime: bool = False
) -> None:
    lines = []
    for string_entry in user_string_results(report, include_runtime=include_runtime):
        wide_prefix = "L" if string_entry.get("text_type") == "wchar" else ""
        lines.append(
            f'{string_entry.get("call_addr")}\t{wide_prefix}"{string_entry.get("text")}"'
        )
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


__all__ = [
    "Obfusk8Analyzer",
    "UniversalResult",
    "analyze_binary",
    "is_runtime_literal",
    "user_string_results",
    "write_json",
    "write_txt",
]
