from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _iter_binaries(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    for p in sorted(path.glob("*.exe")):
        if p.is_file():
            yield p


def _recovered_strings(report: Dict[str, Any], *, include_runtime: bool = False) -> List[str]:
    out: List[str] = []
    for r in report.get("strings", {}).get("results", []):
        if not r.get("text"):
            continue
        if not include_runtime and r.get("filtered_by_default"):
            continue
        out.append(r["text"])
    return out


def _syscall_intents(report: Dict[str, Any]) -> List[str]:
    return [
        x.get("name")
        for x in report.get("k8_syscalls", {}).get("syscall_intents", [])
        if x.get("name")
    ]


def _count_field(report: Dict[str, Any], field: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in report.get("strings", {}).get("results", []):
        if not r.get("text") or r.get("filtered_by_default"):
            continue
        value = str(r.get(field) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return counts


def compare_one(name: str, report: Dict[str, Any], expected: Dict[str, Any]) -> Dict[str, Any]:
    exp = expected.get(name, {})
    exp_strings = exp.get("strings", [])
    exp_syscalls = exp.get("syscalls", [])
    got_strings = _recovered_strings(report)
    got_syscalls = _syscall_intents(report)
    missing_strings = [x for x in exp_strings if x not in got_strings]
    extra_strings = [x for x in got_strings if x not in exp_strings] if exp_strings else []
    missing_syscalls = [x for x in exp_syscalls if x not in got_syscalls]
    extra_syscalls = [x for x in got_syscalls if x not in exp_syscalls] if exp_syscalls else []
    return {
        "ok": not missing_strings and not extra_strings and not missing_syscalls and not extra_syscalls,
        "missing_strings": missing_strings,
        "extra_strings": extra_strings,
        "missing_syscalls": missing_syscalls,
        "extra_syscalls": extra_syscalls,
    }


def _terminate_process_tree(proc: subprocess.Popen[Any]) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_cli(cmd: List[str], *, cwd: str, env: Dict[str, str], log_path: Path, timeout: int) -> int:
    with log_path.open("w", encoding="utf-8") as log_file:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            text=True,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=(os.name == "posix"),
        )
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process_tree(proc)
            proc.wait(timeout=10)
            raise


def run_corpus(
    input_path: str,
    out_dir: str,
    *,
    expected_path: Optional[str] = None,
    include_runtime: bool = False,
    include_unreferenced_hashes: bool = False,
    slice_limit: int = 0,
    verbose: bool = False,
    full_local_threshold: int = 8,
    local_max_steps: int = 80000,
    fast: bool = False,
    deep: bool = False,
    sample_timeout: int = 180,
) -> Dict[str, Any]:
    if fast and deep:
        raise ValueError("fast and deep are mutually exclusive")
    if fast:
        full_local_threshold = min(full_local_threshold, 4)
        local_max_steps = min(local_max_steps, 20000)
    elif deep:
        local_max_steps = max(local_max_steps, 120000)

    inp = Path(input_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    expected: Dict[str, Any] = {}
    if expected_path:
        expected = json.loads(Path(expected_path).read_text(encoding="utf-8"))

    package_root = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = package_root + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")

    summary: Dict[str, Any] = {
        "input": str(inp),
        "out_dir": str(out),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "samples": {},
    }

    for binary in _iter_binaries(inp):
        name = binary.name
        stem = binary.stem
        json_path = out / f"{stem}.json"
        txt_path = out / f"{stem}.txt"
        comments_path = out / f"{stem}_comments.txt"
        ida_path = out / f"{stem}_ida.py"
        ghidra_path = out / f"{stem}_ghidra.py"
        log_path = out / f"{stem}.log"
        cmd = [
            sys.executable,
            "-u",
            "-m",
            "deobfusk8",
            str(binary),
            "--json",
            str(json_path),
            "--txt",
            str(txt_path),
            "--comments",
            str(comments_path),
            "--ida",
            str(ida_path),
            "--ghidra",
            str(ghidra_path),
            "--full-local-threshold",
            str(full_local_threshold),
            "--local-max-steps",
            str(local_max_steps),
        ]
        if fast:
            cmd.append("--fast")
        if deep:
            cmd.append("--deep")
        if include_runtime:
            cmd.append("--include-runtime")
        if include_unreferenced_hashes:
            cmd.append("--include-unreferenced-hashes")
        if slice_limit:
            cmd += ["--slice-limit", str(slice_limit)]
        if verbose:
            cmd.append("--verbose")
        print(f"[*] Corpus sample: {name}", flush=True)
        t0 = time.time()
        try:
            code = _run_cli(cmd, cwd=package_root, env=env, log_path=log_path, timeout=sample_timeout)
            if code != 0:
                raise RuntimeError(f"sample exited with code {code}; see {log_path}")
            report = json.loads(json_path.read_text(encoding="utf-8"))
            item: Dict[str, Any] = {
                "ok": True,
                "elapsed_sec": round(time.time() - t0, 3),
                "user_strings": _recovered_strings(report, include_runtime=include_runtime),
                "user_string_count": report.get("strings", {}).get("recovered_user_strings", 0),
                "filtered_runtime_literals": report.get("strings", {}).get("filtered_runtime_literals", 0),
                "syscalls": _syscall_intents(report),
                "resolve8_hit_count": report.get("resolve8_api_hashes", {}).get("hit_count", 0),
                "build_hash": report.get("build_hash"),
                "key_status_counts": _count_field(report, "key_status"),
                "source_strategy_counts": _count_field(report, "source_strategy"),
                "json": json_path.name,
                "txt": txt_path.name,
                "comments": comments_path.name,
                "ida": ida_path.name,
                "ghidra": ghidra_path.name,
                "log": log_path.name,
            }
            if expected:
                item["compare"] = compare_one(name, report, expected)
            summary["samples"][name] = item
            print(f"    strings={item['user_string_count']} syscalls={len(item['syscalls'])} runtime={item['filtered_runtime_literals']} elapsed={item['elapsed_sec']}s", flush=True)
        except Exception as e:
            summary["samples"][name] = {"ok": False, "elapsed_sec": round(time.time() - t0, 3), "error": repr(e), "log": log_path.name}
            print(f"    ERROR: {e!r}", flush=True)

    failed = [name for name, item in summary["samples"].items() if not item.get("ok")]
    mismatched = [name for name, item in summary["samples"].items() if item.get("compare") and not item["compare"].get("ok")]
    summary["failed"] = failed
    summary["mismatched"] = mismatched
    summary["ok"] = not failed and not mismatched
    (out / "corpus_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run Deobfusk8 against a directory of PE samples")
    ap.add_argument("input", help="Sample EXE or directory containing *.exe")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--expected", help="Optional expected corpus JSON")
    ap.add_argument("--include-runtime", action="store_true")
    ap.add_argument("--include-unreferenced-hashes", action="store_true")
    ap.add_argument("--slice-limit", type=int, default=0)
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--full-local-threshold", type=int, default=8)
    ap.add_argument("--local-max-steps", type=int, default=80000)
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--sample-timeout", type=int, default=180)
    ap.add_argument("--fail-on-mismatch", action="store_true")
    args = ap.parse_args(argv)
    summary = run_corpus(
        args.input,
        args.out,
        expected_path=args.expected,
        include_runtime=args.include_runtime,
        include_unreferenced_hashes=args.include_unreferenced_hashes,
        slice_limit=args.slice_limit,
        verbose=args.verbose,
        full_local_threshold=args.full_local_threshold,
        local_max_steps=args.local_max_steps,
        fast=args.fast,
        deep=args.deep,
        sample_timeout=args.sample_timeout,
    )
    print(json.dumps({"ok": summary["ok"], "failed": summary["failed"], "mismatched": summary["mismatched"]}, indent=2), flush=True)
    return 2 if args.fail_on_mismatch and not summary["ok"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
