from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .animator import print_scrambled
from .exporters import write_comments, write_ghidra_script, write_ida_script
from .key import MBASimplifier
from .strings import analyze_binary, write_json, write_txt


def _print_summary(
    report: dict[str, Any], *, include_runtime: bool = False, show_keys: bool = False
) -> None:
    string_report = report.get("strings", {})
    resolve8_report = report.get("resolve8_api_hashes", {})
    syscall_report = report.get("k8_syscalls", {})
    inline_report = report.get("inline_decrypt_discovery", {})
    slice_report = report.get("runtime_key_slices", {})

    print(f"[+] ImageBase: {report.get('image_base')}")
    print(
        f"[+] Build hash: {report.get('build_hash')} from {report.get('build_hash_inputs')}"
    )
    print(
        f"[+] Recovered user strings: {string_report.get('recovered_user_strings', 0)}"
    )
    print(
        f"[+] Filtered runtime literals: {string_report.get('filtered_runtime_literals', 0)}"
    )
    print(
        f"[+] Resolve8 HASH_IV: {resolve8_report.get('hash_iv')} "
        f"dword_hits={resolve8_report.get('hit_count', 0)} "
        f"name_hits={resolve8_report.get('recovered_name_count', 0)}"
    )
    print(f"[+] K8 syscall intents: {len(syscall_report.get('syscall_intents', []))}")
    print(f"[+] Inline decrypt candidates: {len(inline_report.get('candidates', []))}")
    print(
        f"[+] Runtime-key slices complete: {slice_report.get('complete', 0)}/{slice_report.get('total', 0)}"
    )
    print(f"[+] Runtime: {report.get('elapsed_sec', 0):.2f}s")
    print("\n" + "=" * 104)
    print("RECOVERED STRINGS" + (" (including runtime)" if include_runtime else ""))
    print("=" * 104)
    for string_entry in string_report.get("results", []):
        if not string_entry.get("text"):
            continue
        if not include_runtime and string_entry.get("filtered_by_default"):
            continue
        wide_prefix = "L" if string_entry.get("text_type") == "wchar" else ""
        source_strategy = (
            string_entry.get("source_strategy")
            or string_entry.get("source")
            or "unknown"
        )
        key_status = string_entry.get("key_status") or (
            "recovered" if string_entry.get("runtime_key") else "missing"
        )
        line_prefix = (
            f"{string_entry.get('call_addr'):>12}  "
            f"class={string_entry.get('classification'):<26} "
            f"conf={string_entry.get('confidence'):<6} "
            f"key={key_status:<27} "
            f'src={source_strategy:<24} {wide_prefix}"'
        )
        plaintext_tail = f'{string_entry.get("text")}"'
        print_scrambled(line_prefix, plaintext_tail)
        if show_keys and string_entry.get("runtime_key"):
            print(
                f"              key={string_entry.get('runtime_key')} "
                f"key_source={string_entry.get('key_source')}"
            )
        if show_keys and string_entry.get("warnings"):
            print(
                f"              warnings={'; '.join(string_entry.get('warnings') or [])}"
            )

    name_hits = resolve8_report.get("recovered_name_hits") or []
    if name_hits:
        print("\n" + "=" * 104)
        print("RESOLVE8 / STEALTH NAME HITS")
        print("=" * 104)
        for api_hit in name_hits:
            line = (
                f"{api_hit.get('name', ''):<34} "
                f"kind={api_hit.get('kind', ''):<14} "
                f"hash={api_hit.get('hash_hex', '-')} "
                f"source={api_hit.get('source', '-')}"
            )
            print_scrambled("", line, steps=10)
    if syscall_report.get("syscall_intents"):
        print("\n" + "=" * 104)
        print("K8 SYSCALL INTENTS")
        print("=" * 104)
        for syscall_intent in syscall_report.get("syscall_intents", []):
            print(
                f"{syscall_intent['name']:<34} "
                f"source={syscall_intent['source']:<22} "
                f"hash={syscall_intent.get('hash_hex') or '-'}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deobfusk8: static Obfusk8 extractor with strings, Resolve8, K8 and IDA/Ghidra output",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog, max_help_position=52, width=120
        ),
    )
    parser.add_argument("binary", nargs="?", help="Path to PE64 binary")
    parser.add_argument("--json", dest="json_path", help="Write full report JSON")
    parser.add_argument("--txt", dest="txt_path", help="Write recovered strings only")
    parser.add_argument(
        "--comments",
        dest="comments_path",
        help="Write plain comment map: 0xADDR ; OBFUSCATE_STRING -> ...",
    )
    parser.add_argument(
        "--ida", dest="ida_path", help="Write IDAPython annotation script"
    )
    parser.add_argument(
        "--ghidra", dest="ghidra_path", help="Write Ghidra/Jython annotation script"
    )
    parser.add_argument(
        "--show-keys", action="store_true", help="Print recovered runtime AES keys"
    )
    parser.add_argument(
        "--include-runtime",
        action="store_true",
        help="Include Obfusk8 runtime literals in console/TXT/export output",
    )
    parser.add_argument(
        "--include-unreferenced-hashes",
        action="store_true",
        help="Include API hashes not found as DWORD constants",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--no-pro-fallback", action="store_true")
    parser.add_argument("--no-symbolic", action="store_true")
    parser.add_argument("--full-local-threshold", type=int, default=8)
    parser.add_argument(
        "--local-max-steps",
        type=int,
        default=80000,
        help="Max local-interpreter steps per call-site; default favors quality over speed",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Use a conservative fast preset: fewer local steps and lower full-local threshold",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Use a deeper preset for harder wrappers: more local steps",
    )
    parser.add_argument("--slice-limit", type=int, default=0)
    parser.add_argument("--z3-self-test", action="store_true")
    parser.add_argument(
        "--compare-expected",
        help="Compare recovered strings against expected corpus JSON",
    )
    parser.add_argument(
        "--write-expected",
        help="Write expected corpus JSON from current recovered strings",
    )
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args(argv)
    if args.z3_self_test:
        proof = MBASimplifier.prove_with_z3()
        print(json.dumps(proof, indent=2, ensure_ascii=False))
        if proof.get("available") and any(
            (v != "unsat" for v in proof.get("proofs", {}).values())
        ):
            return 2
        return 0
    if not args.binary or not Path(args.binary).is_file():
        parser.print_help()
        return 1
    if args.fast and args.deep:
        print("[-] --fast and --deep are mutually exclusive")
        return 1
    full_local_threshold = args.full_local_threshold
    local_max_steps = args.local_max_steps
    if args.fast:
        full_local_threshold = min(full_local_threshold, 4)
        local_max_steps = min(local_max_steps, 20000)
    elif args.deep:
        local_max_steps = max(local_max_steps, 120000)
    print(f"[*] Loaded: {args.binary}")
    report = analyze_binary(
        args.binary,
        include_unreferenced_hashes=args.include_unreferenced_hashes,
        slice_limit=args.slice_limit,
        verbose=args.verbose,
        no_pro_fallback=args.no_pro_fallback,
        no_symbolic=args.no_symbolic,
        full_local_threshold=full_local_threshold,
        local_max_steps=local_max_steps,
    )
    report.setdefault("analysis_options", {})
    report["analysis_options"].update(
        {
            "full_local_threshold": full_local_threshold,
            "local_max_steps": local_max_steps,
            "fast": bool(args.fast),
            "deep": bool(args.deep),
        }
    )
    _print_summary(
        report, include_runtime=args.include_runtime, show_keys=args.show_keys
    )
    if args.json_path:
        write_json(report, args.json_path)
        print(f"[+] JSON written: {args.json_path}")
    if args.txt_path:
        write_txt(report, args.txt_path, include_runtime=args.include_runtime)
        print(f"[+] TXT written: {args.txt_path}")
    if args.comments_path:
        write_comments(report, args.comments_path, include_runtime=args.include_runtime)
        print(f"[+] Comment map written: {args.comments_path}")
    if args.ida_path:
        write_ida_script(report, args.ida_path, include_runtime=args.include_runtime)
        print(f"[+] IDA script written: {args.ida_path}")
    if args.ghidra_path:
        write_ghidra_script(
            report, args.ghidra_path, include_runtime=args.include_runtime
        )
        print(f"[+] Ghidra script written: {args.ghidra_path}")
    recovered = [
        string_entry.get("text")
        for string_entry in report.get("strings", {}).get("results", [])
        if string_entry.get("text")
        and (args.include_runtime or not string_entry.get("filtered_by_default"))
    ]
    if args.write_expected:
        with open(args.write_expected, "w", encoding="utf-8") as expected_file:
            json.dump(
                {"expected_strings": recovered},
                expected_file,
                indent=2,
                ensure_ascii=False,
            )
        print(f"[+] Expected corpus written: {args.write_expected}")
    if args.compare_expected:
        with open(args.compare_expected, "r", encoding="utf-8") as expected_file:
            expected_payload = json.load(expected_file)
        expected = expected_payload.get(
            "expected_strings",
            expected_payload if isinstance(expected_payload, list) else [],
        )
        missing = [text for text in expected if text not in recovered]
        extra = [text for text in recovered if text not in expected]
        ok = not missing and (not extra)
        print("\n" + "=" * 104)
        print("EXPECTED COMPARISON")
        print("=" * 104)
        print(f"ok={ok}")
        for text in missing:
            print(f"  missing: {text}")
        for text in extra:
            print(f"  extra: {text}")
        if not ok and args.fail_on_mismatch:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
