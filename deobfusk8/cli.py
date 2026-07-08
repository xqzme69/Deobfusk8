from __future__ import annotations
import argparse
import json
import os
from .strings import analyze_binary, write_json, write_txt
from .exporters import write_comments, write_ida_script, write_ghidra_script
from .key import MBASimplifier
from .animator import print_scrambled

def _print_summary(
    report: dict, *, include_runtime: bool = False, show_keys: bool = False
) -> None:
    strings = report.get("strings", {})
    api = report.get("resolve8_api_hashes", {})
    syscall = report.get("k8_syscalls", {})
    inline = report.get("inline_decrypt_discovery", {})
    slices = report.get("runtime_key_slices", {})
    print(f"[+] ImageBase: {report.get('image_base')}")
    print(
        f"[+] Build hash: {report.get('build_hash')} from {report.get('build_hash_inputs')}"
    )
    print(f"[+] Recovered user strings: {strings.get('recovered_user_strings', 0)}")
    print(
        f"[+] Filtered runtime literals: {strings.get('filtered_runtime_literals', 0)}"
    )
    print(
        f"[+] Resolve8 HASH_IV: {api.get('hash_iv')} "
        f"dword_hits={api.get('hit_count', 0)} "
        f"name_hits={api.get('recovered_name_count', 0)}"
    )
    print(f"[+] K8 syscall intents: {len(syscall.get('syscall_intents', []))}")
    print(f"[+] Inline decrypt candidates: {len(inline.get('candidates', []))}")
    print(
        f"[+] Runtime-key slices complete: {slices.get('complete', 0)}/{slices.get('total', 0)}"
    )
    print(f"[+] Runtime: {report.get('elapsed_sec', 0):.2f}s")
    print("\n" + "=" * 104)
    print("RECOVERED STRINGS" + (" (including runtime)" if include_runtime else ""))
    print("=" * 104)
    for d in strings.get("results", []):
        if not d.get("text"):
            continue
        if not include_runtime and d.get("filtered_by_default"):
            continue
        prefix = "L" if d.get("text_type") == "wchar" else ""
        source_strategy = d.get("source_strategy") or d.get("source") or "unknown"
        key_status = d.get("key_status") or (
            "recovered" if d.get("runtime_key") else "missing"
        )
        prefix_str = f'''{d.get("call_addr"):>12}  class={d.get("classification"):<26} conf={d.get("confidence"):<6} key={key_status:<27} src={source_strategy:<24} {prefix}"'''
        secret_str = f'''{d.get("text")}"'''
        print_scrambled(prefix_str, secret_str)
        if show_keys and d.get("runtime_key"):
            print(
                f"              key={d.get('runtime_key')} key_source={d.get('key_source')}"
            )
        if show_keys and d.get("warnings"):
            print(f"              warnings={'; '.join(d.get('warnings') or [])}")
    name_hits = api.get("recovered_name_hits") or []
    if name_hits:
        print("\n" + "=" * 104)
        print("RESOLVE8 / STEALTH NAME HITS")
        print("=" * 104)
        for item in name_hits:
            line = f"{item.get('name', ''):<34} kind={item.get('kind', ''):<14} hash={item.get('hash_hex', '-')} source={item.get('source', '-')}"
            print_scrambled("", line, steps=10)
    if syscall.get("syscall_intents"):
        print("\n" + "=" * 104)
        print("K8 SYSCALL INTENTS")
        print("=" * 104)
        for s in syscall.get("syscall_intents", []):
            print(
                f"{s['name']:<34} source={s['source']:<22} hash={s.get('hash_hex') or '-'}"
            )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deobfusk8: static Obfusk8 extractor with strings, Resolve8, K8 and IDA/Ghidra output",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52, width=120)
    )
    ap.add_argument("binary", nargs="?", help="Path to PE64 binary")
    ap.add_argument("--json", dest="json_path", help="Write full report JSON")
    ap.add_argument("--txt", dest="txt_path", help="Write recovered strings only")
    ap.add_argument(
        "--comments",
        dest="comments_path",
        help="Write plain comment map: 0xADDR ; OBFUSCATE_STRING -> ...",
    )
    ap.add_argument("--ida", dest="ida_path", help="Write IDAPython annotation script")
    ap.add_argument(
        "--ghidra", dest="ghidra_path", help="Write Ghidra/Jython annotation script"
    )
    ap.add_argument(
        "--show-keys", action="store_true", help="Print recovered runtime AES keys"
    )
    ap.add_argument(
        "--include-runtime",
        action="store_true",
        help="Include Obfusk8 runtime literals in console/TXT/export output",
    )
    ap.add_argument(
        "--include-unreferenced-hashes",
        action="store_true",
        help="Include API hashes not found as DWORD constants",
    )
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--no-pro-fallback", action="store_true")
    ap.add_argument("--no-symbolic", action="store_true")
    ap.add_argument("--full-local-threshold", type=int, default=8)
    ap.add_argument(
        "--local-max-steps",
        type=int,
        default=80000,
        help="Max local-interpreter steps per call-site; default favors quality over speed",
    )
    ap.add_argument(
        "--fast",
        action="store_true",
        help="Use a conservative fast preset: fewer local steps and lower full-local threshold",
    )
    ap.add_argument(
        "--deep",
        action="store_true",
        help="Use a deeper preset for harder wrappers: more local steps",
    )
    ap.add_argument("--slice-limit", type=int, default=0)
    ap.add_argument("--z3-self-test", action="store_true")
    ap.add_argument(
        "--compare-expected",
        help="Compare recovered strings against expected corpus JSON",
    )
    ap.add_argument(
        "--write-expected",
        help="Write expected corpus JSON from current recovered strings",
    )
    ap.add_argument("--fail-on-mismatch", action="store_true")
    args = ap.parse_args(argv)
    if args.z3_self_test:
        proof = MBASimplifier.prove_with_z3()
        print(json.dumps(proof, indent=2, ensure_ascii=False))
        if proof.get("available") and any(
            (v != "unsat" for v in proof.get("proofs", {}).values())
        ):
            return 2
        return 0
    if not args.binary or not os.path.isfile(args.binary):
        ap.print_help()
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
        d.get("text")
        for d in report.get("strings", {}).get("results", [])
        if d.get("text") and (args.include_runtime or not d.get("filtered_by_default"))
    ]
    if args.write_expected:
        with open(args.write_expected, "w", encoding="utf-8") as f:
            json.dump({"expected_strings": recovered}, f, indent=2, ensure_ascii=False)
        print(f"[+] Expected corpus written: {args.write_expected}")
    if args.compare_expected:
        with open(args.compare_expected, "r", encoding="utf-8") as f:
            exp = json.load(f)
        expected = exp.get("expected_strings", exp if isinstance(exp, list) else [])
        missing = [x for x in expected if x not in recovered]
        extra = [x for x in recovered if x not in expected]
        ok = not missing and (not extra)
        print("\n" + "=" * 104)
        print("EXPECTED COMPARISON")
        print("=" * 104)
        print(f"ok={ok}")
        for x in missing:
            print(f"  missing: {x}")
        for x in extra:
            print(f"  extra: {x}")
        if not ok and args.fail_on_mismatch:
            return 2
    return 0


if __name__ == "__main__":
    import os
    import sys

    code = int(main() or 0)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
