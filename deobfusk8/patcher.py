from __future__ import annotations
import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class _Section:
    name: str
    va: int
    vsize: int
    raw_offset: int
    raw_size: int


def _load_pe(path: str) -> Tuple[int, List[_Section]]:
    try:
        import pefile
    except ImportError:
        raise SystemExit("[-] pefile not installed: pip install pefile")
    pe = pefile.PE(path)
    base = int(pe.OPTIONAL_HEADER.ImageBase)
    sections: List[_Section] = []
    for s in pe.sections:
        sections.append(
            _Section(
                name=s.Name.rstrip(b"\x00").decode(errors="replace"),
                va=base + int(s.VirtualAddress),
                vsize=int(s.Misc_VirtualSize),
                raw_offset=int(s.PointerToRawData),
                raw_size=int(s.SizeOfRawData),
            )
        )
    pe.close()
    return (base, sections)


def _va_to_offset(va: int, sections: List[_Section]) -> Optional[int]:
    for s in sections:
        span = max(s.vsize, s.raw_size)
        if s.va <= va < s.va + span:
            return s.raw_offset + (va - s.va)
    return None


def _parse_hex(s: Optional[str]) -> Optional[int]:
    if not s:
        return None
    try:
        return int(s, 16)
    except (ValueError, TypeError):
        return None


@dataclass
class PatchDetail:
    call_addr: str
    text: str
    source_va: Optional[str]
    source_strategy: str
    source_patch: str
    nop_patch: str


@dataclass
class PatchResult:
    binary: str
    report: str
    output: str
    dry_run: bool
    source_patches_ok: int = 0
    source_patches_skipped: int = 0
    source_patches_failed: int = 0
    nop_patches_ok: int = 0
    nop_patches_skipped: int = 0
    nop_patches_failed: int = 0
    details: List[PatchDetail] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"[deobfusk8 patcher] {('DRY RUN - ' if self.dry_run else '')}output: {self.output}",
            f"  source patches : {self.source_patches_ok} ok / {self.source_patches_skipped} skipped / {self.source_patches_failed} failed",
            f"  call NOPs      : {self.nop_patches_ok} ok / {self.nop_patches_skipped} skipped / {self.nop_patches_failed} failed",
        ]
        return "\n".join(lines)


def patch_binary(
    binary_path: str,
    report_path: str,
    output_path: str,
    *,
    patch_sources: bool = True,
    nop_calls: bool = False,
    include_runtime: bool = False,
    dry_run: bool = False,
    verbose: bool = False,
) -> PatchResult:
    report: Dict[str, Any] = json.loads(Path(report_path).read_text(encoding="utf-8"))
    raw = bytearray(Path(binary_path).read_bytes())
    _base, sections = _load_pe(binary_path)
    result = PatchResult(
        binary=binary_path, report=report_path, output=output_path, dry_run=dry_run
    )
    results = report.get("strings", {}).get("results", [])
    if not results:
        print("[-] No string results found in report.")
        return result
    for r in results:
        text = r.get("text")
        if not text:
            continue
        if not include_runtime and r.get("filtered_by_default"):
            continue
        call_addr_s: str = r.get("call_addr") or ""
        source_va_s: Optional[str] = r.get("source_va")
        raw_size: Optional[int] = r.get("raw_size")
        text_type: str = r.get("text_type") or "char"
        source_strategy: str = r.get("source_strategy") or ""
        detail = PatchDetail(
            call_addr=call_addr_s,
            text=text,
            source_va=source_va_s,
            source_strategy=source_strategy,
            source_patch="",
            nop_patch="",
        )
        patchable_strategy = source_strategy in (
            "static_source",
            "local_plaintext_buffer",
        ) or source_strategy.startswith("static_source")
        if patch_sources and source_va_s and patchable_strategy:
            source_va = _parse_hex(source_va_s)
            if source_va is None:
                detail.source_patch = "failed: unparseable source_va"
                result.source_patches_failed += 1
            else:
                file_off = _va_to_offset(source_va, sections)
                if file_off is None or file_off < 0 or file_off >= len(raw):
                    detail.source_patch = f"failed: VA {source_va_s} not in file"
                    result.source_patches_failed += 1
                else:
                    try:
                        if text_type == "wchar":
                            plaintext = text.encode("utf-16le") + b"\x00\x00"
                        else:
                            plaintext = text.encode("utf-8") + b"\x00"
                        blob_size = (
                            raw_size if raw_size and raw_size > 0 else len(plaintext)
                        )
                        blob = (plaintext + b"\x00" * blob_size)[:blob_size]
                        end = file_off + len(blob)
                        if end > len(raw):
                            blob = blob[: len(raw) - file_off]
                        if not dry_run:
                            raw[file_off : file_off + len(blob)] = blob
                        detail.source_patch = f"ok @ file+0x{file_off:X} ({len(blob)} bytes written, {len(plaintext)} plain)"
                        result.source_patches_ok += 1
                        if verbose:
                            print(
                                f"  [+] source {source_va_s} -> file+0x{file_off:X}: {repr(text)[:72]}"
                            )
                    except Exception as exc:
                        detail.source_patch = f"failed: {exc}"
                        result.source_patches_failed += 1
                        if verbose:
                            print(f"  [-] source {source_va_s}: {exc}")
        else:
            if not patch_sources:
                detail.source_patch = "skipped: --patch-sources off"
            elif not source_va_s:
                detail.source_patch = "skipped: no source_va (AES-only or failed)"
            else:
                detail.source_patch = f"skipped: strategy={source_strategy}"
            result.source_patches_skipped += 1
        if nop_calls and call_addr_s:
            call_va = _parse_hex(call_addr_s)
            if call_va is None:
                detail.nop_patch = "failed: unparseable call_addr"
                result.nop_patches_failed += 1
            else:
                call_off = _va_to_offset(call_va, sections)
                if call_off is None or call_off < 0 or call_off + 5 > len(raw):
                    detail.nop_patch = f"failed: VA {call_addr_s} not in file"
                    result.nop_patches_failed += 1
                else:
                    opcode = raw[call_off]
                    if opcode == 232:
                        if not dry_run:
                            raw[call_off : call_off + 5] = b"\x90" * 5
                        detail.nop_patch = f"ok @ file+0x{call_off:X} (E8 -> NOP x5)"
                        result.nop_patches_ok += 1
                        if verbose:
                            print(f"  [+] NOP  {call_addr_s} -> file+0x{call_off:X}")
                    elif opcode == 255 and raw[call_off + 1] & 56 == 16:
                        detail.nop_patch = f"skipped: indirect CALL at file+0x{call_off:X} (not safe to blindly NOP)"
                        result.nop_patches_skipped += 1
                    else:
                        detail.nop_patch = f"skipped: unexpected opcode 0x{opcode:02X} at file+0x{call_off:X} (expected E8)"
                        result.nop_patches_skipped += 1
        else:
            detail.nop_patch = "skipped" if not nop_calls else "skipped: no call_addr"
            result.nop_patches_skipped += 1
        result.details.append(detail)
    if not dry_run:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(bytes(raw))
    print(result)
    return result


def write_patch_report(result: PatchResult, path: str) -> None:
    from dataclasses import asdict

    Path(path).write_text(
        json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[+] Patch report written: {path}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deobfusk8 binary patcher: write a static-analysis-friendly copy of an Obfusk8-protected PE with plaintext strings at source blobs."
    )
    ap.add_argument("binary", help="Original protected PE64 binary")
    ap.add_argument("report", help="Deobfusk8 JSON report (--json output)")
    ap.add_argument("output", help="Destination for the patched binary")
    ap.add_argument(
        "--nop-calls",
        action="store_true",
        help="NOP-out decrypt call-site instructions (5-byte CALL rel32 -> 5xNOP)",
    )
    ap.add_argument(
        "--no-patch-sources",
        action="store_true",
        help="Skip overwriting source blobs with plaintext",
    )
    ap.add_argument(
        "--include-runtime",
        action="store_true",
        help="Also patch Obfusk8 runtime literals (usually noise)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute patches but do not write any files",
    )
    ap.add_argument(
        "--patch-report",
        dest="patch_report_path",
        help="Write a JSON summary of all patches applied",
    )
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)
    if not os.path.isfile(args.binary):
        print(f"[-] Binary not found: {args.binary}")
        return 1
    if not os.path.isfile(args.report):
        print(f"[-] Report not found: {args.report}")
        return 1
    print(f"[*] Binary : {args.binary}")
    print(f"[*] Report : {args.report}")
    print(f"[*] Output : {args.output}")
    if args.dry_run:
        print("[*] DRY RUN - no files will be written")
    result = patch_binary(
        args.binary,
        args.report,
        args.output,
        patch_sources=not args.no_patch_sources,
        nop_calls=args.nop_calls,
        include_runtime=args.include_runtime,
        dry_run=args.dry_run,
        verbose=args.verbose,
    )
    if args.patch_report_path and (not args.dry_run):
        write_patch_report(result, args.patch_report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
