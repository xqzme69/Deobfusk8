# deobfusk8

static strings and api extractor for x86byte/obfusk8 protected pe64 binaries. zero execution.


## install

install directly from source:
```bash
git clone https://github.com/xqzme69/Deobfusk8.git
cd Deobfusk8
python -m pip install -e .
```
dependencies (`pefile`, `capstone`, `z3-solver`) will be installed automatically.

## features

- aes key recovery via static analysis & symbolic execution
- resolve8 stealth api hashing recovery
- k8 syscall intent extraction
- ida pro / ghidra python script generation
- portable cli and api

## usage

run full analysis on a target binary, dumping results to json, raw text, and generating annotation scripts for your disassembler of choice:

```bash
deobfusk8 sample.exe \
  --json report.json \
  --txt strings.txt \
  --comments comments.txt \
  --ida ida_deobfusk8.py \
  --ghidra ghidra_deobfusk8.py \
  --show-keys
```

### tune

use `--fast` or `--deep` depending on wrapper hardness. default favors quality over speed (80k local steps per site).

```bash
# triage preset (fast)
deobfusk8 sample.exe --fast --json report.fast.json

# heavy wrappers (deep)
deobfusk8 sample.exe --deep --json report.deep.json
```

## sample output

```text
[+] ImageBase: 0x140000000
[+] Recovered user strings: 45
[+] Filtered runtime literals: 5
[+] Resolve8 HASH_IV: 0x36a06363 dword_hits=0 name_hits=14
[+] K8 syscall intents: 4
[+] Runtime-key slices complete: 0/0
[+] Runtime: 21.38s

========================================================================================================
RECOVERED STRINGS
========================================================================================================
 0x14001de67  class=user_literal               conf=medium key=recovered                   src=local_plaintext_buffer   "kernel32.dll"
 0x14001e5ce  class=user_literal               conf=medium key=recovered                   src=static_source            L"Found target file: "
 0x14001fc96  class=user_literal               conf=medium key=recovered                   src=static_source            "CryptAcquireContextW"
```

## field explanation

each recovered string entry in the json/txt output contains specific metadata:

- **confidence**: `high`, `medium`, `low`, or `failed`.
- **source_strategy**: where the plaintext was extracted from.
  - `aes_decrypt`: plaintext recovered by decrypting Obfusk8 AES8 blocks with the recovered runtime key.
  - `static_source`: string exists as a static sequence.
  - `local_plaintext_buffer`: z3/capstone local state interpreter materialized it.
- **key_status**:
  - `recovered`: runtime key was found.
  - `missing`: unable to slice/trace key.
  - `not_required_static_source` / `not_required_local_plaintext`: string was materialized without AES constraints.

## known limitations

### resolve8 direct dwords vs recovered names
`resolve8_api_hashes` reports two distinct signals:
- **hit_count**: direct dword hash constants physically found in the .text section.
- **recovered_name_hits**: dll/api names successfully recovered from string materialization that match known resolve8 hashes using the extracted `HASH_IV`.

we do not conflate a recovered string with a direct hash hit to avoid false positives. short api names (like `FindFirstFileW` or `.docx`) are typically recovered via the local interpreter buffer due to static source truncation in the wrapper.

## corpus validation

the `deobfusk8.corpus` module can be used to validate extraction accuracy against a known truth-set of strings.
```bash
python -m deobfusk8.corpus ./samples --out ./corpus_out --expected corpus_expected.json
```
latest local validation passed on the current simulator corpus under the default preset.
