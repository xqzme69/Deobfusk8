# deobfusk8

static strings and api extractor for x86byte/obfusk8 protected pe64 binaries. zero execution.

## usage

```bash
python -m deobfusk8 <target.exe> --json out.json --ida script.py
```

## features
- aes key recovery
- static / local-interpreter decrypt
- resolve8 stealth api hashing recovery
- k8 syscall extraction
- ida/ghidra export

## tune
use `--fast` or `--deep` depending on wrapper hardness. default is 80k local steps.
