from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import re
import struct
from .aes import SBOX

COMMON_DLLS = [
    "kernel32.dll",
    "kernelbase.dll",
    "ntdll.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "winhttp.dll",
    "wininet.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
    "vcruntime140.dll",
    "combase.dll",
    "gdi32.dll",
    "secur32.dll",
    "iphlpapi.dll",
    "psapi.dll",
    "dbghelp.dll",
    "shlwapi.dll",
    "rpcrt4.dll",
    "version.dll",
]
COMMON_APIS = [
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "VirtualFree",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "CreateProcessA",
    "CreateProcessW",
    "OpenProcess",
    "TerminateProcess",
    "CreateThread",
    "CreateRemoteThread",
    "ExitProcess",
    "ExitThread",
    "HeapAlloc",
    "HeapFree",
    "HeapCreate",
    "GetProcessHeap",
    "ReadProcessMemory",
    "WriteProcessMemory",
    "GetCurrentProcess",
    "GetCurrentProcessId",
    "GetCurrentThread",
    "GetCurrentThreadId",
    "SuspendThread",
    "ResumeThread",
    "QueueUserAPC",
    "WaitForSingleObject",
    "WaitForMultipleObjects",
    "CreateMutexA",
    "CreateMutexW",
    "OpenMutexA",
    "GetEnvironmentVariableA",
    "GetEnvironmentVariableW",
    "GetTempPathA",
    "GetTempPathW",
    "ShellExecuteA",
    "ShellExecuteW",
    "ShellExecuteExA",
    "CoInitializeEx",
    "CoCreateInstance",
    "MapViewOfFile",
    "CreateFileMappingA",
    "CreateFileMappingW",
    "FlushInstructionCache",
    "GetThreadContext",
    "SetThreadContext",
    "Wow64GetThreadContext",
    "Wow64SetThreadContext",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "Sleep",
    "GetTickCount",
    "QueryPerformanceCounter",
    "MessageBoxA",
    "MessageBoxW",
    "GetWindowTextA",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "UnhookWindowsHookEx",
    "CreateToolhelp32Snapshot",
    "Process32First",
    "Process32Next",
    "Thread32First",
    "Thread32Next",
    "Module32First",
    "Module32Next",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegSetValueExA",
    "RegSetValueExW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegCloseKey",
    "RegEnumKeyExA",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "FindClose",
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptHashData",
    "CryptDeriveKey",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptDestroyHash",
    "CryptDestroyKey",
    "CryptReleaseContext",
    "CryptGenRandom",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetConnectA",
    "InternetConnectW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "InternetReadFile",
    "InternetCloseHandle",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpReadData",
    "WinHttpCloseHandle",
    "WSAStartup",
    "socket",
    "connect",
    "send",
    "recv",
    "bind",
    "listen",
    "accept",
    "closesocket",
    "inet_ntoa",
    "gethostbyname",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtClose",
    "NtQuerySystemInformation",
    "NtQueryInformationProcess",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    "NtDelayExecution",
    "ZwAllocateVirtualMemory",
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwReadVirtualMemory",
    "ZwCreateThreadEx",
    "ZwOpenProcess",
    "ZwClose",
    "ZwQuerySystemInformation",
    "ZwQueryInformationProcess",
    "ZwMapViewOfSection",
    "ZwUnmapViewOfSection",
    "ZwCreateSection",
    "ZwDelayExecution",
    "RtlInitUnicodeString",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
]


@dataclass
class APIHashHit:
    hash_hex: str
    name: str
    kind: str
    locations: List[str] = field(default_factory=list)
    confidence: int = 50
    source: str = "direct_dword"


class Resolve8HashResolver:
    def __init__(
        self,
        analyzer: SymbolicAnalyzer,
        recovered_strings: Optional[Iterable[str]] = None,
    ):
        self.an = analyzer
        self.recovered_strings = list(recovered_strings or [])
        self.time_seed: Optional[int] = None
        self.hash_iv: Optional[int] = None
        self.hits: List[APIHashHit] = []

    @staticmethod
    def classify_name(name: str) -> Optional[str]:
        if not name or not all(ord(ch) < 128 for ch in name):
            return None
        lower = name.lower()
        if lower.endswith(".dll"):
            return "dll"
        known_apis = set(COMMON_APIS)
        if name in known_apis:
            return "api"
        if re.match(
            r"^(Nt|Zw|Rtl|Ldr|Get|Set|Create|Open|Close|Read|Write|Virtual|"
            r"Internet|Http|WinHttp|Win|Crypt|Find|Reg|WSA|socket|connect|send|recv)[A-Za-z0-9_]+$",
            name,
        ):
            if any(api.startswith(name) and api != name for api in known_apis):
                return None
            return "api-candidate"
        return None

    @classmethod
    def recovered_name_candidates(cls, strings: Iterable[str]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        seen = set()
        for text in strings:
            kind = cls.classify_name(str(text))
            if kind is None:
                continue
            key = (str(text), kind)
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    @staticmethod
    def parse_time_seed(inputs: Sequence[str]) -> Optional[int]:
        for s in inputs:
            m = re.search("\\b(\\d{2}):(\\d{2}):(\\d{2})\\b", str(s))
            if m:
                hh, mm, ss = map(int, m.groups())
                if 0 <= hh < 24 and 0 <= mm < 60 and (0 <= ss < 60):
                    return hh * 3600 + mm * 60 + ss
        return None

    @staticmethod
    def hash_iv_from_time_seed(seed: int) -> int:
        return (
            SBOX[seed & 255] << 24
            | SBOX[seed >> 8 & 255] << 16
            | SBOX[seed >> 16 & 255] << 8
            | SBOX[seed >> 24 & 255]
        ) & 4294967295

    @staticmethod
    def runtime_hash_aes(name: str, hash_iv: int, wide: bool = False) -> int:
        h = hash_iv & 4294967295
        for ch in name:
            c = ord(ch)
            if ord("a") <= c <= ord("z"):
                c -= 32
            if wide:
                c &= 255
            else:
                c &= 255
            low = h & 255 ^ c
            sub = SBOX[low]
            h = (h >> 8 | h << 24 & 4294967295) & 4294967295
            h ^= sub
            h &= 4294967295
        return h

    def _scan_dword_locations(self, value: int, max_locs: int = 24) -> List[str]:
        pat = struct.pack("<I", value & 4294967295)
        locs: List[str] = []
        for s in self.an.pe.sections:
            data = s["data"]
            idx = 0
            while len(locs) < max_locs:
                idx = data.find(pat, idx)
                if idx < 0:
                    break
                locs.append(hex(s["va"] + idx))
                idx += 1
        return locs

    def run(self, include_unreferenced: bool = False) -> Dict[str, Any]:
        if self.an.build_hash is None:
            self.an.detect_build_hash()
        self.time_seed = self.parse_time_seed(self.an.build_hash_inputs)
        if self.time_seed is None:
            return {"ok": False, "reason": "build_time_not_found", "hits": []}
        self.hash_iv = self.hash_iv_from_time_seed(self.time_seed)
        names: List[Tuple[str, str]] = []
        for dll_name in COMMON_DLLS:
            names.append((dll_name, "dll"))
            names.append((dll_name.upper().replace(".DLL", ""), "dll"))
        for api_name in COMMON_APIS:
            names.append((api_name, "api"))

        recovered_names = self.recovered_name_candidates(self.recovered_strings)
        names.extend(recovered_names)
        unique: Dict[str, str] = {}
        for name, kind in names:
            unique.setdefault(name, kind)
        hash_to_names: Dict[int, List[Tuple[str, str]]] = {}
        for name, kind in unique.items():
            hv = self.runtime_hash_aes(name, self.hash_iv, wide=False)
            hash_to_names.setdefault(hv, []).append((name, kind))
        loc_map: Dict[int, List[str]] = {}
        max_locs = 24
        for hv in hash_to_names:
            pat = struct.pack("<I", hv & 4294967295)
            locs: List[str] = []
            for sec in self.an.pe.sections:
                data = sec["data"]
                base = sec["va"]
                start = 0
                while len(locs) < max_locs:
                    idx = data.find(pat, start)
                    if idx < 0:
                        break
                    locs.append(hex(base + idx))
                    start = idx + 1
                if len(locs) >= max_locs:
                    break
            loc_map[hv] = locs
        hits: List[APIHashHit] = []
        recovered_lookup = {name for name, _kind in recovered_names}
        recovered_hits: List[APIHashHit] = []
        for hv, nk in hash_to_names.items():
            locs = loc_map.get(hv, [])
            for name, kind in nk:
                if locs or include_unreferenced:
                    hits.append(
                        APIHashHit(
                            hash_hex=f"0x{hv:08X}",
                            name=name,
                            kind=kind,
                            locations=locs,
                            confidence=90 if locs else 35,
                            source="direct_dword" if locs else "dictionary",
                        )
                    )
                if name in recovered_lookup:
                    recovered_hits.append(
                        APIHashHit(
                            hash_hex=f"0x{hv:08X}",
                            name=name,
                            kind=kind,
                            locations=[],
                            confidence=75 if kind in {"api", "dll"} else 60,
                            source="recovered_string",
                        )
                    )
        hits.sort(
            key=lambda h: (len(h.locations), h.confidence, h.kind, h.name), reverse=True
        )
        recovered_hits.sort(key=lambda h: (h.kind, h.name))
        self.hits = hits
        return {
            "ok": True,
            "time_seed": self.time_seed,
            "hash_iv": f"0x{self.hash_iv:08X}",
            "hits": [asdict(h) for h in hits],
            "hit_count": len([h for h in hits if h.locations]),
            "recovered_name_hits": [asdict(h) for h in recovered_hits],
            "recovered_name_count": len(recovered_hits),
            "dictionary_size": len(unique),
        }
