__version__ = "1.0.0"
from .strings import analyze_binary, write_txt, write_json, is_runtime_literal
from .resolve8 import Resolve8HashResolver, APIHashHit
from .k8_syscall import (
    K8SyscallAnalyzer,
    InlineDecryptDiscovery,
    RuntimeKeyBackwardSlicer,
)

__all__ = [
    "__version__",
    "analyze_binary",
    "write_txt",
    "write_json",
    "is_runtime_literal",
    "Resolve8HashResolver",
    "APIHashHit",
    "K8SyscallAnalyzer",
    "InlineDecryptDiscovery",
    "RuntimeKeyBackwardSlicer",
]
