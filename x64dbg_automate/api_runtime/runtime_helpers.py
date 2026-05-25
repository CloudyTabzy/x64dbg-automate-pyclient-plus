"""Low-level helpers shared by the composite / memory / workflow tool layers.

These operate directly on an ``X64DbgClient`` and contain no MCP/response concerns.
"""

from __future__ import annotations

from typing import Any

_GP_REGS_64 = [
    "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
]
_GP_REGS_32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip", "eflags"]


def resolve_addr(client: Any, value: Any) -> int:
    """Resolve a hex literal or x64dbg expression to an integer address.

    Bare numbers are treated as hex (matching the existing server). Non-hex strings
    (symbols, ``rsp+0x20``, ``kernel32:CreateFileA``) fall back to the expression
    evaluator. Raises ValueError if unresolvable.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        val, success = client.eval_sync(s)
        if not success:
            raise ValueError(f"Cannot resolve address/expression: {value!r}")
        return val


def gp_regs(arch: str) -> list[str]:
    """General-purpose register names for the architecture ('x64' or 'x32')."""
    return _GP_REGS_64 if arch == "x64" else _GP_REGS_32


def capture_registers(client: Any, arch: str) -> dict[str, str]:
    """Snapshot the general-purpose registers as ``{name: '0x...'}`` (debuggee must be stopped)."""
    out: dict[str, str] = {}
    for reg in gp_regs(arch):
        try:
            out[reg] = f"0x{client.get_reg(reg):X}"
        except Exception:
            pass
    return out


def read_pointer(client: Any, arch: str, addr: int) -> int:
    """Read a pointer-sized value at ``addr`` (qword on x64, dword on x32)."""
    return client.read_qword(addr) if arch == "x64" else client.read_dword(addr)


def diff_bytes(before: bytes, after: bytes, max_runs: int = 64) -> list[dict]:
    """Group differing bytes into contiguous runs ``{offset, before, after}`` (hex strings)."""
    runs: list[dict] = []
    n = min(len(before), len(after))
    i = 0
    while i < n and len(runs) < max_runs:
        if before[i] != after[i]:
            j = i
            while j < n and before[j] != after[j]:
                j += 1
            runs.append({"offset": i, "before": before[i:j].hex(), "after": after[i:j].hex()})
            i = j
        else:
            i += 1
    return runs
