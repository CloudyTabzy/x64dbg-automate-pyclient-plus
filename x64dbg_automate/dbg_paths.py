"""x64dbg / x32dbg executable path resolution.

Shared by the MCP server and the runtime SandboxManager so that debugger-binary
selection (x64 vs x32, env-var fallback, x96dbg launcher resolution) has a single
implementation.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path


def pe_bitness(exe_path: str) -> int:
    """Read the PE Machine field to determine if an executable is 32- or 64-bit."""
    with open(exe_path, "rb") as f:
        mz = f.read(2)
        if mz != b"MZ":
            raise ValueError(f"Not a valid PE file: {exe_path}")
        f.seek(0x3C)
        pe_offset = struct.unpack("<I", f.read(4))[0]
        f.seek(pe_offset)
        sig = f.read(4)
        if sig != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature in: {exe_path}")
        machine = struct.unpack("<H", f.read(2))[0]
    if machine == 0x8664:
        return 64
    if machine == 0x14C:
        return 32
    raise ValueError(f"Unknown PE machine type 0x{machine:X} in: {exe_path}")


def resolve_x64dbg_path_with_env(x64dbg_path: str) -> str:
    """Resolve x64dbg path from the parameter, falling back to the X64DBG_PATH env var.

    Raises:
        FileNotFoundError: If neither the parameter nor the env var provides a path.
    """
    path = x64dbg_path.strip() if x64dbg_path else ""
    if not path:
        path = os.environ.get("X64DBG_PATH", "").strip()
    if not path:
        raise FileNotFoundError(
            "x64dbg path not provided and X64DBG_PATH environment variable is not set."
        )
    return path


def resolve_debugger_path(x64dbg_path: str, target_exe: str = "") -> str:
    """Resolve x96dbg.exe to the correct x64dbg.exe / x32dbg.exe based on target bitness.

    If the path already points to x64dbg.exe or x32dbg.exe, it is returned as-is.
    """
    p = Path(x64dbg_path)
    name_lower = p.name.lower()
    if name_lower not in ("x96dbg.exe", "x96dbg"):
        return x64dbg_path
    # x96dbg launcher — resolve to the correct binary
    if target_exe.strip():
        bitness = pe_bitness(target_exe.strip())
    else:
        bitness = 64  # default when no target specified
    arch_dir = "x64" if bitness == 64 else "x32"
    dbg_name = "x64dbg.exe" if bitness == 64 else "x32dbg.exe"
    candidates = [
        p.parent / arch_dir / dbg_name,        # release/x64/x64dbg.exe (standard layout)
        p.parent / dbg_name,                    # release/x64dbg.exe (flat layout)
        p.parent / "release" / dbg_name,        # alongside release/ folder
        p.parent / "release" / arch_dir / dbg_name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError(
        f"Cannot find {dbg_name} relative to {x64dbg_path}. "
        f"Pass the path to {dbg_name} directly instead of x96dbg.exe."
    )
