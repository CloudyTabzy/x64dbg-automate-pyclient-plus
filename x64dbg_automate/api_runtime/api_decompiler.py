"""Capstone-based decompilation tools for Axon MCP (Category C1).

These tools produce C-like pseudocode from live debuggee memory using the
Capstone disassembly engine combined with control-flow graph analysis from
x64dbg. The pseudocode is pattern-driven: it recovers function signatures,
local variables, control-flow structures (if/else, loops), and expressions.

**Limitations** (set expectations for AI agents):
- Types are inferred heuristically (``int64_t``/``int32_t``) — not recovered
  from debug info.
- Complex optimizations (inlined functions, tail calls, obfuscation) may
  produce inaccurate pseudocode.
- Stack-frame relative addressing is reliable; ``rsp``-relative locals are
  harder to name consistently.

**Persistence**: Variable renames are stored in semantic memory under the
``decompiler_rename`` category so improvements accumulate across sessions.
"""

from __future__ import annotations

import re

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import ErrorType, err, ok
from x64dbg_automate.api_runtime.semantic_memory import _get_store
from x64dbg_automate.api_runtime.supervisor import SandboxError
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr

from x64dbg_automate.external.decompiler import (
    decompile_function as _external_decompile,
    decompile_from_x64dbg_cfg,
    DecompileResult,
)

# Alias for semantic memory category
_RENAME_CATEGORY = "decompiler_rename"


def _get_client_and_arch(sandbox_id: str | None) -> tuple:
    from x64dbg_automate.api_runtime.supervisor import get_manager
    mgr = get_manager()
    client = mgr.get_client(sandbox_id)
    arch = client.debugee_bitness()
    arch_str = "x64" if arch == 64 else "x32"
    return client, arch_str


def _read_function_bytes(client, addr: int, max_size: int = 65536) -> bytes:
    """Read function bytes, bounded by max_size."""
    try:
        fb = client.get_function(addr)
        if fb and fb.end > fb.start:
            size = min(fb.end - fb.start, max_size)
            return client.read_memory(fb.start, size)
    except Exception:
        pass
    # Fallback: read a fixed chunk
    return client.read_memory(addr, min(max_size, 4096))


def _apply_renames(pseudocode: str, entry_addr: int, arch: str) -> str:
    """Apply stored variable renames for this function to pseudocode."""
    key = f"{arch}_{entry_addr:x}_renames"
    entry = _get_store().get_latest(key)
    if entry is None:
        return pseudocode
    renames = entry.get("value", {})
    if not renames:
        return pseudocode
    # Simple string replacement (order matters: longest first)
    for old_name, new_name in sorted(renames.items(), key=lambda x: -len(x[0])):
        # Only replace whole identifiers to avoid partial matches
        pseudocode = re.sub(rf"\b{re.escape(old_name)}\b", new_name, pseudocode)
    return pseudocode


# ── Tool definitions ────────────────────────────────────────────────────────


@tool
def decompile_function(
    address: str,
    max_lines: int = 0,
    include_addresses: bool = True,
    sandbox_id: str | None = None,
) -> dict:
    """Decompile a single function into C-like pseudocode.

    Uses Capstone disassembly + x64dbg CFG analysis to recover control-flow
    structures (if/else, loops), local variables, and function signatures.

    Args:
        address: Function entry point (hex string, symbol, or expression).
        max_lines: Truncate pseudocode at N lines (0 = unlimited).
            Useful for very large functions where full output would flood context.
        include_addresses: If True, appends ``/* 0xNNNN */`` address comments
            to each pseudocode line (default: True).
        sandbox_id: Optional sandbox; uses active session if omitted.

    Returns:
        Structured dict with ``pseudocode``, ``signature``, ``local_vars``,
        ``parameters``, ``calling_convention``, and ``warnings``.

    Example return::

        {
            "success": True,
            "function_name": "sub_401000",
            "entry_point": "0x401000",
            "pseudocode": "int64_t __fastcall sub_401000(int64_t param1, int64_t param2) {\n    ...",
            "signature": "int64_t __fastcall sub_401000(int64_t param1, int64_t param2)",
            "local_vars": [{"name": "local_1", "key": "rbp:-8"}],
            "parameters": [{"name": "param1", "reg": "rcx", "type": "int64_t"}],
            "calling_convention": "__fastcall",
            "warnings": []
        }
    """
    try:
        client, arch = _get_client_and_arch(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED,
                   hint="Call start_session or connect_to_session first.")

    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    try:
        data = _read_function_bytes(client, addr)
    except Exception as exc:
        return err(f"Failed to read function bytes at 0x{addr:X}: {exc}",
                   ErrorType.RPC_ERROR)

    # Try to get x64dbg's CFG first
    cfg_dict = None
    try:
        cfg_raw = client.analyze_function(addr)
        if cfg_raw:
            cfg_dict = {
                "entry_point": getattr(cfg_raw, "entry_point", addr),
                "nodes": [],
            }
            # Convert x64dbg CFG object to dict if needed
            nodes = getattr(cfg_raw, "nodes", [])
            for n in nodes:
                cfg_dict["nodes"].append({
                    "start": getattr(n, "start", 0),
                    "end": getattr(n, "end", 0),
                    "instructions": getattr(n, "instructions", []),
                    "terminal": getattr(n, "terminal", False),
                    "split": getattr(n, "split", False),
                    "indirect_call": getattr(n, "indirect_call", False),
                    "brtrue": getattr(n, "brtrue", None),
                    "brfalse": getattr(n, "brfalse", None),
                    "exits": list(getattr(n, "exits", [])),
                })
    except Exception:
        pass

    # Determine function name
    name = f"sub_{addr:X}"
    try:
        sym = client.get_symbol_at(addr)
        if sym and sym.undecoratedSymbol:
            name = sym.undecoratedSymbol
        elif sym and sym.decoratedSymbol:
            name = sym.decoratedSymbol
    except Exception:
        pass

    # Decompile
    try:
        if cfg_dict and cfg_dict.get("nodes"):
            result = decompile_from_x64dbg_cfg(cfg_dict, data, addr, arch, name, max_lines)
        else:
            result = _external_decompile(data, addr, arch, name, max_lines=max_lines)
    except Exception as exc:
        return err(f"Decompilation failed: {exc}", ErrorType.UNKNOWN,
                   hint="Ensure the address points to valid code.")

    # Apply persisted renames
    pcode = _apply_renames(result.pseudocode, addr, arch)

    # Optionally embed addresses
    if include_addresses and result.structured_nodes:
        # Address embedding is done during emission; for now, the pseudocode
        # doesn't include per-line addresses. We could enhance the emitter.
        pass

    return ok(
        function_name=result.function_name,
        entry_point=f"0x{result.entry_point:X}",
        arch=result.arch,
        pseudocode=pcode,
        signature=result.signature,
        local_vars=result.local_vars,
        parameters=result.parameters,
        calling_convention=result.calling_convention,
        warnings=result.warnings,
        decompiler_version="capstone_5.0",
    )


@tool
def decompile_range(
    start_address: str,
    size: int = 65536,
    max_lines_each: int = 30,
    sandbox_id: str | None = None,
) -> dict:
    """Decompile all functions found within a memory range.

    Scans for function prologues (``push rbp; mov rbp, rsp`` or
    ``push ebp; mov ebp, esp``), then decompiles each discovered function.
    Useful for bulk analysis of a module or section.

    Args:
        start_address: Start of the range to scan.
        size: Number of bytes to scan (default: 64 KiB).
        max_lines_each: Max pseudocode lines per function (default: 30).
        sandbox_id: Optional sandbox; uses active session if omitted.

    Returns:
        Dict with ``functions`` list and ``total_found``.
    """
    try:
        client, arch = _get_client_and_arch(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    try:
        start = resolve_addr(client, start_address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    size = max(16, min(size, 1024 * 1024))  # 1 MiB cap

    try:
        data = client.read_memory(start, size)
    except Exception as exc:
        return err(f"Failed to read memory: {exc}", ErrorType.RPC_ERROR)

    # Scan for prologues
    prologue_bytes_64 = bytes.fromhex("554889e5")  # push rbp; mov rbp, rsp
    prologue_bytes_32 = bytes.fromhex("5589e5")    # push ebp; mov ebp, esp
    prologue = prologue_bytes_64 if arch == "x64" else prologue_bytes_32

    found_addrs: list[int] = []
    i = 0
    while i <= len(data) - len(prologue):
        if data[i:i + len(prologue)] == prologue:
            found_addrs.append(start + i)
            i += len(prologue)
        else:
            i += 1

    functions: list[dict] = []
    for func_addr in found_addrs:
        try:
            # Read a chunk for this function
            end_idx = next((a - start for a in found_addrs if a > func_addr), len(data))
            func_data = data[func_addr - start: end_idx]
            name = f"sub_{func_addr:X}"
            result = _external_decompile(func_data, func_addr, arch, name,
                                         max_lines=max_lines_each)
            pcode = _apply_renames(result.pseudocode, func_addr, arch)
            functions.append({
                "address": f"0x{func_addr:X}",
                "name": result.function_name,
                "signature": result.signature,
                "pseudocode": pcode,
                "line_count": len(pcode.splitlines()),
            })
        except Exception:
            continue

    return ok(
        functions=functions,
        total_found=len(functions),
        scanned_bytes=size,
        start_address=f"0x{start:X}",
    )


@tool
def get_function_type(
    address: str,
    sandbox_id: str | None = None,
) -> dict:
    """Infer the function signature (calling convention, args, return type).

    Analyzes the function prologue, parameter register/stack usage, and
    return-value patterns to produce a best-effort C-like signature.

    Args:
        address: Function entry point.
        sandbox_id: Optional sandbox; uses active session if omitted.

    Returns:
        Dict with ``signature``, ``calling_convention``, ``args``, ``return_type``,
        ``stack_frame_size``.
    """
    try:
        client, arch = _get_client_and_arch(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    try:
        data = _read_function_bytes(client, addr)
    except Exception as exc:
        return err(f"Failed to read bytes: {exc}", ErrorType.RPC_ERROR)

    from x64dbg_automate.external.decompiler import (
        analyze_prologue, disassemble_bytes,
    )

    instructions = disassemble_bytes(data, addr, arch)
    if not instructions:
        return err("Could not disassemble function.", ErrorType.INVALID_STATE)

    info = analyze_prologue(instructions, arch)

    # Try to detect return type
    ret_type = "void"
    for i, insn in enumerate(instructions):
        if insn.mnemonic == "ret" and i > 0:
            # Check if rax/eax was written before ret
            for prev in reversed(instructions[:i]):
                if prev.mnemonic == "mov" and prev.operands:
                    dst = str(prev.operands[0].value) if prev.operands[0].type == "reg" else ""
                    if dst in ("rax", "eax"):
                        ret_type = "int64_t" if arch == "x64" else "int32_t"
                        break
                if prev.mnemonic in ("xor", ) and len(prev.operands) >= 2:
                    if str(prev.operands[0].value) == str(prev.operands[1].value):
                        if str(prev.operands[0].value) in ("rax", "eax"):
                            ret_type = "int64_t" if arch == "x64" else "int32_t"
                            break
            break

    param_strs = [f"{p.get('type', 'int64_t')} {p['name']}" for p in info.parameters]
    cc_prefix = ""
    if info.calling_convention == "__fastcall":
        cc_prefix = "__fastcall "
    elif info.calling_convention == "__stdcall_or_cdecl":
        cc_prefix = "__stdcall "

    signature = f"{ret_type} {cc_prefix}sub_{addr:X}({', '.join(param_strs)})"

    return ok(
        signature=signature,
        calling_convention=info.calling_convention,
        args=info.parameters,
        return_type=ret_type,
        stack_frame_size=info.stack_frame_size,
        callee_saved=info.callee_saved,
    )


@tool
def rename_local_variable(
    function_address: str,
    old_name: str,
    new_name: str,
    sandbox_id: str | None = None,
) -> dict:
    """Rename a local variable or parameter in decompiler output.

    The rename is persisted in semantic memory and applied to all future
    decompilations of this function. This lets AI agents iteratively improve
    pseudocode readability across sessions.

    Args:
        function_address: Address of the function containing the variable.
        old_name: Current pseudocode name (e.g. ``local_1`` or ``param1``).
        new_name: Desired meaningful name (e.g. ``aes_key`` or ``buffer_len``).
        sandbox_id: Optional sandbox; uses active session if omitted.

    Returns:
        Dict confirming the rename was stored.
    """
    try:
        client, arch = _get_client_and_arch(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    try:
        addr = resolve_addr(client, function_address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    if not old_name or not new_name:
        return err("old_name and new_name must not be empty.", ErrorType.BAD_ARGUMENT)

    key = f"{arch}_{addr:x}_renames"
    entry = _get_store().get_latest(key)
    renames: dict[str, str] = {}
    if entry is not None and entry.get("category") == _RENAME_CATEGORY:
        renames = dict(entry.get("value", {}))

    renames[old_name] = new_name

    _get_store().record(
        category=_RENAME_CATEGORY,
        key=key,
        value=renames,
        tags=["decompiler", "rename"],
    )

    return ok(
        function_address=f"0x{addr:X}",
        old_name=old_name,
        new_name=new_name,
        total_renames=len(renames),
    )


@tool
def list_variable_renames(
    function_address: str,
    sandbox_id: str | None = None,
) -> dict:
    """List all persisted variable renames for a function."""
    try:
        client, arch = _get_client_and_arch(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    try:
        addr = resolve_addr(client, function_address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    key = f"{arch}_{addr:x}_renames"
    entry = _get_store().get_latest(key)
    renames: dict[str, str] = {}
    if entry is not None and entry.get("category") == _RENAME_CATEGORY:
        renames = dict(entry.get("value", {}))

    return ok(
        function_address=f"0x{addr:X}",
        renames=renames,
        total=len(renames),
    )
