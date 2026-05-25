"""Structural analysis tools leveraging x64dbg's native analysis engine.

These expose x64dbg's internal control-flow graph, cross-reference, function
boundary, thread, module, and handle enumeration to AI agents. Unlike raw
memory reads, these return *interpreted* structural data ("this is a function
with 3 basic blocks", "0x401000 is called from 5 locations").
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

_XREF_TYPE_NAMES = {0: "NONE", 1: "DATA", 2: "JMP", 3: "CALL"}


def _xref_name(t: int) -> str:
    return _XREF_TYPE_NAMES.get(t, f"UNKNOWN({t})")


@tool
def get_threads(sandbox_id: str) -> dict:
    """List all threads in the debuggee with their state (CIP, suspend count, priority)."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        threads = client.get_threads()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        threads=[t.model_dump() for t in threads],
        total=len(threads),
        current_thread_index=0,  # x64dbg tracks current thread separately
    )


@tool
def get_xrefs(sandbox_id: str, address: str) -> dict:
    """Get cross-references (calls, jumps, data refs) to/from an address.

    Args:
        sandbox_id: Sandbox to query.
        address: Address, symbol, or expression to look up xrefs for.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        xrefs = client.get_xrefs(addr)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{addr:X}",
        xrefs=[{"address": f"0x{x.address:X}", "type": _xref_name(x.xref_type)} for x in xrefs],
        total=len(xrefs),
    )


@tool
def get_function_boundaries(sandbox_id: str, address: str) -> dict:
    """Get the start/end boundaries and instruction count of the function at an address.

    Args:
        sandbox_id: Sandbox to query.
        address: Address within the function (address, symbol, or expression).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        fb = client.get_function(addr)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if fb is None:
        return err(f"No function found at or near 0x{addr:X}.", ErrorType.NOT_FOUND,
                   hint="x64dbg may need to run analysis first (try 'anal' command or let auto-analysis finish).",
                   sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{addr:X}",
        start=f"0x{fb.start:X}",
        end=f"0x{fb.end:X}",
        instruction_count=fb.instruction_count,
        manual=fb.manual,
    )


@tool
def analyze_function_cfg(sandbox_id: str, address: str) -> dict:
    """Analyze a function and return its control flow graph (CFG).

    Returns basic blocks with branch targets, instruction counts, terminal
    flags, and the raw instruction bytes in each block. This is the runtime
    equivalent of IDA's graph view.

    Args:
        sandbox_id: Sandbox to query.
        address: Function entry point (address, symbol, or expression).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        entry = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        cfg = client.analyze_function(entry)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if cfg is None:
        return err(f"Failed to analyze function at 0x{entry:X}.", ErrorType.INVALID_STATE,
                   hint="Ensure the address is the start of a valid function.", sandbox_id=sandbox_id)
    nodes = []
    for n in cfg["nodes"]:
        nodes.append({
            "start": f"0x{n['start']:X}",
            "end": f"0x{n['end']:X}",
            "instruction_count": n["instruction_count"],
            "terminal": n["terminal"],
            "split": n["split"],
            "indirect_call": n["indirect_call"],
            "brtrue": (f"0x{n['brtrue']:X}" if n["brtrue"] else None),
            "brfalse": (f"0x{n['brfalse']:X}" if n["brfalse"] else None),
            "exits": [f"0x{e:X}" for e in n["exits"]],
            "instructions": [
                {"address": f"0x{ins['address']:X}", "bytes": to_hex(ins["bytes"])}
                for ins in n["instructions"]
            ],
        })
    return ok(
        sandbox_id=sandbox_id,
        entry_point=f"0x{cfg['entry_point']:X}",
        node_count=len(nodes),
        nodes=nodes,
    )


@tool
def get_string_at(sandbox_id: str, address: str) -> dict:
    """Read an auto-detected string (ASCII/Unicode) at an address.

    Args:
        sandbox_id: Sandbox to query.
        address: Address to check (address, symbol, or expression).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        text = client.get_string_at(addr)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not text:
        return err(f"No auto-detected string at 0x{addr:X}.", ErrorType.NOT_FOUND, sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, address=f"0x{addr:X}", string=text)


@tool
def get_patches(sandbox_id: str) -> dict:
    """List all patched bytes in the debuggee (memory modifications made by the debugger/user)."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        patches = client.get_patches()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        patches=[{"address": f"0x{p.address:X}", "old": f"0x{p.old_byte:02X}", "new": f"0x{p.new_byte:02X}"} for p in patches],
        total=len(patches),
    )


@tool
def get_modules(sandbox_id: str) -> dict:
    """List all loaded modules (DLLs/exe) in the debuggee with base/size/entry/name/path."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        modules = client.get_modules()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        modules=[{"base": f"0x{m.base:X}", "size": m.size, "entry": f"0x{m.entry:X}",
                  "name": m.name, "path": m.path, "section_count": m.section_count} for m in modules],
        total=len(modules),
    )


@tool
def get_seh_chain(sandbox_id: str) -> dict:
    """Get the Structured Exception Handling (SEH) chain for the current thread.

    Useful for understanding exception handler chains and anti-debug tricks that
    manipulate SEH records.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        records = client.get_seh_chain()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        records=[{"address": f"0x{r.address:X}", "handler": f"0x{r.handler:X}"} for r in records],
        total=len(records),
    )


@tool
def get_handles(sandbox_id: str) -> dict:
    """Enumerate all handles in the debuggee process.

    Identifies open files, mutexes, events, threads, processes, registry keys,
    and debug objects. Great for spotting anti-debug handles or resource leaks.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        handles = client.get_handles()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        handles=[{"handle": f"0x{h.handle:X}", "type_number": h.type_number,
                  "granted_access": f"0x{h.granted_access:08X}"} for h in handles],
        total=len(handles),
    )
