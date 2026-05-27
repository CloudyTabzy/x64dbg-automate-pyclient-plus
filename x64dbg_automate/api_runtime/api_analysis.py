"""Structural analysis tools leveraging x64dbg's native analysis engine.

These expose x64dbg's internal control-flow graph, cross-reference, function
boundary, thread, module, and handle enumeration to AI agents. Unlike raw
memory reads, these return *interpreted* structural data ("this is a function
with 3 basic blocks", "0x401000 is called from 5 locations").
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, is_bug, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import (
    detect_function_bounds, disasm_instructions, resolve_addr,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

_XREF_TYPE_NAMES = {0: "NONE", 1: "DATA", 2: "JMP", 3: "CALL"}

# Memory constants for the scan-based xref fallback.
_MEM_COMMIT = 0x1000
_PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80  # EXECUTE | _READ | _READWRITE | _WRITECOPY
_XREF_SCAN_DEFAULT_MAX = 64 * 1024 * 1024  # 64 MiB scan ceiling


def _xref_name(t: int) -> str:
    return _XREF_TYPE_NAMES.get(t, f"UNKNOWN({t})")


def _scan_xrefs_to(client, target: int, arch: str, max_bytes: int = _XREF_SCAN_DEFAULT_MAX) -> tuple[list[dict], bool]:
    """Scan executable memory for direct rel32 CALL/JMP sites that target ``target``.

    This is the fallback the reviewer performed by hand (``memory_search_pattern``
    for ``E8 ?? ?? ?? ??`` + manual offset math). It finds only *direct* near
    call/jmp (E8/E9 rel32) references — indirect/register/memory-indirect targets
    can't be resolved statically. Each byte-level candidate is verified with the
    real disassembler so data bytes that merely look like E8/E9 are rejected.

    Returns ``(refs, truncated)`` where ``truncated`` is True if the scan ceiling
    was hit before all executable memory was covered.
    """
    mask = 0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF
    try:
        pages = client.memmap()
    except Exception:
        return [], False

    refs: list[dict] = []
    scanned = 0
    truncated = False
    seen: set[int] = set()

    for page in pages:
        if (page.state & _MEM_COMMIT) == 0:
            continue
        if (page.protect & _PAGE_EXECUTE_ANY) == 0:
            continue
        size = page.region_size
        if scanned + size > max_bytes:
            truncated = True
            break
        try:
            data = client.read_memory(page.base_address, size)
        except Exception:
            continue
        if not data:
            continue
        scanned += len(data)

        base = page.base_address
        # Locate candidate opcodes, then verify each with the disassembler.
        start = 0
        n = len(data)
        while start < n - 4:
            # find next E8 or E9
            i_call = data.find(0xE8, start)
            i_jmp = data.find(0xE9, start)
            candidates = [c for c in (i_call, i_jmp) if c != -1 and c <= n - 5]
            if not candidates:
                break
            i = min(candidates)
            rel = int.from_bytes(data[i + 1:i + 5], "little", signed=True)
            site = base + i
            computed = (site + 5 + rel) & mask
            if computed == target and site not in seen:
                kind = "CALL" if data[i] == 0xE8 else "JMP"
                # Verify with the real disassembler to reject false positives.
                try:
                    ins = client.disassemble_at(site)
                except Exception:
                    ins = None
                if ins is not None:
                    mnem = ins.instruction.strip().lower()
                    if mnem.startswith(("call", "jmp")):
                        seen.add(site)
                        refs.append({
                            "address": f"0x{site:X}",
                            "type": kind,
                            "instruction": ins.instruction,
                            "source": "scan",
                        })
            start = i + 1

    return refs, truncated


@tool
def get_threads(sandbox_id: str | None = None) -> dict:
    """List all threads in the debuggee with their state (CIP, suspend count, priority)."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        threads = client.get_threads()
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        threads=[t.model_dump() for t in threads],
        total=len(threads),
        current_thread_index=0,  # x64dbg tracks current thread separately
    )


@tool
def get_xrefs(
    *,
    sandbox_id: str | None = None,
    address: str,
    analyze: bool = True,
    scan_fallback: bool = True,
) -> dict:
    """Get cross-references (calls, jumps, data refs) to an address — reliably.

    x64dbg's native xref database is empty until the target module has been
    analyzed, so a raw query on a freshly-loaded image fails with
    ``XERROR_XREF_FAILED``. This tool makes xrefs dependable for autonomous use:

    1. Try the native xref database.
    2. If it fails or is empty and ``analyze`` is set, run x64dbg analysis on the
       containing module (``analr``) and retry — this populates the database.
    3. If still empty and ``scan_fallback`` is set, scan executable memory for
       direct rel32 CALL/JMP sites and verify each with the disassembler.

    The response ``source`` field reports which path produced the results
    (``native`` | ``scan``), and ``scan_truncated`` flags an incomplete scan.

    Args:
        sandbox_id: Sandbox to query.
        address: Address, symbol, or expression to look up xrefs for.
        analyze: Run module analysis and retry if the native DB is empty (default True).
        scan_fallback: Fall back to a memory scan for direct callers (default True).
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

    def _native() -> list | None:
        try:
            return client.get_xrefs(addr)
        except Exception as exc:  # noqa: BLE001
            if is_bug(exc):
                raise
            return None  # XERROR_XREF_FAILED or RPC error → treat as "no DB"

    notes: list[str] = []
    xrefs = _native()

    # Native DB empty/failed → optionally analyze the module and retry.
    if (not xrefs) and analyze:
        try:
            if client.cmd_sync(f"analr 0x{addr:X}"):
                notes.append("Ran module analysis (analr) to populate the xref database.")
                xrefs = _native()
        except Exception:
            pass

    if xrefs:
        return ok(
            sandbox_id=sandbox_id,
            address=f"0x{addr:X}",
            source="native",
            xrefs=[{"address": f"0x{x.address:X}", "type": _xref_name(x.xref_type)} for x in xrefs],
            total=len(xrefs),
            notes=notes or None,
        )

    # Still nothing → scan-based fallback for direct callers.
    if scan_fallback:
        arch = "x64"
        try:
            sb = mgr.get_sandbox(sandbox_id)
            arch = sb.debugger_arch or "x64"
        except Exception:
            pass
        try:
            refs, truncated = _scan_xrefs_to(client, addr, arch)
        except Exception as exc:  # noqa: BLE001
            if is_bug(exc):
                raise
            return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
        notes.append(
            "Native xref DB was empty; results are direct rel32 CALL/JMP callers "
            "found by scanning executable memory. Indirect references are not included."
        )
        return ok(
            sandbox_id=sandbox_id,
            address=f"0x{addr:X}",
            source="scan",
            xrefs=refs,
            total=len(refs),
            scan_truncated=truncated,
            notes=notes,
        )

    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{addr:X}",
        source="native",
        xrefs=[],
        total=0,
        notes=["No xrefs found. The module may be unanalyzed — retry with analyze=True "
               "or scan_fallback=True."],
    )


@tool
def get_function_boundaries(*, sandbox_id: str | None = None, address: str) -> dict:
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
        if is_bug(exc):
            raise
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


_PAGE_PROTECT_NAMES = {
    0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE", 0x08: "WRITECOPY",
    0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY",
}


def _protect_name(protect: int) -> str:
    # PAGE_GUARD (0x100) and PAGE_NOCACHE (0x200) are modifier flags on the base.
    base_only = protect & 0xFF
    name = _PAGE_PROTECT_NAMES.get(base_only, f"0x{protect:X}")
    flags = []
    if protect & 0x100:
        flags.append("GUARD")
    if protect & 0x200:
        flags.append("NOCACHE")
    return name + ("|" + "|".join(flags) if flags else "")


@tool
def resolve_address(*, sandbox_id: str | None = None, address: str) -> dict:
    """Normalize any address into the full picture an RE agent needs.

    Accepts an absolute address, RVA-looking value, symbol, or x64dbg expression
    and returns every representation at once so the agent never has to do manual
    base arithmetic (the documented "#1 agent trap"):

    - ``absolute`` — the live virtual address
    - ``module`` / ``module_base`` / ``module_path`` — containing module
    - ``module_rva`` — offset from the containing module's base
    - ``image_rva`` — offset from the *main* image base (matches RVAs hardcoded
      in source/IDA that assume the default image base)
    - ``section`` / ``protection`` / ``executable`` — region metadata
    - ``symbol`` / ``label`` — nearest symbol and any user label

    Args:
        sandbox_id: Sandbox to query (omit for active session).
        address: Absolute address, symbol, or expression (e.g. ``0x88729D``,
                 ``kernel32:CreateFileA``, ``rip``, ``mod.base()+0x48729D``).
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

    result: dict = {"query": address, "absolute": f"0x{addr:X}"}

    # ── Containing module + module-relative RVA ────────────────────────────
    containing = None
    try:
        for m in client.get_modules():
            if m.base <= addr < m.base + m.size:
                containing = m
                break
    except Exception:
        pass
    if containing is not None:
        result.update({
            "module": containing.name,
            "module_base": f"0x{containing.base:X}",
            "module_path": containing.path,
            "module_rva": f"0x{addr - containing.base:X}",
        })
    else:
        result["module"] = None

    # ── Main-image RVA (the "0x88729D → 0x48729D" case) ────────────────────
    try:
        pinfo = client.get_process_info()
        if pinfo and pinfo.image_base:
            result["image_base"] = f"0x{pinfo.image_base:X}"
            if pinfo.image_base <= addr < pinfo.image_base + (pinfo.image_size or (1 << 31)):
                result["image_rva"] = f"0x{addr - pinfo.image_base:X}"
    except Exception:
        pass

    # ── Section / protection from the live memory map ──────────────────────
    try:
        for p in client.memmap():
            if p.base_address <= addr < p.base_address + p.region_size:
                result["section"] = p.info or None
                result["protection"] = _protect_name(p.protect)
                result["executable"] = bool(p.protect & _PAGE_EXECUTE_ANY)
                result["region_base"] = f"0x{p.base_address:X}"
                result["region_size"] = p.region_size
                break
    except Exception:
        pass

    # ── Nearest symbol + user label ────────────────────────────────────────
    try:
        sym = client.get_symbol_at(addr)
        if sym and (sym.undecoratedSymbol or sym.decoratedSymbol):
            result["symbol"] = sym.undecoratedSymbol or sym.decoratedSymbol
            result["symbol_address"] = f"0x{sym.addr:X}"
    except Exception:
        pass
    try:
        label = client.get_label_at(addr)
        if label:
            result["label"] = label
    except Exception:
        pass

    return ok(sandbox_id=sandbox_id, **result)


@tool
def find_function_start(*, sandbox_id: str | None = None, address: str) -> dict:
    """Find the start of the function containing an address (even without analysis).

    Where ``get_function_boundaries`` returns NOT_FOUND on un-analyzed images,
    this always resolves *something* via a layered heuristic (x64dbg analysis →
    backward prologue scan → RET scan → fixed window) and reports how it was
    found so the agent can gauge trust.

    Args:
        sandbox_id: Sandbox to query.
        address: Any address inside the function (address, symbol, or expression).

    Returns ``start``, ``end``, ``size``, ``method`` (x64dbg | prologue_scan |
    ret_scan | fallback), and ``confidence`` (high | medium | low).
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
        bounds = detect_function_bounds(client, addr)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    result = ok(
        sandbox_id=sandbox_id,
        query=f"0x{addr:X}",
        start=f"0x{bounds.start:X}",
        end=f"0x{bounds.end:X}",
        size=bounds.size,
        contains_query=bounds.start <= addr < bounds.end,
        method=bounds.method,
        confidence=bounds.confidence,
    )
    if bounds.note:
        result["note"] = bounds.note
    return result


@tool
def disassemble_function(
    *,
    sandbox_id: str | None = None,
    address: str,
    max_instructions: int = 512,
) -> dict:
    """Disassemble the entire function containing an address.

    Unlike ``disassemble_range`` (linear from an exact address — which yields
    garbage if the address is mid-instruction), this first detects the function
    boundaries, then walks instructions from the *start* so decoding is aligned.
    This is the tool to reach for when verifying a crash site or reading a whole
    routine, because the agent doesn't have to know the prologue address.

    Args:
        sandbox_id: Sandbox to read from.
        address: Any address inside the function (address, symbol, or expression).
        max_instructions: Safety cap on instructions decoded (default 512).

    Returns the detected bounds (with ``method``/``confidence``), the instruction
    list, and ``query_index`` — the index of the instruction that contains the
    queried address, so the agent can locate it immediately.
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
        bounds = detect_function_bounds(client, addr)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    cap = max(1, min(max_instructions, 4096))
    # Disassemble from the function start, walking by real instruction size, and
    # stop once we pass the detected end (or hit the cap). disasm_instructions
    # already halts at a trailing RET.
    try:
        raw = disasm_instructions(client, bounds.start, cap)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    instructions = []
    query_index = None
    truncated = False
    for idx, ins in enumerate(raw):
        ins_addr = int(ins["address"], 16)
        if ins_addr >= bounds.end and bounds.method != "fallback":
            truncated = False
            break
        instructions.append(ins)
        ins_size = ins.get("size", 0) or 0
        if ins_addr <= addr < ins_addr + ins_size:
            query_index = len(instructions) - 1
        if len(instructions) >= cap:
            truncated = True
            break

    result = ok(
        sandbox_id=sandbox_id,
        query=f"0x{addr:X}",
        start=f"0x{bounds.start:X}",
        end=f"0x{bounds.end:X}",
        size=bounds.size,
        method=bounds.method,
        confidence=bounds.confidence,
        instruction_count=len(instructions),
        instructions=instructions,
        query_index=query_index,
        truncated=truncated,
    )
    if bounds.note:
        result["note"] = bounds.note
    return result


@tool
def analyze_function_cfg(*, sandbox_id: str | None = None, address: str) -> dict:
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
        if is_bug(exc):
            raise
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
def get_string_at(*, sandbox_id: str | None = None, address: str) -> dict:
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
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not text:
        return err(f"No auto-detected string at 0x{addr:X}.", ErrorType.NOT_FOUND, sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, address=f"0x{addr:X}", string=text)


@tool
def get_patches(sandbox_id: str | None = None) -> dict:
    """List all patched bytes in the debuggee (memory modifications made by the debugger/user)."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        patches = client.get_patches()
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        patches=[{"address": f"0x{p.address:X}", "old": f"0x{p.old_byte:02X}", "new": f"0x{p.new_byte:02X}"} for p in patches],
        total=len(patches),
    )


@tool
def get_modules(sandbox_id: str | None = None) -> dict:
    """List all loaded modules (DLLs/exe) in the debuggee with base/size/entry/name/path."""
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        modules = client.get_modules()
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        modules=[{"base": f"0x{m.base:X}", "size": m.size, "entry": f"0x{m.entry:X}",
                  "name": m.name, "path": m.path, "section_count": m.section_count} for m in modules],
        total=len(modules),
    )


@tool
def get_seh_chain(sandbox_id: str | None = None) -> dict:
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
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        records=[{"address": f"0x{r.address:X}", "handler": f"0x{r.handler:X}"} for r in records],
        total=len(records),
    )


@tool
def get_handles(sandbox_id: str | None = None) -> dict:
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
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        handles=[{"handle": f"0x{h.handle:X}", "type_number": h.type_number,
                  "granted_access": f"0x{h.granted_access:08X}"} for h in handles],
        total=len(handles),
    )


# ── Call Graph Construction ─────────────────────────────────────────────────

import dataclasses
from collections import deque
from typing import Any


@dataclasses.dataclass(frozen=True)
class _CallGraphNode:
    """Internal representation of a call-graph node (function or import)."""
    address: int
    name: str
    module: str
    size: int = 0
    size_estimated: bool = False
    node_type: str = "function"  # function | import | unresolved


@dataclasses.dataclass(frozen=True)
class _CallGraphEdge:
    """Internal representation of a call-graph edge."""
    source: int
    target: int
    edge_type: str  # direct_call | indirect_call | import_call | tail_call | unresolved
    instruction_address: int


class _CallGraphBuilder:
    """BFS-based call-graph builder with Capstone disassembly.

    Design goals:
    1. **Reliable classification** — Capstone instruction IDs (not string parsing)
       classify CALL vs JMP vs conditional branch.
    2. **Graceful degradation** — If x64dbg hasn't analyzed a function, we fall
       back to reading its bytes and disassembling with Capstone.
    3. **Import awareness** — Calls through the IAT are resolved to import names
       when possible, so the graph shows ``kernel32.CreateFileA`` rather than an
       opaque address.
    4. **Bounded exploration** — ``max_depth`` + ``max_nodes`` prevent runaway
       recursion on large binaries.
    """

    def __init__(
        self,
        client: Any,
        arch: str,
        max_depth: int = 3,
        max_nodes: int = 100,
        include_imports: bool = True,
        follow_tail_calls: bool = True,
    ):
        self.client = client
        self.arch = arch
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.include_imports = include_imports
        self.follow_tail_calls = follow_tail_calls

        self.nodes: dict[int, _CallGraphNode] = {}
        self.edges: list[_CallGraphEdge] = []
        self.visited: set[int] = set()
        self._unresolved_counter: int = 0
        self._diagnostics: list[str] = []

        # Module cache for fast address→module lookups
        self._modules: list[Any] = []
        self._load_modules()

    # ── Module cache ──────────────────────────────────────────────────────

    def _load_modules(self) -> None:
        try:
            self._modules = self.client.get_modules()
        except Exception:
            self._modules = []

    def _module_for_addr(self, addr: int) -> tuple[str, int]:
        """Return (module_name, module_base) for ``addr``, or ('unknown', 0)."""
        for mod in self._modules:
            if mod.base <= addr < mod.base + mod.size:
                return mod.name, mod.base
        return "unknown", 0

    # ── Symbol resolution ─────────────────────────────────────────────────

    def _symbol_name(self, addr: int) -> str | None:
        try:
            sym = self.client.get_symbol_at(addr)
            if sym and sym.undecoratedSymbol:
                return sym.undecoratedSymbol
        except Exception:
            pass
        return None

    def _node_name(self, addr: int) -> str:
        name = self._symbol_name(addr)
        if name:
            return name
        return f"sub_{addr:X}"

    # ── Function boundaries ───────────────────────────────────────────────

    def _get_function_bounds(self, addr: int) -> tuple[int, int]:
        """Return (start, end) for the function containing ``addr``.

        Delegates to the shared :func:`detect_function_bounds` heuristic so the
        call-graph builder, ``find_function_start`` and ``disassemble_function``
        all agree on boundaries. Never returns ``None``.
        """
        from x64dbg_automate.api_runtime.runtime_helpers import detect_function_bounds

        fb = detect_function_bounds(self.client, addr)
        if fb.method == "fallback":
            self._diagnostics.append(
                f"Could not determine bounds for 0x{addr:X}; using 4 KiB fallback"
            )
        return fb.start, fb.end

    # ── Disassembly ───────────────────────────────────────────────────────

    def _disassemble_function(self, start: int, end: int) -> list[Any]:
        """Disassemble bytes in [start, end) using Capstone."""
        size = end - start
        if size <= 0 or size > 0x20000:  # 128 KiB safety cap per function
            return []
        try:
            data = self.client.read_memory(start, size)
        except Exception:
            return []
        if not data:
            return []

        from x64dbg_automate.external.decompiler import disassemble_bytes
        try:
            return disassemble_bytes(data, start, self.arch)
        except Exception:
            return []

    # ── Call-target resolution ────────────────────────────────────────────

    def _resolve_call_target(
        self, insn: Any, func_start: int, func_end: int
    ) -> tuple[int | None, str, str | None]:
        """Resolve the target of a CALL or JMP instruction.

        Returns:
            (target_addr, edge_type, extra_info)
            target_addr may be None for unresolved indirect calls.
        """
        from x64dbg_automate.external.decompiler import X86_INS_CALL, X86_INS_JMP

        is_call = insn.id == X86_INS_CALL
        is_jmp = insn.id == X86_INS_JMP

        if not insn.operands:
            return None, "unresolved", None

        op0 = insn.operands[0]

        # ── Immediate operand ─────────────────────────────────────────────
        if op0.type == "imm":
            target = op0.value
            if is_jmp:
                # Tail call if target is outside current function
                if target < func_start or target >= func_end:
                    return target, "tail_call", None
                # Internal jump — ignore for call graph
                return None, "internal_jump", None
            # Direct call
            return target, "direct_call", None

        # ── Memory operand ────────────────────────────────────────────────
        if op0.type == "mem":
            mem = op0.value
            disp = mem.get("disp", 0)
            if mem.get("base") in ("rip", "eip") and disp:
                ea = insn.address + insn.size + disp
                try:
                    ptr = (
                        self.client.read_qword(ea)
                        if self.arch == "x64"
                        else self.client.read_dword(ea)
                    )
                    sym = self._symbol_name(ptr)
                    if sym:
                        return ptr, "import_call", sym
                    return ptr, "indirect_call", None
                except Exception:
                    pass
                return ea, "indirect_call", None
            if disp and not mem.get("base") and not mem.get("index"):
                try:
                    ptr = (
                        self.client.read_qword(disp)
                        if self.arch == "x64"
                        else self.client.read_dword(disp)
                    )
                    sym = self._symbol_name(ptr)
                    if sym:
                        return ptr, "import_call", sym
                    return ptr, "indirect_call", None
                except Exception:
                    pass
                return disp, "indirect_call", None
            return None, "indirect_call", None

        # ── Register operand ──────────────────────────────────────────────
        if op0.type == "reg":
            return None, "indirect_call", str(op0.value)

        return None, "unresolved", None

    # ── Node creation ─────────────────────────────────────────────────────

    def _ensure_node(self, addr: int, node_type: str = "function", name_hint: str | None = None) -> _CallGraphNode:
        if addr in self.nodes:
            return self.nodes[addr]

        mod_name, _ = self._module_for_addr(addr)
        name = name_hint or self._node_name(addr)

        # Try to get size from x64dbg analysis; if that fails use the heuristic
        size = 0
        size_estimated = False
        try:
            fb = self.client.get_function(addr)
            if fb:
                size = fb.end - fb.start
        except Exception:
            pass

        if size == 0:
            bounds = self._get_function_bounds(addr)
            if bounds:
                size = bounds[1] - bounds[0]
                size_estimated = True

        node = _CallGraphNode(
            address=addr,
            name=name,
            module=mod_name,
            size=size,
            size_estimated=size_estimated,
            node_type=node_type,
        )
        self.nodes[addr] = node
        return node

    # ── BFS traversal ─────────────────────────────────────────────────────

    def build(self, start_addr: int) -> dict:
        """Build the call graph starting from ``start_addr``.

        Returns a JSON-serializable dict with nodes, edges, and metadata.
        """
        queue: deque[tuple[int, int]] = deque()
        queue.append((start_addr, 0))
        self.visited.add(start_addr)
        self._ensure_node(start_addr)

        max_depth_reached = 0
        unresolved_indirect: list[dict] = []
        truncated = False

        while queue and len(self.nodes) < self.max_nodes:
            addr, depth = queue.popleft()
            if depth > max_depth_reached:
                max_depth_reached = depth
            if depth >= self.max_depth:
                continue

            bounds = self._get_function_bounds(addr)
            func_start, func_end = bounds

            # Update size for the currently-processed node if we got real bounds
            if addr in self.nodes:
                old = self.nodes[addr]
                if old.size == 0 or old.size_estimated:
                    real_size = func_end - func_start
                    if real_size > old.size:
                        self.nodes[addr] = dataclasses.replace(
                            old, size=real_size, size_estimated=False
                        )

            instructions = self._disassemble_function(func_start, func_end)
            for insn in instructions:
                if not (insn.is_call or (self.follow_tail_calls and insn.is_jump)):
                    continue

                target, edge_type, extra = self._resolve_call_target(
                    insn, func_start, func_end
                )

                if edge_type == "internal_jump":
                    continue

                if target is None and edge_type == "indirect_call":
                    # Record unresolved indirect call as metadata — do NOT
                    # create a synthetic hash-based node (fixes A2).
                    self._unresolved_counter += 1
                    unresolved_indirect.append({
                        "source": f"0x{addr:X}",
                        "instruction_address": f"0x{insn.address:X}",
                        "reason": extra or "unknown indirect target",
                    })
                    continue

                if target is None:
                    continue

                # Respect max_nodes — skip new nodes when at limit
                if target not in self.nodes and len(self.nodes) >= self.max_nodes:
                    truncated = True
                    continue

                target_mod, _ = self._module_for_addr(target)
                source_mod, _ = self._module_for_addr(addr)

                if edge_type == "direct_call" and target_mod != source_mod and target_mod != "unknown":
                    edge_type = "import_call"

                if edge_type == "import_call" and extra:
                    self._ensure_node(target, node_type="import", name_hint=extra)
                else:
                    self._ensure_node(target, node_type="function")

                self.edges.append(
                    _CallGraphEdge(
                        source=addr,
                        target=target,
                        edge_type=edge_type,
                        instruction_address=insn.address,
                    )
                )

                if target not in self.visited and len(self.nodes) < self.max_nodes:
                    self.visited.add(target)
                    queue.append((target, depth + 1))

        return self._to_dict(
            start_addr, max_depth_reached, unresolved_indirect, truncated
        )

    # ── Serialization ─────────────────────────────────────────────────────

    def _to_dict(
        self, start_addr: int, max_depth: int, unresolved: list[dict], truncated: bool
    ) -> dict:
        return {
            "start_node": f"0x{start_addr:X}",
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "max_depth_reached": max_depth,
            "truncated": truncated,
            "unresolved_indirect_calls": len(unresolved),
            "unresolved_calls_detail": unresolved,
            "diagnostics": self._diagnostics,
            "nodes": [
                {
                    "id": f"0x{n.address:X}",
                    "address": f"0x{n.address:X}",
                    "name": n.name,
                    "module": n.module,
                    "size": n.size,
                    "size_estimated": n.size_estimated,
                    "type": n.node_type,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": f"0x{e.source:X}",
                    "target": f"0x{e.target:X}",
                    "type": e.edge_type,
                    "instruction_address": f"0x{e.instruction_address:X}",
                }
                for e in self.edges
            ],
        }


@tool
def graph_call_graph(
    *,
    sandbox_id: str | None = None,
    address: str = "",
    max_depth: int = 3,
    max_nodes: int = 100,
    include_imports: bool = True,
    follow_tail_calls: bool = True,
) -> dict:
    """Build a structured call graph from a function entry point.

    Uses Capstone disassembly + x64dbg symbol/module metadata to discover
    direct calls, indirect calls, import calls, and tail calls.  The graph
    is returned as node/edge JSON suitable for visualization or automated
    analysis.

    Args:
        sandbox_id: Sandbox to analyze.
        address: Function entry point (hex, symbol, or expression).
                 Defaults to the debuggee's entry point.
        max_depth: How many call levels to follow (default 3).
        max_nodes: Hard limit on total nodes (default 100).
        include_imports: Include imported DLL functions as nodes (default True).
        follow_tail_calls: Treat JMP-to-function as calls (default True).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    sandbox = mgr.get_sandbox(sandbox_id)
    arch = sandbox.debugger_arch if sandbox else "x64"

    if address:
        try:
            start = resolve_addr(client, address)
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    else:
        try:
            info = client.get_process_info()
            start = info.image_base + info.entry_point
        except Exception as exc:
            return err(f"Cannot determine entry point: {exc}", ErrorType.INVALID_STATE,
                       sandbox_id=sandbox_id)

    builder = _CallGraphBuilder(
        client=client,
        arch=arch,
        max_depth=max(max_depth, 1),
        max_nodes=max(max_nodes, 1),
        include_imports=include_imports,
        follow_tail_calls=follow_tail_calls,
    )

    try:
        result = builder.build(start)
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(sandbox_id=sandbox_id, **result)
