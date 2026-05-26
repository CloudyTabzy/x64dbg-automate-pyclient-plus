"""Structural analysis tools leveraging x64dbg's native analysis engine.

These expose x64dbg's internal control-flow graph, cross-reference, function
boundary, thread, module, and handle enumeration to AI agents. Unlike raw
memory reads, these return *interpreted* structural data ("this is a function
with 3 basic blocks", "0x401000 is called from 5 locations").
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, is_bug, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

_XREF_TYPE_NAMES = {0: "NONE", 1: "DATA", 2: "JMP", 3: "CALL"}


def _xref_name(t: int) -> str:
    return _XREF_TYPE_NAMES.get(t, f"UNKNOWN({t})")


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
def get_xrefs(*, sandbox_id: str | None = None, address: str) -> dict:
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
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{addr:X}",
        xrefs=[{"address": f"0x{x.address:X}", "type": _xref_name(x.xref_type)} for x in xrefs],
        total=len(xrefs),
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

    def _get_function_bounds(self, addr: int) -> tuple[int, int] | None:
        """Return (start, end) for the function containing ``addr``.

        Tries x64dbg's ``get_function`` first; falls back to a heuristic scan
        (backward for prologue, forward for RET) so we still work on images
        where auto-analysis hasn't run.
        """
        try:
            fb = self.client.get_function(addr)
            if fb:
                return fb.start, fb.end
        except Exception:
            pass

        # Heuristic fallback — scan backward for common prologues
        try:
            prologue_patterns = (b"\x55\x8B\xEC", b"\x55\x89\xE5", b"\x48\x89\x5C\x24")
            scan_start = max(0, addr - 0x2000)
            for off in range(addr, scan_start, -1):
                data = self.client.read_memory(off, 8)
                if any(data.startswith(p) for p in prologue_patterns):
                    func_start = off
                    # Scan forward for RET
                    for foff in range(addr, addr + 0x8000):
                        b = self.client.read_memory(foff, 1)
                        if b == b"\xC3" or b == b"\xC2":
                            return func_start, foff + 1
                    return func_start, addr + 0x1000
        except Exception:
            pass
        return None

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

        size = 0
        try:
            fb = self.client.get_function(addr)
            if fb:
                size = fb.end - fb.start
        except Exception:
            pass

        node = _CallGraphNode(
            address=addr,
            name=name,
            module=mod_name,
            size=size,
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
        unresolved_indirect = 0

        while queue and len(self.nodes) < self.max_nodes:
            addr, depth = queue.popleft()
            if depth > max_depth_reached:
                max_depth_reached = depth
            if depth >= self.max_depth:
                continue

            bounds = self._get_function_bounds(addr)
            if bounds is None:
                continue
            func_start, func_end = bounds

            if addr in self.nodes and self.nodes[addr].size == 0:
                self.nodes[addr] = dataclasses.replace(
                    self.nodes[addr], size=func_end - func_start
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
                    unresolved_indirect += 1
                    pseudo_id = f"indirect_{addr:X}_{insn.address:X}"
                    pseudo_addr = hash(pseudo_id) & 0xFFFFFFFFFFFFFFFF
                    self._ensure_node(pseudo_addr, node_type="unresolved", name_hint=pseudo_id)
                    self.edges.append(
                        _CallGraphEdge(
                            source=addr,
                            target=pseudo_addr,
                            edge_type="unresolved",
                            instruction_address=insn.address,
                        )
                    )
                    continue

                if target is None:
                    continue

                # Respect max_nodes — skip new nodes when at limit
                if target not in self.nodes and len(self.nodes) >= self.max_nodes:
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

        return self._to_dict(start_addr, max_depth_reached, unresolved_indirect)

    # ── Serialization ─────────────────────────────────────────────────────

    def _to_dict(self, start_addr: int, max_depth: int, unresolved: int) -> dict:
        return {
            "start_node": f"0x{start_addr:X}",
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "max_depth_reached": max_depth,
            "unresolved_indirect_calls": unresolved,
            "nodes": [
                {
                    "id": f"0x{n.address:X}",
                    "address": f"0x{n.address:X}",
                    "name": n.name,
                    "module": n.module,
                    "size": n.size,
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
