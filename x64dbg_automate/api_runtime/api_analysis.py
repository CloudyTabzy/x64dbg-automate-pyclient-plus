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
    detect_function_bounds, disasm_instructions, is_potential_entry, resolve_addr,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

_XREF_TYPE_NAMES = {0: "NONE", 1: "DATA", 2: "JMP", 3: "CALL"}

# Memory constants for the scan-based xref fallback.
_MEM_COMMIT = 0x1000
_PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80  # EXECUTE | _READ | _READWRITE | _WRITECOPY
_PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80  # any readable protection
_XREF_SCAN_DEFAULT_MAX = 64 * 1024 * 1024  # 64 MiB scan ceiling
_ADDR_SCAN_DEFAULT_MAX = 128 * 1024 * 1024  # 128 MiB ceiling for pointer scan
_ADDR_SCAN_MAX_RESULTS = 50  # max pointer-ref hits before truncating


def _xref_name(t: int) -> str:
    return _XREF_TYPE_NAMES.get(t, f"UNKNOWN({t})")


def _scan_xrefs_to(client, target: int, arch: str, max_bytes: int = _XREF_SCAN_DEFAULT_MAX) -> tuple[list[dict], bool]:
    """Scan executable memory for direct rel32 CALL/JMP sites that target ``target``.

    This is the fallback the reviewer performed by hand (``memory_search_pattern``
    for ``E8 ?? ?? ?? ??`` + manual offset math). It finds only *direct* near
    call/jmp (E8/E9 rel32) references — indirect/register/memory-indirect targets
    can't be resolved statically. Each byte-level candidate is verified with the
    real disassembler so data bytes that merely look like E8/E9 are rejected.

    The module containing ``target`` is scanned fully regardless of ``max_bytes``;
    other executable pages are capped at ``max_bytes`` total. This prevents
    callers being missed when the target is in a large game image.

    Returns ``(refs, truncated)`` where ``truncated`` is True if non-target-module
    pages were cut short by the ``max_bytes`` ceiling.
    """
    mask = 0xFFFFFFFFFFFFFFFF if arch == "x64" else 0xFFFFFFFF

    # Identify the module that owns the target so we can scan it without a ceiling.
    target_mod_base = 0
    target_mod_size = 0
    try:
        for mod in client.get_modules():
            if mod.base <= target < mod.base + mod.size:
                target_mod_base = mod.base
                target_mod_size = mod.size
                break
    except Exception:
        pass

    try:
        pages = client.memmap()
    except Exception:
        return [], False

    refs: list[dict] = []
    scanned_other = 0
    truncated = False
    seen: set[int] = set()

    for page in pages:
        if (page.state & _MEM_COMMIT) == 0:
            continue
        if (page.protect & _PAGE_EXECUTE_ANY) == 0:
            continue
        size = page.region_size
        in_target_mod = (
            target_mod_size > 0
            and target_mod_base <= page.base_address < target_mod_base + target_mod_size
        )
        if not in_target_mod:
            # Apply the bytes ceiling only to non-target-module pages.
            remaining = max_bytes - scanned_other
            if remaining <= 0:
                truncated = True
                continue
            size = min(size, remaining)
        try:
            data = client.read_memory(page.base_address, size)
        except Exception:
            continue
        if not data:
            continue
        if not in_target_mod:
            scanned_other += len(data)

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


def _scan_pointer_refs_to(
    client,
    target: int,
    arch: str,
    max_bytes: int = _ADDR_SCAN_DEFAULT_MAX,
) -> list[dict]:
    """Scan all committed readable memory for the target address stored as a pointer.

    Finds vtable entries, dispatch tables, function pointer arrays, and indirect
    call stubs that hold the target's address as a DWORD (x86) or QWORD (x64) value.
    Complements the E8/E9 direct-call scan for functions reachable only via
    register-indirect or table-based dispatch.

    Each result includes ``type`` (``DATA_PTR`` for data pages, ``CODE_PTR`` for
    executable pages) so agents can distinguish vtable entries from call stubs.

    Returns up to ``_ADDR_SCAN_MAX_RESULTS`` matches.
    """
    ptr_size = 8 if arch == "x64" else 4
    try:
        target_bytes = target.to_bytes(ptr_size, "little")
    except OverflowError:
        return []

    try:
        pages = client.memmap()
    except Exception:
        return []

    refs: list[dict] = []
    scanned = 0

    for page in pages:
        if len(refs) >= _ADDR_SCAN_MAX_RESULTS:
            break
        if (page.state & _MEM_COMMIT) == 0:
            continue
        # Skip NOACCESS and GUARD pages
        low_prot = page.protect & 0xFF
        if low_prot in (0x00, 0x01) or (page.protect & 0x100):
            continue
        if (page.protect & _PAGE_READABLE) == 0 and (page.protect & _PAGE_EXECUTE_ANY) == 0:
            continue
        if scanned >= max_bytes:
            break

        size = min(page.region_size, max_bytes - scanned)
        if size > 16 * 1024 * 1024:  # skip individual pages > 16 MiB to stay fast
            size = 16 * 1024 * 1024
        try:
            data = client.read_memory(page.base_address, size)
        except Exception:
            continue
        if not data:
            continue
        scanned += len(data)

        is_exec = bool(page.protect & _PAGE_EXECUTE_ANY)
        ref_type = "CODE_PTR" if is_exec else "DATA_PTR"

        pos = 0
        while pos <= len(data) - ptr_size:
            i = data.find(target_bytes, pos)
            if i == -1:
                break
            abs_addr = page.base_address + i
            # Require pointer alignment to reduce false positives
            if abs_addr % ptr_size == 0:
                refs.append({
                    "address": f"0x{abs_addr:X}",
                    "type": ref_type,
                    "section": page.info or "",
                    "source": "addr_scan",
                })
                if len(refs) >= _ADDR_SCAN_MAX_RESULTS:
                    break
            pos = i + 1

    return refs


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
            "found by scanning executable memory. The target module was scanned fully; "
            "other loaded modules are subject to the scan ceiling."
        )

        # When direct scan finds nothing, scan all committed memory for the target
        # address stored as a pointer (vtable entries, dispatch tables, etc.).
        dispatch_refs: list[dict] = []
        if not refs:
            try:
                dispatch_refs = _scan_pointer_refs_to(client, addr, arch)
            except Exception:
                pass

        if not refs and not dispatch_refs:
            addr_bytes = addr.to_bytes(4 if arch != "x64" else 8, "little")
            notes.append(
                f"No direct or dispatch callers found for 0x{addr:X}. "
                "The function may be called via a computed register target (FF D0/FF D1) "
                "with no static pointer in memory. Consider setting a hardware execute "
                "breakpoint at the function and letting the debuggee run to catch callers "
                "dynamically."
            )
        elif not refs and dispatch_refs:
            notes.append(
                f"No direct CALL/JMP callers found; {len(dispatch_refs)} potential dispatch "
                "site(s) found where the function's address is stored as a pointer "
                "(vtable entries, function pointer arrays, import stubs). "
                "Inspect these sites to identify the actual call mechanism."
            )

        result = ok(
            sandbox_id=sandbox_id,
            address=f"0x{addr:X}",
            source="scan",
            xrefs=refs,
            total=len(refs),
            scan_truncated=truncated,
            notes=notes,
        )
        if dispatch_refs:
            result["dispatch_refs"] = dispatch_refs
            result["dispatch_refs_total"] = len(dispatch_refs)
        return result

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
    """Get the start/end (absolute VAs) of the function containing an address.

    Uses x64dbg's native analysis when it returns bounds that actually contain
    the queried address; otherwise falls back to the heuristic scanner (the same
    one `find_function_start`/`get_cfg` use) so a stale/mis-framed analysis DB no
    longer yields confidently-wrong bounds. Reports `method` and `confidence`.

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
        bounds = detect_function_bounds(client, addr)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    result = ok(
        sandbox_id=sandbox_id,
        address=f"0x{addr:X}",
        start=f"0x{bounds.start:X}",
        end=f"0x{bounds.end:X}",
        size=bounds.size,
        contains_query=bounds.start <= addr < bounds.end,
        method=bounds.method,
        confidence=bounds.confidence,
        **_module_rva(client, bounds.start),
    )
    if bounds.note:
        result["note"] = bounds.note

    # Nesting check: when the queried address is interior to the outer function
    # AND looks like its own entry point, report it as an inner callable so the
    # agent can target the right function boundary for decompilation/xrefs.
    if addr != bounds.start and bounds.start < addr < bounds.end:
        try:
            if is_potential_entry(client, addr):
                from x64dbg_automate.api_runtime.runtime_helpers import _find_end_from
                inner_end = _find_end_from(client, addr)
                result["inner_callable"] = {
                    "start": f"0x{addr:X}",
                    "end": f"0x{inner_end:X}",
                    "size": max(0, inner_end - addr),
                    "confidence": "low",
                    "note": (
                        "The queried address has a function prologue / post-padding "
                        "signature and may be a distinct inner callable nested within "
                        f"the outer function at 0x{bounds.start:X}. Use this start for "
                        "xref lookups targeting this specific subroutine."
                    ),
                }
        except Exception:
            pass

    return result


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

    # ── Section / protection from the (cached) live memory map ─────────────
    from x64dbg_automate.api_runtime.runtime_helpers import region_info
    region = region_info(mgr, sandbox_id, addr)
    if region is not None:
        result.update(region)

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


def _module_rva(client, addr: int) -> dict:
    """Best-effort {module, module_rva} for an absolute VA (empty dict on failure)."""
    try:
        for m in client.get_modules():
            if m.base <= addr < m.base + m.size:
                return {"module": m.name, "module_rva": f"0x{addr - m.base:X}"}
    except Exception:
        pass
    return {}


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
        **_module_rva(client, bounds.start),
    )
    if bounds.note:
        result["note"] = bounds.note

    # Same nesting check as get_function_boundaries.
    if addr != bounds.start and bounds.start < addr < bounds.end:
        try:
            if is_potential_entry(client, addr):
                from x64dbg_automate.api_runtime.runtime_helpers import _find_end_from
                inner_end = _find_end_from(client, addr)
                result["inner_callable"] = {
                    "start": f"0x{addr:X}",
                    "end": f"0x{inner_end:X}",
                    "size": max(0, inner_end - addr),
                    "confidence": "low",
                    "note": (
                        "The queried address has a function prologue / post-padding "
                        "signature and may be a distinct inner callable nested within "
                        f"the outer function at 0x{bounds.start:X}."
                    ),
                }
        except Exception:
            pass

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


def _disasm_map(client, start: int, size: int, arch: str) -> dict[int, dict]:
    """Disassemble [start, start+size) once → {addr: {bytes, mnemonic}}.

    x64dbg's analyze_function returns instruction "bytes" in a serialized form
    that isn't raw opcodes (it embeds addresses), so the CFG bytes were garbage.
    We instead read real memory and disassemble it, then look up each block's
    instructions by address — accurate bytes + mnemonics, and consistent with
    the Capstone fallback path.
    """
    if size <= 0 or size > 0x20000:
        size = min(max(size, 0x40), 0x20000)
    try:
        data = client.read_memory(start, size)
    except Exception:
        return {}
    if not data:
        return {}
    from x64dbg_automate.external.decompiler import disassemble_bytes
    out: dict[int, dict] = {}
    try:
        for i in disassemble_bytes(data, start, arch):
            out[i.address] = {
                "bytes": i.bytes.hex(),
                "mnemonic": (i.mnemonic + (" " + i.raw_op_str if i.raw_op_str else "")).strip(),
            }
    except Exception:
        return out
    return out


def _cfg_from_x64dbg(cfg: dict, dmap: dict[int, dict]) -> dict:
    """Convert x64dbg's analyze_function result into the unified CFG shape.

    Block topology comes from x64dbg (superior boundaries); instruction bytes /
    mnemonics come from ``dmap`` (real disassembly) rather than x64dbg's bogus
    serialized bytes.
    """
    blocks = []
    edges = []
    for n in cfg["nodes"]:
        start = n["start"]
        succ = []
        brtrue, brfalse = n.get("brtrue"), n.get("brfalse")
        if brtrue:
            succ.append(brtrue)
            edges.append({"from": f"0x{start:X}", "to": f"0x{brtrue:X}",
                          "type": "branch_taken" if brfalse else "jump"})
        if brfalse:
            succ.append(brfalse)
            edges.append({"from": f"0x{start:X}", "to": f"0x{brfalse:X}", "type": "fallthrough"})
        for e in n.get("exits", []):
            if e not in (brtrue, brfalse):
                succ.append(e)
                edges.append({"from": f"0x{start:X}", "to": f"0x{e:X}", "type": "exit"})
        instructions = []
        for ins in n["instructions"]:
            ia = ins["address"]
            entry = dmap.get(ia)
            item = {"address": f"0x{ia:X}"}
            if entry:
                item["bytes"] = entry["bytes"]
                item["mnemonic"] = entry["mnemonic"]
            instructions.append(item)
        blocks.append({
            "start": f"0x{start:X}",
            "end": f"0x{n['end']:X}",
            "instruction_count": n["instruction_count"],
            "terminal": n["terminal"],
            "indirect_call": n.get("indirect_call", False),
            "successors": [f"0x{s:X}" for s in succ],
            "instructions": instructions,
        })
    return {"blocks": blocks, "edges": edges}


def _cfg_from_capstone(client, bounds, arch: str) -> dict | None:
    """Build a CFG by disassembling [start,end) with Capstone — used when x64dbg
    analysis is unavailable. Returns None if the bytes can't be read."""
    from x64dbg_automate.external.decompiler import build_cfg, disassemble_bytes

    size = bounds.size
    if size <= 0 or size > 0x20000:
        size = min(max(size, 0x40), 0x20000)
    try:
        data = client.read_memory(bounds.start, size)
    except Exception:
        return None
    if not data:
        return None
    insns = disassemble_bytes(data, bounds.start, arch)
    if not insns:
        return None
    cfg = build_cfg(insns, bounds.start)

    blocks = []
    edges = []
    for start in sorted(cfg.blocks):
        blk = cfg.blocks[start]
        last = blk.last_insn
        if last is None:
            terminator = "empty"
        elif last.is_ret:
            terminator = "ret"
        elif last.is_jump:
            terminator = "jmp"
        elif last.is_cond_jump:
            terminator = "cond_jump"
        elif last.is_call:
            terminator = "call"
        else:
            terminator = "fallthrough"
        for s in blk.successors:
            etype = "fallthrough"
            if terminator == "jmp":
                etype = "jump"
            elif terminator == "cond_jump":
                etype = "branch_taken" if s != (last.address + last.size) else "fallthrough"
            edges.append({"from": f"0x{start:X}", "to": f"0x{s:X}", "type": etype})
        blocks.append({
            "start": f"0x{start:X}",
            "end": f"0x{blk.end:X}",
            "instruction_count": len(blk.instructions),
            "terminal": (last.is_ret if last else False),
            "terminator": terminator,
            "successors": [f"0x{s:X}" for s in blk.successors],
            "predecessors": [f"0x{p:X}" for p in blk.predecessors],
            "instructions": [
                {"address": f"0x{i.address:X}", "bytes": i.bytes.hex(),
                 "mnemonic": (i.mnemonic + (" " + i.raw_op_str if i.raw_op_str else "")).strip()}
                for i in blk.instructions
            ],
        })
    return {"blocks": blocks, "edges": edges}


def _detect_loops(blocks: list[dict], edges: list[dict]) -> list[dict]:
    """Identify back-edges (target address <= source block start) as loop markers."""
    starts = {b["start"] for b in blocks}
    loops = []
    for e in edges:
        try:
            if e["to"] in starts and int(e["to"], 16) <= int(e["from"], 16):
                loops.append({"header": e["to"], "back_edge_from": e["from"]})
        except Exception:
            continue
    return loops


@tool
def get_cfg(*, sandbox_id: str | None = None, address: str) -> dict:
    """Return the control-flow graph (basic blocks + edges) of a function.

    Reliable on un-analyzed images: tries x64dbg's native analysis first
    (``confidence=high``), and if that hasn't run, falls back to a Capstone
    basic-block reconstruction over the heuristically detected function bounds
    (``confidence=medium``). Gives an agent the structure needed to reason about
    large functions instead of a flat instruction stream.

    Args:
        sandbox_id: Sandbox to query.
        address: Any address inside the function (entry preferred; address,
                 symbol, or expression).

    Returns ``blocks`` (start/end/instructions/successors/terminator), ``edges``
    (from/to/type), ``loops`` (back-edges), plus ``method`` and ``confidence``.
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
    entry = bounds.start

    # 1. Native x64dbg analysis (authoritative when available).
    cfg_data = None
    method = None
    confidence = None
    try:
        native = client.analyze_function(entry)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        native = None
    if native and native.get("nodes"):
        nodes = native["nodes"]
        span_start = min(n["start"] for n in nodes)
        span_end = max(n["end"] for n in nodes)
        arch = "x64"
        try:
            arch = mgr.get_sandbox(sandbox_id).debugger_arch or "x64"
        except Exception:
            pass
        dmap = _disasm_map(client, span_start, span_end - span_start + 16, arch)
        cfg_data = _cfg_from_x64dbg(native, dmap)
        method, confidence = "x64dbg", "high"

    # 2. Capstone fallback over the detected bounds.
    if cfg_data is None:
        arch = "x64"
        try:
            sb = mgr.get_sandbox(sandbox_id)
            arch = sb.debugger_arch or "x64"
        except Exception:
            pass
        cfg_data = _cfg_from_capstone(client, bounds, arch)
        method, confidence = "capstone_fallback", "medium"

    if not cfg_data:
        return err(
            f"Could not build a CFG for the function at 0x{entry:X}.",
            ErrorType.INVALID_STATE,
            hint="The code bytes may be unreadable, or the address isn't code.",
            sandbox_id=sandbox_id,
        )

    loops = _detect_loops(cfg_data["blocks"], cfg_data["edges"])
    return ok(
        sandbox_id=sandbox_id,
        entry_point=f"0x{entry:X}",
        function_start=f"0x{bounds.start:X}",
        function_end=f"0x{bounds.end:X}",
        method=method,
        confidence=confidence,
        block_count=len(cfg_data["blocks"]),
        edge_count=len(cfg_data["edges"]),
        blocks=cfg_data["blocks"],
        edges=cfg_data["edges"],
        loops=loops,
    )


@tool
def analyze_function_cfg(*, sandbox_id: str | None = None, address: str) -> dict:
    """Analyze a function and return its control flow graph (CFG).

    Backwards-compatible alias for ``get_cfg`` (the runtime equivalent of IDA's
    graph view). Prefer ``get_cfg`` for new code — it also works on un-analyzed
    images via a Capstone fallback and reports method/confidence.
    """
    return get_cfg(sandbox_id=sandbox_id, address=address)


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
def refresh_modules(
    sandbox_id: str | None = None,
    wait_for: str = "",
    timeout_sec: float = 5.0,
) -> dict:
    """Refresh the module list and optionally wait for a specific module to appear.

    The live module list is always fetched fresh from x64dbg — no local cache
    needs clearing. Pass ``wait_for`` to poll until a module whose name or path
    contains that string (case-insensitive) is loaded.

    Typical workflow for ASI / plugin modules::

        sandbox_continue()                          # resume past system breakpoint
        refresh_modules(wait_for="SilentPatch", timeout_sec=10)  # wait for the ASI

    Args:
        sandbox_id: Sandbox to refresh (omit for active session).
        wait_for: Module name fragment to wait for (case-insensitive; omit to
                  return immediately).
        timeout_sec: Maximum seconds to poll when ``wait_for`` is set (default 5).
    """
    import time as _time

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    def _fetch():
        try:
            return client.get_modules()
        except Exception as exc:
            if is_bug(exc):
                raise
            return []

    def _to_list(modules):
        return [
            {"base": f"0x{m.base:X}", "size": m.size, "entry": f"0x{m.entry:X}",
             "name": m.name, "path": m.path, "section_count": m.section_count}
            for m in modules
        ]

    if not wait_for.strip():
        modules = _fetch()
        return ok(sandbox_id=sandbox_id, modules=_to_list(modules), total=len(modules))

    target = wait_for.strip().lower()
    deadline = _time.monotonic() + max(0.1, timeout_sec)
    found_mod = None
    while _time.monotonic() < deadline:
        modules = _fetch()
        for m in modules:
            if target in m.name.lower() or target in (m.path or "").lower():
                found_mod = m
                break
        if found_mod is not None:
            break
        _time.sleep(0.25)

    if found_mod is None:
        modules = _fetch()
        return ok(
            sandbox_id=sandbox_id,
            modules=_to_list(modules),
            total=len(modules),
            waited_for=wait_for,
            found=False,
            note=f"Module matching '{wait_for}' did not appear within {timeout_sec}s. "
                 "Ensure the debuggee has been resumed past the point where the module loads.",
        )

    modules = _fetch()
    return ok(
        sandbox_id=sandbox_id,
        modules=_to_list(modules),
        total=len(modules),
        waited_for=wait_for,
        found=True,
        found_module={
            "base": f"0x{found_mod.base:X}",
            "size": found_mod.size,
            "name": found_mod.name,
            "path": found_mod.path,
        },
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
def enumerate_exception_handlers(sandbox_id: str | None = None) -> dict:
    """Enumerate active exception handlers in the debuggee process.

    Returns two sections:

    **SEH** (x86 only) — the Structured Exception Handling chain for the
    current thread, walked from ``FS:[0]``. Each record contains the frame
    address and handler function address (resolved to a symbol when available).

    **VEH** — the Vectored Exception Handler list in ntdll, walked from
    ``ntdll!LdrpVectorHandlerList``. This private symbol requires ntdll PDB
    symbols to be loaded in x64dbg. If the symbol can't be resolved, a hint is
    returned. On Windows Vista+, handler addresses are RtlEncodePointer-encoded
    (XOR + rotate with a per-process cookie) and cannot be decoded without the
    cookie from ntdll.

    Args:
        sandbox_id: Sandbox to inspect (omit for active session).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    arch = "x64"
    try:
        sb = mgr.get_sandbox(sandbox_id)
        arch = sb.debugger_arch or "x64"
    except Exception:
        pass

    # ── SEH chain ─────────────────────────────────────────────────────────────
    seh_records: list[dict] = []
    seh_note: str | None = None

    if arch == "x64":
        seh_note = (
            "SEH chain walk (FS:[0]) is x86-only. x64 uses table-based SEH "
            "defined in the PE exception directory — no runtime linked list exists."
        )
    else:
        try:
            records = client.get_seh_chain()
            for r in records:
                sym = None
                try:
                    s = client.get_symbol_at(r.handler)
                    if s:
                        sym = s.undecoratedSymbol or s.decoratedSymbol
                except Exception:
                    pass
                seh_records.append({
                    "address": f"0x{r.address:X}",
                    "handler": f"0x{r.handler:X}",
                    "symbol": sym,
                })
        except Exception:
            seh_note = "SEH chain could not be read."

    # ── VEH list ──────────────────────────────────────────────────────────────
    veh_handlers: list[dict] = []
    veh_list_head: int = 0
    veh_note: str | None = None

    # LdrpVectorHandlerList is a non-exported internal ntdll variable.
    # It only resolves if the ntdll PDB is loaded in x64dbg.
    for sym_expr in ("ntdll:LdrpVectorHandlerList", "ntdll.LdrpVectorHandlerList"):
        try:
            val, success = client.eval_sync(sym_expr)
            if success and val:
                veh_list_head = val
                break
        except Exception:
            pass

    if veh_list_head:
        # Node layout: [Flink:ptr][Blink:ptr][Refs:ULONG][pad?][Handler_encoded:ptr]
        # x86: Flink(4)+Blink(4)+Refs(4) = 12 before Handler
        # x64: Flink(8)+Blink(8)+Refs(4)+pad(4) = 24 before Handler
        ptr_size = 4 if arch == "x32" else 8
        handler_offset = 12 if arch == "x32" else 24
        max_nodes = 64
        seen: set[int] = {veh_list_head}
        try:
            raw = client.read_memory(veh_list_head, ptr_size)
            flink = int.from_bytes(raw, "little") if raw else 0
            while flink and flink not in seen and len(veh_handlers) < max_nodes:
                seen.add(flink)
                if flink == veh_list_head:
                    break
                handler_raw = client.read_memory(flink + handler_offset, ptr_size)
                handler_enc = int.from_bytes(handler_raw, "little") if handler_raw else 0
                sym_name = None
                # Encoded pointer probably won't resolve, but try cheaply.
                try:
                    s = client.get_symbol_at(handler_enc)
                    if s and (s.undecoratedSymbol or s.decoratedSymbol):
                        sym_name = s.undecoratedSymbol or s.decoratedSymbol
                except Exception:
                    pass
                veh_handlers.append({
                    "node_address": f"0x{flink:X}",
                    "handler_encoded": f"0x{handler_enc:X}",
                    "symbol_guess": sym_name,
                })
                next_raw = client.read_memory(flink, ptr_size)
                flink = int.from_bytes(next_raw, "little") if next_raw else 0
        except Exception:
            veh_note = "VEH list walk interrupted — partial results returned."

        if not veh_note:
            veh_note = (
                "Handler pointers are RtlEncodePointer-encoded on Windows Vista+ "
                "(XOR + _rotr3 with a per-process cookie stored in ntdll). "
                "To decode: read the cookie from ntdll!RtlpProcessHeapKey and "
                "apply: handler = _rotl(encoded_ptr ^ cookie, 3)."
            )
    else:
        veh_note = (
            "ntdll!LdrpVectorHandlerList could not be resolved — ntdll PDB symbols "
            "are not loaded. In x64dbg: Options → Preferences → Symbols, enable "
            "symbol server, then run 'sym ntdll' in the command bar. Alternatively, "
            "use a hardware execute breakpoint at RtlAddVectoredExceptionHandler to "
            "catch VEH registrations dynamically."
        )

    return ok(
        sandbox_id=sandbox_id,
        arch=arch,
        seh={
            "records": seh_records,
            "count": len(seh_records),
            "note": seh_note,
        },
        veh={
            "list_head": f"0x{veh_list_head:X}" if veh_list_head else None,
            "handlers": veh_handlers,
            "count": len(veh_handlers),
            "note": veh_note,
        },
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

    if result["total_nodes"] == 1 and result["total_edges"] == 0:
        result.setdefault("notes", []).append(
            "Isolated call graph — no outgoing calls were resolved. "
            "The function likely uses indirect dispatch (FF D0/FF D1 register calls, "
            "vtable, or computed targets). Use get_xrefs to find callers TO this "
            "function, or disassemble_function to inspect the call pattern manually."
        )

    return ok(sandbox_id=sandbox_id, **result)
