"""Semantic memory tools: typed struct reads, entropy discovery, IAT resolution, diffs.

Turns ``read_memory(addr, size)`` raw-byte access into interpretable queries an agent
can reason about.
"""

from __future__ import annotations

import time

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, is_bug, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import capture_registers, diff_bytes, disasm_instructions, resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.api_runtime.utils import parse_region
from x64dbg_automate.external.entropy import shannon_entropy
from x64dbg_automate.external.pattern_scanner import scan_pattern

# Fixed-layout struct field tables: name -> (byte offset, type). "ptr" is arch-sized.
_PEB_FIELDS = {
    "x64": [("BeingDebugged", 0x02, "u8"), ("ImageBaseAddress", 0x10, "ptr"),
            ("Ldr", 0x18, "ptr"), ("ProcessParameters", 0x20, "ptr"),
            ("ProcessHeap", 0x30, "ptr"), ("NtGlobalFlag", 0xBC, "u32")],
    "x32": [("BeingDebugged", 0x02, "u8"), ("ImageBaseAddress", 0x08, "ptr"),
            ("Ldr", 0x0C, "ptr"), ("ProcessParameters", 0x10, "ptr"),
            ("ProcessHeap", 0x18, "ptr"), ("NtGlobalFlag", 0x68, "u32")],
}
_TEB_FIELDS = {
    "x64": [("StackBase", 0x08, "ptr"), ("StackLimit", 0x10, "ptr"),
            ("ThreadLocalStoragePointer", 0x58, "ptr"),
            ("ProcessEnvironmentBlock", 0x60, "ptr"), ("LastErrorValue", 0x68, "u32")],
    "x32": [("StackBase", 0x04, "ptr"), ("StackLimit", 0x08, "ptr"),
            ("ThreadLocalStoragePointer", 0x2C, "ptr"),
            ("ProcessEnvironmentBlock", 0x30, "ptr"), ("LastErrorValue", 0x34, "u32")],
}
_FIXED_SCHEMAS = {"peb": _PEB_FIELDS, "teb": _TEB_FIELDS}
_AUTO_BASE_EXPR = {"peb": "peb()", "teb": "teb()"}
_AVAILABLE_SCHEMAS = sorted(list(_FIXED_SCHEMAS) + ["rc4_state"])

_TYPE_SIZES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}


def _read_fixed_struct(client, base: int, fields: list[tuple[str, int, str]], ptr_size: int) -> dict:
    span = max(off + (ptr_size if typ == "ptr" else _TYPE_SIZES[typ]) for _, off, typ in fields)
    blob = client.read_memory(base, span)
    out: dict[str, str | int | bool] = {}
    for name, off, typ in fields:
        size = ptr_size if typ == "ptr" else _TYPE_SIZES[typ]
        raw = blob[off:off + size]
        val = int.from_bytes(raw, "little")
        if typ == "u8" and name == "BeingDebugged":
            out[name] = bool(val)
        elif typ in ("ptr",) or size >= 4:
            out[name] = f"0x{val:X}"
        else:
            out[name] = val
    return out


@tool
def read_struct(*, sandbox_id: str | None = None, schema: str, address: str = "") -> dict:
    """Read memory as a named structure with labeled fields.

    Built-in schemas: 'peb', 'teb' (address auto-resolved if omitted), and 'rc4_state'
    (256-byte S-box at the given address; reports whether it is still an identity
    permutation). Layout is selected automatically for the sandbox's architecture.

    Args:
        sandbox_id: Sandbox to read from.
        schema: One of the built-in schema names.
        address: Base address (optional for peb/teb; required for rc4_state).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    sandbox = mgr.get_sandbox(sandbox_id)
    arch = sandbox.debugger_arch
    ptr_size = 8 if arch == "x64" else 4
    schema = (schema or "").strip().lower()

    try:
        if schema in _FIXED_SCHEMAS:
            if address.strip():
                base = resolve_addr(client, address)
            else:
                base, success = client.eval_sync(_AUTO_BASE_EXPR[schema])
                if not success or not base:
                    return err(f"Could not auto-resolve {schema} base.", ErrorType.NOT_FOUND,
                               hint="Pass an explicit address.", sandbox_id=sandbox_id)
            fields = _read_fixed_struct(client, base, _FIXED_SCHEMAS[schema][arch], ptr_size)
            return ok(sandbox_id=sandbox_id, schema=schema, base=f"0x{base:X}", arch=arch, fields=fields)

        if schema == "rc4_state":
            if not address.strip():
                return err("rc4_state requires an address.", ErrorType.BAD_ARGUMENT)
            base = resolve_addr(client, address)
            data = client.read_memory(base, 256)
            is_identity = data == bytes(range(256))
            is_permutation = sorted(data) == list(range(256))
            return ok(
                sandbox_id=sandbox_id, schema=schema, base=f"0x{base:X}",
                is_identity=is_identity, is_valid_permutation=is_permutation,
                sbox=to_hex(data),
            )
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return err(f"Unknown schema '{schema}'.", ErrorType.BAD_ARGUMENT,
               hint=f"Available schemas: {', '.join(_AVAILABLE_SCHEMAS)}.")


@tool
def find_initialized_data(
    sandbox_id: str | None = None,
    min_entropy: float = 4.0,
    max_regions: int = 50,
    sample_bytes: int = 65536,
) -> dict:
    """Find committed memory regions holding high-entropy initialized data (tables/keys/buffers).

    Samples each committed, readable region and ranks by Shannon entropy. Skips uniform
    (all-zero / all-0xFF) regions. Great for locating where runtime tables live.

    Args:
        sandbox_id: Sandbox to scan.
        min_entropy: Minimum Shannon entropy (0–8) to include a region.
        max_regions: Cap on returned candidates.
        sample_bytes: Bytes to sample from the start of each region for entropy.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        mgr.ensure_stopped(client)
        pages = client.memmap()
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    candidates: list[dict] = []
    for page in pages:
        if page.state != 0x1000:  # MEM_COMMIT
            continue
        low = page.protect & 0xFF
        if low in (0x00, 0x01):  # NOACCESS / undefined
            continue
        if page.protect & 0x100:  # PAGE_GUARD
            continue
        sample = min(sample_bytes, page.region_size)
        try:
            data = client.read_memory(page.base_address, sample)
        except Exception:
            continue
        if not data or data.count(data[0]) == len(data):  # uniform
            continue
        ent = shannon_entropy(data)
        if ent < min_entropy:
            continue
        candidates.append({
            "address": f"0x{page.base_address:X}",
            "region_size": page.region_size,
            "sampled": len(data),
            "entropy": round(ent, 4),
            "protect": f"0x{page.protect:X}",
            "info": page.info,
        })

    candidates.sort(key=lambda c: c["entropy"], reverse=True)
    truncated = len(candidates) > max_regions
    return ok(
        sandbox_id=sandbox_id,
        min_entropy=min_entropy,
        regions=candidates[:max_regions],
        total=len(candidates),
        truncated=truncated,
    )


@tool
def resolve_iat_slot(*, sandbox_id: str | None = None, address: str) -> dict:
    """Resolve an import-address-table slot to the function it points at.

    Reads the pointer stored at the slot and resolves the target's symbol/module.

    Args:
        sandbox_id: Sandbox to read from.
        address: IAT slot address (e.g. '0x7FF6A0002000').
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    sandbox = mgr.get_sandbox(sandbox_id)

    try:
        slot = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    try:
        target = client.read_qword(slot) if sandbox.debugger_arch == "x64" else client.read_dword(slot)
        symbol = None
        decorated = None
        try:
            sym = client.get_symbol_at(target)
            if sym:
                symbol = sym.undecoratedSymbol or sym.decoratedSymbol
                decorated = sym.decoratedSymbol
        except Exception:
            pass
        module = None
        page = client.virt_query(target)
        if page is not None:
            module = page.info
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(
        sandbox_id=sandbox_id,
        slot=f"0x{slot:X}",
        target_address=f"0x{target:X}",
        target_symbol=symbol,
        target_decorated=decorated,
        target_module=module,
    )


@tool
def memory_search_pattern(*, sandbox_id: str | None = None, address: str, size: int, pattern: str) -> dict:
    """Search a sandbox memory region for a hex byte pattern with ?? wildcards.

    Example pattern: '55 8B EC' or 'E8 ?? ?? ?? ?? 83 C4 04'.

    Args:
        sandbox_id: Sandbox to search.
        address: Region start (address, symbol, or expression).
        size: Region length in bytes.
        pattern: Hex byte pattern; '??' matches any byte.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        base = resolve_addr(client, address)
        data = client.read_memory(base, size)
        offsets = scan_pattern(data, pattern)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    matches = [f"0x{base + off:X}" for off in offsets[:200]]
    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{base:X}",
        size=size,
        pattern=pattern,
        matches=matches,
        total=len(offsets),
        truncated=len(offsets) > len(matches),
    )


@tool
def read_memory_range(
    *,
    sandbox_id: str | None = None,
    address: str,
    size: int,
    chunk_size: int = 65536,
    offset: int = 0,
) -> dict:
    """Read a large memory region in one call, returning hex-encoded chunks.

    Designed for reading multi-MB regions (large sections ~10 MB) without
    the 4096-byte cap of the legacy ``read_memory`` tool. Reads are done in
    ``chunk_size``-byte pieces and reassembled.

    Args:
        sandbox_id: Sandbox to read from.
        address: Region start (address, symbol, or expression).
        size: Total bytes to read (max 64 MiB).
        chunk_size: Internal read chunk (default 64 KiB; reduce if hitting RPC timeouts).
        offset: Skip this many bytes from the start before returning data (for pagination).
    """
    _MAX_READ = 64 * 1024 * 1024  # 64 MiB hard cap

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        base = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    if size <= 0:
        return err("size must be > 0.", ErrorType.BAD_ARGUMENT)
    if size > _MAX_READ:
        return err(f"size exceeds 64 MiB limit ({size} bytes requested).", ErrorType.BAD_ARGUMENT,
                   hint="Use paginated reads with offset to read sections incrementally.")

    chunk_size = max(256, min(chunk_size, 4 * 1024 * 1024))

    try:
        mgr.ensure_stopped(client)
        buf = bytearray()
        pos = 0
        failed_chunks: list[str] = []
        while pos < size:
            this = min(chunk_size, size - pos)
            try:
                data = client.read_memory(base + pos, this)
                buf.extend(data)
                pos += len(data)
                if len(data) < this:
                    break  # short read — likely hit unmapped page
            except Exception:
                # Unreadable sub-region — fill with zeros and continue.
                buf.extend(b"\x00" * this)
                failed_chunks.append(f"0x{base + pos:X}+{this:#x}")
                pos += this
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    payload = bytes(buf)
    if offset:
        payload = payload[offset:]

    result = ok(
        sandbox_id=sandbox_id,
        address=f"0x{base:X}",
        requested=size,
        read=len(buf),
        offset=offset,
        returned=len(payload),
        hex=payload.hex(),
    )
    if failed_chunks:
        result["unreadable_chunks"] = failed_chunks
    return result


@tool
def memory_diff(*, sandbox_id: str | None = None, checkpoint_a: str, checkpoint_b: str, region: str = "") -> dict:
    """Compare the captured memory of two checkpoints in a sandbox.

    Diffs the regions captured by both checkpoints (see sandbox_checkpoint). Optionally
    restrict to a single 'addr:size' region.

    Args:
        sandbox_id: Sandbox holding the checkpoints.
        checkpoint_a: First checkpoint name.
        checkpoint_b: Second checkpoint name.
        region: Optional 'addr:size' to restrict the comparison.
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)

    cp_a = sandbox.checkpoints.get(checkpoint_a)
    cp_b = sandbox.checkpoints.get(checkpoint_b)
    if cp_a is None or cp_b is None:
        missing = checkpoint_a if cp_a is None else checkpoint_b
        return err(f"No checkpoint '{missing}'.", ErrorType.NOT_FOUND,
                   hint="Use sandbox_info to list checkpoints.", sandbox_id=sandbox_id)

    only_addr = None
    if region.strip():
        try:
            only_addr, _ = parse_region(region)
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)

    shared = sorted(set(cp_a.memory) & set(cp_b.memory))
    region_diffs: list[dict] = []
    for addr in shared:
        if only_addr is not None and addr != only_addr:
            continue
        before, after = cp_a.memory[addr], cp_b.memory[addr]
        runs = diff_bytes(before, after)
        region_diffs.append({
            "address": f"0x{addr:X}",
            "size": min(len(before), len(after)),
            "changed_runs": len(runs),
            "diffs": runs,
        })

    reg_changes = {
        name: {"a": f"0x{cp_a.registers[name]:X}", "b": f"0x{cp_b.registers.get(name, 0):X}"}
        for name in cp_a.registers
        if name in cp_b.registers and cp_a.registers[name] != cp_b.registers[name]
    }

    return ok(
        sandbox_id=sandbox_id,
        checkpoint_a=checkpoint_a,
        checkpoint_b=checkpoint_b,
        region_diffs=region_diffs,
        register_changes=reg_changes,
    )


@tool
def checkpoint_diff(
    *,
    sandbox_id: str | None = None,
    checkpoint_a: str,
    checkpoint_b: str,
) -> dict:
    """Produce a full structured semantic diff between two checkpoints.

    Compares every observable dimension captured by ``sandbox_checkpoint``:
    GP registers, auto-captured memory (stack + instruction window), thread
    lifecycle, module loads/unloads, breakpoint hit counts, applied patches,
    and PEB anti-debug flags.

    The ``summary`` field gives a one-line human-readable synopsis suitable for
    agent reasoning ("2 registers changed (rax, rcx); 48 stack bytes differ;
    1 thread added; ntdll.dll loaded").

    Args:
        sandbox_id: Sandbox holding both checkpoints.
        checkpoint_a: Name of the 'before' checkpoint.
        checkpoint_b: Name of the 'after' checkpoint.
    """
    _t0 = time.perf_counter()

    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)

    cp_a = sandbox.checkpoints.get(checkpoint_a)
    cp_b = sandbox.checkpoints.get(checkpoint_b)
    if cp_a is None or cp_b is None:
        missing = checkpoint_a if cp_a is None else checkpoint_b
        return err(f"No checkpoint '{missing}'.", ErrorType.NOT_FOUND,
                   hint="Use sandbox_info to list checkpoints.", sandbox_id=sandbox_id)

    arch = cp_a.arch
    sp_key = "rsp" if arch == "x64" else "esp"
    ip_key = "rip" if arch == "x64" else "eip"

    # --- Registers ---
    reg_changed = []
    for name in sorted(set(cp_a.registers) | set(cp_b.registers)):
        va = cp_a.registers.get(name, 0)
        vb = cp_b.registers.get(name, 0)
        if va != vb:
            delta = vb - va
            sign = "+" if delta >= 0 else "-"
            reg_changed.append({
                "name": name,
                "before": f"0x{va:X}",
                "after": f"0x{vb:X}",
                "delta": f"{sign}0x{abs(delta):X}",
            })
    reg_unchanged = max(0, len(cp_a.registers) - len(reg_changed))

    # --- Memory (label auto-captured regions by their source) ---
    sp_a = cp_a.registers.get(sp_key, 0)
    ip_a = cp_a.registers.get(ip_key, 0)

    def _region_label(addr: int) -> str:
        if sp_a and addr == sp_a:
            return "stack"
        if ip_a and abs(addr - max(0, ip_a - 16)) <= 4:
            return "instruction_window"
        return f"0x{addr:X}"

    region_diffs = []
    total_changed_bytes = 0
    for addr in sorted(set(cp_a.memory) & set(cp_b.memory)):
        before, after = cp_a.memory[addr], cp_b.memory[addr]
        runs = diff_bytes(before, after)
        changed = sum(len(r["before"]) // 2 for r in runs)
        total_changed_bytes += changed
        region_diffs.append({
            "address": f"0x{addr:X}",
            "label": _region_label(addr),
            "size": min(len(before), len(after)),
            "changed_bytes": changed,
            "diffs": runs,
        })

    # --- Threads ---
    tids_a = {t["thread_id"] for t in cp_a.threads_snapshot}
    tids_b = {t["thread_id"] for t in cp_b.threads_snapshot}
    by_id_a = {t["thread_id"]: t for t in cp_a.threads_snapshot}
    by_id_b = {t["thread_id"]: t for t in cp_b.threads_snapshot}

    threads_added = [by_id_b[tid] for tid in sorted(tids_b - tids_a)]
    threads_removed = [by_id_a[tid] for tid in sorted(tids_a - tids_b)]
    cip_changed = [
        {"thread_id": tid,
         "cip_before": f"0x{by_id_a[tid]['cip']:X}",
         "cip_after": f"0x{by_id_b[tid]['cip']:X}"}
        for tid in sorted(tids_a & tids_b)
        if by_id_a[tid]["cip"] != by_id_b[tid]["cip"]
    ]

    # --- Modules ---
    bases_a = {m["base"] for m in cp_a.modules_snapshot}
    bases_b = {m["base"] for m in cp_b.modules_snapshot}
    by_base_b = {m["base"]: m for m in cp_b.modules_snapshot}
    by_base_a = {m["base"]: m for m in cp_a.modules_snapshot}
    modules_loaded = [by_base_b[b] for b in sorted(bases_b - bases_a)]
    modules_unloaded = [by_base_a[b] for b in sorted(bases_a - bases_b)]

    # --- Breakpoints ---
    def _bp_key(bp: dict) -> tuple:
        return (bp["addr"], bp["type"])

    bps_a = {_bp_key(bp): bp for bp in cp_a.breakpoints_snapshot}
    bps_b = {_bp_key(bp): bp for bp in cp_b.breakpoints_snapshot}
    bps_added = [bps_b[k] for k in sorted(bps_b.keys() - bps_a.keys())]
    bps_removed = [bps_a[k] for k in sorted(bps_a.keys() - bps_b.keys())]
    hit_count_changed = [
        {"addr": f"0x{bps_a[k]['addr']:X}", "name": bps_a[k]["name"], "type": bps_a[k]["type"],
         "hit_count_before": bps_a[k]["hit_count"], "hit_count_after": bps_b[k]["hit_count"]}
        for k in sorted(bps_a.keys() & bps_b.keys())
        if bps_a[k]["hit_count"] != bps_b[k]["hit_count"]
    ]

    # --- Patches ---
    addrs_a = {p.get("address", p.get("addr")) for p in cp_a.patches_snapshot}
    patches_added = [
        p for p in cp_b.patches_snapshot
        if p.get("address", p.get("addr")) not in addrs_a
    ]

    # --- PEB ---
    peb_section = None
    if cp_a.peb_snapshot is not None and cp_b.peb_snapshot is not None:
        peb_changes = [
            {"field": f, "before": cp_a.peb_snapshot.get(f), "after": cp_b.peb_snapshot.get(f)}
            for f in ("being_debugged", "nt_global_flag", "heap_flags", "heap_force_flags")
            if cp_a.peb_snapshot.get(f) != cp_b.peb_snapshot.get(f)
        ]
        peb_section = {"changed": peb_changes}
    elif cp_b.peb_snapshot is not None:
        peb_section = {"note": "PEB was not captured in checkpoint_a; cannot diff.", "snapshot_b": cp_b.peb_snapshot}

    # --- Summary ---
    parts = []
    if reg_changed:
        names = ", ".join(r["name"] for r in reg_changed[:4])
        suffix = f" +{len(reg_changed) - 4} more" if len(reg_changed) > 4 else ""
        parts.append(f"{len(reg_changed)} register(s) changed ({names}{suffix})")
    if total_changed_bytes:
        parts.append(f"{total_changed_bytes} memory byte(s) differ")
    if threads_added:
        parts.append(f"{len(threads_added)} thread(s) added")
    if threads_removed:
        parts.append(f"{len(threads_removed)} thread(s) removed")
    if cip_changed:
        parts.append(f"{len(cip_changed)} thread CIP(s) changed")
    if modules_loaded:
        names = ", ".join(m["name"] for m in modules_loaded[:3])
        parts.append(f"{len(modules_loaded)} module(s) loaded ({names})")
    if modules_unloaded:
        parts.append(f"{len(modules_unloaded)} module(s) unloaded")
    if hit_count_changed:
        parts.append(f"{len(hit_count_changed)} breakpoint(s) hit")
    if bps_added:
        parts.append(f"{len(bps_added)} breakpoint(s) added")
    if patches_added:
        parts.append(f"{len(patches_added)} patch(es) applied")
    if peb_section and peb_section.get("changed"):
        fields = ", ".join(c["field"] for c in peb_section["changed"])
        parts.append(f"PEB changed ({fields})")
    summary = "; ".join(parts) if parts else "No changes detected"

    elapsed = (cp_b.created_at - cp_a.created_at).total_seconds()
    computation_ms = round((time.perf_counter() - _t0) * 1000, 2)

    return ok(
        sandbox_id=sandbox_id,
        checkpoint_a=checkpoint_a,
        checkpoint_b=checkpoint_b,
        elapsed_sec=round(elapsed, 3),
        computation_ms=computation_ms,
        registers={"changed": reg_changed, "unchanged_count": reg_unchanged},
        memory={"regions": region_diffs, "total_changed_bytes": total_changed_bytes},
        threads={
            "added": threads_added,
            "removed": threads_removed,
            "cip_changed": cip_changed,
            "total_before": len(cp_a.threads_snapshot),
            "total_after": len(cp_b.threads_snapshot),
        },
        modules={
            "loaded": modules_loaded,
            "unloaded": modules_unloaded,
            "total_before": len(cp_a.modules_snapshot),
            "total_after": len(cp_b.modules_snapshot),
        },
        breakpoints={
            "added": bps_added,
            "removed": bps_removed,
            "hit_count_changed": hit_count_changed,
        },
        patches={"added": patches_added},
        peb=peb_section,
        summary=summary,
    )


@tool
def disassemble_range(*, 
    sandbox_id: str | None = None,
    address: str,
    count: int = 16,
) -> dict:
    """Disassemble a range of instructions starting at an address.

    Args:
        sandbox_id: Sandbox to read from.
        address: Start address, symbol, or expression.
        count: Number of instructions to disassemble (default 16, max 128).
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        base = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    count = max(1, min(count, 128))
    try:
        instructions = disasm_instructions(client, base, count)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(sandbox_id=sandbox_id, start=f"0x{base:X}", instructions=instructions, total=len(instructions))


@tool
def get_call_stack(sandbox_id: str | None = None) -> dict:
    """Retrieve the current call stack (most recent frame first).

    Uses x64dbg's native stack walker so it handles FPO, unwind info, and
    inline frames better than a naive frame-pointer walk.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        frames = client.get_call_stack()
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    stack = []
    for f in frames:
        sym = None
        try:
            s = client.get_symbol_at(f.address)
            if s:
                sym = s.undecoratedSymbol or s.decoratedSymbol
        except Exception:
            pass
        stack.append({
            "address": f"0x{f.address:X}",
            "from": f"0x{f.from_addr:X}",
            "to": f"0x{f.to_addr:X}",
            "comment": f.comment,
            "symbol": sym,
        })

    return ok(sandbox_id=sandbox_id, frames=stack, depth=len(stack))


@tool
def graph_memory_layout(
    sandbox_id: str | None = None,
    sample_entropy: bool = True,
    entropy_sample_bytes: int = 4096,
) -> dict:
    """Produce a structured memory layout map with anomaly highlighting.

    Groups adjacent committed regions by type/module, labels protection flags,
    and flags anomalies: RWX (read-write-execute), PAGE_GUARD, high-entropy
    regions, and executable non-module pages.

    Args:
        sandbox_id: Sandbox to inspect.
        sample_entropy: Whether to sample region entropy (adds RPC overhead).
        entropy_sample_bytes: Bytes to sample per region for entropy (default 4 KiB).
    """
    _MEM_COMMIT = 0x1000
    _MEM_PRIVATE = 0x20000
    _MEM_MAPPED = 0x40000
    _MEM_IMAGE = 0x1000000

    _PROT_NAMES = {
        0x01: "noaccess",
        0x02: "readonly",
        0x04: "readwrite",
        0x08: "writecopy",
        0x10: "execute",
        0x20: "execute_read",
        0x40: "execute_readwrite",
        0x80: "execute_writecopy",
    }

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        pages = client.memmap()
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    committed = [p for p in pages if p.state == _MEM_COMMIT]
    if not committed:
        return ok(sandbox_id=sandbox_id, regions=[], total=0, anomalies=[])

    regions: list[dict] = []
    for page in committed:
        # Type label
        if page.type == _MEM_IMAGE:
            rtype = "image"
        elif page.type == _MEM_MAPPED:
            rtype = "mapped"
        elif page.type == _MEM_PRIVATE:
            rtype = "private"
        else:
            rtype = "unknown"

        # Protection decode
        low_prot = page.protect & 0xFF
        prot_str = _PROT_NAMES.get(low_prot, f"0x{low_prot:X}")
        is_guard = bool(page.protect & 0x100)
        is_rwx = low_prot == 0x40
        is_executable = low_prot in (0x10, 0x20, 0x40, 0x80)

        # Anomalies
        anomalies: list[str] = []
        if is_rwx:
            anomalies.append("RWX")
        if is_guard:
            anomalies.append("PAGE_GUARD")
        if is_executable and not page.info and rtype != "image":
            anomalies.append("EXEC_NON_MODULE")

        # Entropy (optional, sampled to avoid RPC thrashing)
        entropy: float | None = None
        if sample_entropy:
            sample = min(entropy_sample_bytes, page.region_size)
            try:
                data = client.read_memory(page.base_address, sample)
                if data and data.count(data[0]) != len(data):
                    entropy = round(shannon_entropy(data), 4)
                    if entropy >= 7.0:
                        anomalies.append("HIGH_ENTROPY")
            except Exception:
                pass

        regions.append({
            "start": f"0x{page.base_address:X}",
            "end": f"0x{page.base_address + page.region_size:X}",
            "size": page.region_size,
            "type": rtype,
            "name": page.info or "",
            "protection": f"0x{page.protect:X}",
            "protection_str": prot_str,
            "entropy": entropy,
            "anomalies": anomalies,
        })

    # Group adjacent regions with same type and name
    grouped: list[dict] = []
    if regions:
        cur = {
            "start": regions[0]["start"],
            "end": regions[0]["end"],
            "size": regions[0]["size"],
            "type": regions[0]["type"],
            "name": regions[0]["name"],
            "protection": regions[0]["protection"],
            "protection_str": regions[0]["protection_str"],
            "anomalies": list(regions[0]["anomalies"]),
            "sub_regions": 1,
            "entropy": regions[0].get("entropy"),
        }
        for r in regions[1:]:
            # Check adjacency: current end == next start
            cur_end = int(cur["end"], 16)
            r_start = int(r["start"], 16)
            if (cur_end == r_start and cur["type"] == r["type"]
                    and cur["name"] == r["name"]
                    and cur["protection_str"] == r["protection_str"]):
                cur["end"] = r["end"]
                cur["size"] += r["size"]
                cur["sub_regions"] += 1
                for a in r["anomalies"]:
                    if a not in cur["anomalies"]:
                        cur["anomalies"].append(a)
                if r.get("entropy") is not None:
                    cur["entropy"] = max(cur.get("entropy") or 0, r["entropy"])
            else:
                grouped.append(cur)
                cur = {
                    "start": r["start"],
                    "end": r["end"],
                    "size": r["size"],
                    "type": r["type"],
                    "name": r["name"],
                    "protection": r["protection"],
                    "protection_str": r["protection_str"],
                    "anomalies": list(r["anomalies"]),
                    "sub_regions": 1,
                    "entropy": r.get("entropy"),
                }
        grouped.append(cur)

    # Anomaly summary
    summary = {
        "rwx_count": sum(1 for g in grouped if "RWX" in g["anomalies"]),
        "guard_count": sum(1 for g in grouped if "PAGE_GUARD" in g["anomalies"]),
        "exec_non_module_count": sum(
            1 for g in grouped if "EXEC_NON_MODULE" in g["anomalies"]
        ),
        "high_entropy_count": sum(1 for g in grouped if "HIGH_ENTROPY" in g["anomalies"]),
        "total_grouped": len(grouped),
        "total_raw": len(regions),
    }

    return ok(
        sandbox_id=sandbox_id,
        regions=grouped,
        summary=summary,
    )


@tool
def sandbox_cross_diff(
    sandbox_a_id: str,
    sandbox_b_id: str,
    compare_memory: bool = False,
    memory_address_a: str = "",
    memory_address_b: str = "",
    memory_size: int = 4096,
) -> dict:
    """Compare live state between two different sandboxes.

    This is the cross-sandbox counterpart to ``checkpoint_diff`` (which compares
    two checkpoints within the *same* sandbox). Use it to compare a clean run
    versus a patched run, or two different execution paths.

    Args:
        sandbox_a_id: First sandbox to compare.
        sandbox_b_id: Second sandbox to compare.
        compare_memory: Also read and diff a memory region.
        memory_address_a: Region start in sandbox A (required if compare_memory=True).
        memory_address_b: Region start in sandbox B (required if compare_memory=True).
        memory_size: Bytes to read from each (default 4 KiB, max 1 MiB).
    """
    _MAX_SIZE = 1024 * 1024
    if compare_memory:
        if memory_size <= 0:
            return err("memory_size must be > 0.", ErrorType.BAD_ARGUMENT)
        if memory_size > _MAX_SIZE:
            return err("memory_size exceeds 1 MiB limit.", ErrorType.BAD_ARGUMENT)
        if not memory_address_a.strip() or not memory_address_b.strip():
            return err("memory_address_a and memory_address_b are required when compare_memory=True.",
                       ErrorType.BAD_ARGUMENT)

    mgr = get_manager()
    try:
        client_a = mgr.get_client(sandbox_a_id)
        client_b = mgr.get_client(sandbox_b_id)
        sandbox_a = mgr.get_sandbox(sandbox_a_id)
        sandbox_b = mgr.get_sandbox(sandbox_b_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    arch_a = sandbox_a.debugger_arch
    arch_b = sandbox_b.debugger_arch

    # --- Registers ---
    regs_a = capture_registers(client_a, arch_a)
    regs_b = capture_registers(client_b, arch_b)
    reg_changed = []
    all_reg_names = sorted(set(regs_a) | set(regs_b))
    for reg in all_reg_names:
        va_str = regs_a.get(reg, "0x0")
        vb_str = regs_b.get(reg, "0x0")
        # Parse hex strings back to int for comparison
        try:
            va = int(va_str, 16) if isinstance(va_str, str) else va_str
        except (ValueError, TypeError):
            va = 0
        try:
            vb = int(vb_str, 16) if isinstance(vb_str, str) else vb_str
        except (ValueError, TypeError):
            vb = 0
        if va != vb:
            delta = vb - va
            sign = "+" if delta >= 0 else "-"
            reg_changed.append({
                "name": reg,
                "sandbox_a": f"0x{va:X}",
                "sandbox_b": f"0x{vb:X}",
                "delta": f"{sign}0x{abs(delta):X}",
            })

    # --- Modules ---
    modules_a: list[dict] = []
    modules_b: list[dict] = []
    try:
        for m in client_a.get_modules():
            modules_a.append({"base": m.base, "size": m.size, "name": m.name})
    except Exception:
        pass
    try:
        for m in client_b.get_modules():
            modules_b.append({"base": m.base, "size": m.size, "name": m.name})
    except Exception:
        pass

    names_a = {m["name"] for m in modules_a}
    names_b = {m["name"] for m in modules_b}
    modules_only_a = sorted(names_a - names_b)
    modules_only_b = sorted(names_b - names_a)

    # --- Threads ---
    threads_a = 0
    threads_b = 0
    try:
        threads_a = len(client_a.get_threads())
    except Exception:
        pass
    try:
        threads_b = len(client_b.get_threads())
    except Exception:
        pass

    # --- Memory diff (optional) ---
    memory_diff = None
    if compare_memory:
        try:
            base_a = resolve_addr(client_a, memory_address_a)
            base_b = resolve_addr(client_b, memory_address_b)
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)

        try:
            data_a = client_a.read_memory(base_a, memory_size)
            data_b = client_b.read_memory(base_b, memory_size)
            runs = diff_bytes(data_a, data_b)
            changed_bytes = sum(len(r["before"]) // 2 for r in runs)
            memory_diff = {
                "address_a": f"0x{base_a:X}",
                "address_b": f"0x{base_b:X}",
                "size": memory_size,
                "identical": changed_bytes == 0,
                "changed_bytes": changed_bytes,
                "diff_runs": runs,
            }
        except Exception as exc:
            if is_bug(exc):
                raise
            return err(f"Memory read failed: {exc}", classify_exception(exc))

    # --- Summary ---
    parts = []
    if reg_changed:
        parts.append(f"{len(reg_changed)} register(s) differ")
    if modules_only_a or modules_only_b:
        parts.append(f"{len(modules_only_a)} module(s) only in A, {len(modules_only_b)} only in B")
    if threads_a != threads_b:
        parts.append(f"Thread count differs ({threads_a} vs {threads_b})")
    if memory_diff and not memory_diff["identical"]:
        parts.append(f"{memory_diff['changed_bytes']} memory byte(s) differ")
    summary = "; ".join(parts) if parts else "No differences detected"

    return ok(
        sandbox_a_id=sandbox_a_id,
        sandbox_b_id=sandbox_b_id,
        arch_a=arch_a,
        arch_b=arch_b,
        registers={"changed": reg_changed, "total_checked": len(all_reg_names)},
        modules={
            "count_a": len(modules_a),
            "count_b": len(modules_b),
            "only_in_a": modules_only_a,
            "only_in_b": modules_only_b,
        },
        threads={"count_a": threads_a, "count_b": threads_b},
        memory=memory_diff,
        summary=summary,
    )
