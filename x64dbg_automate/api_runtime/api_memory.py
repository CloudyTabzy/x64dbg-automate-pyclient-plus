"""Semantic memory tools: typed struct reads, entropy discovery, IAT resolution, diffs.

Turns ``read_memory(addr, size)`` raw-byte access into interpretable queries an agent
can reason about.
"""

from __future__ import annotations

import struct

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, is_bug, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import disasm_instructions, resolve_addr
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
        address: IAT slot address (e.g. '0x43D070').
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

    Designed for reading multi-MB regions (SecuROM Stext section is ~10 MB) without
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
    from x64dbg_automate.api_runtime.runtime_helpers import diff_bytes

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
