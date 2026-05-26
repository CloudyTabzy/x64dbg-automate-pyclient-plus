"""Composite runtime-analysis tools.

These replace fragile chains of low-level debugger commands with single, structured
queries — the runtime analogue of IDA's ``analyze_function``.
"""

from __future__ import annotations

import time

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, is_bug, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import (
    capture_registers, diff_bytes, disasm_instructions, read_pointer, resolve_addr,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.api_runtime.utils import detect_crypto_constants, parse_region
from x64dbg_automate.models import MemoryBreakpointType

_MAX_REGION_READ = 4 * 1024 * 1024  # safety cap per region read


def _symbol_name(client, addr: int) -> str | None:
    try:
        sym = client.get_symbol_at(addr)
        if sym and sym.undecoratedSymbol:
            return sym.undecoratedSymbol
    except Exception:
        pass
    return None


@tool
def capture_function_context(*, 
    sandbox_id: str | None = None,
    addr: str,
    capture_memory_regions: list[str] | None = None,
    capture_inputs: bool = True,
    capture_outputs: bool = True,
    include_disassembly: bool = False,
    timeout_sec: int = 30,
) -> dict:
    """Run a function to its entry (and return) once and capture its full runtime context.

    Sets a one-shot breakpoint at the function, resumes until it's hit (register inputs +
    memory snapshot), then breaks at its return address (register outputs + memory snapshot),
    diffs the regions, and flags any crypto constants that appeared. No manual stepping.

    Args:
        sandbox_id: Sandbox to operate on (must be debugging and able to reach the function).
        addr: Function address, symbol, or expression.
        capture_memory_regions: Regions to snapshot before/after, as 'addr:size' strings.
        capture_inputs: Capture register state at entry.
        capture_outputs: Capture register state at the return.
        include_disassembly: Include a short disassembly at the entry point.
        timeout_sec: Max seconds to wait for the entry and the return breakpoints.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    sandbox = mgr.get_sandbox(sandbox_id)
    arch = sandbox.debugger_arch

    try:
        target = resolve_addr(client, addr)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    regions: list[tuple[int, int]] = []
    for spec in (capture_memory_regions or []):
        try:
            a, s = parse_region(spec)
            if s > _MAX_REGION_READ:
                return err(f"Region too large (>{_MAX_REGION_READ} bytes): {spec!r}", ErrorType.BAD_ARGUMENT)
            regions.append((a, s))
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)

    result: dict = {
        "sandbox_id": sandbox_id,
        "addr": f"0x{target:X}",
        "name": _symbol_name(client, target),
    }

    try:
        # Entry breakpoint
        client.set_breakpoint(target, singleshoot=True)
        if not client.go() or not client.wait_until_stopped(timeout_sec):
            return err("Function entry not reached before timeout.", ErrorType.TIMEOUT,
                       hint="Increase timeout_sec, or drive the target closer to the call first.",
                       **result)
        if client.get_reg("cip") != target:
            # Stopped for another reason (different bp/exception)
            result["entry_hit"] = False
            return err("Stopped before reaching the function entry (other breakpoint/exception).",
                       ErrorType.INVALID_STATE, **result)
        result["entry_hit"] = True

        if capture_inputs:
            result["register_inputs"] = capture_registers(client, arch)

        memory_before: dict[str, str] = {}
        raw_before: dict[str, bytes] = {}
        for a, s in regions:
            data = client.read_memory(a, s)
            raw_before[f"0x{a:X}:{s}"] = data
            memory_before[f"0x{a:X}:{s}"] = to_hex(data)
        if regions:
            result["memory_before"] = memory_before

        if include_disassembly:
            result["disassembly"] = disasm_instructions(client, target, 24)

        # Return breakpoint: return address sits at the top of the stack on entry.
        sp = client.get_reg("rsp" if arch == "x64" else "esp")
        ret_addr = read_pointer(client, arch, sp)
        result["return_addr"] = f"0x{ret_addr:X}"

        if capture_outputs or regions:
            client.set_breakpoint(ret_addr, singleshoot=True)
            if not client.go() or not client.wait_until_stopped(timeout_sec):
                result["return_hit"] = False
                result["note"] = "Entry captured; return not reached before timeout."
                return ok(**result)
            result["return_hit"] = True

            if capture_outputs:
                result["register_outputs"] = capture_registers(client, arch)

            if regions:
                memory_after: dict[str, str] = {}
                diffs: dict[str, list] = {}
                crypto: list[dict] = []
                for a, s in regions:
                    key = f"0x{a:X}:{s}"
                    data = client.read_memory(a, s)
                    memory_after[key] = to_hex(data)
                    diffs[key] = diff_bytes(raw_before[key], data)
                    crypto.extend(detect_crypto_constants(data, base_addr=a))
                result["memory_after"] = memory_after
                result["memory_diffs"] = diffs
                if crypto:
                    result["crypto_detected"] = crypto
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), **result)

    return ok(**result)



@tool
def trace_until_memory_change(*, 
    sandbox_id: str | None = None,
    address: str,
    size: int,
    timeout_sec: int = 30,
) -> dict:
    """Resume the target until a memory region is written, using a memory write breakpoint.

    Returns the before/after bytes, the changed byte runs, and the instruction (cip) that
    was executing when the write fired.

    Args:
        sandbox_id: Sandbox to operate on.
        address: Region start (address, symbol, or expression).
        size: Number of bytes to monitor.
        timeout_sec: Max seconds to wait for a change.
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
    if size <= 0 or size > _MAX_REGION_READ:
        return err("size must be between 1 and 4 MiB.", ErrorType.BAD_ARGUMENT)

    try:
        mgr.ensure_stopped(client)
        before = client.read_memory(base, size)
        client.set_memory_breakpoint(base, bp_type=MemoryBreakpointType.w)
        deadline = time.time() + timeout_sec
        changed = False
        cip = None
        after = before
        while time.time() < deadline:
            remaining = max(1, int(deadline - time.time()))
            if not client.go() or not client.wait_until_stopped(remaining):
                break
            after = client.read_memory(base, size)
            if after != before:
                changed = True
                try:
                    cip = client.get_reg("cip")
                except Exception:
                    cip = None
                break
        client.clear_memory_breakpoint(base)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    if not changed:
        return err("No memory change observed before timeout.", ErrorType.TIMEOUT,
                   sandbox_id=sandbox_id, address=f"0x{base:X}", size=size,
                   hint="Increase timeout_sec or confirm the region is the right one.")
    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{base:X}",
        size=size,
        before=to_hex(before),
        after=to_hex(after),
        diffs=diff_bytes(before, after),
        changed_by_instruction=(f"0x{cip:X}" if cip is not None else None),
    )


@tool
def find_crypto_material(
    sandbox_id: str | None = None,
    scan_mode: str = "all",
    regions: list[str] | None = None,
) -> dict:
    """Scan sandbox memory for cryptographic constant tables (AES/SHA/MD5/CRC32/RC4).

    Identifies S-boxes, round constants, init states, and CRC tables so a buffer can be
    interpreted instead of guessed at.

    Args:
        sandbox_id: Sandbox to scan.
        scan_mode: 'all' or a filter like 'aes', 'sha256', 'rc4', 'crc32'.
        regions: Regions to scan as 'addr:size'. Defaults to the main module image.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    scan_regions: list[tuple[int, int]] = []
    if regions:
        for spec in regions:
            try:
                scan_regions.append(parse_region(spec))
            except ValueError as exc:
                return err(str(exc), ErrorType.BAD_ARGUMENT)
    else:
        try:
            info = client.get_process_info()
            scan_regions.append((info.image_base, info.image_size))
        except Exception as exc:  # noqa: BLE001
            return err(f"Could not determine main module: {exc}", ErrorType.INVALID_STATE,
                       hint="Pass explicit regions=['0xADDR:size'].", sandbox_id=sandbox_id)

    findings: list[dict] = []
    bytes_scanned = 0
    try:
        mgr.ensure_stopped(client)
        for base, size in scan_regions:
            region_findings, scanned = _scan_region(client, base, size, scan_mode)
            findings.extend(region_findings)
            bytes_scanned += scanned
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    findings.sort(key=lambda f: int(f["address"], 16))
    return ok(
        sandbox_id=sandbox_id,
        scan_mode=scan_mode,
        regions_scanned=[f"0x{b:X}:{s}" for b, s in scan_regions],
        bytes_scanned=bytes_scanned,
        findings=findings,
        total=len(findings),
    )


@tool
def trace_execution(
    sandbox_id: str | None = None,
    max_steps: int = 100,
    stop_condition: str = "",
    record_registers: bool = False,
    timeout_sec: int = 60,
) -> dict:
    """Single-step the target and record a trace log (software trace fallback).

    Because x64dbg's native TraceRecord is not exposed over RPC, this tool
    performs a controlled single-step loop, capturing each instruction's address,
    disassembly, and (optionally) register state. Use this to reconstruct the
    path leading to an interesting write or call.

    Args:
        sandbox_id: Sandbox to operate on.
        max_steps: Maximum single-steps to record (default 100, max 500).
        stop_condition: Optional x64dbg expression; trace stops when this is non-zero.
        record_registers: If true, snapshot GP registers after each step.
        timeout_sec: Max seconds for the entire trace.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    sandbox = mgr.get_sandbox(sandbox_id)
    arch = sandbox.debugger_arch

    max_steps = max(1, min(max_steps, 500))
    deadline = time.time() + timeout_sec
    trace_log: list[dict] = []

    try:
        mgr.ensure_stopped(client)
        for step in range(max_steps):
            if time.time() > deadline:
                return err("Trace exceeded timeout.", ErrorType.TIMEOUT,
                           sandbox_id=sandbox_id, steps_recorded=len(trace_log),
                           hint="Increase timeout_sec or reduce max_steps.")

            cip = client.get_reg("cip")
            ins = client.disassemble_at(cip)
            if ins is None:
                trace_log.append({"address": f"0x{cip:X}", "mnemonic": "<invalid>", "size": 0})
                break

            entry: dict = {
                "step": step,
                "address": f"0x{cip:X}",
                "mnemonic": ins.instruction,
                "size": ins.instr_size,
            }
            if record_registers:
                entry["registers"] = capture_registers(client, arch)
            trace_log.append(entry)

            if stop_condition:
                val, success = client.eval_sync(stop_condition)
                if success and val:
                    break

            client.stepi()
            if not client.wait_until_stopped(5):
                return err("Step did not complete (target may be running or dead).",
                           ErrorType.TIMEOUT, sandbox_id=sandbox_id,
                           steps_recorded=len(trace_log))
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   steps_recorded=len(trace_log))

    return ok(sandbox_id=sandbox_id, steps_recorded=len(trace_log), trace=trace_log)


def _scan_region(client, base: int, size: int, scan_mode: str,
                 chunk: int = 1 << 20, overlap: int = 512) -> tuple[list[dict], int]:
    """Read a region in overlapping chunks and detect crypto constants. Returns (findings, bytes_read)."""
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    offset = 0
    total_read = 0
    while offset < size:
        this = min(chunk, size - offset)
        try:
            data = client.read_memory(base + offset, this)
        except Exception:
            # Unreadable sub-region; skip ahead a chunk.
            offset += chunk
            continue
        total_read += len(data)
        for f in detect_crypto_constants(data, base_addr=base + offset, scan_mode=scan_mode):
            key = (f["algorithm"] + f["detail"], int(f["address"], 16))
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
        if this < chunk:
            break
        offset += chunk - overlap
    return findings, total_read
