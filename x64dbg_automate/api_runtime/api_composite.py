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
def watch_memory_writes(*,
    sandbox_id: str | None = None,
    address: str,
    size: int,
    max_records: int = 50,
    timeout_sec: int = 60,
) -> dict:
    """Monitor a memory region and record every write that changes its contents.

    Uses a persistent memory-write breakpoint. Each time the target stops because of a
    write anywhere in the watched page(s), the region is re-read. If the bytes actually
    changed, a record is appended. Stops when ``max_records`` is reached or ``timeout_sec``
    elapses.  This is a multi-record upgrade of ``trace_until_memory_change``.

    Args:
        sandbox_id: Sandbox to operate on.
        address: Region start (address, symbol, or expression).
        size: Number of bytes to monitor (1 – 4 MiB).
        max_records: How many distinct changes to capture before returning (1 – 500).
        timeout_sec: Hard wall-clock limit for the entire watch session.

    Returns:
        Structured dict with a ``records`` list (each entry has before/after/diffs/cip),
        plus aggregate metadata (total_changes, timed_out, page_level_hits, etc.).
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
    max_records = max(1, min(max_records, 500))

    records: list[dict] = []
    page_level_hits = 0
    snapshot: bytes | None = None
    bp_set = False
    deadline = time.time() + timeout_sec

    try:
        mgr.ensure_stopped(client)
        snapshot = client.read_memory(base, size)
        if snapshot is None or len(snapshot) != size:
            return err(f"Failed to read {size} bytes from 0x{base:X}.",
                       ErrorType.INVALID_STATE, sandbox_id=sandbox_id)

        client.set_memory_breakpoint(base, bp_type=MemoryBreakpointType.w, singleshoot=False)
        bp_set = True

        while len(records) < max_records and time.time() < deadline:
            remaining = max(1, int(deadline - time.time()))
            if not client.go():
                break
            if not client.wait_until_stopped(remaining):
                break

            # Memory BPs are page-granular; the write may not be in our exact region.
            current = client.read_memory(base, size)
            if current is None or len(current) != size:
                # Region became unreadable (e.g. deallocated) — stop gracefully.
                break

            if current == snapshot:
                page_level_hits += 1
                continue  # false positive: write hit the page but not our bytes

            # Record the change
            cip = None
            try:
                cip = client.get_reg("cip")
            except Exception:
                pass

            records.append({
                "index": len(records) + 1,
                "timestamp": time.strftime("%H:%M:%S"),
                "changed_by_instruction": (f"0x{cip:X}" if cip is not None else None),
                "before": to_hex(snapshot),
                "after": to_hex(current),
                "diffs": diff_bytes(snapshot, current),
            })
            snapshot = current

    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   records_captured=len(records))
    finally:
        if bp_set:
            try:
                client.clear_memory_breakpoint(base)
            except Exception:
                pass

    timed_out = time.time() >= deadline
    if not records and timed_out:
        return err("No memory changes observed before timeout.", ErrorType.TIMEOUT,
                   sandbox_id=sandbox_id, address=f"0x{base:X}", size=size,
                   hint="Increase timeout_sec or confirm the region is the right one.")

    return ok(
        sandbox_id=sandbox_id,
        address=f"0x{base:X}",
        size=size,
        max_records=max_records,
        timeout_sec=timeout_sec,
        total_changes=len(records),
        timed_out=timed_out,
        page_level_hits=page_level_hits,
        records=records,
        final_snapshot=to_hex(snapshot) if snapshot is not None else None,
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


@tool
def trace_until_call(
    target_addr: str,
    sandbox_id: str | None = None,
    max_steps: int = 500,
    timeout_sec: int = 60,
) -> dict:
    """Single-step until a CALL instruction to the target address is encountered.

    Uses software single-stepping and disassembles each instruction. Stops when
    a CALL (E8 / FF) targeting the specified address is found, or when max_steps
    or timeout is reached.

    Args:
        target_addr: Address to watch for CALLs to (hex, symbol, or expression).
        sandbox_id: Sandbox to operate on.
        max_steps: Maximum steps to trace (default 500, max 2000).
        timeout_sec: Max seconds for the entire trace.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        target = resolve_addr(client, target_addr)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    max_steps = max(1, min(max_steps, 2000))
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
            trace_log.append(entry)

            # Detect CALL to target: E8 rel32 (relative) or FF /2 or FF /3 (indirect)
            mnemonic_lower = ins.instruction.lower()
            if mnemonic_lower.startswith("call"):
                # Try to resolve the call target via expression evaluator
                try:
                    # Extract operand after "call "
                    operand = ins.instruction[5:].strip()
                    val, success = client.eval_sync(operand)
                    if success and val == target:
                        return ok(
                            sandbox_id=sandbox_id,
                            target=f"0x{target:X}",
                            steps_recorded=len(trace_log),
                            hit_at=f"0x{cip:X}",
                            trace=trace_log,
                        )
                except Exception:
                    pass
                # Also check if instruction bytes encode a relative CALL to target
                try:
                    data = client.read_memory(cip, ins.instr_size)
                    if data and len(data) >= 5 and data[0] == 0xE8:
                        rel = int.from_bytes(data[1:5], "little", signed=True)
                        if cip + 5 + rel == target:
                            return ok(
                                sandbox_id=sandbox_id,
                                target=f"0x{target:X}",
                                steps_recorded=len(trace_log),
                                hit_at=f"0x{cip:X}",
                                trace=trace_log,
                            )
                except Exception:
                    pass

            client.stepi()
            if not client.wait_until_stopped(5):
                return err("Step did not complete (target may be running or dead).",
                           ErrorType.TIMEOUT, sandbox_id=sandbox_id,
                           steps_recorded=len(trace_log))
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   steps_recorded=len(trace_log))

    return ok(
        sandbox_id=sandbox_id,
        target=f"0x{target:X}",
        steps_recorded=len(trace_log),
        hit_at=None,
        trace=trace_log,
        hint="No CALL to target observed within step limit. Try increasing max_steps.",
    )


@tool
def trace_until_register_equals(
    register: str,
    value: str,
    sandbox_id: str | None = None,
    max_steps: int = 500,
    timeout_sec: int = 60,
) -> dict:
    """Single-step until a register equals the specified value.

    Args:
        register: Register name to monitor (e.g. 'rax', 'eip', 'r8').
        value: Hex or decimal value to match (e.g. '0x401000', '42').
        sandbox_id: Sandbox to operate on.
        max_steps: Maximum steps to trace (default 500, max 2000).
        timeout_sec: Max seconds for the entire trace.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        target_val = int(value, 0)
    except ValueError:
        return err(f"Cannot parse value: {value}", ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    max_steps = max(1, min(max_steps, 2000))
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
            try:
                reg_val = client.get_reg(register)
            except Exception:
                return err(f"Cannot read register: {register}", ErrorType.BAD_ARGUMENT,
                           sandbox_id=sandbox_id)

            ins = client.disassemble_at(cip)
            mnemonic = ins.instruction if ins else "<invalid>"
            trace_log.append({
                "step": step,
                "address": f"0x{cip:X}",
                "mnemonic": mnemonic,
                f"{register}": f"0x{reg_val:X}",
            })

            if reg_val == target_val:
                return ok(
                    sandbox_id=sandbox_id,
                    register=register,
                    target_value=f"0x{target_val:X}",
                    steps_recorded=len(trace_log),
                    hit_at=f"0x{cip:X}",
                    trace=trace_log,
                )

            client.stepi()
            if not client.wait_until_stopped(5):
                return err("Step did not complete (target may be running or dead).",
                           ErrorType.TIMEOUT, sandbox_id=sandbox_id,
                           steps_recorded=len(trace_log))
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   steps_recorded=len(trace_log))

    return ok(
        sandbox_id=sandbox_id,
        register=register,
        target_value=f"0x{target_val:X}",
        steps_recorded=len(trace_log),
        hit_at=None,
        trace=trace_log,
        hint="Register did not reach target value within step limit. Try increasing max_steps.",
    )


@tool
def trace_until_write(
    address: str,
    size: int = 1,
    sandbox_id: str | None = None,
    timeout_sec: int = 30,
) -> dict:
    """Resume the target until a memory region is written (alias for trace_until_memory_change).

    Sets a memory-write breakpoint on the region and waits for it to fire.

    Args:
        address: Region start (address, symbol, or expression).
        size: Number of bytes to monitor.
        sandbox_id: Sandbox to operate on.
        timeout_sec: Max seconds to wait for a change.
    """
    # Delegate to the existing implementation for consistency
    from x64dbg_automate.api_runtime.api_composite import trace_until_memory_change
    return trace_until_memory_change(
        sandbox_id=sandbox_id,
        address=address,
        size=size,
        timeout_sec=timeout_sec,
    )


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



@tool
def trace_call_tree(
    sandbox_id: str | None = None,
    max_steps: int = 500,
    timeout_sec: int = 60,
    follow_tail_calls: bool = True,
) -> dict:
    """Single-step trace the debuggee and record a dynamic call hierarchy tree.

    Steps through execution, watching for ``call`` / ``ret`` / ``jmp``
    instructions. Builds a nested tree showing which functions called which,
    at what depth, and whether each call was direct, indirect, or a tail call.

    Args:
        sandbox_id: Sandbox to trace.
        max_steps: Maximum instructions to step (default 500, max 2000).
        timeout_sec: Hard timeout for the entire trace.
        follow_tail_calls: Treat unconditional ``jmp`` outside the current
            function as an implicit return + call (tail call optimisation).

    Returns:
        Structured dict with ``tree`` (nested), ``flat_calls`` (linear list),
        ``max_depth_reached``, ``total_calls``, and ``unresolved_indirect_calls``.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    max_steps = max(1, min(max_steps, 2000))
    deadline = time.time() + timeout_sec

    # -- Helpers -----------------------------------------------------------
    def _resolve_call_target(cip: int, insn_str: str, insn_size: int) -> tuple[int | None, str]:
        """Resolve the target of a CALL or JMP instruction.

        Returns (target_addr, call_type) where call_type is one of:
        'direct', 'indirect', 'import', 'unresolved'.
        """
        # Strategy 1: expression evaluator
        try:
            operand = insn_str.split(None, 1)[1].strip()
            val, success = client.eval_sync(operand)
            if success and val:
                # Distinguish imports by symbol lookup
                try:
                    sym = client.get_symbol_at(val)
                    if sym and sym.undecoratedSymbol:
                        return val, "import"
                except Exception:
                    pass
                return val, "direct"
        except Exception:
            pass

        # Strategy 2: decode E8 rel32 for direct CALL
        try:
            data = client.read_memory(cip, insn_size)
            if data and len(data) >= 5 and data[0] == 0xE8:
                rel = int.from_bytes(data[1:5], "little", signed=True)
                return cip + 5 + rel, "direct"
        except Exception:
            pass

        # Strategy 3: decode FF 15 / FF 25 (indirect via memory)
        try:
            data = client.read_memory(cip, insn_size)
            if data and len(data) >= 6 and data[0] == 0xFF:
                # FF 15 → call [rip+disp32] (x64)
                # FF 25 → jmp [rip+disp32] (x64)
                if data[1] in (0x15, 0x25):
                    disp = int.from_bytes(data[2:6], "little", signed=True)
                    ea = cip + 6 + disp
                    try:
                        ptr = client.read_qword(ea) if mgr.get_sandbox(sandbox_id).debugger_arch == "x64" else client.read_dword(ea)
                        return ptr, "indirect"
                    except Exception:
                        return ea, "indirect"
        except Exception:
            pass

        return None, "unresolved"

    def _node_name(addr: int) -> str:
        try:
            sym = client.get_symbol_at(addr)
            if sym and sym.undecoratedSymbol:
                return sym.undecoratedSymbol
            if sym and sym.decoratedSymbol:
                return sym.decoratedSymbol
        except Exception:
            pass
        return f"sub_{addr:X}"

    def _is_inside_function(cip: int, func_start: int, func_end: int) -> bool:
        return func_start <= cip < func_end

    # -- Tree structures ---------------------------------------------------
    # Each frame: {"address", "name", "call_type", "call_insn", "children": []}
    # The stack holds references to the *same* dicts that end up in the tree.
    root_addr = 0
    try:
        root_addr = client.get_reg("cip")
    except Exception:
        return err("Could not read CIP to start trace.", ErrorType.INVALID_STATE, sandbox_id=sandbox_id)

    root_node: dict = {
        "address": f"0x{root_addr:X}",
        "name": _node_name(root_addr),
        "call_type": "root",
        "call_instruction": None,
        "children": [],
    }
    call_stack: list[dict] = [root_node]
    flat_calls: list[dict] = []
    unresolved_count = 0
    max_depth = 0

    # Track current function bounds heuristically for tail-call detection.
    # We use the nearest symbol / function start, or fall back to CIP itself.
    current_func_start = root_addr
    current_func_end = root_addr + 0xFFFF
    try:
        fb = client.get_function(root_addr)
        if fb:
            current_func_start = fb.start
            current_func_end = fb.end
    except Exception:
        pass

    # -- Trace loop --------------------------------------------------------
    try:
        mgr.ensure_stopped(client)
        for step in range(max_steps):
            if time.time() > deadline:
                break

            cip = client.get_reg("cip")
            ins = client.disassemble_at(cip)
            if ins is None:
                # Can't disassemble — attempt one step then continue
                client.stepi()
                client.wait_until_stopped(2)
                continue

            mnemonic_lower = ins.instruction.lower()
            op = mnemonic_lower.split()[0]

            # -- CALL ------------------------------------------------------
            if op == "call":
                target, ctype = _resolve_call_target(cip, ins.instruction, ins.instr_size)
                if target is None:
                    unresolved_count += 1
                    target_name = "unresolved"
                    target_str = None
                else:
                    target_name = _node_name(target)
                    target_str = f"0x{target:X}"

                child = {
                    "address": target_str,
                    "name": target_name,
                    "call_type": ctype,
                    "call_instruction": f"0x{cip:X}",
                    "children": [],
                }
                call_stack[-1]["children"].append(child)
                call_stack.append(child)
                flat_calls.append({
                    "depth": len(call_stack) - 1,
                    "caller": call_stack[-2]["address"] if len(call_stack) > 1 else None,
                    "callee": target_str,
                    "callee_name": target_name,
                    "call_type": ctype,
                    "instruction": f"0x{cip:X}",
                })
                max_depth = max(max_depth, len(call_stack) - 1)

                # Update heuristic function bounds for tail-call detection
                if target is not None:
                    current_func_start = target
                    current_func_end = target + 0xFFFF
                    try:
                        fb = client.get_function(target)
                        if fb:
                            current_func_start = fb.start
                            current_func_end = fb.end
                    except Exception:
                        pass

            # -- RET -------------------------------------------------------
            elif op in ("ret", "retn"):
                if len(call_stack) > 1:
                    call_stack.pop()
                    # Restore function bounds to caller's context
                    caller_addr = int(call_stack[-1]["address"], 16)
                    current_func_start = caller_addr
                    current_func_end = caller_addr + 0xFFFF
                    try:
                        fb = client.get_function(caller_addr)
                        if fb:
                            current_func_start = fb.start
                            current_func_end = fb.end
                    except Exception:
                        pass

            # -- JMP (tail call) -------------------------------------------
            elif follow_tail_calls and op == "jmp":
                target, ctype = _resolve_call_target(cip, ins.instruction, ins.instr_size)
                if target is not None and not _is_inside_function(target, current_func_start, current_func_end):
                    # Treat as tail call: pop current frame, push new one
                    if len(call_stack) > 1:
                        call_stack.pop()

                    child = {
                        "address": f"0x{target:X}",
                        "name": _node_name(target),
                        "call_type": "tail_call",
                        "call_instruction": f"0x{cip:X}",
                        "children": [],
                    }
                    call_stack[-1]["children"].append(child)
                    call_stack.append(child)
                    flat_calls.append({
                        "depth": len(call_stack) - 1,
                        "caller": call_stack[-2]["address"] if len(call_stack) > 1 else None,
                        "callee": f"0x{target:X}",
                        "callee_name": _node_name(target),
                        "call_type": "tail_call",
                        "instruction": f"0x{cip:X}",
                    })
                    max_depth = max(max_depth, len(call_stack) - 1)

                    current_func_start = target
                    current_func_end = target + 0xFFFF
                    try:
                        fb = client.get_function(target)
                        if fb:
                            current_func_start = fb.start
                            current_func_end = fb.end
                    except Exception:
                        pass

            # -- Step ------------------------------------------------------
            client.stepi()
            if not client.wait_until_stopped(5):
                break

    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   steps_recorded=step + 1 if 'step' in dir() else 0)

    # -- Result ------------------------------------------------------------
    total_calls = len(flat_calls)
    truncated = step + 1 >= max_steps if 'step' in dir() else False
    timed_out = time.time() > deadline if 'deadline' in dir() else False

    return ok(
        sandbox_id=sandbox_id,
        start_address=root_node["address"],
        max_steps=max_steps,
        steps_recorded=step + 1 if 'step' in dir() else 0,
        tree=root_node,
        flat_calls=flat_calls,
        max_depth_reached=max_depth,
        total_calls=total_calls,
        unresolved_indirect_calls=unresolved_count,
        truncated=truncated,
        timed_out=timed_out,
    )
