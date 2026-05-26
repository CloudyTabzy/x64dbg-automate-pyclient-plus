"""High-level protected-binary workflows that orchestrate the runtime tools.

These compose the lower-level tools (sandbox lifecycle, anti-debug, composite capture)
into one-call investigations and return a single consolidated report.
"""

from __future__ import annotations

import subprocess

from x64dbg_automate.api_runtime.api_antidebug import attach_safe
from x64dbg_automate.api_runtime.api_composite import find_crypto_material
from x64dbg_automate.api_runtime.api_memory import resolve_iat_slot
from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, lookup_error, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import capture_registers, resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.api_runtime.utils import detect_crypto_constants, parse_region
from x64dbg_automate.external.entropy import shannon_entropy


@tool
def workflow_capture_binary_state(
    target_exe: str,
    regions: list[str] | None = None,
    iat_slots: list[str] | None = None,
    serial_window_title: str = "",
    x64dbg_path: str = "",
    timeout_sec: int = 120,
    keep_sandbox: bool = False,
) -> dict:
    """One-call runtime capture: launch undebugged, attach after decryption, extract.

    Dual-path: the target is launched WITHOUT a debugger so its startup decryption/anti-debug
    runs unimpeded; once its serial dialog appears (tables are initialized in RAM), a sandbox
    attaches with anti-debug evasion and captures the requested tables + crypto material.

    Args:
        target_exe: Full path to the protected executable.
        regions: Tables to capture as 'addr:size' (default: identity array + bitmask table).
        iat_slots: IAT slot addresses to resolve to crypto functions.
        serial_window_title: Window-title substring signaling decryption is complete.
        x64dbg_path: Path to x64dbg/x96dbg (falls back to X64DBG_PATH).
        timeout_sec: Max seconds to wait for the serial dialog.
        keep_sandbox: If true, leave the sandbox alive for further inspection.
    """
    from x64dbg_automate.external.process_dumper import wait_for_window

    regions = regions or ["0x448300:4096", "0x44A460:1152"]
    iat_slots = iat_slots or ["0x43D070"]
    report: dict = {"target_exe": target_exe, "steps": []}

    parsed_regions: list[tuple[int, int]] = []
    for spec in regions:
        try:
            parsed_regions.append(parse_region(spec))
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)

    # 1. Launch without a debugger.
    try:
        proc = subprocess.Popen([target_exe], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001
        return err(f"Failed to launch target: {exc}", classify_exception(exc))
    pid = proc.pid
    report["launched_pid"] = pid
    report["steps"].append(f"launched {target_exe} (pid {pid}) without debugger")

    # 2. Wait for the serial dialog (decryption complete).
    if not wait_for_window(pid, serial_window_title, timeout_sec):
        _kill(pid)
        return err(f"Serial window '{serial_window_title}' not seen within {timeout_sec}s.",
                   ErrorType.TIMEOUT, **report)
    report["steps"].append(f"observed window containing '{serial_window_title}'")

    # 3. Attach a sandbox to the running, decrypted process.
    mgr = get_manager()
    try:
        sandbox = mgr.create_sandbox(attach_pid=pid, x64dbg_path=x64dbg_path)
    except Exception as exc:  # noqa: BLE001
        _kill(pid)
        return err(f"Failed to attach sandbox: {exc}", classify_exception(exc), **report)
    sandbox_id = sandbox.sandbox_id
    report["sandbox_id"] = sandbox_id
    report["steps"].append(f"attached sandbox {sandbox_id} ({sandbox.debugger_arch})")

    try:
        client = mgr.get_client(sandbox_id)

        # 4. Anti-debug evasion.
        report["attach_safe"] = attach_safe(sandbox_id)

        # 5. Capture the requested tables (already initialized by now → read directly).
        mgr._ensure_stopped(client)
        captured: dict[str, dict] = {}
        for (addr, size), spec in zip(parsed_regions, regions):
            data = client.read_memory(addr, size)
            captured[spec] = {
                "address": f"0x{addr:X}",
                "size": size,
                "entropy": round(shannon_entropy(data), 4),
                "nonzero_bytes": sum(1 for b in data if b),
                "crypto_detected": detect_crypto_constants(data, base_addr=addr),
                "bytes": to_hex(data),
            }
        report["tables"] = captured

        # 6. Resolve IAT slots.
        report["iat"] = {slot: resolve_iat_slot(sandbox_id, slot) for slot in iat_slots}

        # 7. Broad crypto scan of the main image.
        report["crypto_scan"] = find_crypto_material(sandbox_id)
    except Exception as exc:  # noqa: BLE001
        report["error_during_capture"] = str(exc)
    finally:
        if not keep_sandbox:
            try:
                mgr.destroy_sandbox(sandbox_id)
                report["steps"].append(f"destroyed sandbox {sandbox_id}")
            except Exception:
                pass
            _kill(pid)

    return ok(**report)


@tool
def workflow_trace_crypto_pipeline(*, 
    sandbox_id: str | None = None,
    stages: list[str],
    watch_regions: list[str] | None = None,
    timeout_sec: int = 30,
) -> dict:
    """Trace an ordered set of pipeline stages, capturing registers + watched regions at each.

    Set a breakpoint at each stage in order, resume, and on each hit record the registers and
    the contents (with crypto detection) of the watched regions. Builds a timeline of how data
    flows through e.g. serial -> token -> XOR -> KSA -> cipher.

    Args:
        sandbox_id: Sandbox to operate on (already attached/hardened).
        stages: Ordered stage breakpoints as 'name@addr' or just 'addr' (address/symbol/expr).
        watch_regions: Regions to snapshot at each stage, as 'addr:size'.
        timeout_sec: Max seconds to wait for each stage breakpoint.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    sandbox = mgr.get_sandbox(sandbox_id)
    arch = sandbox.debugger_arch

    parsed_watch: list[tuple[int, int]] = []
    for spec in (watch_regions or []):
        try:
            parsed_watch.append(parse_region(spec))
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)

    parsed_stages: list[tuple[str, int]] = []
    for spec in stages:
        name, _, addr_part = spec.partition("@")
        addr_str = addr_part if addr_part else name
        try:
            parsed_stages.append((name if addr_part else addr_str, resolve_addr(client, addr_str)))
        except ValueError as exc:
            return err(f"Bad stage '{spec}': {exc}", ErrorType.BAD_ARGUMENT)

    timeline: list[dict] = []
    try:
        for name, addr in parsed_stages:
            client.set_breakpoint(addr, singleshoot=True)
            reached = client.go() and client.wait_until_stopped(timeout_sec)
            stage_entry: dict = {"stage": name, "addr": f"0x{addr:X}", "reached": bool(reached)}
            if not reached:
                stage_entry["note"] = "stage breakpoint not reached before timeout"
                timeline.append(stage_entry)
                break
            stage_entry["registers"] = capture_registers(client, arch)
            region_snaps: dict[str, dict] = {}
            for raddr, rsize in parsed_watch:
                data = client.read_memory(raddr, rsize)
                region_snaps[f"0x{raddr:X}:{rsize}"] = {
                    "entropy": round(shannon_entropy(data), 4),
                    "crypto_detected": detect_crypto_constants(data, base_addr=raddr),
                    "bytes": to_hex(data),
                }
            if region_snaps:
                stage_entry["regions"] = region_snaps
            timeline.append(stage_entry)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id, timeline=timeline)

    return ok(sandbox_id=sandbox_id, stages_reached=sum(1 for t in timeline if t.get("reached")),
              timeline=timeline)


def _kill(pid: int) -> None:
    try:
        import psutil

        psutil.Process(pid).kill()
    except Exception:
        pass
