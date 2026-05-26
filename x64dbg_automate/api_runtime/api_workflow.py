"""High-level protected-binary workflows that orchestrate the runtime tools.

These compose the lower-level tools (sandbox lifecycle, anti-debug, composite capture)
into one-call investigations and return a single consolidated report.
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import classify_exception, err, ok, to_hex
from x64dbg_automate.api_runtime.runtime_helpers import capture_registers, resolve_addr
from x64dbg_automate.api_runtime.supervisor import get_manager
from x64dbg_automate.api_runtime.utils import detect_crypto_constants, parse_region
from x64dbg_automate.external.entropy import shannon_entropy


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
    flows through e.g. input -> token -> XOR -> KSA -> cipher.

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



