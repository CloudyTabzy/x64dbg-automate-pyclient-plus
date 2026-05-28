"""Infrastructure and visibility tools for Axon MCP (Category C15/C16 extended).

Provides AI agents with explicit control over and visibility into the debugger's
execution state.  These tools complement the hardened ``running_guard`` and
``ensure_running`` mechanisms by giving agents structured queries instead of
forcing them to guess why an operation stalled.
"""

from __future__ import annotations

import os

from x64dbg_automate.api_runtime.registry import get_telemetry, reset_telemetry, tool
from x64dbg_automate.api_runtime.responses import ErrorType, err, lookup_error, ok
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

# System DLLs that generate automatic pause events during process startup
# (system breakpoint, DLL load, WOW64 thunk). sandbox_run_to_entry auto-resumes
# through these so agents land cleanly at the target entry point.
_STARTUP_SKIP_MODULES = frozenset({
    # Core OS loader / WOW64 thunk layer
    "ntdll.dll", "ntdll32.dll",
    "kernel32.dll", "kernelbase.dll",
    "wow64.dll", "wow64win.dll", "wow64cpu.dll",
    # Windows system DLLs with TLS callbacks that fire during complex process startups
    # (reported in V5 feedback: dbghelp.dll and gdi32full.dll trigger repeated paused_event
    # stops that prevent sandbox_run_to_entry from reaching the target entry point)
    "dbghelp.dll",
    "gdi32full.dll",
    "ucrtbase.dll",
    "vcruntime140.dll", "vcruntime140_1.dll",
    "msvcp140.dll", "msvcp_win.dll",
    "concrt140.dll",
})


@tool
def get_debugger_state(*, sandbox_id: str | None = None) -> dict:
    """Return the current debugger state-machine snapshot.

    Includes current state (running/stopped/paused_event/etc.), recent
    transitions, and health status.  Use this after any timeout or
    unexpected pause to understand what x64dbg is doing.

    Returns:
        Dict with ``state``, ``is_healthy``, ``recent_transitions``,
        ``is_executing``, ``is_paused``.
    """
    try:
        mgr = get_manager()
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    sm = getattr(client, "_axon_state_machine", None)
    if sm is None:
        # Fallback: simple polling
        try:
            running = client.is_running()
            debugging = client.is_debugging()
        except Exception as exc:
            return err(f"State query failed: {exc}", ErrorType.UNKNOWN)
        state = "running" if running else ("stopped" if debugging else "disconnected")
        return ok(
            state=state,
            is_healthy=debugging,
            is_executing=running,
            is_paused=debugging and not running,
            recent_transitions=[],
            hint="Install the hardened client for full state-machine tracking.",
        )

    recent = [
        {
            "from": tx.from_state,
            "to": tx.to_state,
            "reason": tx.reason,
            "event_type": tx.event_type,
            "timestamp": tx.timestamp,
        }
        for tx in sm.get_recent_events(20)
    ]

    return ok(
        state=sm.current_state,
        is_healthy=sm.is_healthy(),
        is_executing=sm.is_executing(),
        is_paused=sm.is_paused(),
        recent_transitions=recent,
    )


@tool
def wait_for_stable_state(
    *,
    sandbox_id: str | None = None,
    desired_state: str = "running",
    timeout: float = 10.0,
    poll_interval: float = 0.25,
) -> dict:
    """Block until the debugger reaches a desired stable state.

    Useful after ``sandbox_continue`` or ``go()`` to confirm the debuggee
    transitioned to the expected state before making further queries.

    Args:
        desired_state: One of ``running``, ``stopped``, ``paused``,
                       ``paused_event`` (DLL-load / OutputDebugString pauses),
                       or ``paused_breakpoint``.  ``paused`` matches any
                       non-running stopped state.
        timeout: Max seconds to wait (default 10).
        poll_interval: Seconds between polls (default 0.25).

    Returns:
        Dict with ``reached`` (bool), ``actual_state``, and ``waited`` seconds.
    """
    import time

    try:
        mgr = get_manager()
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    desired = desired_state.lower().strip()
    _valid = {"running", "stopped", "paused", "paused_event", "paused_breakpoint"}
    if desired not in _valid:
        return err(
            f"Unknown desired_state '{desired_state}'. Valid: {', '.join(sorted(_valid))}.",
            ErrorType.BAD_ARGUMENT,
        )

    end = time.time() + timeout
    actual = "unknown"  # always defined so the timeout branch can reference it

    while time.time() < end:
        try:
            running = client.is_running()
            debugging = client.is_debugging()
        except Exception as exc:
            return err(f"State poll failed: {exc}", ErrorType.UNKNOWN)

        # Derive actual state — prefer the state machine when available for
        # paused_event vs paused_breakpoint discrimination.
        if not debugging:
            actual = "disconnected"
        elif running:
            actual = "running"
        else:
            sm = getattr(client, "_axon_state_machine", None)
            if sm is not None:
                sm_state = str(sm.current_state)
                actual = sm_state if sm_state in _valid else "paused"
            else:
                actual = "paused"

        # Early-exit on disconnected so callers don't loop until timeout.
        if actual == "disconnected":
            return err(
                "Debugger disconnected while waiting.",
                ErrorType.NOT_CONNECTED,
                hint="The debuggee may have exited. Use sandbox_info to inspect.",
                actual_state=actual,
            )

        waited = timeout - (end - time.time())
        if actual == desired:
            return ok(reached=True, actual_state=actual, waited=waited)
        # "paused" is a superset that matches any non-running state.
        if desired == "paused" and actual in ("paused", "paused_event", "paused_breakpoint", "stopped"):
            return ok(reached=True, actual_state=actual, waited=waited)
        # "stopped" and generic "paused" are interchangeable in many callers.
        if desired == "stopped" and actual in ("stopped", "paused", "paused_breakpoint"):
            return ok(reached=True, actual_state=actual, waited=waited)

        time.sleep(poll_interval)

    return err(
        f"Timeout waiting for state '{desired}' after {timeout}s.",
        ErrorType.TIMEOUT,
        hint=(
            "Use get_debugger_state to inspect. If stuck at a startup event, "
            "call sandbox_run_to_entry instead of sandbox_continue."
        ),
        actual_state=actual,
    )


@tool
def force_resume(
    *,
    sandbox_id: str | None = None,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
) -> dict:
    """Emergency resume — calls ``go()`` up to 3 times with error swallowing.

    Use this when the debuggee is paused on an untracked event and the
    agent needs to unblock execution immediately.  This is a "big hammer";
    prefer ``running_guard`` for normal flow control.

    Args:
        pass_exceptions: Pass exceptions to the debuggee.
        swallow_exceptions: Swallow exceptions (silently continue).

    Returns:
        Dict with ``attempts`` and ``success``.
    """
    import time

    try:
        mgr = get_manager()
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    if pass_exceptions and swallow_exceptions:
        return err(
            "Cannot pass and swallow exceptions simultaneously.",
            ErrorType.BAD_ARGUMENT,
        )

    for attempt in range(1, 4):
        try:
            if client.go(pass_exceptions=pass_exceptions, swallow_exceptions=swallow_exceptions):
                return ok(success=True, attempts=attempt)
        except Exception:
            pass
        time.sleep(0.1)

    return err(
        "force_resume failed after 3 attempts.",
        ErrorType.UNKNOWN,
        hint="x64dbg may be hung or the debuggee may have crashed. "
             "Try 'session_summary' to inspect, or restart the sandbox.",
    )


@tool
def sandbox_run_to_entry(
    *,
    sandbox_id: str | None = None,
    timeout_sec: float = 30.0,
) -> dict:
    """Run the debuggee from the system breakpoint to its executable entry point.

    Process startup fires a succession of automatic pauses — system breakpoint,
    DLL load events, WOW64 thunk, optional TLS callbacks — that defeat simple
    ``go()`` / ``sandbox_continue`` loops.  This tool handles them all:

    * Sets a one-shot breakpoint at the target module's entry point.
    * Loops calling ``go()`` and auto-resumes whenever the pause is inside a
      known OS startup module (ntdll, kernel32, kernelbase, wow64*).
    * Stops and reports if the process halts in **non-startup code** that is not
      the entry point (a user-set breakpoint fired before EP, or an exception) —
      giving the agent full visibility rather than blindly continuing.

    Use this immediately after ``sandbox_create`` instead of ``sandbox_continue``
    to reliably land at the entry point.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        timeout_sec: Max seconds to wait (default 30). Increase for slow loaders.

    Returns:
        On success: ``reached_entry=True``, ``entry_point``, ``module``,
        ``resume_count``, ``registers``.
        On non-startup stop: ``reached_entry=False``, ``current_ip``, ``module``.
    """
    import time

    from x64dbg_automate.api_runtime.runtime_helpers import capture_registers

    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    if sandbox.client is None:
        return err(
            f"Sandbox '{sandbox.sandbox_id}' has no active debugger client.",
            ErrorType.NOT_CONNECTED,
        )

    client = sandbox.client
    arch = sandbox.debugger_arch
    ip_reg = "rip" if arch == "x64" else "eip"

    # ── locate the target module and its entry point ──────────────────────
    try:
        modules = client.get_modules() or []
    except Exception as exc:
        return err(f"get_modules failed: {exc}", ErrorType.RPC_ERROR,
                   hint="The process may not be at a loader pause yet. Try force_resume first.")

    target_module = None
    if sandbox.target_exe:
        exe_name = os.path.basename(sandbox.target_exe).lower()
        for m in modules:
            if m.name.lower() == exe_name or m.path.lower().endswith(os.sep + exe_name):
                target_module = m
                break
    if target_module is None:
        for m in modules:
            if not m.name.lower().endswith(".dll"):
                target_module = m
                break
    if target_module is None and modules:
        target_module = modules[0]

    if target_module is None:
        return err(
            "No modules loaded yet — cannot locate the entry point.",
            ErrorType.NOT_FOUND,
            hint="Ensure the process is past the initial system breakpoint. "
                 "Call force_resume once if needed, then retry.",
        )

    entry_point = target_module.entry
    if not entry_point:
        return err(
            f"Module '{target_module.name}' reports no entry point.",
            ErrorType.NOT_FOUND,
            hint="The target may be a pure-data DLL or x64dbg analysis has not run yet.",
        )

    # ── set a one-shot sentinel BP at the entry point ─────────────────────
    try:
        bp_ok = client.set_breakpoint(entry_point, name="__axon_run_to_entry__", singleshoot=True)
    except Exception as exc:
        bp_ok = False

    if not bp_ok:
        # EP may already be set (duplicate) or already past it — check IP first.
        try:
            current_ip = client.get_reg(ip_reg)
        except Exception:
            current_ip = None
        if current_ip == entry_point:
            regs = capture_registers(client, arch)
            return ok(
                sandbox_id=sandbox.sandbox_id,
                reached_entry=True,
                entry_point=f"0x{entry_point:X}",
                module=target_module.name,
                resume_count=0,
                registers=regs,
                note="Already at entry point.",
            )
        # A pre-existing BP at the entry point (e.g. set by sandbox_create or a
        # previous run) can serve as our sentinel — reuse it rather than failing.
        _pre_existing = False
        try:
            from x64dbg_automate.models import BreakpointType
            existing = client.get_breakpoints(BreakpointType.BpNormal) or []
            _pre_existing = any(bp.addr == entry_point for bp in existing)
        except Exception:
            pass
        if not _pre_existing:
            return err(
                f"Could not set entry-point breakpoint at 0x{entry_point:X}.",
                ErrorType.RPC_ERROR,
                hint="A duplicate breakpoint may exist or the address is not executable. "
                     "Check breakpoint_list and clear any conflicts.",
            )

    # ── drive through startup events until we reach the entry point ───────
    deadline = time.time() + timeout_sec
    resume_count = 0
    _current_modules = {m.name.lower(): m for m in modules}

    def _refresh_modules():
        try:
            for m in (client.get_modules() or []):
                _current_modules[m.name.lower()] = m
        except Exception:
            pass

    def _module_for_ip(ip: int):
        for m in _current_modules.values():
            if m.base <= ip < m.base + m.size:
                return m
        return None

    # Kick off execution if currently paused.
    try:
        if not client.is_running():
            client.go()
            resume_count += 1
    except Exception:
        pass

    while time.time() < deadline:
        time.sleep(0.1)

        try:
            running = client.is_running()
        except Exception:
            running = False

        if running:
            continue  # still executing — wait for the next stop

        # Process is paused — determine where.
        try:
            current_ip = client.get_reg(ip_reg)
        except Exception:
            current_ip = None

        if current_ip == entry_point:
            # ✓ Reached the entry point.
            try:
                client.clear_breakpoint(entry_point)
            except Exception:
                pass
            mgr.refresh_state(sandbox)
            regs = capture_registers(client, arch)
            return ok(
                sandbox_id=sandbox.sandbox_id,
                reached_entry=True,
                entry_point=f"0x{entry_point:X}",
                module=target_module.name,
                resume_count=resume_count,
                registers=regs,
            )

        # Not at entry point. Classify the stop.
        _refresh_modules()
        ip_mod = _module_for_ip(current_ip) if current_ip is not None else None
        ip_mod_name = ip_mod.name.lower() if ip_mod else ""

        if ip_mod_name in _STARTUP_SKIP_MODULES or ip_mod is None:
            # Startup event (system DLL or unknown) — resume automatically.
            try:
                client.go()
                resume_count += 1
            except Exception:
                pass
            continue

        # Stopped in user / non-startup code that is NOT the entry point.
        # A user-set breakpoint or exception fired before EP. Report and stop.
        try:
            client.clear_breakpoint(entry_point)
        except Exception:
            pass
        mgr.refresh_state(sandbox)
        regs = capture_registers(client, arch)
        return ok(
            sandbox_id=sandbox.sandbox_id,
            reached_entry=False,
            current_ip=f"0x{current_ip:X}" if current_ip is not None else None,
            entry_point=f"0x{entry_point:X}",
            module=ip_mod.name if ip_mod else None,
            resume_count=resume_count,
            registers=regs,
            note=(
                f"Process paused in '{ip_mod.name if ip_mod else 'unknown'}' before the entry point — "
                "a user breakpoint or exception fired first. "
                "Call sandbox_continue to proceed toward the entry point."
            ),
        )

    # ── timeout ───────────────────────────────────────────────────────────
    try:
        client.clear_breakpoint(entry_point)
    except Exception:
        pass
    try:
        current_ip = client.get_reg(ip_reg)
        ip_str = f"0x{current_ip:X}"
    except Exception:
        ip_str = "unknown"

    return err(
        f"Timed out after {timeout_sec}s waiting to reach entry point 0x{entry_point:X}.",
        ErrorType.TIMEOUT,
        hint=(
            "Increase timeout_sec for slow loaders, or inspect with get_debugger_state. "
            "If stuck in a user module, a breakpoint fired before EP — use sandbox_continue."
        ),
        sandbox_id=sandbox.sandbox_id,
        entry_point=f"0x{entry_point:X}",
        module=target_module.name,
        current_ip=ip_str,
        resume_count=resume_count,
    )


@tool
def get_execution_log(*, sandbox_id: str | None = None, n: int = 20) -> dict:
    """Return the recent execution event log.

    Shows state transitions, auto-resume triggers, and untracked pauses.
    This is the "flight recorder" for the hardened execution infrastructure.

    Args:
        n: Number of recent transitions to return.

    Returns:
        Dict with ``transitions`` list.
    """
    try:
        mgr = get_manager()
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    sm = getattr(client, "_axon_state_machine", None)
    if sm is None:
        return err(
            "State machine not initialized.",
            ErrorType.NOT_CONNECTED,
            hint="Use a sandbox created with the hardened client.",
        )

    transitions = [
        {
            "from": tx.from_state,
            "to": tx.to_state,
            "reason": tx.reason,
            "event_type": tx.event_type,
            "timestamp": tx.timestamp,
        }
        for tx in sm.get_recent_events(n)
    ]

    return ok(transitions=transitions, count=len(transitions))



@tool
def tool_usage_stats(reset: bool = False) -> dict:
    """Return per-tool usage statistics: call counts, error rates, average latency.

    Helps agents and operators understand which tools are heavily used, which
    fail often, and where latency hotspots exist. Pass ``reset=True`` to clear
    all counters after reading.

    Args:
        reset: If True, zero all counters after returning the snapshot.

    Returns:
        Dict with ``tools`` list (name, calls, errors, avg_ms, success_rate)
        and aggregate totals.
    """
    raw = get_telemetry()
    if not raw:
        return ok(
            tools=[], total_calls=0, total_errors=0, avg_latency_ms=0.0,
            note="No telemetry recorded yet.",
        )

    tools: list[dict] = []
    total_calls = 0
    total_errors = 0
    total_ms = 0.0

    for name, data in sorted(raw.items()):
        calls = data.get("calls", 0)
        errors = data.get("errors", 0)
        ms = data.get("total_ms", 0.0)
        avg_ms = round(ms / calls, 3) if calls else 0.0
        success_rate = round((calls - errors) / calls * 100, 1) if calls else 0.0
        tools.append({
            "name": name,
            "calls": calls,
            "errors": errors,
            "avg_ms": avg_ms,
            "success_rate": success_rate,
        })
        total_calls += calls
        total_errors += errors
        total_ms += ms

    overall_avg = round(total_ms / total_calls, 3) if total_calls else 0.0

    result = ok(
        tools=tools,
        total_calls=total_calls,
        total_errors=total_errors,
        avg_latency_ms=overall_avg,
        tool_count=len(tools),
    )

    if reset:
        reset_telemetry()
        result["reset"] = True

    return result
