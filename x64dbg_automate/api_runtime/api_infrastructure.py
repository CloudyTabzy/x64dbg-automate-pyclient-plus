"""Infrastructure and visibility tools for Axon MCP (Category C15/C16 extended).

Provides AI agents with explicit control over and visibility into the debugger's
execution state.  These tools complement the hardened ``running_guard`` and
``ensure_running`` mechanisms by giving agents structured queries instead of
forcing them to guess why an operation stalled.
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, err, ok
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr


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

    Useful when an agent knows it just resumed execution (``go()``) and
    wants to confirm x64dbg is actually running before proceeding with
    memory reads or thread operations.

    Args:
        desired_state: One of ``running``, ``stopped``, ``paused``.
        timeout: Max seconds to wait.
        poll_interval: Seconds between polls.

    Returns:
        Dict with ``reached`` (bool) and ``actual_state``.
    """
    import time

    try:
        mgr = get_manager()
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return err(str(exc), ErrorType.NOT_CONNECTED)

    desired = desired_state.lower().strip()
    end = time.time() + timeout

    while time.time() < end:
        try:
            running = client.is_running()
            debugging = client.is_debugging()
        except Exception as exc:
            return err(f"State poll failed: {exc}", ErrorType.UNKNOWN)

        if not debugging:
            actual = "disconnected"
        elif running and desired == "running":
            return ok(reached=True, actual_state="running", waited=timeout - (end - time.time()))
        elif not running and desired == "stopped":
            return ok(reached=True, actual_state="stopped", waited=timeout - (end - time.time()))
        elif not running and desired == "paused" and debugging:
            return ok(reached=True, actual_state="paused", waited=timeout - (end - time.time()))

        time.sleep(poll_interval)

    return err(
        f"Timeout waiting for state '{desired}' after {timeout}s.",
        ErrorType.TIMEOUT,
        hint="Use 'get_debugger_state' to inspect, then 'force_resume' or 'stepi' manually.",
        actual_state=actual if 'actual' in dir() else "unknown",
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
