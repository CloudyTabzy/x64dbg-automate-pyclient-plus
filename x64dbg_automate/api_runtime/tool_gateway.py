"""Universal tool gateway for Axon MCP.

The ``@guarded`` decorator wraps every runtime tool with:
1. Pre-flight ``ensure_running()`` — resumes x64dbg if unexpectedly paused
2. State-machine tracking — records debugger state before/after
3. Structured error responses — converts exceptions into agent-actionable dicts
4. Optional timeout enforcement
5. Read-only safety enforcement

Usage::

    @tool
    @guarded(pre_flight=True, timeout=30.0)
    def read_memory(*, sandbox_id: str | None = None, address: str, size: int) -> dict:
        ...
"""

from __future__ import annotations

import functools
import inspect
import time
from typing import Callable, TypeVar

from x64dbg_automate.api_runtime.registry import tool as _registry_tool, _REGISTERED, is_unsafe
from x64dbg_automate.api_runtime.responses import ErrorType, err, ok
from x64dbg_automate.api_runtime.supervisor import get_manager, SandboxError

T = TypeVar("T")


def _resolve_client(kwargs: dict):
    """Extract sandbox_id from kwargs and return the corresponding client."""
    sandbox_id = kwargs.get("sandbox_id")
    mgr = get_manager()
    return mgr.get_client(sandbox_id)


def guarded(
    pre_flight: bool = True,
    post_flight: bool = True,
    timeout: float | None = None,
    enforce_readonly: bool = True,
):
    """Decorator that hardens an MCP tool against debugger stalls.

    Args:
        pre_flight: Call ``ensure_running()`` before executing the tool.
        post_flight: Validate debugger state after execution.
        timeout: If set, wrap the tool body in a time limit.
        enforce_readonly: Block ``@unsafe`` tools when ``X64DBG_MCP_READ_ONLY=1``.
    """
    def decorator(fn: Callable[..., dict]) -> Callable[..., dict]:
        is_tool = hasattr(fn, "_mcp_tool_name")
        tool_name = getattr(fn, "_mcp_tool_name", fn.__name__)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> dict:
            # ── Read-only safety ────────────────────────────────────────────
            if enforce_readonly and is_unsafe(tool_name):
                return err(
                    f"Tool '{tool_name}' is marked unsafe and read-only mode is active.",
                    ErrorType.UNSAFE_OPERATION,
                    hint="Set X64DBG_MCP_READ_ONLY=0 or use a read-safe alternative.",
                )

            # ── Resolve client & state machine ──────────────────────────────
            try:
                client = _resolve_client(kwargs)
            except (KeyError, SandboxError) as exc:
                return err(str(exc), ErrorType.NOT_CONNECTED)

            # Attach state machine if not present
            from x64dbg_automate.api_runtime.debugger_state import DebuggerStateMachine, DebuggerState
            if not hasattr(client, "_axon_state_machine"):
                client._axon_state_machine = DebuggerStateMachine()
            sm = client._axon_state_machine

            # ── Pre-flight: ensure running ──────────────────────────────────
            if pre_flight:
                try:
                    if not client.ensure_running(timeout=2.0):
                        sm.transition(DebuggerState.ERROR, reason="ensure_running() failed pre-flight")
                        return err(
                            "Debugger is paused and could not be resumed.",
                            ErrorType.TIMEOUT,
                            hint="The debuggee may be stopped at a breakpoint or exception. "
                                 "Use 'get_debugger_state' to inspect, then 'go' or 'stepi' manually.",
                        )
                except Exception as exc:
                    sm.transition(DebuggerState.ERROR, reason=f"pre_flight exception: {exc}")
                    return err(f"Pre-flight resume failed: {exc}", ErrorType.UNKNOWN)

            # ── Execute tool body ───────────────────────────────────────────
            start = time.time()
            try:
                if timeout is not None:
                    # Simple elapsed-time guard (not a hard thread timeout, but
                    # sufficient for cooperative x64dbg RPC operations)
                    result = fn(*args, **kwargs)
                    elapsed = time.time() - start
                    if elapsed > timeout:
                        return err(
                            f"Tool '{tool_name}' exceeded {timeout}s timeout ({elapsed:.2f}s elapsed).",
                            ErrorType.TIMEOUT,
                            hint="The operation may have stalled due to a paused debuggee. "
                                 "Check 'get_debugger_state' and use 'force_resume' if needed.",
                        )
                else:
                    result = fn(*args, **kwargs)
            except Exception as exc:
                sm.transition(DebuggerState.ERROR, reason=f"{tool_name} exception: {exc}")
                return err(
                    f"{tool_name} failed: {exc}",
                    ErrorType.UNKNOWN,
                    hint="Check the debuggee state with 'get_debugger_state'.",
                )

            # ── Post-flight: validate state ─────────────────────────────────
            if post_flight:
                try:
                    if not client.is_running() and not client.is_debugging():
                        sm.transition(DebuggerState.DISCONNECTED, reason="post_flight: not debugging")
                    elif not client.is_running():
                        sm.transition(DebuggerState.STOPPED, reason="post_flight: paused after tool")
                    else:
                        sm.transition(DebuggerState.RUNNING, reason="post_flight: running after tool")
                except Exception:
                    pass

            # Ensure we always return a dict
            if not isinstance(result, dict):
                return ok(raw_result=str(result))
            return result

        # Preserve MCP tool metadata if present
        if is_tool:
            wrapper._mcp_tool_name = tool_name
        return wrapper
    return decorator
