"""Tool registry and the read-only safety model for the runtime API.

Mirrors Synapse's ``@tool`` / ``@unsafe`` pattern. Functions decorated with
:func:`tool` are collected and later bound onto the FastMCP server by
:func:`register_all`. Functions also decorated with :func:`unsafe` are flagged as
state-mutating; when the server runs in read-only mode they are refused.

**Protocol-level safety hints:** Every registered tool carries MCP ``ToolAnnotations``
so AI clients can see ``readOnlyHint`` / ``destructiveHint`` before calling.
"""

from __future__ import annotations

import functools
import os
import threading
import time
from typing import Callable

from mcp.types import ToolAnnotations

from x64dbg_automate.api_runtime.responses import ErrorType, err

_REGISTERED: list[Callable] = []
_UNSAFE_NAMES: set[str] = set()

# ---------------------------------------------------------------------------
# Telemetry — per-tool call counts, errors, and timing
# ---------------------------------------------------------------------------
_telemetry_lock = threading.Lock()
_telemetry: dict[str, dict] = {}  # tool_name -> {"calls": int, "errors": int, "total_ms": float}


def _record_call(name: str, elapsed_ms: float, success: bool) -> None:
    with _telemetry_lock:
        entry = _telemetry.setdefault(name, {"calls": 0, "errors": 0, "total_ms": 0.0})
        entry["calls"] += 1
        entry["total_ms"] += elapsed_ms
        if not success:
            entry["errors"] += 1


def get_telemetry() -> dict[str, dict]:
    """Return a snapshot of per-tool usage statistics."""
    with _telemetry_lock:
        return {k: dict(v) for k, v in _telemetry.items()}


def reset_telemetry() -> None:
    """Clear all telemetry counters."""
    with _telemetry_lock:
        _telemetry.clear()


def _telemetry_wrap(func: Callable) -> Callable:
    """Wrap a tool function to capture call count, errors, and timing."""
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            success = bool(result.get("success")) if isinstance(result, dict) else True
        except Exception:
            success = False
            raise
        finally:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            _record_call(func.__name__, elapsed_ms, success)
        return result
    return _wrapper


def tool(func: Callable) -> Callable:
    """Register ``func`` as a runtime MCP tool. Wraps it with telemetry."""
    wrapped = _telemetry_wrap(func)
    if wrapped not in _REGISTERED:
        _REGISTERED.append(wrapped)
    return wrapped  # module-level name now refers to wrapped version


def unsafe(func: Callable) -> Callable:
    """Flag a tool as state-mutating (not read-only safe)."""
    _UNSAFE_NAMES.add(func.__name__)
    return func


def is_unsafe(name: str) -> bool:
    """True if the named tool is flagged ``@unsafe``."""
    return name in _UNSAFE_NAMES


def registered_tools() -> list[Callable]:
    """Snapshot of all registered tool callables (for introspection/tests)."""
    return list(_REGISTERED)


def read_only_enabled() -> bool:
    """Whether the server is configured to refuse state-mutating tools."""
    return os.environ.get("X64DBG_MCP_READ_ONLY", "").strip().lower() in ("1", "true", "yes", "on")


def _make_read_only_stub(func: Callable) -> Callable:
    @functools.wraps(func)
    def _stub(*args, **kwargs):
        return err(
            f"Tool '{func.__name__}' is disabled: server is in read-only mode.",
            error_type=ErrorType.READ_ONLY,
            hint="Unset X64DBG_MCP_READ_ONLY to enable state-mutating (@unsafe) tools.",
        )

    return _stub


def _tool_annotations(func: Callable) -> ToolAnnotations | None:
    """Build MCP ToolAnnotations for a registered function."""
    destructive = func.__name__ in _UNSAFE_NAMES
    return ToolAnnotations(
        title=func.__name__.replace("_", " ").title(),
        readOnlyHint=not destructive,
        destructiveHint=destructive,
        idempotentHint=not destructive,
    )


def register_all(mcp) -> int:
    """Bind every registered runtime tool onto a FastMCP instance.

    In read-only mode, ``@unsafe`` tools are bound to a stub that refuses to run
    (the schema is preserved so agents still see the tool and a clear reason).

    Returns:
        Number of tools registered.
    """
    read_only = read_only_enabled()
    count = 0
    for func in _REGISTERED:
        target = func
        if read_only and func.__name__ in _UNSAFE_NAMES:
            # Use __wrapped__ (preserved by functools.wraps) to get the original
            # function for the stub, then re-wrap with telemetry.
            orig = getattr(func, "__wrapped__", func)
            target = _telemetry_wrap(_make_read_only_stub(orig))
        mcp.tool(annotations=_tool_annotations(func))(target)
        count += 1
    return count
