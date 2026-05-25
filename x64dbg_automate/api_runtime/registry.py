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
from typing import Callable

from mcp.types import ToolAnnotations

from x64dbg_automate.api_runtime.responses import ErrorType, err

_REGISTERED: list[Callable] = []
_UNSAFE_NAMES: set[str] = set()


def tool(func: Callable) -> Callable:
    """Register ``func`` as a runtime MCP tool. Returns it unchanged (still callable)."""
    if func not in _REGISTERED:
        _REGISTERED.append(func)
    return func


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
            target = _make_read_only_stub(func)
        mcp.tool(annotations=_tool_annotations(func))(target)
        count += 1
    return count
