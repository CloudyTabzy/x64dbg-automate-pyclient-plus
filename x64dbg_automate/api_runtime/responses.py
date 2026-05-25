"""Structured response shape shared by every runtime API tool.

Every runtime tool returns a JSON-serializable ``dict`` with a stable base shape so
AI agents can reason about results and recover from errors deterministically:

    {
        "success": bool,
        # on success: tool-specific fields
        # on failure: "error", "error_type", and an optional "hint"
        ...
    }

Bytes are never returned raw (not JSON-serializable); use :func:`to_hex`.
"""

from __future__ import annotations

from typing import Any


class ErrorType:
    """Standardized ``error_type`` values. Agents can branch on these."""

    NOT_FOUND = "NOT_FOUND"                       # address/symbol/sandbox doesn't exist
    TIMEOUT = "TIMEOUT"                            # operation exceeded its time budget
    INVALID_STATE = "INVALID_STATE"               # process not in the expected run state
    PERMISSION_DENIED = "PERMISSION_DENIED"       # needs elevation / access
    ANTI_DEBUG_TRIGGERED = "ANTI_DEBUG_TRIGGERED" # target detected the debugger
    SNAPSHOT_FAILED = "SNAPSHOT_FAILED"           # PssCaptureSnapshot / dump failed
    NOT_CONNECTED = "NOT_CONNECTED"               # no debugger client for the sandbox
    BAD_ARGUMENT = "BAD_ARGUMENT"                 # malformed/region/expression argument
    RPC_ERROR = "RPC_ERROR"                       # underlying x64dbg RPC failed
    READ_ONLY = "READ_ONLY"                       # blocked by read-only server mode
    UNSUPPORTED = "UNSUPPORTED"                   # operation not supported in this mode
    UNKNOWN = "UNKNOWN"


def ok(**fields: Any) -> dict:
    """Build a success response carrying the given tool-specific fields."""
    result: dict[str, Any] = {"success": True}
    result.update(fields)
    return result


def err(
    message: str,
    error_type: str = ErrorType.UNKNOWN,
    hint: str | None = None,
    **fields: Any,
) -> dict:
    """Build a failure response.

    Args:
        message: Human-readable error description.
        error_type: One of :class:`ErrorType` for programmatic branching.
        hint: Optional concrete suggestion for how the agent should recover.
        **fields: Extra context (e.g. ``sandbox_id``, ``addr``) to echo back.
    """
    result: dict[str, Any] = {"success": False, "error": message, "error_type": error_type}
    if hint:
        result["hint"] = hint
    result.update(fields)
    return result


def to_hex(data: bytes) -> str:
    """Encode bytes as a lowercase hex string (JSON-safe). Empty for falsy input."""
    if not data:
        return ""
    return data.hex()


def lookup_error(exc: BaseException) -> dict:
    """Map a sandbox lookup/availability failure to a structured error.

    Identifies types by name to avoid importing the supervisor (layering).
    """
    name = type(exc).__name__
    msg = str(exc).strip("'\"")
    if name == "KeyError":
        return err(msg, ErrorType.NOT_FOUND, hint="Use sandbox_list to see active sandbox ids.")
    if name == "SandboxError":
        return err(msg, ErrorType.INVALID_STATE, hint="The sandbox has no live debugger; recreate it.")
    return err(msg, classify_exception(exc))


def classify_exception(exc: BaseException) -> str:
    """Best-effort mapping from a raised exception to an :class:`ErrorType`."""
    name = type(exc).__name__
    msg = str(exc).lower()
    if isinstance(exc, TimeoutError) or "timeout" in msg or "timed out" in msg:
        return ErrorType.TIMEOUT
    if isinstance(exc, (KeyError, LookupError)) or "not found" in msg or "no such" in msg:
        return ErrorType.NOT_FOUND
    if isinstance(exc, (ValueError, TypeError)):
        return ErrorType.BAD_ARGUMENT
    if "access" in msg or "denied" in msg or "elevat" in msg or "administrator" in msg:
        return ErrorType.PERMISSION_DENIED
    if name == "RuntimeError" and "xerror_" in msg:
        return ErrorType.RPC_ERROR
    if "not connected" in msg or "no active" in msg:
        return ErrorType.NOT_CONNECTED
    return ErrorType.UNKNOWN
