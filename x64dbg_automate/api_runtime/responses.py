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


_ERROR_HINTS: dict[str, str] = {
    ErrorType.NOT_CONNECTED:       "Call start_session or connect_to_session first.",
    ErrorType.TIMEOUT:             "Increase wait_timeout or reduce the size of the operation.",
    ErrorType.INVALID_STATE:       "Check get_debugger_status — the process may not be in the expected run/paused state.",
    ErrorType.BAD_ARGUMENT:        "Check address/expression format: use '0x401000', a register name like 'RIP', or a symbol like 'kernel32:CreateFileA'.",
    ErrorType.PERMISSION_DENIED:   "Run as administrator. Some operations require elevated privileges.",
    ErrorType.RPC_ERROR:           "x64dbg plugin returned failure. Check get_debugger_status or reconnect.",
    ErrorType.NOT_FOUND:           "Verify the address or symbol exists. Use get_memory_map or get_modules to find valid ranges.",
    ErrorType.ANTI_DEBUG_TRIGGERED:"Use sandbox_create() on a clean clone before attaching.",
    ErrorType.SNAPSHOT_FAILED:     "Ensure the process is accessible and not protected by anti-dump.",
    ErrorType.READ_ONLY:           "Server is in read-only mode (X64DBG_MCP_READ_ONLY=1). Unsafe operations are blocked.",
    ErrorType.UNSUPPORTED:         "This operation is not supported in the current debugger mode.",
    ErrorType.UNKNOWN:             "Use get_debugger_status to check the current debugger state.",
}


def err_from_exc(exc: BaseException, **context: Any) -> dict:
    """Build a structured error from an exception with auto-classified type and hint.

    Re-raises programming errors (AttributeError, NameError, NotImplementedError)
    so they surface as bugs rather than being silently swallowed.
    """
    if is_bug(exc):
        raise exc
    etype = classify_exception(exc)
    hint = _ERROR_HINTS.get(etype, _ERROR_HINTS[ErrorType.UNKNOWN])
    return err(str(exc), etype, hint=hint, **context)


def is_bug(exc: BaseException) -> bool:
    """Return True if this exception signals a programming error that should propagate.

    Bare ``except Exception`` clauses in tools catch everything, including
    ``AttributeError`` from a misspelled method name.  By re-raising those we
    keep real bugs visible during development while still returning structured
    errors for genuine runtime failures.
    """
    return isinstance(exc, (AttributeError, NameError, NotImplementedError))
