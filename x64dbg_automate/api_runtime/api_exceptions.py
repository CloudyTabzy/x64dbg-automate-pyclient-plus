"""Exception handling control tools (Phase 9 C7).

Wraps x64dbg's exception breakpoint commands over the existing ``cmd_sync``
RPC channel — no new C++ commands needed.

Exception actions:
    ``"break"``    — Set an exception breakpoint (x64dbg pauses on first-chance).
    ``"pass"``     — Delete the exception breakpoint (x64dbg passes to the handler).
    ``"second"``   — Break only on second-chance exceptions.
    ``"all"``      — Break on first AND second chance.

Common exception codes for protected binary analysis::

    0xC0000005  ACCESS_VIOLATION
    0xC0000094  INT_DIVIDE_BY_ZERO   ← anti-debug trap
    0xC0000096  PRIVILEGED_INSTRUCTION
    0xC000001D  ILLEGAL_INSTRUCTION
    0x80000003  BREAKPOINT (INT 3)
    0x80000004  SINGLE_STEP
    0xC0000025  NONCONTINUABLE_EXCEPTION

The ``get_breakpoints`` tool returns exception BPs with type ``BP_EXCEPTION``;
use it to list active exception breakpoints.
"""

from __future__ import annotations

# Well-known exception codes for documentation / display.
_EXCEPTION_NAMES: dict[int, str] = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0x80000003: "BREAKPOINT",
    0x80000004: "SINGLE_STEP",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC0000008: "INVALID_HANDLE",
    0xC0000374: "HEAP_CORRUPTION",
}

_VALID_ACTIONS = {"break", "pass", "second", "all"}

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, ok,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager


def _require_client(sandbox_id):
    mgr = get_manager()
    sandbox = mgr.get_sandbox(sandbox_id)
    if sandbox.client is None:
        raise SandboxError(f"Sandbox '{sandbox.sandbox_id}' has no active debugger client")
    return sandbox, sandbox.client


def _parse_exception_code(code_str: str) -> int | None:
    """Parse hex or decimal exception code string. Returns None on failure."""
    code_str = code_str.strip()
    try:
        return int(code_str, 0)
    except (ValueError, TypeError):
        return None


@tool
@unsafe
def exception_set_handler(
    *,
    sandbox_id: str | None = None,
    exception_code: str,
    action: str = "break",
) -> dict:
    """Configure how x64dbg handles a specific exception code.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        exception_code: NTSTATUS/exception code as hex or decimal string,
            e.g. ``"0xC0000094"`` or ``"3221225620"``.
        action: One of ``"break"`` (first-chance breakpoint), ``"second"``
            (second-chance only), ``"all"`` (first + second), or ``"pass"``
            (delete exception BP, let handler run).
    """
    action = action.lower().strip()
    if action not in _VALID_ACTIONS:
        return err(
            f"Unknown action '{action}'.",
            ErrorType.BAD_ARGUMENT,
            hint=f"Valid actions: {', '.join(sorted(_VALID_ACTIONS))}",
        )

    code = _parse_exception_code(exception_code)
    if code is None:
        return err(
            f"Cannot parse exception_code '{exception_code}'.",
            ErrorType.BAD_ARGUMENT,
            hint="Use hex (e.g. '0xC0000094') or decimal notation.",
        )

    try:
        sandbox, client = _require_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        from x64dbg_automate.api_runtime.responses import lookup_error
        return lookup_error(exc)

    try:
        get_manager().ensure_stopped(client)
        if action == "pass":
            client.cmd_sync(f"DeleteExceptionBPX 0x{code:X}")
        elif action == "second":
            client.cmd_sync(f"SetExceptionBPX 0x{code:X}, second")
        elif action == "all":
            client.cmd_sync(f"SetExceptionBPX 0x{code:X}, all")
        else:  # "break" = first chance
            client.cmd_sync(f"SetExceptionBPX 0x{code:X}, first")
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    name = _EXCEPTION_NAMES.get(code, f"0x{code:X}")
    return ok(
        sandbox_id=sandbox.sandbox_id,
        exception_code=f"0x{code:X}",
        exception_name=name,
        action=action,
    )


@tool
@unsafe
def exception_clear_handler(
    *,
    sandbox_id: str | None = None,
    exception_code: str,
) -> dict:
    """Remove an exception breakpoint for a specific exception code.

    Equivalent to ``exception_set_handler(action="pass")``.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        exception_code: Exception code as hex or decimal string.
    """
    return exception_set_handler(
        sandbox_id=sandbox_id,
        exception_code=exception_code,
        action="pass",
    )


@tool
def exception_list_known() -> dict:
    """Return the built-in table of well-known Windows exception codes.

    No debugger connection required — this is a static reference.

    Returns a list of ``{code, name}`` entries for common NTSTATUS exception
    codes, useful for protected binary anti-debug analysis.
    """
    entries = [
        {"code": f"0x{code:X}", "name": name}
        for code, name in sorted(_EXCEPTION_NAMES.items())
    ]
    return ok(exceptions=entries, total=len(entries))


@tool
@unsafe
def exception_configure_protected(*, sandbox_id: str | None = None) -> dict:
    """Apply the recommended exception handler configuration for protected binary analysis.

    Sets up x64dbg to:
    - **Pass** through INT_DIVIDE_BY_ZERO (0xC0000094) — anti-debug trap.
    - **Break** on ACCESS_VIOLATION (0xC0000005) — unexpected crashes.
    - **Pass** through SINGLE_STEP (0x80000004) — normal trace noise.

    This is the baseline recommended starting configuration; adjust per target.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    steps = [
        ("0xC0000094", "pass"),   # INT_DIVIDE_BY_ZERO — anti-debug trap, pass through
        ("0xC0000005", "break"),  # ACCESS_VIOLATION — real crash, break
        ("0x80000004", "pass"),   # SINGLE_STEP — trace noise, pass through
    ]
    applied: list[dict] = []
    for code_str, action in steps:
        result = exception_set_handler(
            sandbox_id=sandbox_id,
            exception_code=code_str,
            action=action,
        )
        applied.append({
            "exception_code": code_str,
            "action": action,
            "success": result.get("success", False),
        })

    all_ok = all(r["success"] for r in applied)
    return ok(
        sandbox_id=sandbox_id,
        applied=applied,
        all_succeeded=all_ok,
    )
