"""Code coverage tracking tools (Phase 9 C3).

Coverage is collected via the x64dbg TRACEEXECUTE plugin callback, which fires
on every instruction during ``TraceIntoConditional`` / ``TraceOverConditional``
(and any other x64dbg trace operation).

Workflow:
    1. ``coverage_start(sandbox_id)`` — arm the collector.
    2. Issue a trace command via ``cmd_sync("TraceIntoConditional 0, 10000")``.
    3. ``coverage_stop(sandbox_id)`` — disarm and get count.
    4. ``coverage_query(sandbox_id, ...)`` — inspect collected addresses.
    5. ``coverage_clear(sandbox_id)`` — reset for the next run.

Coverage data is **global to the plugin process** (one set shared by all
sandboxes), because the TRACEEXECUTE callback has no per-session context.
``sandbox_id`` is accepted for API consistency but is informational only.
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, ok,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager


def _require_client(sandbox_id):
    """Return (sandbox, client) or raise SandboxError/KeyError."""
    mgr = get_manager()
    sandbox = mgr.get_sandbox(sandbox_id)
    if sandbox.client is None:
        raise SandboxError(f"Sandbox '{sandbox.sandbox_id}' has no active debugger client")
    return sandbox, sandbox.client


@tool
@unsafe
def coverage_start(*, sandbox_id: str | None = None) -> dict:
    """Arm the coverage collector.

    After calling this, any x64dbg trace operation (``TraceIntoConditional``,
    ``TraceOverConditional``, etc.) will record every executed instruction
    address into an in-memory set inside the plugin.

    Coverage data is global to the plugin — it accumulates across all trace
    operations until cleared with ``coverage_clear``.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    try:
        sandbox, client = _require_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        from x64dbg_automate.api_runtime.responses import lookup_error
        return lookup_error(exc)

    try:
        active, existing_count = client.coverage_start()
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(
        sandbox_id=sandbox.sandbox_id,
        active=active,
        existing_count=existing_count,
        hint="Issue a TraceIntoConditional or similar command to collect coverage.",
    )


@tool
@unsafe
def coverage_stop(*, sandbox_id: str | None = None) -> dict:
    """Disarm the coverage collector.

    Stops recording new addresses.  Collected data is preserved until
    ``coverage_clear`` is called.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    try:
        sandbox, client = _require_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        from x64dbg_automate.api_runtime.responses import lookup_error
        return lookup_error(exc)

    try:
        active, total_count = client.coverage_stop()
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(
        sandbox_id=sandbox.sandbox_id,
        active=active,
        total_count=total_count,
    )


@tool
def coverage_query(
    *,
    sandbox_id: str | None = None,
    start_address: str = "",
    end_address: str = "",
    group_by_module: bool = False,
) -> dict:
    """Return addresses recorded in the coverage set.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        start_address: Optional filter lower bound (inclusive) — address or
            x64dbg expression.  Empty string = no filter.
        end_address: Optional filter upper bound (exclusive).  Empty string = no filter.
        group_by_module: If True, organise results into ``{module_name: [addrs]}``
            using the module list from the sandbox's debugger session.  If the
            debugger is not connected the flat list is returned instead.
    """
    try:
        sandbox, client = _require_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        from x64dbg_automate.api_runtime.responses import lookup_error
        return lookup_error(exc)

    try:
        from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr
        start = resolve_addr(client, start_address) if start_address else 0
        end = resolve_addr(client, end_address) if end_address else 0
        addrs = client.coverage_get(start, end)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    if not group_by_module:
        return ok(
            sandbox_id=sandbox.sandbox_id,
            addresses=[f"0x{a:X}" for a in addrs],
            total=len(addrs),
        )

    # Group by module base range
    try:
        modules = client.get_modules()
        module_map: list[tuple[int, int, str]] = []
        for m in modules:
            module_map.append((m.base, m.base + m.size, m.name))
        module_map.sort()
    except Exception:
        modules = []
        module_map = []

    grouped: dict[str, list[str]] = {}
    ungrouped: list[str] = []
    for addr in addrs:
        matched = False
        for base, end_m, name in module_map:
            if base <= addr < end_m:
                grouped.setdefault(name, []).append(f"0x{addr:X}")
                matched = True
                break
        if not matched:
            ungrouped.append(f"0x{addr:X}")

    if ungrouped:
        grouped["<unknown>"] = ungrouped

    return ok(
        sandbox_id=sandbox.sandbox_id,
        modules=grouped,
        total=len(addrs),
    )


@tool
@unsafe
def coverage_clear(*, sandbox_id: str | None = None) -> dict:
    """Reset the coverage set to empty.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    try:
        sandbox, client = _require_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        from x64dbg_automate.api_runtime.responses import lookup_error
        return lookup_error(exc)

    try:
        client.coverage_clear()
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(sandbox_id=sandbox.sandbox_id, cleared=True)
