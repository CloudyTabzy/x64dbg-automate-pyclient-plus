"""Sandbox-native interactive debug control: registers, memory writes,
breakpoints, and single-stepping.

These are the control primitives that previously lived only as "legacy" tools
bound to a separate global connection. Here they are ``sandbox_id``-aware and
route through the same ``SandboxManager`` connection as every other runtime
tool, so they inherit the unified self-healing transport (heartbeat + reconnect
+ read-only retry) instead of failing with NOT_CONNECTED. The legacy equivalents
remain as thin deprecated wrappers.

State-mutating tools are marked ``@unsafe`` (so they are gated in read-only mode
and never auto-retried by the healing layer — a half-applied step/write must not
be silently replayed).
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, lookup_error, ok,
)
from x64dbg_automate.api_runtime.runtime_helpers import (
    capture_registers, capture_segment_registers, gp_regs, resolve_addr,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager


def _client_or_error(sandbox_id):
    """Return (client, sandbox, None) or (None, None, error_dict)."""
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return None, None, lookup_error(exc)
    if sandbox.client is None:
        return None, None, err(
            f"Sandbox '{sandbox.sandbox_id}' has no active debugger client.",
            ErrorType.NOT_CONNECTED,
        )
    return sandbox.client, sandbox, None


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

@tool
def read_registers(sandbox_id: str | None = None) -> dict:
    """Read all general-purpose registers of the sandbox debuggee (hex strings).

    The debuggee must be paused; this pauses it if needed. Sandbox-native
    replacement for the legacy ``get_all_registers``.
    """
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        regs = capture_registers(client, sandbox.debugger_arch)
        seg_regs = capture_segment_registers(client)
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        arch=sandbox.debugger_arch,
        registers=regs,
        segment_registers=seg_regs,
        count=len(regs),
    )


@tool
def read_register(*, sandbox_id: str | None = None, register: str) -> dict:
    """Read a single register or subregister (e.g. 'rax', 'eip', 'rsp')."""
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        value = client.get_reg(register)
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except (ValueError, TypeError) as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, register=register.lower(),
              value=f"0x{value:X}", value_int=value)


@tool
@unsafe
def write_register(*, sandbox_id: str | None = None, register: str, value: int) -> dict:
    """Set a register to a value (debuggee is paused first). State-mutating."""
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        success = client.set_reg(register, int(value))
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except (ValueError, TypeError) as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not success:
        return err(f"Failed to set register {register!r}.", ErrorType.INVALID_STATE,
                   sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, register=register.lower(), value=f"0x{int(value):X}")


# ---------------------------------------------------------------------------
# Memory write
# ---------------------------------------------------------------------------

@tool
@unsafe
def write_memory(*, sandbox_id: str | None = None, address: str, data_hex: str) -> dict:
    """Write raw bytes (hex string) into the sandbox debuggee's memory.

    The original on-disk binary is never touched — this patches the disposable
    debugged instance only. State-mutating.

    Args:
        sandbox_id: Target sandbox.
        address: Destination address, symbol, or expression.
        data_hex: Bytes to write, hex-encoded (e.g. '9090' or '0x90 0x90' style
                  without spaces: '9090').
    """
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    cleaned = data_hex.strip().replace(" ", "").replace("0x", "")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return err(f"data_hex is not valid hex: {data_hex!r}.", ErrorType.BAD_ARGUMENT)
    if not data:
        return err("data_hex decoded to zero bytes.", ErrorType.BAD_ARGUMENT)
    mgr = get_manager()
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        mgr.ensure_stopped(client)
        success = client.write_memory(addr, data)
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not success:
        return err(f"Write failed at 0x{addr:X}.", ErrorType.INVALID_STATE,
                   hint="The page may be unmapped or read-only; check the memory map.",
                   sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, address=f"0x{addr:X}", bytes_written=len(data))


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------

@tool
@unsafe
def breakpoint_set(
    *,
    sandbox_id: str | None = None,
    address: str,
    bp_class: str = "software",
    singleshoot: bool = False,
    name: str = "",
) -> dict:
    """Set a breakpoint in the sandbox debuggee. State-mutating.

    Args:
        sandbox_id: Target sandbox.
        address: Address, symbol, or expression for the breakpoint.
        bp_class: 'software' (default), 'hardware', or 'memory'.
        singleshoot: One-shot breakpoint (software/memory only).
        name: Optional label (software only).
    """
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)

    cls = bp_class.lower().strip()
    try:
        if cls == "software":
            success = client.set_breakpoint(addr, name=name or None, singleshoot=singleshoot)
        elif cls == "hardware":
            success = client.set_hardware_breakpoint(addr)
        elif cls == "memory":
            success = client.set_memory_breakpoint(addr, singleshoot=singleshoot)
        else:
            return err(f"Unknown bp_class {bp_class!r}.", ErrorType.BAD_ARGUMENT,
                       hint="Use 'software', 'hardware', or 'memory'.")
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not success:
        return err(f"Failed to set {cls} breakpoint at 0x{addr:X}.", ErrorType.INVALID_STATE,
                   sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, address=f"0x{addr:X}", bp_class=cls, singleshoot=singleshoot)


@tool
@unsafe
def breakpoint_clear(*, sandbox_id: str | None = None, address: str = "", bp_class: str = "software") -> dict:
    """Remove a breakpoint (or all of a class when address is omitted). State-mutating."""
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    target = None
    if address.strip():
        try:
            target = resolve_addr(client, address)
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    cls = bp_class.lower().strip()
    try:
        if cls == "software":
            success = client.clear_breakpoint(target)
        elif cls == "hardware":
            success = client.clear_hardware_breakpoint(target)
        elif cls == "memory":
            success = client.clear_memory_breakpoint(target)
        else:
            return err(f"Unknown bp_class {bp_class!r}.", ErrorType.BAD_ARGUMENT,
                       hint="Use 'software', 'hardware', or 'memory'.")
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, bp_class=cls,
              address=(f"0x{target:X}" if target is not None else None),
              cleared=bool(success))


@tool
@unsafe
def breakpoint_toggle(*, sandbox_id: str | None = None, address: str, enabled: bool = True) -> dict:
    """Enable or disable a software breakpoint. State-mutating."""
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT, sandbox_id=sandbox_id)
    try:
        success = client.toggle_breakpoint(addr, on=enabled)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, address=f"0x{addr:X}", enabled=enabled, success=bool(success))


@tool
def breakpoint_list(sandbox_id: str | None = None) -> dict:
    """List all breakpoints in the sandbox debuggee (software/hardware/memory)."""
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    from x64dbg_automate.models import BreakpointType
    bps: list[dict] = []
    try:
        for bt in (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory):
            for bp in (client.get_breakpoints(bt) or []):
                bps.append({
                    "address": f"0x{bp.addr:X}",
                    "type": bt.name,
                    "enabled": bp.enabled,
                    "hit_count": bp.hitCount,
                    "name": bp.name,
                })
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, breakpoints=bps, total=len(bps))


# ---------------------------------------------------------------------------
# Single-stepping
# ---------------------------------------------------------------------------

def _step(sandbox_id, fn_name: str, **kwargs) -> dict:
    client, sandbox, error = _client_or_error(sandbox_id)
    if error:
        return error
    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        fn = getattr(client, fn_name)
        success = fn(**kwargs)
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    result = ok(sandbox_id=sandbox_id, stepped=bool(success))
    # Report the new instruction pointer so the agent sees where it landed.
    try:
        ip = client.get_reg("cip")
        result["cip"] = f"0x{ip:X}"
    except Exception:
        pass
    return result


@tool
@unsafe
def step_into(*, sandbox_id: str | None = None, count: int = 1) -> dict:
    """Single-step into ``count`` instructions (follows calls). State-mutating."""
    return _step(sandbox_id, "stepi", step_count=max(1, count))


@tool
@unsafe
def step_over(*, sandbox_id: str | None = None, count: int = 1) -> dict:
    """Single-step over ``count`` instructions (skips into calls). State-mutating."""
    return _step(sandbox_id, "stepo", step_count=max(1, count))


@tool
@unsafe
def step_out(*, sandbox_id: str | None = None, frames: int = 1) -> dict:
    """Run until the current function returns (``frames`` levels). State-mutating."""
    return _step(sandbox_id, "ret", frames=max(1, frames))
