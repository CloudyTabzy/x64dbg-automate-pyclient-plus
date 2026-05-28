"""Sandbox lifecycle tools: create / destroy / list / info / checkpoint / restore / dump.

A sandbox is a disposable debugged session (see :mod:`supervisor`). Creating one
launches or attaches the target under x64dbg/x32dbg; destroying one terminates that
debugger instance. The original on-disk binary is never modified.
"""

from __future__ import annotations

import os
from pathlib import Path

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, lookup_error, ok
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.api_runtime.utils import parse_region


@tool
def sandbox_create(
    target_exe: str = "",
    attach_pid: int = 0,
    cmdline: str = "",
    current_dir: str = "",
    x64dbg_path: str = "",
) -> dict:
    """Create a disposable debugged session (a sandbox) and return its metadata.

    Provide exactly one of target_exe or attach_pid. The correct x64dbg/x32dbg
    binary is auto-selected from the target's PE bitness. The original binary on
    disk is never patched, so the sandbox can be traced, patched in-memory, or
    crashed freely — destroy it when done.

    Args:
        target_exe: Path to an executable to launch under the debugger.
        attach_pid: PID of an already-running process to attach to (use instead of target_exe).
        cmdline: Command-line arguments for the launched target (target_exe mode only).
        current_dir: Working directory for the launched target (target_exe mode only).
        x64dbg_path: Path to x64dbg/x96dbg (falls back to the X64DBG_PATH env var).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.create_sandbox(
            target_exe=target_exe or None,
            attach_pid=attach_pid or None,
            cmdline=cmdline,
            current_dir=current_dir,
            x64dbg_path=x64dbg_path,
        )
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)
    except FileNotFoundError as exc:
        return err(str(exc), ErrorType.NOT_FOUND,
                   hint="Set X64DBG_PATH or pass x64dbg_path to a valid x64dbg/x96dbg.exe.")
    except SandboxError as exc:
        return err(str(exc), ErrorType.SNAPSHOT_FAILED,
                   hint="Check the target path/PID and that the x64dbg plugin is loaded.")
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc))
    return ok(**sandbox.to_info())


@tool
@unsafe
def sandbox_destroy(sandbox_id: str | None = None) -> dict:
    """Terminate a sandbox's debugger process and forget it. The original target is unaffected."""
    mgr = get_manager()
    try:
        terminated = mgr.destroy_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc))
    return ok(sandbox_id=sandbox_id, terminated=terminated)


@tool
def sandbox_list() -> dict:
    """List all active sandboxes with their live state."""
    mgr = get_manager()
    sandboxes = []
    for sb in mgr.list_sandboxes():
        mgr.refresh_state(sb)
        sandboxes.append(sb.to_info())
    return ok(sandboxes=sandboxes, total=len(sandboxes))


@tool
def sandbox_info(sandbox_id: str | None = None, *, probe_connection: bool = True) -> dict:
    """Get a sandbox's metadata and refreshed live debugger state.

    Includes a ``connection_alive`` field from a cheap PING probe so an agent
    can distinguish "debugger process is alive but the RPC link is dead" (the
    classic silent-disconnect trap) from a genuinely healthy session. When the
    link is dead, call ``sandbox_reconnect``.

    Args:
        sandbox_id: Sandbox to inspect (omit for active session).
        probe_connection: Set False to skip the PING probe (saves one round-trip).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    mgr.refresh_state(sandbox)
    info = sandbox.to_info()
    if probe_connection:
        alive = None
        client = sandbox.client
        probe = getattr(client, "is_connection_alive", None) if client else None
        if callable(probe):
            try:
                alive = bool(probe())
            except Exception:
                alive = False
        info["connection_alive"] = alive
        if alive is False:
            info["reconnect_hint"] = (
                "RPC link is down but the sandbox is registered — call "
                "sandbox_reconnect to re-establish it."
            )
        # True when the sandbox has a live ZMQ connection — agents can use ALL
        # tools (including legacy ones) without an additional connect_to_session.
        # After sandbox_create this is always True if the sandbox launched OK.
        try:
            port = int(getattr(client, "sess_req_rep_port", 0) or 0)
        except Exception:
            port = 0
        info["legacy_connection_active"] = (
            client is not None
            and port > 0
            and alive is not False
        )
    return ok(**info)


@tool
def sandbox_reconnect(sandbox_id: str | None = None) -> dict:
    """Re-establish a dropped or poisoned debugger RPC connection.

    Use when ``sandbox_info`` reports ``connection_alive: false``, or after any
    tool returns a connection-reset error. Rediscovers the x64dbg session by its
    debugger PID and rebuilds the ZMQ sockets — the original debuggee is
    untouched. Fails only if the x64dbg process itself is gone (recreate the
    sandbox in that case).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)

    try:
        reconnected = mgr.reconnect_sandbox(sandbox.sandbox_id)
    except SandboxError as exc:
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox.sandbox_id)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox.sandbox_id)

    if not reconnected:
        return err(
            "Reconnect failed — the x64dbg session may be hung or terminated.",
            ErrorType.NOT_CONNECTED,
            hint="Verify the debugger process is alive; otherwise sandbox_destroy "
                 "and sandbox_create a fresh session.",
            sandbox_id=sandbox.sandbox_id,
            last_error=sandbox.last_error,
        )

    mgr.refresh_state(sandbox)
    return ok(reconnected=True, **sandbox.to_info())


@tool
def sandbox_continue(sandbox_id: str | None = None) -> dict:
    """Resume execution of the sandbox's debuggee (lets it run toward the next event)."""
    import time

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    # Idempotent: already running is a success
    try:
        if client.is_running():
            sandbox = mgr.get_sandbox(sandbox_id)
            return ok(sandbox_id=sandbox_id, resumed=True, state=mgr.refresh_state(sandbox),
                     note="Debuggee was already running.")
    except Exception:
        pass

    try:
        resumed = client.go()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    # Verify with short poll
    for _ in range(10):
        try:
            if client.is_running():
                break
        except Exception:
            break
        time.sleep(0.05)

    # Transition state machine if available
    sm = getattr(client, "_axon_state_machine", None)
    if sm is not None and resumed:
        from x64dbg_automate.api_runtime.debugger_state import DebuggerState
        sm.transition(DebuggerState.RUNNING, reason="sandbox_continue")

    sandbox = mgr.get_sandbox(sandbox_id)
    return ok(sandbox_id=sandbox_id, resumed=bool(resumed), state=mgr.refresh_state(sandbox))


@tool
def sandbox_pause(sandbox_id: str | None = None) -> dict:
    """Pause the sandbox's debuggee so its state can be inspected."""
    import time

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    # Idempotent: already paused is a success
    try:
        if not client.is_running() and client.is_debugging():
            sandbox = mgr.get_sandbox(sandbox_id)
            return ok(sandbox_id=sandbox_id, paused=True, state=mgr.refresh_state(sandbox),
                     note="Debuggee was already paused.")
    except Exception:
        pass

    try:
        paused = client.pause()
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    # Verify with short poll
    for _ in range(10):
        try:
            if not client.is_running():
                break
        except Exception:
            break
        time.sleep(0.05)

    # Transition state machine if available
    sm = getattr(client, "_axon_state_machine", None)
    if sm is not None and paused:
        from x64dbg_automate.api_runtime.debugger_state import DebuggerState
        sm.transition(DebuggerState.STOPPED, reason="sandbox_pause")

    sandbox = mgr.get_sandbox(sandbox_id)
    return ok(sandbox_id=sandbox_id, paused=bool(paused), state=mgr.refresh_state(sandbox))


@tool
def sandbox_checkpoint(*, sandbox_id: str | None = None, name: str, regions: list[str] | None = None) -> dict:
    """Save a best-effort userland checkpoint: registers + semantic state + memory.

    Always captures: GP registers, thread list, module list, breakpoints, applied
    patches, and PEB fields. When *regions* is omitted, also auto-captures the
    current stack window (SP to SP+256) and instruction window (IP-16 to IP+80) —
    making zero-configuration checkpoints useful for ``checkpoint_diff``. Pass
    ``regions=[]`` to skip memory entirely.

    This is NOT a kernel-level process fork — handles, new threads, and kernel object
    state are NOT restored. Use ``sandbox_restore`` to write back registers + memory.

    Args:
        sandbox_id: Sandbox to snapshot.
        name: Checkpoint label (re-using a name overwrites the previous one).
        regions: Memory regions as 'addr:size' strings (e.g. ['0x401000:4096']).
                 Omit to auto-capture stack + instruction window. Pass [] to skip memory.
    """
    mgr = get_manager()
    # None → pass None so the manager auto-captures stack + instruction window.
    # Empty list → pass [] to skip memory entirely.
    if regions is None:
        parsed = None
    else:
        parsed = []
        for spec in regions:
            try:
                parsed.append(parse_region(spec))
            except ValueError as exc:
                return err(str(exc), ErrorType.BAD_ARGUMENT)
    try:
        cp = mgr.checkpoint(sandbox_id, name, parsed)
    except KeyError as exc:
        return lookup_error(exc)
    except SandboxError as exc:
        # Preserve the actionable message from ensure_stopped or other SandboxErrors.
        return err(str(exc), ErrorType.INVALID_STATE, sandbox_id=sandbox_id)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    result = ok(sandbox_id=sandbox_id, checkpoint=cp.to_info())
    # Surface capture warnings at the top level so agents don't miss them.
    capture_warnings = [w for w in cp.warnings if "fail" in w.lower()]
    if capture_warnings:
        result["capture_warnings"] = capture_warnings
    return result


@tool
@unsafe
def sandbox_restore(*, sandbox_id: str | None = None, name: str) -> dict:
    """Restore a previously saved checkpoint (writes registers + captured memory back)."""
    mgr = get_manager()
    try:
        regs_restored, regions_restored, warnings = mgr.restore_checkpoint(sandbox_id, name)
    except KeyError as exc:
        return lookup_error(exc)
    except SandboxError as exc:
        return lookup_error(exc)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    result = ok(
        sandbox_id=sandbox_id,
        checkpoint=name,
        registers_restored=regs_restored,
        regions_restored=regions_restored,
    )
    if warnings:
        result["warnings"] = warnings
    return result


@tool
def sandbox_dump(*, sandbox_id: str | None = None, output_dir: str = "", method: str = "procdump") -> dict:
    """Take a read-only forensic memory dump of the sandbox's debuggee.

    Uses a process clone/minidump (the original is not paused beyond what the method
    requires). Useful for capturing decrypted memory for offline section extraction.

    Args:
        sandbox_id: Sandbox whose debuggee to dump.
        output_dir: Directory for the .dmp (default: ./dumps).
        method: 'procdump' (clone), 'comsvcs' (built-in), or 'minidump' (ctypes).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    pid = sandbox.debuggee_pid
    if not pid:
        return err("Sandbox has no known debuggee PID.", ErrorType.INVALID_STATE,
                   hint="Ensure the sandbox is debugging a target (sandbox_info).", sandbox_id=sandbox_id)

    from x64dbg_automate.external.process_dumper import (
        dump_via_comsvcs, dump_via_minidumpwritedump, dump_via_procdump_clone,
    )

    out_dir = output_dir or os.path.join(Path.cwd(), "dumps")
    os.makedirs(out_dir, exist_ok=True)
    dump_path = os.path.join(out_dir, f"sandbox_{sandbox_id}_{pid}.dmp")

    dispatch = {
        "procdump": dump_via_procdump_clone,
        "comsvcs": dump_via_comsvcs,
        "minidump": dump_via_minidumpwritedump,
    }
    fn = dispatch.get(method)
    if fn is None:
        return err(f"Unknown dump method '{method}'.", ErrorType.BAD_ARGUMENT,
                   hint="Use 'procdump', 'comsvcs', or 'minidump'.")
    try:
        success = fn(pid, dump_path)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    if not (success and os.path.exists(dump_path)):
        return err("Dump failed.", ErrorType.SNAPSHOT_FAILED,
                   hint="Try running as Administrator or a different method.", sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, dump_path=dump_path, size=os.path.getsize(dump_path), method=method)


# ── Headless window-suppression hooks ─────────────────────────────────────────
# x64 Windows calling convention: args 1-4 in RCX/RDX/R8/R9; rest on stack.
#   CreateWindowEx: dwExStyle=RCX, lpClass=RDX, lpName=R8, dwStyle=R9  → strip WS_VISIBLE from R9
#   ShowWindow:     hWnd=RCX, nCmdShow=RDX                             → force SW_HIDE (0) via RDX
# x86 stdcall: args at [esp+4], [esp+8], … (CALL has pushed the return address).
#   CreateWindowEx arg4 (dwStyle) = [esp+10]
#   ShowWindow     arg2 (nCmdShow) = [esp+8]
_HEADLESS_CMDS_X64: dict[str, str] = {
    "user32.CreateWindowExW": "r9 &= 0xEFFFFFFF",   # clear WS_VISIBLE bit
    "user32.CreateWindowExA": "r9 &= 0xEFFFFFFF",
    "user32.ShowWindow":       "rdx &= 0",           # SW_HIDE = 0
}
_HEADLESS_CMDS_X32: dict[str, str] = {
    "user32.CreateWindowExW": "[esp+10] &= 0xEFFFFFFF",
    "user32.CreateWindowExA": "[esp+10] &= 0xEFFFFFFF",
    "user32.ShowWindow":       "[esp+8] &= 0",
}


@tool
def sandbox_enable_headless(*, sandbox_id: str | None = None) -> dict:
    """Suppress the debuggee's windows so it runs hidden in the background.

    Sets silent breakpoints on ``CreateWindowExW``, ``CreateWindowExA``, and
    ``ShowWindow``. Each hook strips ``WS_VISIBLE`` from the window-style argument
    (so the window is created hidden) or forces ``nCmdShow=0`` (``SW_HIDE``), then
    resumes the debuggee automatically via a trailing ``run`` command.

    Call while the target is paused (e.g. at the system breakpoint after
    ``sandbox_create``), then resume with ``sandbox_continue``. The game runs at
    full speed with no window appearing on screen.

    If the debuggee pauses unexpectedly at one of these hooks it means the
    auto-resume ``run`` command was not recognised by the running x64dbg version
    — call ``sandbox_continue`` once to proceed. The window will still be hidden
    because the argument patch fires before the pause.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    if sandbox.client is None:
        return err(
            f"Sandbox '{sandbox.sandbox_id}' has no active debugger client.",
            ErrorType.NOT_FOUND,
        )

    client = sandbox.client
    hooks = _HEADLESS_CMDS_X64 if sandbox.debugger_arch == "x64" else _HEADLESS_CMDS_X32

    applied: list[str] = []
    failed: list[dict] = []
    for fn, cmd in hooks.items():
        # Append "run" so the debugger auto-resumes after the argument patch fires.
        # The \n is the x64dbg script command separator.
        full_cmd = f"{cmd}\nrun"
        try:
            r1 = client.cmd_sync(f"bp {fn}")
            r2 = client.cmd_sync(f'SetBreakpointCommand {fn}, "{full_cmd}"')
            r3 = client.cmd_sync(f"SetBreakpointFastResume {fn}, 1")
            if r1 and r2 and r3:
                applied.append(fn)
            else:
                failed.append({"function": fn, "error": f"cmd_sync returned False ({r1},{r2},{r3})"})
        except Exception as exc:  # noqa: BLE001
            failed.append({"function": fn, "error": str(exc)})

    sandbox.headless = bool(applied)
    result = ok(
        sandbox_id=sandbox.sandbox_id,
        arch=sandbox.debugger_arch,
        hooked=applied,
        note=(
            "WS_VISIBLE stripped from CreateWindowEx; nCmdShow forced to SW_HIDE. "
            "Resume the process — the game window will remain hidden."
        ),
    )
    if failed:
        result["failed"] = failed
        result["warning"] = (
            "Some hooks failed. Ensure user32.dll is loaded and the process is stopped. "
            "Most games import user32 statically so it loads before the entry point."
        )
    return result


@tool
def sandbox_disable_headless(*, sandbox_id: str | None = None) -> dict:
    """Remove the window-suppression hooks placed by sandbox_enable_headless.

    Clears the ``CreateWindowExW``, ``CreateWindowExA``, and ``ShowWindow``
    breakpoints. Subsequent window-creation and show calls will behave normally.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    if sandbox.client is None:
        return err(
            f"Sandbox '{sandbox.sandbox_id}' has no active debugger client.",
            ErrorType.NOT_FOUND,
        )

    client = sandbox.client
    hooks = _HEADLESS_CMDS_X64 if sandbox.debugger_arch == "x64" else _HEADLESS_CMDS_X32

    removed: list[str] = []
    failed: list[dict] = []
    for fn in hooks:
        try:
            if client.cmd_sync(f"bc {fn}"):
                removed.append(fn)
            else:
                failed.append({"function": fn, "error": "bc returned False"})
        except Exception as exc:  # noqa: BLE001
            failed.append({"function": fn, "error": str(exc)})

    sandbox.headless = False
    result = ok(
        sandbox_id=sandbox.sandbox_id,
        removed=removed,
        note="Window-suppression hooks removed. Next window creation will be visible.",
    )
    if failed:
        result["failed"] = failed
    return result
