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
def sandbox_info(sandbox_id: str | None = None) -> dict:
    """Get a sandbox's metadata and refreshed live debugger state."""
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    mgr.refresh_state(sandbox)
    return ok(**sandbox.to_info())


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
    """Save a best-effort userland checkpoint: active-thread registers + chosen memory regions.

    This is NOT a kernel-level process fork — handles, new threads, and kernel object
    state are not captured. It is ideal for "retry this trace from a known point".

    Args:
        sandbox_id: Sandbox to snapshot.
        name: Checkpoint label (re-using a name overwrites it).
        regions: Memory regions to capture as 'addr:size' strings (e.g. ['0x7FF6A0001000:4096']).
    """
    mgr = get_manager()
    parsed: list[tuple[int, int]] = []
    for spec in (regions or []):
        try:
            parsed.append(parse_region(spec))
        except ValueError as exc:
            return err(str(exc), ErrorType.BAD_ARGUMENT)
    try:
        cp = mgr.checkpoint(sandbox_id, name, parsed)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    return ok(sandbox_id=sandbox_id, checkpoint=cp.to_info())


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
