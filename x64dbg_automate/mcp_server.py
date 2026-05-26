"""MCP server for x64dbg-automate. Exposes x64dbg automation as MCP tools."""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("MCP dependency not installed. Install with: pip install x64dbg_automate[mcp]", file=sys.stderr)
    sys.exit(1)

from x64dbg_automate import X64DbgClient
from x64dbg_automate.dbg_paths import (
    pe_bitness as _pe_bitness,
    resolve_debugger_path as _resolve_debugger_path,
    resolve_x64dbg_path_with_env as _resolve_x64dbg_path_with_env,
)
from x64dbg_automate.events import EventType
from x64dbg_automate.models import (
    BreakpointType,
    HardwareBreakpointType,
    MemoryBreakpointType,
)

from x64dbg_automate.external.entropy import shannon_entropy, sliding_entropy, is_likely_code, is_likely_encrypted
from x64dbg_automate.external.string_finder import find_strings as _ext_find_strings, find_strings_utf16le, find_specific_strings
from x64dbg_automate.external.pattern_scanner import scan_pattern
from x64dbg_automate.external.memory_analysis import analyze_region as _analyze_region, validate_extracted_section
from x64dbg_automate.external.pe_analyzer import (
    get_sections, get_tls_callbacks, get_entry_point, get_image_base, get_bitness,
    get_imports, get_exports, check_security,
)
from x64dbg_automate.external.process_dumper import (
    dump_via_comsvcs, dump_via_procdump_clone, dump_via_minidumpwritedump,
    wait_for_window, find_process_by_window_title,
)
from x64dbg_automate.external.process_control import nt_suspend_process, nt_resume_process
from x64dbg_automate.workflows.protected_extract import (
    workflow_extract_binary, ExtractionResult, TARGET_SECTIONS,
)
from x64dbg_automate.api_runtime.responses import (
    ErrorType, err, ok, err_from_exc, _ERROR_HINTS,
)

mcp = FastMCP(
    "x64dbg-automate",
    instructions=(
        "Axon MCP — AI-native runtime analysis platform for x64dbg. "
        "Unified session model: start_session creates a session, then use ANY tool. "
        "Runtime tools (get_threads, analyze_function_cfg, trace_execution, etc.) work "
        "with the active session automatically — no sandbox_id required. "
        "Legacy tools and runtime tools share the same session registry. "
        "Addresses are hex strings (e.g. '0x7FF6A0001000') or expressions (e.g. 'RIP', 'rsp+0x20')."
    ),
)

_client: X64DbgClient | None = None


def _get_unified_manager():
    """Return the unified SandboxManager (legacy + runtime sessions)."""
    from x64dbg_automate.api_runtime.supervisor import get_manager
    return get_manager()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_client() -> X64DbgClient:
    """Return the active client or raise a clear error."""
    if _client is None:
        raise RuntimeError("Not connected to x64dbg. Use connect_to_session or start_session first.")
    return _client


def _parse_address_or_expression(s: str) -> int:
    """Parse an address string to int.

    Accepts hex literals ('0x7FF6...', '7FF6...'), and falls back to
    x64dbg's expression evaluator so registers ('RIP'), symbols
    ('kernel32:CreateFileA'), and arithmetic ('rsp+0x20') all work.
    """
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        pass
    # Fall back to x64dbg expression evaluator
    client = _require_client()
    val, success = client.eval_sync(s)
    if not success:
        raise ValueError(f"Cannot resolve address: {s}")
    return val


def _format_address(addr: int) -> str:
    """Format an integer address as a hex string."""
    return f"0x{addr:X}"


def _get_all_breakpoints(client) -> list:
    """Aggregate breakpoints across all useful types (software, hardware, memory).

    ``client.get_breakpoints()`` requires a ``BreakpointType`` argument.
    This helper iterates over the common types and concatenates the results.
    """
    all_bps: list = []
    for bt in (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory):
        try:
            all_bps.extend(client.get_breakpoints(bt))
        except Exception:
            pass
    return all_bps


def _format_memory(data: bytes, base: int) -> str:
    """Format bytes as a standard hex dump with ASCII sidebar."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{_format_address(base + offset)}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


# Debugger-path helpers (_pe_bitness, _resolve_debugger_path,
# _resolve_x64dbg_path_with_env) now live in x64dbg_automate.dbg_paths and are
# imported as aliases above so the SandboxManager can share them.


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

@mcp.tool()
def list_sessions() -> dict:
    """List all managed debugger sessions.

    Returns the unified sessions known to the session manager. Use the
    ``session_id`` from these entries as ``sandbox_id`` for runtime tools.
    Also includes any running x64dbg instances not yet connected (``available``).
    """
    try:
        mgr = _get_unified_manager()
        # Collect sandbox IDs (PIDs) already tracked so we can deduplicate.
        tracked_pids = {s.debugger_pid for s in mgr.list_sandboxes()}

        # Discover unregistered running x64dbg instances from lock files.
        available = []
        try:
            for s in X64DbgClient.list_sessions():
                if s.pid not in tracked_pids:
                    exe_path = s.cmdline[0].strip() if s.cmdline and s.cmdline[0].strip() else "unknown"
                    available.append({
                        "debugger_pid": s.pid,
                        "path": exe_path,
                        "window_title": s.window_title,
                        "req_rep_port": s.sess_req_rep_port,
                        "pub_sub_port": s.sess_pub_sub_port,
                        "hint": "Use connect_to_session(session_pid=...) to attach.",
                    })
        except Exception:
            pass

        sessions = []
        for sb in mgr.list_sandboxes():
            mgr.refresh_state(sb)
            sessions.append(sb.to_info())

        return {
            "success": True,
            "sessions": sessions,
            "active_session_id": mgr.get_active_session_id(),
            "total": len(sessions),
            "available_unconnected": available,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "error_type": "LIST_FAILED"}


@mcp.tool()
def start_session(x64dbg_path: str = "", target_exe: str = "", cmdline: str = "", current_dir: str = "") -> dict:
    """Launch a new x64dbg instance and optionally load an executable.

    Creates a unified session that both legacy and runtime tools can use.
    Returns a session_id — pass it to runtime tools, or omit sandbox_id to use
    the active session automatically.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe). Falls back to X64DBG_PATH env var if not provided.
        target_exe: Path to executable to debug (optional)
        cmdline: Command-line arguments for the target (optional)
        current_dir: Working directory for the target (optional)
    """
    global _client
    try:
        path = _resolve_x64dbg_path_with_env(x64dbg_path)
        resolved = _resolve_debugger_path(path, target_exe)
        _client = X64DbgClient(resolved)
        pid = _client.start_session(target_exe, cmdline, current_dir)
        arch = "x64" if "x64dbg" in Path(resolved).name.lower() else "x32"
        mgr = _get_unified_manager()
        sandbox = mgr.register_legacy_session(_client, pid, arch)
        return {
            "success": True,
            "session_id": sandbox.sandbox_id,
            "debugger_pid": pid,
            "debugger_path": resolved,
            "debugger_arch": arch,
            "message": f"Session started. Debugger PID: {pid}",
            "hint": "Use this session_id with runtime tools, or call other tools directly — they use the active session.",
        }
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "STARTUP_FAILED", "hint": "Check X64DBG_PATH and that x64dbg is installed."}


@mcp.tool()
def connect_to_session(x64dbg_path: str = "", session_pid: int = 0) -> dict:
    """Connect to an already-running x64dbg instance.

    If x96dbg.exe is given, it is resolved to x64dbg.exe (default).
    The actual debugger binary must already be running.

    Args:
        x64dbg_path: Path to x64dbg installation (x96dbg.exe, x64dbg.exe, or x32dbg.exe). Falls back to X64DBG_PATH env var if not provided.
        session_pid: PID of the x64dbg process to attach to
    """
    if not session_pid:
        return {"success": False, "error": "session_pid is required", "error_type": "BAD_ARGUMENT", "hint": "Use list_sessions to find the PID."}
    global _client
    try:
        path = _resolve_x64dbg_path_with_env(x64dbg_path)
        resolved = _resolve_debugger_path(path)
        _client = X64DbgClient(resolved)
        _client.attach_session(session_pid)
        arch = "x64" if "x64dbg" in Path(resolved).name.lower() else "x32"
        mgr = _get_unified_manager()
        sandbox = mgr.register_legacy_session(_client, session_pid, arch)
        return {"success": True, "session_id": sandbox.sandbox_id, "debugger_pid": session_pid, "message": f"Connected to session PID {session_pid}."}
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "CONNECTION_FAILED", "hint": "Verify the PID is correct and x64dbg is running with the plugin loaded."}


@mcp.tool()
def connect_remote(host: str, req_rep_port: int, pub_sub_port: int) -> dict:
    """Connect to a remote x64dbg instance running on another machine or VM.

    Bypasses local session discovery (lockfiles). The x64dbg plugin on the
    remote machine must be configured to bind to an accessible address
    (e.g. 0.0.0.0) via the [XAutomate] section in x64dbg.ini.

    Args:
        host: Remote hostname or IP address (e.g. '192.168.1.100')
        req_rep_port: The REQ/REP port the plugin is listening on
        pub_sub_port: The PUB/SUB port the plugin is listening on
    """
    global _client
    try:
        _client = X64DbgClient.connect_remote(host, req_rep_port, pub_sub_port)
        mgr = _get_unified_manager()
        # Remote connections don't have a local PID; use a synthetic ID
        sandbox = mgr.register_legacy_session(_client, 0, "x64")
        return {"success": True, "session_id": sandbox.sandbox_id, "host": host, "req_rep_port": req_rep_port, "message": f"Connected to remote x64dbg at {host}:{req_rep_port}."}
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "CONNECTION_FAILED", "hint": "Verify the remote plugin is configured for remote mode and the port/firewall is open."}


@mcp.tool()
def disconnect() -> dict:
    """Disconnect from the current x64dbg session without terminating the debugger."""
    global _client
    if _client is None:
        return {"success": False, "error": "No active connection", "error_type": "NOT_CONNECTED", "hint": "Call start_session or connect_to_session first."}
    try:
        # Remove from unified manager
        mgr = _get_unified_manager()
        active = mgr.get_active_session_id()
        if active:
            try:
                mgr.destroy_sandbox(active)
            except Exception:
                pass
        _client.detach_session()
        _client = None
        return {"success": True, "message": "Disconnected."}
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "DISCONNECT_FAILED"}


@mcp.tool()
def terminate_session() -> dict:
    """Terminate the connected x64dbg debugger process."""
    global _client
    if _client is None:
        return {"success": False, "error": "No active session.", "error_type": "NOT_CONNECTED",
                "hint": "Call start_session or connect_to_session first."}
    try:
        mgr = _get_unified_manager()
        active = mgr.get_active_session_id()
        if active:
            # destroy_sandbox terminates the debugger via _safe_terminate — don't call again.
            mgr.destroy_sandbox(active)
        else:
            # No sandbox registered; fall back to the raw client terminate.
            _client.terminate_session()
        _client = None
        return {"success": True, "message": "Session terminated."}
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "TERMINATE_FAILED"}


# ---------------------------------------------------------------------------
# Debug Control
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugger_status() -> dict:
    """Get consolidated debugger status: debugging state, running state, PID, bitness, elevated."""
    try:
        client = _require_client()
        debugging = client.is_debugging()
        running = client.is_running()
        pid = client.debugee_pid() if debugging else None
        bitness = client.debugee_bitness() if debugging else None
        elevated = client.debugger_is_elevated()
        return ok(debugging=debugging, running=running, debuggee_pid=pid, bitness=bitness, elevated=elevated)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def go(pass_exceptions: bool = False, swallow_exceptions: bool = False) -> dict:
    """Resume debuggee execution.

    Args:
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
    """
    try:
        client = _require_client()
        result = client.go(pass_exceptions=pass_exceptions, swallow_exceptions=swallow_exceptions)
        if not result:
            return err("Failed to resume.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok()
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def pause() -> dict:
    """Pause the debuggee."""
    try:
        client = _require_client()
        result = client.pause()
        if not result:
            return err("Failed to pause.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok()
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def step_into(count: int = 1) -> dict:
    """Step into one or more instructions.

    Args:
        count: Number of instructions to step into
    """
    try:
        client = _require_client()
        result = client.stepi(step_count=count)
        if not result:
            return err("Step into failed.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(steps=count)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def step_over(count: int = 1) -> dict:
    """Step over one or more instructions.

    Args:
        count: Number of instructions to step over
    """
    try:
        client = _require_client()
        result = client.stepo(step_count=count)
        if not result:
            return err("Step over failed.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(steps=count)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def skip_instruction(count: int = 1) -> dict:
    """Skip instructions without executing them.

    Args:
        count: Number of instructions to skip
    """
    try:
        client = _require_client()
        result = client.skip(skip_count=count)
        if not result:
            return err("Skip failed.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(steps=count)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def run_to_return(frames: int = 1) -> dict:
    """Run until a return instruction is encountered.

    Args:
        frames: Number of return frames to seek
    """
    try:
        client = _require_client()
        result = client.ret(frames=frames)
        if not result:
            return err("Run to return failed.", ErrorType.INVALID_STATE, hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(frames=frames)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def trace_into(
    break_condition: str,
    max_steps: int = 50000,
    log_text: str | None = None,
    log_condition: str | None = None,
    command_text: str | None = None,
    command_condition: str | None = None,
    log_file: str | None = None,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
    wait_timeout: int = 60,
) -> dict:
    """Trace into (single-step into calls) until a condition is met.

    Steps one instruction at a time, following into calls, until break_condition
    evaluates to non-zero or max_steps is reached. Optionally logs each step.

    Args:
        break_condition: x64dbg expression that stops the trace when non-zero (e.g. 'cip == 0x401000')
        max_steps: Maximum steps before giving up (default 50000)
        log_text: Formatted text to log each step (e.g. '{p:cip} {i:cip}')
        log_condition: Expression controlling when log_text is printed
        command_text: x64dbg command to execute each step
        command_condition: Expression controlling when command_text runs
        log_file: Path to redirect trace log output to a file
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
        wait_timeout: Max seconds to wait for trace completion
    """
    try:
        client = _require_client()
        result = client.trace_into(
            break_condition=break_condition,
            max_steps=max_steps,
            log_text=log_text,
            log_condition=log_condition,
            command_text=command_text,
            command_condition=command_condition,
            log_file=log_file,
            pass_exceptions=pass_exceptions,
            swallow_exceptions=swallow_exceptions,
            wait_timeout=wait_timeout,
        )
        if not result:
            return err("Trace into failed or max_steps reached.", ErrorType.INVALID_STATE,
                       hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(break_condition=break_condition)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def trace_over(
    break_condition: str,
    max_steps: int = 50000,
    log_text: str | None = None,
    log_condition: str | None = None,
    command_text: str | None = None,
    command_condition: str | None = None,
    log_file: str | None = None,
    pass_exceptions: bool = False,
    swallow_exceptions: bool = False,
    wait_timeout: int = 60,
) -> dict:
    """Trace over (single-step over calls) until a condition is met.

    Steps one instruction at a time, stepping over calls, until break_condition
    evaluates to non-zero or max_steps is reached. Optionally logs each step.

    Args:
        break_condition: x64dbg expression that stops the trace when non-zero (e.g. 'cip == 0x401000')
        max_steps: Maximum steps before giving up (default 50000)
        log_text: Formatted text to log each step (e.g. '{p:cip} {i:cip}')
        log_condition: Expression controlling when log_text is printed
        command_text: x64dbg command to execute each step
        command_condition: Expression controlling when command_text runs
        log_file: Path to redirect trace log output to a file
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
        wait_timeout: Max seconds to wait for trace completion
    """
    try:
        client = _require_client()
        result = client.trace_over(
            break_condition=break_condition,
            max_steps=max_steps,
            log_text=log_text,
            log_condition=log_condition,
            command_text=command_text,
            command_condition=command_condition,
            log_file=log_file,
            pass_exceptions=pass_exceptions,
            swallow_exceptions=swallow_exceptions,
            wait_timeout=wait_timeout,
        )
        if not result:
            return err("Trace over failed or max_steps reached.", ErrorType.INVALID_STATE,
                       hint=_ERROR_HINTS[ErrorType.INVALID_STATE])
        return ok(break_condition=break_condition)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, size: int = 256) -> dict:
    """Read memory from the debuggee.

    Returns hex-encoded bytes and a formatted hex dump with ASCII sidebar.

    Args:
        address: Address — hex ('0x7FF6A0001000'), register ('RSP'), symbol, or expression ('rsp+0x20')
        size: Number of bytes to read (max 4096)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = min(size, 4096)
        data = client.read_memory(addr, size)
        return ok(
            address=_format_address(addr),
            size=len(data),
            bytes=data.hex(),
            hex_dump=_format_memory(data, addr),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def read_memory_raw(address: str, size: int = 256) -> dict:
    """Read raw bytes from debuggee memory. Returns hex-encoded string, no ASCII sidebar.

    Unlike read_memory, this returns structured JSON and supports sizes up to 64KB.

    Args:
        address: Address — hex ('0x7FF6A0001000'), register ('RSP'), symbol, or expression
        size: Number of bytes to read (max 65536)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = min(size, 65536)
        data = client.read_memory(addr, size)
        return {
            "success": True,
            "address": _format_address(addr),
            "size": len(data),
            "bytes": data.hex(),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "error_type": "READ_FAILED"}


@mcp.tool()
def write_memory(address: str, hex_data: str) -> dict:
    """Write bytes to debuggee memory.

    Args:
        address: Hex address to write to
        hex_data: Hex string of bytes to write (e.g. '90 90 90' or '909090')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        cleaned = hex_data.replace(" ", "").replace("\n", "")
        data = bytes.fromhex(cleaned)
        result = client.write_memory(addr, data)
        if not result:
            return err("Write failed.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR],
                       address=_format_address(addr))
        return ok(address=_format_address(addr), bytes_written=len(data))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def allocate_memory(size: int = 4096, address: str = "0") -> dict:
    """Allocate memory in the debuggee's address space (VirtualAlloc).

    Args:
        size: Number of bytes to allocate
        address: Preferred address (0 for any)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virt_alloc(n=size, addr=addr)
        return ok(address=_format_address(result), size=size)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def free_memory(address: str) -> dict:
    """Free memory in the debuggee's address space (VirtualFree).

    Args:
        address: Address of memory to free
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        client.virt_free(addr)
        return ok(address=_format_address(addr))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_memory_map() -> dict:
    """List all memory regions in the debuggee's address space."""
    try:
        client = _require_client()
        pages = client.memmap()
        regions = [
            {
                "base_address": _format_address(p.base_address),
                "region_size": p.region_size,
                "protect": f"0x{p.protect:X}",
                "state": f"0x{p.state:X}",
                "info": p.info,
            }
            for p in pages
        ]
        return ok(regions=regions, total=len(regions))
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

@mcp.tool()
def get_register(register: str) -> dict:
    """Read a single register value.

    Args:
        register: Register name (e.g. 'rax', 'eip', 'rsp', 'eflags')
    """
    try:
        client = _require_client()
        val = client.get_reg(register)
        return ok(register=register, value=_format_address(val), value_int=val)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def set_register(register: str, value: str) -> dict:
    """Write a value to a register.

    Args:
        register: Register name (e.g. 'rax', 'eip')
        value: Hex value to set
    """
    try:
        client = _require_client()
        val = _parse_address_or_expression(value)
        result = client.set_reg(register, val)
        if not result:
            return err("Failed to set register.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], register=register)
        return ok(register=register, value=_format_address(val))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_all_registers() -> dict:
    """Dump all general-purpose registers and flags."""
    try:
        client = _require_client()
        regs = client.get_regs()
        ctx = regs.context
        registers = {
            field_name: _format_address(getattr(ctx, field_name))
            for field_name in type(ctx).model_fields
            if isinstance(getattr(ctx, field_name), int)
        }
        flags = {k: int(v) for k, v in regs.flags.model_dump().items()}
        return ok(registers=registers, flags=flags)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Expressions & Commands
# ---------------------------------------------------------------------------

@mcp.tool()
def validate_address(expression: str) -> dict:
    """Validate and resolve an address expression.

    Tells the agent whether an address, symbol, register, or arithmetic expression
    can be resolved BEFORE using it in a tool call. Prevents silent failures from
    invalid expressions evaluating to 0.

    Args:
        expression: Expression to validate — hex ('0x401000'), register ('RAX'),
                    symbol ('kernel32:CreateFileA'), or arithmetic ('rsp+0x20')
    """
    try:
        resolved = _parse_address_or_expression(expression)
        addr_type = "hex_literal"
        expr_upper = expression.strip().upper()
        if expr_upper in (
            "RAX", "RBX", "RCX", "RDX", "RSP", "RBP", "RSI", "RDI", "RIP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
            "EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "ESI", "EDI", "EIP",
        ):
            addr_type = "register"
        elif ":" in expression:
            addr_type = "symbol"
        elif any(c in expression for c in "+-*/"):
            addr_type = "arithmetic"
        return ok(
            valid=True,
            resolved=f"0x{resolved:X}",
            expression=expression,
            type=addr_type,
        )
    except ValueError as exc:
        return err(
            str(exc), ErrorType.BAD_ARGUMENT,
            expression=expression,
            valid=False,
            hint="Check the expression spelling. For symbols, use 'module:SymbolName' format.",
        )
    except Exception as exc:
        return err(
            str(exc), ErrorType.UNKNOWN,
            expression=expression,
            valid=False,
            hint="Unexpected error resolving expression.",
        )


@mcp.tool()
def eval_expression(expression: str) -> dict:
    """Evaluate an x64dbg expression. Supports symbols, registers, arithmetic.

    Args:
        expression: Expression to evaluate (e.g. 'kernel32:CreateFileA', 'rax+0x10')
    """
    try:
        client = _require_client()
        val, success = client.eval_sync(expression)
        if not success:
            return err(f"Evaluation failed for: {expression}", ErrorType.BAD_ARGUMENT,
                       hint=_ERROR_HINTS[ErrorType.BAD_ARGUMENT], expression=expression)
        return ok(expression=expression, value=_format_address(val), value_int=val)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def execute_command(command: str) -> dict:
    """Execute a raw x64dbg command.

    See https://help.x64dbg.com/en/latest/commands/ for available commands.

    Args:
        command: x64dbg command string
    """
    try:
        client = _require_client()
        result = client.cmd_sync(command)
        return ok(command=command, result=result)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------

@mcp.tool()
def set_breakpoint(
    address_or_symbol: str,
    bp_type: str = "software",
    name: str | None = None,
    hardware_mode: str = "x",
    memory_mode: str = "a",
    singleshot: bool = False,
    condition: str = "",
) -> dict:
    """Set a breakpoint (software, hardware, or memory).

    Args:
        address_or_symbol: Hex address or symbol name.
        bp_type: 'software', 'hardware', or 'memory'.
        name: Optional label for the breakpoint (software only).
        hardware_mode: Hardware BP type: 'r' (read), 'w' (write), 'x' (execute).
        memory_mode: Memory BP type: 'r', 'w', 'x', 'a' (access).
        singleshot: Remove after the first hit.
        condition: x64dbg expression; breakpoint only fires when this evaluates non-zero.
                   Example: 'eax == 0' or 'poi(rsp+8) == 1'.
    """
    try:
        client = _require_client()
        try:
            addr: int | str = _parse_address_or_expression(address_or_symbol)
        except (ValueError, TypeError):
            addr = address_or_symbol

        if bp_type == "hardware":
            hw = HardwareBreakpointType(hardware_mode)
            result = client.set_hardware_breakpoint(addr, bp_type=hw)
        elif bp_type == "memory":
            mm = MemoryBreakpointType(memory_mode)
            result = client.set_memory_breakpoint(addr, bp_type=mm, singleshoot=singleshot)
        else:
            # Pre-flight: detect duplicate SW BP before calling set — x64dbg silently
            # rejects duplicates, and the downstream virt_query diagnostic is unreliable
            # at system BP (returns None for all addresses), producing a misleading hint.
            if isinstance(addr, int):
                duplicate = _find_existing_sw_bp(client, addr)
                if duplicate is not None:
                    return {
                        "success": False,
                        "error": f"A software breakpoint already exists at {address_or_symbol}.",
                        "error_type": "DUPLICATE_BP",
                        "address": address_or_symbol,
                        "existing_bp": {
                            "name": duplicate.name,
                            "enabled": duplicate.enabled,
                            "singleshot": duplicate.singleshoot,
                            "hit_count": duplicate.hitCount,
                        },
                        "hint": (
                            "x64dbg rejects duplicate software breakpoints. "
                            "Call clear_breakpoint(address) to remove the existing one first, "
                            "then set_breakpoint again. "
                            "Tip: x64dbg auto-creates a one-shot BP at the entry point when loading "
                            "a binary — this is the most common cause of this error at the entry address."
                        ),
                    }
            result = client.set_breakpoint(addr, name=name, singleshoot=singleshot)

        if not result:
            hint = _diagnose_bp_failure(client, addr)
            return {
                "success": False,
                "error": f"Failed to set {bp_type} breakpoint at {address_or_symbol}.",
                "address": address_or_symbol,
                "hint": hint,
            }

        # Apply condition expression if requested (software breakpoints only).
        condition_applied = False
        if condition and bp_type == "software" and isinstance(addr, int):
            try:
                client.cmd_sync(f'SetBreakpointCondition {addr:#x}, "{condition}"')
                condition_applied = True
            except Exception:
                pass  # BP is set; condition is best-effort

        return {
            "success": True,
            "address": address_or_symbol,
            "type": bp_type,
            "singleshot": singleshot,
            "condition": condition if condition_applied else None,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "error_type": "UNKNOWN"}


def _find_existing_sw_bp(client, addr: int):
    """Return the existing software BP at addr, or None if there isn't one."""
    try:
        bps = client.get_breakpoints(BreakpointType.BpNormal) or []
        return next((bp for bp in bps if bp.addr == addr), None)
    except Exception:
        return None


def _diagnose_bp_failure(client, addr) -> str:
    """Query memory at addr and return a human-readable explanation of why a BP failed."""
    if not isinstance(addr, int):
        return "Could not resolve address — check the symbol or expression."
    # --- Duplicate BP check (most common cause at entry point) ------------------
    # This is reached when the pre-flight in set_breakpoint was skipped (e.g. the
    # conditional-BP path) or when the addr was not an int at pre-flight time.
    duplicate = _find_existing_sw_bp(client, addr)
    if duplicate is not None:
        extra = " (auto-created by x64dbg at entry)" if duplicate.singleshoot and duplicate.hitCount == 0 else ""
        return (
            f"A software breakpoint{extra} already exists at 0x{addr:X} "
            f"(name='{duplicate.name}', enabled={duplicate.enabled}, singleshot={duplicate.singleshoot}). "
            "x64dbg rejects duplicates. Call clear_breakpoint(address) first, then set_breakpoint again."
        )
    # --- System-breakpoint guard ------------------------------------------------
    # At the initial system breakpoint (ntdll.dll LdrInitializeThunk) the loader
    # has not finished mapping the main image.  x64dbg's bp engine silently fails
    # here even though the address is valid.  Detect this and give a concrete
    # next-step instead of the generic "try anal" hint.
    try:
        cip = client.get_reg("cip")
        sym = client.get_symbol_at(cip)
        mod_name = (sym.mod or "").lower() if sym else ""
        if mod_name in ("ntdll.dll", "kernelbase.dll", "kernel32.dll"):
            mods = client.get_modules()
            if len(mods) <= 1:
                return (
                    "System breakpoint: the debuggee is at the initial ntdll loader breakpoint. "
                    "The main image is not fully initialized yet. "
                    "Run go() then pause() after the entry point is reached before setting breakpoints."
                )
    except Exception:
        pass
    # --- Memory diagnostics -----------------------------------------------------
    try:
        page = client.virt_query(addr)
        if page is None:
            return (
                f"0x{addr:X} is not mapped in the process address space. "
                "If the debuggee is at a system breakpoint, run go() first to let the loader finish."
            )
        state = page.state
        protect = page.protect & 0xFF
        if state != 0x1000:  # not MEM_COMMIT
            return f"Memory at 0x{addr:X} is not committed (state=0x{state:X}). Wrong address?"
        if protect in (0x00, 0x01):  # PAGE_NOACCESS
            return f"Memory at 0x{addr:X} has PAGE_NOACCESS (protect=0x{protect:X}). Cannot set SW breakpoint."
        if protect in (0x02, 0x04):  # READONLY / READWRITE (data, not code)
            return (f"Memory at 0x{addr:X} is data (protect=0x{protect:X}), not executable. "
                    "Use a hardware breakpoint (bp_type='hardware', hardware_mode='x') instead.")
        return (f"Memory at 0x{addr:X} looks valid (protect=0x{protect:X}, state=0x{state:X}). "
                "x64dbg may need analysis — try running 'anal' first via execute_command.")
    except Exception:
        return "Could not query memory region for diagnostic info."


@mcp.tool()
def clear_breakpoint(address: str | None = None, bp_type: str = "software") -> dict:
    """Clear breakpoint(s).

    Args:
        address: Hex address or symbol (None clears all of this type)
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.clear_hardware_breakpoint(target)
        elif bp_type == "memory":
            result = client.clear_memory_breakpoint(target)
        else:
            result = client.clear_breakpoint(target)

        if not result:
            return err("Failed to clear breakpoint(s).", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(address=address, bp_type=bp_type)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def set_conditional_breakpoint(
    address: str,
    condition: str,
    singleshot: bool = False,
    name: str | None = None,
) -> dict:
    """Set a software breakpoint with an expression condition.

    The breakpoint only fires when the condition evaluates to non-zero.
    This is a convenience wrapper over set_breakpoint with bp_type='software'.

    Args:
        address: Hex address or symbol name.
        condition: x64dbg expression; e.g. 'eax == 0', 'poi(rsp+8) == 1', 'cip > 0x401000'.
        singleshot: Remove after the first hit.
        name: Optional label for the breakpoint.
    """
    try:
        client = _require_client()
        try:
            addr = _parse_address_or_expression(address)
        except (ValueError, TypeError):
            addr = address

        result = client.set_breakpoint(addr, name=name, singleshoot=singleshot)
        if not result:
            hint = _diagnose_bp_failure(client, addr)
            return err(
                f"Failed to set conditional breakpoint at {address}.",
                ErrorType.RPC_ERROR,
                address=address,
                condition=condition,
                hint=hint,
            )

        condition_applied = False
        if isinstance(addr, int):
            try:
                client.cmd_sync(f'SetBreakpointCondition {addr:#x}, "{condition}"')
                condition_applied = True
            except Exception:
                pass

        return ok(
            address=address,
            type="software",
            condition=condition if condition_applied else condition,
            condition_applied=condition_applied,
            singleshot=singleshot,
            name=name,
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def toggle_breakpoint(address: str | None = None, bp_type: str = "software", enable: bool = True) -> dict:
    """Enable or disable breakpoint(s).

    Args:
        address: Hex address or symbol (None toggles all of this type)
        bp_type: 'software', 'hardware', or 'memory'
        enable: True to enable, False to disable
    """
    try:
        client = _require_client()
        target: int | str | None = None
        if address is not None:
            try:
                target = _parse_address_or_expression(address)
            except (ValueError, TypeError):
                target = address

        if bp_type == "hardware":
            result = client.toggle_hardware_breakpoint(target, on=enable)
        elif bp_type == "memory":
            result = client.toggle_memory_breakpoint(target, on=enable)
        else:
            result = client.toggle_breakpoint(target, on=enable)

        action = "enabled" if enable else "disabled"
        if not result:
            return err(f"Failed to {action} breakpoint(s).", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(address=address, bp_type=bp_type, enabled=enable)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def list_breakpoints(bp_type: str = "software") -> dict:
    """List all breakpoints of a given type.

    Args:
        bp_type: 'software', 'hardware', or 'memory'
    """
    try:
        client = _require_client()
        type_map = {
            "software": BreakpointType.BpNormal,
            "hardware": BreakpointType.BpHardware,
            "memory": BreakpointType.BpMemory,
        }
        bt = type_map.get(bp_type, BreakpointType.BpNormal)
        bps = client.get_breakpoints(bt)
        breakpoints = [
            {
                "address": _format_address(bp.addr),
                "enabled": bp.enabled,
                "name": bp.name,
                "module": bp.mod,
                "hit_count": bp.hitCount,
                "singleshot": bp.singleshoot,
            }
            for bp in bps
        ]
        return ok(bp_type=bp_type, breakpoints=breakpoints, total=len(breakpoints))
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

@mcp.tool()
def disassemble(address: str, count: int = 10) -> dict:
    """Disassemble instructions at an address.

    Args:
        address: Address — hex ('0x401000'), register ('RIP'), symbol, or expression
        count: Number of instructions to disassemble (max 100)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        count = min(count, 100)
        instructions = []
        current = addr
        for _ in range(count):
            ins = client.disassemble_at(current)
            if ins is None:
                break
            instructions.append({
                "address": _format_address(current),
                "mnemonic": ins.instruction,
                "size": ins.instr_size,
            })
            current += ins.instr_size
        return ok(address=_format_address(addr), instructions=instructions, total=len(instructions))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def assemble(address: str, instruction: str) -> dict:
    """Assemble a single instruction at an address.

    Args:
        address: Hex address to assemble at
        instruction: Assembly instruction (e.g. 'nop', 'mov eax, 1')
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = client.assemble_at(addr, instruction)
        if size is None:
            return err(f"Failed to assemble '{instruction}'.", ErrorType.BAD_ARGUMENT,
                       hint=_ERROR_HINTS[ErrorType.BAD_ARGUMENT], address=_format_address(addr))
        return ok(address=_format_address(addr), instruction=instruction, bytes_written=size)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Annotations & Symbols
# ---------------------------------------------------------------------------

@mcp.tool()
def set_label(address: str, text: str) -> dict:
    """Set a label at an address.

    Args:
        address: Hex address
        text: Label text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_label_at(addr, text)
        if not result:
            return err("Failed to set label.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(address=_format_address(addr), text=text)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_label(address: str) -> dict:
    """Get the label at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        label = client.get_label_at(addr)
        return ok(address=_format_address(addr), label=label or "")
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def set_comment(address: str, text: str) -> dict:
    """Set a comment at an address.

    Args:
        address: Hex address
        text: Comment text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_comment_at(addr, text)
        if not result:
            return err("Failed to set comment.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(address=_format_address(addr), text=text)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_comment(address: str) -> dict:
    """Get the comment at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        comment = client.get_comment_at(addr)
        return ok(address=_format_address(addr), comment=comment or "")
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_symbol(address: str) -> dict:
    """Look up the symbol at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        sym = client.get_symbol_at(addr)
        if sym is None:
            return ok(address=_format_address(addr), symbol=None, found=False)
        return ok(
            address=_format_address(sym.addr),
            found=True,
            decorated=sym.decoratedSymbol,
            undecorated=sym.undecoratedSymbol,
            type=sym.type,
            ordinal=sym.ordinal,
        )
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

@mcp.tool()
def create_thread(entry_address: str, argument: str = "0") -> dict:
    """Create a new thread in the debuggee.

    Args:
        entry_address: Hex address of the thread entry point
        argument: Hex value passed as thread argument
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(entry_address)
        arg = _parse_address_or_expression(argument)
        tid = client.thread_create(addr, arg)
        if tid is None:
            return err("Failed to create thread.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(tid=tid, entry_address=_format_address(addr))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def terminate_thread(tid: int) -> dict:
    """Terminate a thread in the debuggee.

    Args:
        tid: Thread ID to terminate
    """
    try:
        client = _require_client()
        result = client.thread_terminate(tid)
        if not result:
            return err(f"Failed to terminate thread {tid}.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], tid=tid)
        return ok(tid=tid)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def pause_resume_thread(tid: int, action: str = "pause") -> dict:
    """Pause or resume a thread.

    Args:
        tid: Thread ID
        action: 'pause' or 'resume'
    """
    try:
        client = _require_client()
        if action == "resume":
            result = client.thread_resume(tid)
        else:
            result = client.thread_pause(tid)
        if not result:
            return err(f"Failed to {action} thread {tid}.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], tid=tid)
        return ok(tid=tid, action=action)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def switch_thread(tid: int) -> dict:
    """Switch the debugger's active thread context.

    Args:
        tid: Thread ID to switch to
    """
    try:
        client = _require_client()
        result = client.switch_thread(tid)
        if not result:
            return err(f"Failed to switch to thread {tid}.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], tid=tid)
        return ok(tid=tid)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@mcp.tool()
def get_latest_event() -> dict:
    """Pop the latest debug event from the event queue."""
    try:
        client = _require_client()
        event = client.get_latest_debug_event()
        if event is None:
            return ok(has_event=False, event=None)
        event_data = event.event_data.model_dump() if event.event_data is not None else None
        return ok(has_event=True, event_type=str(event.event_type), event_data=event_data)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def wait_for_event(event_type: str, timeout: int = 5) -> dict:
    """Wait for a specific debug event type.

    Args:
        event_type: Event type name (e.g. 'EVENT_BREAKPOINT', 'EVENT_LOAD_DLL')
        timeout: Max seconds to wait
    """
    try:
        client = _require_client()
        try:
            et = EventType(event_type)
        except ValueError:
            return err(f"Unknown event type: {event_type}", ErrorType.BAD_ARGUMENT,
                       hint="Valid types include EVENT_BREAKPOINT, EVENT_LOAD_DLL, EVENT_UNLOAD_DLL.")
        event = client.wait_for_debug_event(et, timeout=timeout)
        if event is None:
            return err(f"Timed out waiting for {event_type}.", ErrorType.TIMEOUT,
                       hint=_ERROR_HINTS[ErrorType.TIMEOUT])
        event_data = event.event_data.model_dump() if event.event_data is not None else None
        return ok(event_type=str(event.event_type), event_data=event_data)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@mcp.tool()
def get_setting(section: str, name: str, type: str = "string") -> dict:
    """Read an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            val = client.get_setting_int(section, name)
        else:
            val = client.get_setting_str(section, name)
        if val is None:
            return err(f"Setting [{section}]{name} not found.", ErrorType.NOT_FOUND,
                       hint=_ERROR_HINTS[ErrorType.NOT_FOUND])
        return ok(section=section, name=name, value=val)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def set_setting(section: str, name: str, value: str, type: str = "string") -> dict:
    """Write an x64dbg setting.

    Args:
        section: Settings section name
        name: Setting name
        value: Setting value
        type: 'string' or 'int'
    """
    try:
        client = _require_client()
        if type == "int":
            result = client.set_setting_int(section, name, int(value))
        else:
            result = client.set_setting_str(section, name, value)
        if not result:
            return err("Failed to update setting.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(section=section, name=name, value=value)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

@mcp.tool()
def log_message(message: str) -> dict:
    """Log a message to the x64dbg log window.

    Args:
        message: Message text to log
    """
    try:
        client = _require_client()
        result = client.log(message)
        if not result:
            return err("Failed to log message.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok(message=message)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def refresh_gui() -> dict:
    """Refresh all x64dbg GUI views."""
    try:
        client = _require_client()
        result = client.gui_refresh_views()
        if not result:
            return err("Failed to refresh GUI.", ErrorType.RPC_ERROR, hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok()
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Memory Analysis — offline (no x64dbg required)
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_entropy(address: str, size: int = 4096, window_size: int = 0) -> dict:
    """Calculate Shannon entropy of a debuggee memory region.

    High entropy (>7.0) = encrypted/compressed.
    Medium (4.5–6.5) = likely x86 code.
    Low (<4.0) = likely data or zeros.

    If window_size > 0, returns sliding window results.
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)

        def _verdict(e: float) -> str:
            if e > 7.0:
                return "ENCRYPTED/COMPRESSED"
            if 4.5 <= e <= 6.5:
                return "LIKELY CODE"
            return "LIKELY DATA"

        if window_size > 0:
            results = sliding_entropy(data, window_size)
            sliding = [
                {
                    "offset": offset,
                    "address": _format_address(addr + offset),
                    "entropy": round(ent, 4),
                    "verdict": _verdict(ent),
                }
                for offset, ent in results
            ]
            return ok(address=_format_address(addr), size=size, window_size=window_size, sliding=sliding)

        ent = shannon_entropy(data)
        return ok(
            address=_format_address(addr),
            size=size,
            entropy=round(ent, 4),
            verdict=_verdict(ent),
            is_code=4.5 <= ent <= 6.5,
            is_encrypted=ent > 7.0,
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def find_strings(address: str, size: int = 65536, min_length: int = 4, encoding: str = "both") -> dict:
    """Extract printable strings from a debuggee memory region."""
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = min(size, 1048576)
        data = client.read_memory(addr, size)

        results = []
        if encoding in ("ascii", "both"):
            results.extend(_ext_find_strings(data, min_length))
        if encoding in ("utf16le", "both"):
            results.extend(find_strings_utf16le(data, min_length))

        shown = results[:100]
        strings = [
            {"offset": offset, "address": _format_address(addr + offset), "value": s}
            for offset, s in shown
        ]
        return ok(
            address=_format_address(addr),
            size=size,
            encoding=encoding,
            strings=strings,
            total=len(results),
            shown=len(shown),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def scan_hex_pattern(address: str, size: int, pattern: str) -> dict:
    """Scan a debuggee memory region for a hex pattern with ?? wildcards.

    Example: '55 8B EC' (x86 function prologue)
    Example: 'E8 ?? ?? ?? ?? 83 C4 04' (call + add esp, 4)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)
        matches = scan_pattern(data, pattern)
        shown = matches[:50]
        return ok(
            pattern=pattern,
            address=_format_address(addr),
            size=size,
            matches=[_format_address(addr + off) for off in shown],
            total=len(matches),
            shown=len(shown),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def find_x86_prologues(
    address: str,
    size: int = 65536,
    patterns: list[str] | None = None,
) -> dict:
    """Find x86/x64 function prologues in a debuggee memory region.

    Detects common function-entry byte patterns. High density indicates
    decrypted machine code.

    Args:
        address: Region start address.
        size: Number of bytes to scan.
        patterns: Optional list of custom hex patterns (e.g. ["55 8B EC"]).
            If omitted, a built-in set of x86 and x64 prologue patterns is used.
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)

        if patterns:
            pattern_list = patterns
        else:
            # Built-in prologue signatures covering x86 and x64
            pattern_list = [
                "55 8B EC",          # x86: push ebp; mov ebp, esp
                "55 89 E5",          # x86: push ebp; mov ebp, esp (alt)
                "40 55",             # x64: push rbp (with REX prefix)
                "48 89 5C 24",       # x64: mov [rsp+8], rbx
                "48 8B EC",          # x64: mov rbp, rsp
                "48 83 EC",          # x64: sub rsp, imm8
                "48 81 EC",          # x64: sub rsp, imm32
                "55 48 8B EC",       # x64: push rbp; mov rbp, rsp
            ]

        all_prologues: set[int] = set()
        for pat in pattern_list:
            try:
                all_prologues.update(scan_pattern(data, pat))
            except Exception:
                pass

        pages = max(1, len(data) / 4096)
        density = len(all_prologues) / pages
        verdict = (
            "DECRYPTED CODE (high confidence)" if density > 1.0
            else "POSSIBLE CODE" if density > 0.1
            else "SPARSE"
        )
        shown = sorted(all_prologues)[:20]
        return ok(
            address=_format_address(addr),
            size=size,
            prologues=[_format_address(addr + off) for off in shown],
            total=len(all_prologues),
            shown=len(shown),
            density=round(density, 2),
            verdict=verdict,
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def analyze_region_full(address: str, size: int = 65536) -> dict:
    """Run comprehensive analysis on a debuggee memory region.

    Returns: entropy, string count, known strings in target binary,
    function prologue density, and a code/data/encrypted verdict.
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)
        result = _analyze_region(data, addr)
        return ok(
            address=_format_address(addr),
            size=result["size"],
            entropy=round(result["entropy"], 4),
            is_likely_code=result["is_likely_code"],
            string_count=result["string_count"],
            prologue_count=result["prologue_count"],
            known_strings=[
                {"address": _format_address(offset), "value": s}
                for offset, s in result["known_strings"]
            ],
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def compare_memory(address_a: str, address_b: str, size: int = 4096) -> dict:
    """Compare two debuggee memory regions byte-by-byte."""
    try:
        client = _require_client()
        a = _parse_address_or_expression(address_a)
        b = _parse_address_or_expression(address_b)
        data_a = client.read_memory(a, size)
        data_b = client.read_memory(b, size)

        if data_a == data_b:
            return ok(equal=True, address_a=_format_address(a), address_b=_format_address(b),
                      size=size, total_differences=0, differences=[])

        diffs = [(i, data_a[i], data_b[i]) for i in range(size) if data_a[i] != data_b[i]]
        shown = diffs[:50]
        return ok(
            equal=False,
            address_a=_format_address(a),
            address_b=_format_address(b),
            size=size,
            total_differences=len(diffs),
            differences=[
                {"address": _format_address(a + offset), "value_a": f"{va:02X}", "value_b": f"{vb:02X}"}
                for offset, va, vb in shown
            ],
            shown=len(shown),
        )
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# External Process — no debugger required
# ---------------------------------------------------------------------------

@mcp.tool()
def launch_process_no_debug(exe_path: str, args: str = "", cwd: str = "", wait: bool = False) -> dict:
    """Launch a process WITHOUT debugger attachment. Returns the PID.

    Use this to run targets normally, then dump them after decryption completes.
    """
    import subprocess
    try:
        cmd = [exe_path]
        if args.strip():
            cmd.extend(args.split())
        proc = subprocess.Popen(cmd, cwd=cwd or None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if wait:
            proc.wait()
            return ok(exe_path=exe_path, pid=proc.pid, exit_code=proc.returncode, completed=True)
        return ok(exe_path=exe_path, pid=proc.pid, completed=False)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def dump_process_no_debugger(pid: int, output_dir: str = "", method: str = "procdump") -> dict:
    """Dump process memory WITHOUT debugger attachment.

    Methods:
      - procdump: ProcDump -r (clone via PssCaptureSnapshot, never pauses)
      - comsvcs: Built-in comsvcs.dll MiniDump (always available)
      - minidump: Python ctypes call to MiniDumpWriteDump
    """
    try:
        if method not in ("procdump", "comsvcs", "minidump"):
            return err(f"Unknown method '{method}'. Use: procdump, comsvcs, minidump.",
                       ErrorType.BAD_ARGUMENT, hint=_ERROR_HINTS[ErrorType.BAD_ARGUMENT])
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "dumps")
        os.makedirs(output_dir, exist_ok=True)
        dump_path = os.path.join(output_dir, f"dump_{pid}.dmp")

        if method == "procdump":
            result = dump_via_procdump_clone(pid, dump_path)
        elif method == "comsvcs":
            result = dump_via_comsvcs(pid, dump_path)
        else:
            result = dump_via_minidumpwritedump(pid, dump_path)

        if result and os.path.exists(dump_path):
            dump_size = os.path.getsize(dump_path)
            return ok(pid=pid, method=method, dump_path=dump_path, size=dump_size)
        return err("Dump failed.", ErrorType.SNAPSHOT_FAILED,
                   hint=_ERROR_HINTS[ErrorType.SNAPSHOT_FAILED], pid=pid, method=method)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def wait_for_window_title(pid: int, title_substring: str, timeout_sec: int = 120) -> dict:
    """Wait until a process window with a specific title appears.

    Use as a signal that initialization is complete.
    """
    if wait_for_window(pid, title_substring, timeout_sec):
        return ok(pid=pid, title_substring=title_substring)
    return err(f"Window '{title_substring}' not found within {timeout_sec}s.",
               ErrorType.TIMEOUT, hint=_ERROR_HINTS[ErrorType.TIMEOUT],
               pid=pid, timeout_sec=timeout_sec)


@mcp.tool()
def list_running_processes(filter_name: str = "") -> dict:
    """List running processes, optionally filtered by name."""
    import psutil
    try:
        procs = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.info
                name = info["name"] or "???"
                if filter_name and filter_name.lower() not in name.lower():
                    continue
                procs.append({"pid": info["pid"], "name": name})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda p: p["pid"])
        return ok(processes=procs, total=len(procs), filter=filter_name)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def terminate_process(pid: int) -> dict:
    """Terminate a process by PID."""
    import psutil
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        return ok(pid=pid, action="terminated")
    except psutil.NoSuchProcess:
        return err(f"Process {pid} not found.", ErrorType.NOT_FOUND,
                   hint=_ERROR_HINTS[ErrorType.NOT_FOUND], pid=pid)
    except psutil.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return ok(pid=pid, action="killed")
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def suspend_process(pid: int) -> dict:
    """Suspend all threads in a process WITHOUT debugger attachment."""
    try:
        if nt_suspend_process(pid):
            return ok(pid=pid)
        return err(f"Failed to suspend process {pid}.", ErrorType.PERMISSION_DENIED,
                   hint=_ERROR_HINTS[ErrorType.PERMISSION_DENIED], pid=pid)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# PE Analysis — read-only, no x64dbg required
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_pe(pe_path: str) -> dict:
    """Parse PE headers, sections, entry point, TLS callbacks (read-only).

    NO patching — PE integrity checks block modified executables.
    """
    try:
        sections = get_sections(pe_path)
        tls = get_tls_callbacks(pe_path)
        ep = get_entry_point(pe_path)
        base = get_image_base(pe_path)
        bits = get_bitness(pe_path)
        return ok(
            file=os.path.basename(pe_path),
            bitness=bits,
            image_base=_format_address(base),
            entry_point=_format_address(base + ep),
            entry_point_rva=f"0x{ep:X}",
            tls_callbacks=[f"0x{cb:X}" for cb in tls],
            sections=[
                {
                    "name": sec["name"],
                    "virtual_address": _format_address(sec["virtual_address"]),
                    "virtual_size": f"0x{sec['virtual_size']:X}",
                    "raw_size": f"0x{sec['size_of_raw_data']:X}",
                }
                for sec in sections
            ],
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_pe_imports(pe_path: str, dll_filter: str = "") -> dict:
    """List imported functions from a PE file."""
    try:
        imports = get_imports(pe_path, dll_filter)
        by_dll: dict[str, list[str]] = {}
        for imp in imports:
            dll = imp["dll"]
            by_dll.setdefault(dll, []).append(imp["function_name"])
        return ok(
            file=os.path.basename(pe_path),
            dll_filter=dll_filter,
            imports=[
                {"dll": dll, "functions": funcs, "count": len(funcs)}
                for dll, funcs in sorted(by_dll.items())
            ],
            total_imports=len(imports),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_pe_exports(pe_path: str, filter_name: str = "") -> dict:
    """List exported functions from a PE file (DLL or EXE with exports).

    Useful for resolving DLL exports that the target binary calls by
    ordinal, and for building a symbol map before attaching the debugger.

    Args:
        pe_path: Path to the PE file on disk.
        filter_name: Optional substring filter on the export name.
    """
    try:
        exports = get_exports(pe_path)
        if filter_name:
            exports = [e for e in exports if filter_name.lower() in (e.get("name") or "").lower()]
        shown = exports[:200]
        return ok(
            file=os.path.basename(pe_path),
            filter=filter_name,
            exports=[
                {
                    "ordinal": exp.get("ordinal"),
                    "address": _format_address(exp.get("virtual_address", 0)),
                    "name": exp.get("name") or "",
                }
                for exp in shown
            ],
            total=len(exports),
            shown=len(shown),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def check_pe_security(pe_path: str) -> dict:
    """Check PE security mitigations: NX, ASLR, CFG, Integrity Check."""
    try:
        result = check_security(pe_path)
        return ok(file=os.path.basename(pe_path), mitigations=result)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def locate_protected_sections(pe_path: str) -> dict:
    """Locate sections with non-standard or obfuscated names.

    Searches for sections whose names contain typical packer/protection
    indicators (e.g. 'text', 'data', 'rsrc', or user-provided patterns).
    """
    try:
        sections = get_sections(pe_path)
        target = {"text", "data", "rsrc", "code", "bss"}
        found = []
        for sec in sections:
            name_lower = sec["name"].lower().strip("\x00").rstrip("\x00")
            if name_lower in target or any(t in name_lower for t in target):
                found.append({
                    "name": sec["name"],
                    "virtual_address": _format_address(sec["virtual_address"]),
                    "virtual_size": f"0x{sec['virtual_size']:X}",
                    "virtual_size_bytes": sec["virtual_size"],
                })
        return ok(file=os.path.basename(pe_path), interesting_sections=found, total=len(found))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def get_pe_tls_callbacks(pe_path: str) -> dict:
    """List TLS callback addresses from a PE file."""
    try:
        callbacks = get_tls_callbacks(pe_path)
        return ok(
            file=os.path.basename(pe_path),
            callbacks=[f"0x{cb:X}" for cb in callbacks],
            total=len(callbacks),
        )
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Section Extraction — dump file analysis
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_section_from_dump(dump_path: str, section_va: str, size: int, output_path: str) -> dict:
    """Extract raw bytes at a VA from a process minidump file.

    Uses memprocfs if available, falls back to the ``minidump`` library for
    proper MINIDUMP_MEMORY_DESCRIPTOR stream parsing, then tries a pefile
    embedded-PE search as a last resort.
    """
    try:
        va = _parse_address_or_expression(section_va)

        extracted = None
        # Fallback 1: memprocfs (works on raw dumps and VM snapshots)
        try:
            import memprocfs
            vmm = memprocfs.Vmm(["-device", dump_path])
            for proc in vmm.process_list():
                try:
                    data = proc.memory.read(va, size)
                    if data and len(data) == size:
                        extracted = bytes(data)
                        break
                except Exception:
                    continue
        except Exception:
            pass

        # Fallback 2: proper minidump stream parsing
        if extracted is None:
            try:
                from minidump.minidumpfile import MinidumpFile
                mf = MinidumpFile.parse(dump_path)
                reader = mf.get_reader()
                data = reader.read(va, size)
                if data and len(data) == size:
                    extracted = bytes(data)
            except Exception:
                pass

        # Fallback 3: embedded PE search (crude, only works if the dump
        # happens to contain a raw PE mapping at a file offset)
        if extracted is None:
            try:
                import pefile as pef
                with open(dump_path, "rb") as f:
                    raw = f.read()
                offset = 0
                while offset < len(raw) - 2 and extracted is None:
                    if raw[offset:offset + 2] == b"MZ":
                        try:
                            pe = pef.PE(data=raw[offset:])
                            image_base = pe.OPTIONAL_HEADER.ImageBase
                            for section in pe.sections:
                                sec_va = image_base + section.VirtualAddress
                                sec_end = sec_va + section.Misc_VirtualSize
                                if sec_va <= va < sec_end:
                                    section_offset = va - sec_va
                                    section_data = section.get_data()
                                    if section_offset + size <= len(section_data):
                                        extracted = section_data[section_offset:section_offset + size]
                                        break
                        except Exception:
                            pass
                    offset += 1
            except ImportError:
                pass

        if extracted is None:
            return err(f"Could not extract bytes at VA {_format_address(va)} from dump.",
                       ErrorType.NOT_FOUND, hint=_ERROR_HINTS[ErrorType.NOT_FOUND],
                       section_va=_format_address(va), dump_path=dump_path)

        with open(output_path, "wb") as f:
            f.write(extracted)
        return ok(section_va=_format_address(va), size=len(extracted), output_path=output_path)
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def validate_extracted_binary(binary_path: str, expected_va: int = 0) -> dict:
    """Validate an extracted section: entropy, prologues, known strings.

    Scores 0–100. >=70 = VALID, >=40 = SUSPECT, <40 = INVALID.
    """
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
        result = validate_extracted_section(data, os.path.basename(binary_path))
        return ok(
            file=os.path.basename(binary_path),
            size=result["size"],
            entropy=round(result["entropy"], 4),
            prologue_count=result["prologue_count"],
            score=result["score"],
            verdict=result["verdict"],
            checks=result["checks"],
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def extract_protected_sections(dump_path: str, output_dir: str = "") -> dict:
    """Extract sections from a process dump file.

    Extracts all sections defined in the target binary's section table.
    """
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")
        os.makedirs(output_dir, exist_ok=True)

        sections = []
        for name, (va, size) in TARGET_SECTIONS.items():
            output = os.path.join(output_dir, f"{name.lower()}.bin")
            extracted = None

            try:
                import memprocfs
                vmm = memprocfs.Vmm(["-device", dump_path])
                for proc in vmm.process_list():
                    try:
                        data = proc.memory.read(va, size)
                        if data and len(data) == size:
                            extracted = bytes(data)
                            break
                    except Exception:
                        continue
            except Exception:
                pass

            if extracted is None:
                sections.append({"name": name, "success": False, "output_path": None})
                continue

            with open(output, "wb") as f:
                f.write(extracted)

            ent = shannon_entropy(extracted)
            prologues = len(scan_pattern(extracted, "55 8B EC")) + len(scan_pattern(extracted, "55 89 E5"))
            sections.append({
                "name": name,
                "success": True,
                "output_path": output,
                "size": len(extracted),
                "entropy": round(ent, 4),
                "prologues": prologues,
            })

        succeeded = sum(1 for s in sections if s["success"])
        return ok(dump_path=dump_path, output_dir=output_dir, sections=sections,
                  total=len(sections), succeeded=succeeded)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Master Workflow — protected binary extraction
# ---------------------------------------------------------------------------

@mcp.tool()
def workflow_extract_binary(
    target_exe: str,
    timeout_sec: int = 120,
    dump_method: str = "procdump",
    output_dir: str = "",
    validate: bool = True,
    window_title: str = "Ready",
) -> dict:
    """Extract sections from a binary via cold dump (no debugger, no patching).

    Steps: launch -> wait for initialization -> dump process -> extract sections -> validate.

    NO debugger, NO PE patching. Works against run-time integrity checks.

    Args:
        target_exe: Full path to the target executable
        timeout_sec: Max wait for initialization signal (default 120)
        dump_method: 'procdump' (recommended), 'comsvcs', or 'minidump'
        output_dir: Output directory (default: ./extracted/)
        validate: Run entropy + string analysis after extraction
        window_title: Window title substring to wait for as init signal (default 'Ready')
    """
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")

        result = workflow_extract_binary(
            target_exe=target_exe,
            timeout_sec=timeout_sec,
            dump_method=dump_method,
            output_dir=output_dir,
            validate=validate,
            terminate_after=True,
            window_title=window_title,
        )

        sections = []
        for section, path in result.sections_extracted.items():
            entry = {"name": section, "path": path, "size": os.path.getsize(path) if os.path.exists(path) else 0}
            analysis = result.analysis.get(section, {})
            if analysis:
                entry["score"] = analysis.get("score")
                entry["verdict"] = analysis.get("verdict")
                entry["checks"] = analysis.get("checks", [])
            sections.append(entry)

        return ok(
            success=result.success,
            target_exe=target_exe,
            pid=result.pid,
            dump_method=result.dump_method,
            dump_path=result.dump_path,
            elapsed_sec=round(result.elapsed_sec, 1),
            sections=sections,
            errors=result.errors,
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def workflow_batch_cold_dump(
    target_exe: str,
    iterations: int = 5,
    dump_method: str = "procdump",
    output_dir: str = "",
) -> dict:
    """Run extraction multiple times, compare dumps for consistency."""
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")

        runs = []
        for i in range(iterations):
            iteration_dir = os.path.join(output_dir, f"run_{i + 1:02d}")
            result = workflow_extract_binary(
                target_exe=target_exe,
                dump_method=dump_method,
                output_dir=iteration_dir,
                sections=["Stext"],
                validate=True,
                terminate_after=True,
            )
            analysis = result.analysis.get("Stext", {})
            runs.append({
                "run": i + 1,
                "success": result.success,
                "score": analysis.get("score", 0),
                "entropy": analysis.get("entropy"),
            })

        succeeded = sum(1 for r in runs if r["success"])
        return ok(target_exe=target_exe, iterations=iterations, runs=runs,
                  succeeded=succeeded, failed=iterations - succeeded)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Phase 2 — New debugger commands
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugee_tls_callbacks() -> dict:
    """Get TLS callback RVAs from the debuggee's PE file on disk."""
    try:
        client = _require_client()
        callbacks = client.get_tls_callbacks()
        return ok(callbacks=[f"0x{cb:X}" for cb in callbacks], total=len(callbacks))
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def debuggee_virtual_protect_ex(address: str, size: int, new_protection: int = 0x20) -> dict:
    """Change memory protection on a debuggee region.

    Uses VirtualProtectEx. Common values:
    0x20 = PAGE_EXECUTE_READ, 0x04 = PAGE_READWRITE, 0x40 = PAGE_EXECUTE_READWRITE
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virtual_protect_ex(addr, size, new_protection)
        if not result:
            return err("VirtualProtectEx failed.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], address=_format_address(addr))
        return ok(address=_format_address(addr), size=size, protection=f"0x{new_protection:02X}")
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def debuggee_suspend_all_threads() -> dict:
    """Suspend all threads in the debuggee via ToolHelp snapshot."""
    try:
        client = _require_client()
        result = client.suspend_all_threads()
        if not result:
            return err("Failed to suspend threads.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR])
        return ok()
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def debuggee_get_peb() -> dict:
    """Read the debuggee's PEB: BeingDebugged, NtGlobalFlag, HeapFlags."""
    try:
        client = _require_client()
        peb = client.get_peb()
        return ok(
            being_debugged=peb.being_debugged,
            nt_global_flag=f"0x{peb.nt_global_flag:08X}",
            heap_flags=f"0x{peb.heap_flags:08X}",
            heap_force_flags=f"0x{peb.heap_force_flags:08X}",
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def debuggee_get_process_info() -> dict:
    """Get debuggee process metadata: PID, entry point, image base, size, path."""
    try:
        client = _require_client()
        info = client.get_process_info()
        return ok(
            pid=info.pid,
            main_thread_id=info.main_thread_id,
            entry_point=_format_address(info.image_base + info.entry_point),
            image_base=_format_address(info.image_base),
            image_size=info.image_size,
            is_64bit=info.is_64bit,
            exe_path=info.exe_path,
        )
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Phase 6 — x64dbg fallback tools
# ---------------------------------------------------------------------------

@mcp.tool()
def debug_and_enumerate_tls(target_exe: str) -> dict:
    """Launch target in x64dbg, apply anti-debug profile, and enumerate TLS callbacks."""
    try:
        client = _require_client()
        client.load_executable(target_exe)
        client.wait_until_debugging(timeout=30)
        callbacks = client.get_tls_callbacks()
        peb = client.get_peb()
        info = client.get_process_info()
        return ok(
            target_exe=target_exe,
            image_base=_format_address(info.image_base),
            entry_point=_format_address(info.image_base + info.entry_point),
            peb_being_debugged=peb.being_debugged,
            peb_nt_global_flag=f"0x{peb.nt_global_flag:08X}",
            tls_callbacks=[
                {"index": i, "rva": f"0x{cb:X}", "va": _format_address(info.image_base + cb)}
                for i, cb in enumerate(callbacks)
            ],
            total_callbacks=len(callbacks),
        )
    except Exception as exc:
        return err_from_exc(exc)


@mcp.tool()
def change_memory_protection(address: str, size: int, protection: str = "PAGE_EXECUTE_READ") -> dict:
    """Change memory protection at a specific address.

    Args:
        address: Target address (hex string or expression).
        size: Number of bytes to affect.
        protection: Windows protection constant name (default: PAGE_EXECUTE_READ).
                    Supported: PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
                    PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE.
    """
    protection_map = {
        "PAGE_NOACCESS": 0x01,
        "PAGE_READONLY": 0x02,
        "PAGE_READWRITE": 0x04,
        "PAGE_EXECUTE": 0x10,
        "PAGE_EXECUTE_READ": 0x20,
        "PAGE_EXECUTE_READWRITE": 0x40,
    }
    prot_val = protection_map.get(protection)
    if prot_val is None:
        return err(f"Unknown protection '{protection}'.", ErrorType.BAD_ARGUMENT,
                   hint=f"Supported: {list(protection_map.keys())}")
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virtual_protect_ex(addr, size, prot_val)
        if not result:
            return err(f"VirtualProtectEx failed for {address}.", ErrorType.RPC_ERROR,
                       hint=_ERROR_HINTS[ErrorType.RPC_ERROR], address=address)
        return ok(address=_format_address(addr), size=size, protection=protection)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Phase 7 — AI-native runtime API (api_runtime package)
# ---------------------------------------------------------------------------
# Registers the structured sandbox / anti-debug / composite / semantic-memory /
# workflow tools onto the same FastMCP instance. Additive — existing tools are
# unchanged. Failure here must not prevent the legacy tools from loading.
try:
    from x64dbg_automate.api_runtime import register_runtime_tools

    _RUNTIME_TOOLS_REGISTERED = register_runtime_tools(mcp)
except Exception as _runtime_reg_err:  # pragma: no cover - defensive
    print(
        f"Warning: failed to register runtime API tools: {_runtime_reg_err}",
        file=sys.stderr,
    )
    _RUNTIME_TOOLS_REGISTERED = 0


# ---------------------------------------------------------------------------
# Infrastructure tools (C16) — health, version, orientation
# ---------------------------------------------------------------------------

@mcp.tool()
def health_check(sandbox_id: str = "") -> dict:
    """Check debugger connection health and round-trip latency.

    Returns server liveness, plugin responsiveness, version compatibility,
    and the RPC round-trip time in milliseconds. Safe to call at any time —
    always returns ``success: true``; failures appear as inline fields.

    Args:
        sandbox_id: Optional sandbox to ping; omit to use the active session or
                    the legacy ``_client`` connection.
    """
    import time as _time
    from x64dbg_automate import COMPAT_VERSION

    result: dict = {"success": True, "server_alive": True, "debugger_connected": False,
                    "client_version": COMPAT_VERSION}

    mgr = _get_unified_manager()
    client = None
    try:
        if sandbox_id:
            client = mgr.get_client(sandbox_id)
        elif _client is not None:
            client = _client
        else:
            active = mgr.get_active_session_id()
            if active:
                client = mgr.get_client(active)
    except Exception:
        pass

    if client is None:
        result["hint"] = "No active session. Call start_session() or sandbox_create() first."
        return result

    try:
        t0 = _time.perf_counter()
        plugin_version = client._get_xauto_compat_version()
        debugger_version = client.get_debugger_version()
        rtt_ms = round((_time.perf_counter() - t0) * 1000, 2)
        compatible = plugin_version == COMPAT_VERSION
        result.update({
            "debugger_connected": True,
            "plugin_version": plugin_version,
            "debugger_version": debugger_version,
            "compatible": compatible,
            "rtt_ms": rtt_ms,
        })
        if not compatible:
            result["hint"] = (
                f"Version mismatch: plugin={plugin_version}, client={COMPAT_VERSION}. "
                "Rebuild and redeploy the x64dbg plugin."
            )
    except Exception as exc:
        result.update({
            "debugger_connected": False,
            "error": str(exc),
            "hint": "x64dbg may have crashed or the Axon_MCP plugin is not loaded.",
        })

    return result


@mcp.tool()
def get_plugin_version() -> dict:
    """Return version compatibility strings for the plugin and Python client.

    ``compatible: true`` means the plugin and client share the same
    ``COMPAT_VERSION`` string (``Axon_MCP``). A mismatch means the plugin
    binary is stale and needs to be rebuilt and redeployed.
    """
    from x64dbg_automate import COMPAT_VERSION

    result: dict = {"success": True, "client_version": COMPAT_VERSION, "compatible": False}

    mgr = _get_unified_manager()
    client = None
    try:
        client = _client
        if client is None:
            active = mgr.get_active_session_id()
            if active:
                client = mgr.get_client(active)
    except Exception:
        pass

    if client is None:
        result["hint"] = "No active session — cannot query plugin version."
        return result

    try:
        plugin_version = client._get_xauto_compat_version()
        debugger_version = client.get_debugger_version()
        result.update({
            "plugin_version": plugin_version,
            "debugger_version": debugger_version,
            "compatible": plugin_version == COMPAT_VERSION,
        })
    except Exception as exc:
        result["error"] = str(exc)

    return result


@mcp.tool()
def session_summary(sandbox_id: str = "") -> dict:
    """Generate a concise status snapshot for agent orientation.

    Aggregates: active sandbox metadata, debugger state, current instruction
    pointer and symbol, loaded-module count, active breakpoints, applied patch
    count, checkpoint count, and semantic-memory statistics. Each section is
    collected independently so a failure in one does not prevent the others.

    Args:
        sandbox_id: Sandbox to summarise; omit for the active session.
    """
    from x64dbg_automate.api_runtime.semantic_memory import _get_store

    summary: dict = {"success": True}
    mgr = _get_unified_manager()

    # --- sandbox / client ---
    client = None
    try:
        if sandbox_id:
            sandbox = mgr.get_sandbox(sandbox_id)
        else:
            try:
                sandbox = mgr.get_sandbox()
            except KeyError:
                sandbox = None
        if sandbox is not None:
            summary["sandbox"] = sandbox.to_info()
            client = sandbox.client
            summary["patches"] = {"total": len(sandbox.patches)}
            summary["checkpoints"] = {"total": len(sandbox.checkpoints)}
    except Exception as exc:
        summary["sandbox_error"] = str(exc)

    if client is None:
        client = _client

    # --- debugger state ---
    dbg: dict = {}
    if client is not None:
        try:
            dbg["is_debugging"] = client.is_debugging()
            dbg["is_running"] = client.is_running()
            try:
                dbg["debuggee_pid"] = client.debugee_pid()
            except Exception:
                pass
        except Exception as exc:
            dbg["error"] = str(exc)

        if dbg.get("is_debugging") and not dbg.get("is_running"):
            try:
                cip = client.get_reg("cip")
                dbg["cip"] = f"0x{cip:X}"
                sym = client.get_symbol_at(cip)
                if sym and sym.undecoratedSymbol:
                    dbg["cip_symbol"] = sym.undecoratedSymbol
            except Exception:
                pass
    else:
        dbg["error"] = "No active client. Call start_session() or connect_to_session() first."
    summary["debugger"] = dbg

    # --- modules ---
    if client is not None:
        try:
            mods = client.get_modules()
            summary["modules"] = {"total": len(mods)}
        except Exception:
            pass

    # --- breakpoints ---
    if client is not None:
        try:
            bps = _get_all_breakpoints(client)
            summary["breakpoints"] = {
                "total": len(bps),
                "enabled": sum(1 for bp in bps if bp.enabled),
            }
        except Exception:
            pass

    # --- semantic memory ---
    try:
        stats = _get_store().stats()
        summary["semantic_memory"] = stats
    except Exception as exc:
        summary["semantic_memory"] = {"error": str(exc)}

    return summary


# ---------------------------------------------------------------------------
# P1 — Agent Orientation & Discovery
# ---------------------------------------------------------------------------

@mcp.tool()
def list_tools_by_group(group: str = "", limit: int = 50) -> dict:
    """List MCP tools filtered by functional group.

    Groups are heuristic categories based on tool names and descriptions.
    Use this to discover tools in a specific domain.

    Args:
        group: Group name — 'session', 'memory', 'register', 'breakpoint',
               'analysis', 'antidebug', 'execution', 'trace', 'workflow',
               'offline', 'semantic', 'macro', 'infrastructure'. Use '' for all.
        limit: Maximum results per group (default 50)
    """
    try:
        tm = getattr(mcp, "_tool_manager", None)
        if tm is None:
            return {"success": False, "error": "Tool manager not available"}
        tools = getattr(tm, "_tools", {})

        group_keywords: dict[str, list[str]] = {
            "session": ["session", "connect", "disconnect", "start", "terminate", "list_sessions"],
            "memory": ["memory", "read_memory", "write_memory", "allocate", "free", "virt", "memmap"],
            "register": ["register", "reg", "get_reg", "set_reg"],
            "breakpoint": ["breakpoint", "bp", "conditional", "hardware", "memory_breakpoint"],
            "analysis": ["analyze", "disassemble", "cfg", "threads", "modules", "symbols", "stack", "seh"],
            "antidebug": ["anti", "debug", "peb", "scylla", "hide", "timing", "tls"],
            "execution": ["go", "pause", "step", "skip", "run_to", "trace"],
            "trace": ["trace", "single_step", "execution_trace"],
            "workflow": ["workflow", "extract", "dump", "protected", "process"],
            "offline": ["pe_", "entropy", "string", "pattern", "extract", "validate", "analyze_pe"],
            "semantic": ["memory_record", "memory_query", "memory_list", "memory_get", "memory_stats", "memory_export", "memory_import", "memory_delete"],
            "macro": ["macro", "script"],
            "infrastructure": ["report", "summary", "tool_search", "suggest", "health", "coverage", "checkpoint"],
        }

        results: list[dict] = []
        groups_found: set[str] = set()

        for name, tool_obj in tools.items():
            desc = getattr(tool_obj, "description", "") or ""
            text = f"{name} {desc}".lower()

            matched_groups: list[str] = []
            for g, keywords in group_keywords.items():
                if any(kw in text for kw in keywords):
                    matched_groups.append(g)

            if not group or group.lower() in matched_groups:
                results.append({
                    "name": name,
                    "description": desc.split("\n")[0] if desc else "",
                    "groups": matched_groups,
                })
                groups_found.update(matched_groups)

        if group and not results:
            return {
                "success": True,
                "group": group,
                "total": 0,
                "results": [],
                "available_groups": sorted(group_keywords.keys()),
                "hint": f"No tools matched group '{group}'. Try one of the available_groups.",
            }

        return {
            "success": True,
            "group": group or "all",
            "total": len(results),
            "results": results[:limit],
            "available_groups": sorted(groups_found) if group else sorted(group_keywords.keys()),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def tool_search(query: str, limit: int = 10) -> dict:
    """Search available MCP tools by keyword.

    Searches tool names and descriptions. Returns the best matches so agents
    can discover capabilities without scrolling through 162 tools.

    Args:
        query: Keyword to search (e.g. 'entropy', 'breakpoint', 'cfg', 'suspend')
        limit: Maximum results to return (default 10)
    """
    try:
        q = query.lower()
        results = []
        # FastMCP stores registered tools in the tool manager
        tm = getattr(mcp, "_tool_manager", None)
        if tm is None:
            return {"success": False, "error": "Tool manager not available"}
        tools = getattr(tm, "_tools", {})
        for name, tool_obj in tools.items():
            desc = getattr(tool_obj, "description", "") or ""
            score = 0
            if q in name.lower():
                score += 100
            if q in desc.lower():
                score += 50
            if score > 0:
                results.append({
                    "name": name,
                    "description": desc.split("\n")[0] if desc else "",
                    "score": score,
                })
        results.sort(key=lambda x: x["score"], reverse=True)
        return {"success": True, "query": query, "total": len(results), "results": results[:limit]}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def suggest_next_actions(context: str = "") -> dict:
    """Suggest logical next actions based on current debugger state and history.

    Analyzes the active session (debugger state, CIP, breakpoints, semantic
    memory) and returns a prioritized list of recommended tools with rationale.

    Args:
        context: Optional extra context from the agent (e.g. 'looking for crypto')
    """
    suggestions = []
    try:
        client = _client
        mgr = _get_unified_manager()
        # Try to get active sandbox info
        sandbox = None
        try:
            sandbox = mgr.get_sandbox()
        except Exception:
            pass

        # --- State-based rules ---
        if client is None:
            suggestions.append({
                "priority": 0,
                "action": "start_session or connect_to_session",
                "rationale": "No active debugger session.",
            })
        else:
            try:
                debugging = client.is_debugging()
                running = client.is_running()
            except Exception:
                debugging = False
                running = False

            if debugging and running:
                suggestions.append({
                    "priority": 1,
                    "action": "pause or sandbox_pause",
                    "rationale": "Debuggee is running — pause to inspect state.",
                })
            elif debugging and not running:
                suggestions.append({
                    "priority": 1,
                    "action": "get_all_registers + disassemble at CIP",
                    "rationale": "Debuggee is paused — inspect current context.",
                })
                try:
                    cip = client.get_reg("cip")
                    sym = client.get_symbol_at(cip)
                    if sym and sym.undecoratedSymbol:
                        suggestions.append({
                            "priority": 2,
                            "action": "analyze_function_cfg",
                            "rationale": f"At known function {sym.undecoratedSymbol} — extract CFG.",
                        })
                except Exception:
                    pass

                # Check if we have breakpoints
                try:
                    bps = _get_all_breakpoints(client)
                    if not bps:
                        suggestions.append({
                            "priority": 3,
                            "action": "set_breakpoint",
                            "rationale": "No breakpoints set — consider placing one on a target function.",
                        })
                except Exception:
                    pass

                # Check modules
                try:
                    mods = client.get_modules()
                    if len(mods) <= 1:
                        suggestions.append({
                            "priority": 4,
                            "action": "wait_until_stopped or go",
                            "rationale": "Only main module loaded — let execution continue to load imports.",
                        })
                except Exception:
                    pass

            elif not debugging:
                suggestions.append({
                    "priority": 1,
                    "action": "start_session or connect_to_session",
                    "rationale": "Debugger is attached but not debugging any process.",
                })

        # --- Semantic memory rules ---
        try:
            from x64dbg_automate.api_runtime.semantic_memory import _get_store
            mem_stats = _get_store().stats()
            if mem_stats.get("total_entries", 0) == 0:
                suggestions.append({
                    "priority": 5,
                    "action": "memory_record_finding",
                    "rationale": "Semantic memory is empty — record findings as you discover them.",
                })
            else:
                suggestions.append({
                    "priority": 5,
                    "action": "memory_query_findings or memory_list_keys",
                    "rationale": f"Semantic memory has {mem_stats['total_entries']} entries — query past findings.",
                })
        except Exception:
            pass

        # --- Context-aware rules ---
        ctx = context.lower()
        if "crypto" in ctx or "encrypt" in ctx or "decrypt" in ctx:
            suggestions.append({
                "priority": 2,
                "action": "crypto_material_search",
                "rationale": "Context mentions crypto — search for high-entropy key material.",
            })
        if "unpack" in ctx or "dump" in ctx or "extract" in ctx:
            suggestions.append({
                "priority": 2,
                "action": "dump_process_section or extract_section_from_dump",
                "rationale": "Context mentions extraction — use dump tools.",
            })
        if "anti-debug" in ctx or "antidebug" in ctx or "rdtsc" in ctx:
            suggestions.append({
                "priority": 2,
                "action": "detect_timing_attacks or check_debug_port",
                "rationale": "Context mentions anti-debug — run detection suite.",
            })
        if "strings" in ctx:
            suggestions.append({
                "priority": 3,
                "action": "extract_strings or get_string_at",
                "rationale": "Context mentions strings — search for interesting strings.",
            })

        # --- Sandbox rules ---
        if sandbox is not None:
            try:
                if not sandbox.checkpoints:
                    suggestions.append({
                        "priority": 3,
                        "action": "sandbox_checkpoint",
                        "rationale": "No checkpoints saved — create one before risky operations.",
                    })
            except Exception:
                pass

        suggestions.sort(key=lambda x: x["priority"])
        return {"success": True, "suggestions": suggestions}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def report_generate(title: str = "", include_memory: bool = True) -> dict:
    """Generate a markdown report of the current session for agent handoffs.

    Compiles debugger state, module list, breakpoints, semantic memory findings,
    and sandbox metadata into a single markdown document suitable for sharing
    across agent sessions or archiving.

    Args:
        title: Report title (default: auto-generated from timestamp)
        include_memory: Include semantic memory findings in the report
    """
    try:
        from datetime import datetime, timezone
        from x64dbg_automate.api_runtime.semantic_memory import _get_store

        report_title = title or f"Axon MCP Session Report — {datetime.now(timezone.utc).isoformat(timespec='minutes')}"
        lines = [f"# {report_title}", ""]

        # --- Session summary ---
        try:
            summary = session_summary()
            lines.append("## Session Summary")
            lines.append(f"```json")
            import json
            lines.append(json.dumps(summary, indent=2, default=str))
            lines.append("```")
            lines.append("")
        except Exception as exc:
            lines.append(f"## Session Summary\n*Error: {exc}*\n")

        # --- Debugger details ---
        client = _client
        if client is not None:
            try:
                lines.append("## Debugger State")
                lines.append(f"- Debugging: {client.is_debugging()}")
                lines.append(f"- Running: {client.is_running()}")
                try:
                    lines.append(f"- Debuggee PID: {client.debugee_pid()}")
                except Exception:
                    pass
                try:
                    lines.append(f"- Bitness: {client.debugee_bitness()}")
                except Exception:
                    pass
                try:
                    cip = client.get_reg("cip")
                    lines.append(f"- CIP: `0x{cip:X}`")
                    sym = client.get_symbol_at(cip)
                    if sym and sym.undecoratedSymbol:
                        lines.append(f"- Symbol: `{sym.undecoratedSymbol}`")
                except Exception:
                    pass
                lines.append("")
            except Exception as exc:
                lines.append(f"## Debugger State\n*Error: {exc}*\n")

            # --- Modules ---
            try:
                mods = client.get_modules()
                lines.append("## Loaded Modules")
                for mod in mods:
                    lines.append(f"- `{mod.name}` @ `0x{mod.base:X}` (size {mod.size:,})")
                lines.append("")
            except Exception as exc:
                lines.append(f"## Loaded Modules\n*Error: {exc}*\n")

            # --- Breakpoints ---
            try:
                bps = _get_all_breakpoints(client)
                lines.append("## Breakpoints")
                if bps:
                    for bp in bps:
                        status = "ON" if bp.enabled else "OFF"
                        lines.append(f"- `0x{bp.addr:X}` [{status}] {bp.name or ''}")
                else:
                    lines.append("*None set.*")
                lines.append("")
            except Exception as exc:
                lines.append(f"## Breakpoints\n*Error: {exc}*\n")

        # --- Semantic Memory ---
        if include_memory:
            try:
                store = _get_store()
                stats = store.stats()
                lines.append("## Semantic Memory")
                lines.append(f"- Total entries: {stats.get('total_entries', 0)}")
                lines.append(f"- Unique keys: {stats.get('unique_keys', 0)}")
                lines.append(f"- Store path: `{stats.get('store_path', '')}`")
                lines.append("")
                entries = store.query(limit=20)
                if entries:
                    lines.append("### Recent Findings")
                    for entry in entries:
                        ts = entry.get("timestamp", "")
                        key = entry.get("key", "")
                        cat = entry.get("category", "")
                        val = entry.get("value", {})
                        lines.append(f"**{key}** (`{cat}`, {ts})")
                        lines.append(f"```json")
                        lines.append(json.dumps(val, indent=2, default=str))
                        lines.append("```")
                    lines.append("")
            except Exception as exc:
                lines.append(f"## Semantic Memory\n*Error: {exc}*\n")

        return {"success": True, "report": "\n".join(lines), "title": report_title}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def resume_process(pid: int) -> dict:
    """Resume all threads in a process WITHOUT debugger attachment.

    Uses NtResumeProcess to atomically resume all threads. Pairs with
    suspend_process for cold-dump workflows where the target must be
    frozen while a clone is dumped.

    Args:
        pid: Process ID to resume
    """
    try:
        if nt_resume_process(pid):
            return ok(pid=pid)
        return err(f"Failed to resume process {pid}.", ErrorType.PERMISSION_DENIED,
                   hint=_ERROR_HINTS[ErrorType.PERMISSION_DENIED], pid=pid)
    except Exception as exc:
        return err_from_exc(exc)


# ---------------------------------------------------------------------------
# Phase 9 — Macro recorder (C4) dispatch-level interceptor
# ---------------------------------------------------------------------------
try:
    from x64dbg_automate.api_runtime.api_macros import (
        install_macro_recorder,
        set_mcp_instance,
    )

    set_mcp_instance(mcp)
    _MACRO_RECORDER_INSTALLED = install_macro_recorder(mcp)
except Exception as _macro_rec_err:  # pragma: no cover - defensive
    print(
        f"Warning: failed to install macro recorder: {_macro_rec_err}",
        file=sys.stderr,
    )
    _MACRO_RECORDER_INSTALLED = False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
