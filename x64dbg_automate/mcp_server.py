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
from x64dbg_automate.workflows.securom_extract import (
    workflow_extract_securom, ExtractionResult, TARGET_SECTIONS,
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
    """List all active x64dbg debugger instances and unified sessions. Does not require an active connection."""
    try:
        # Legacy lockfile sessions
        raw_sessions = X64DbgClient.list_sessions()
        legacy = []
        for s in raw_sessions:
            exe_path = s.cmdline[0].strip() if s.cmdline and s.cmdline[0].strip() else "unknown"
            legacy.append({
                "pid": s.pid,
                "path": exe_path,
                "window_title": s.window_title,
                "req_rep_port": s.sess_req_rep_port,
                "pub_sub_port": s.sess_pub_sub_port,
            })

        # Unified sessions (legacy + sandbox)
        mgr = _get_unified_manager()
        unified = [s.to_info() for s in mgr.list_sandboxes()]

        return {
            "success": True,
            "legacy_sessions": legacy,
            "unified_sessions": unified,
            "active_session_id": mgr.get_active_session_id(),
            "total_legacy": len(legacy),
            "total_unified": len(unified),
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
    try:
        client = _require_client()
        # Remove from unified manager
        mgr = _get_unified_manager()
        active = mgr.get_active_session_id()
        if active:
            try:
                mgr.destroy_sandbox(active)
            except Exception:
                pass
        client.terminate_session()
        _client = None
        return {"success": True, "message": "Session terminated."}
    except Exception as e:
        _client = None
        return {"success": False, "error": str(e), "error_type": "TERMINATE_FAILED"}


# ---------------------------------------------------------------------------
# Debug Control
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugger_status() -> str:
    """Get consolidated debugger status: debugging state, running state, PID, bitness, elevated."""
    try:
        client = _require_client()
        debugging = client.is_debugging()
        running = client.is_running()
        pid = client.debugee_pid() if debugging else None
        bitness = client.debugee_bitness() if debugging else None
        elevated = client.debugger_is_elevated()
        parts = [
            f"Debugging: {debugging}",
            f"Running: {running}",
            f"Debuggee PID: {pid}",
            f"Bitness: {bitness}",
            f"Elevated: {elevated}",
        ]
        return "\n".join(parts)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def go(pass_exceptions: bool = False, swallow_exceptions: bool = False) -> str:
    """Resume debuggee execution.

    Args:
        pass_exceptions: Pass exceptions to the debuggee
        swallow_exceptions: Swallow exceptions
    """
    try:
        client = _require_client()
        result = client.go(pass_exceptions=pass_exceptions, swallow_exceptions=swallow_exceptions)
        return "Resumed." if result else "Failed to resume."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause() -> str:
    """Pause the debuggee."""
    try:
        client = _require_client()
        result = client.pause()
        return "Paused." if result else "Failed to pause."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_into(count: int = 1) -> str:
    """Step into one or more instructions.

    Args:
        count: Number of instructions to step into
    """
    try:
        client = _require_client()
        result = client.stepi(step_count=count)
        return f"Stepped into {count} instruction(s)." if result else "Step into failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def step_over(count: int = 1) -> str:
    """Step over one or more instructions.

    Args:
        count: Number of instructions to step over
    """
    try:
        client = _require_client()
        result = client.stepo(step_count=count)
        return f"Stepped over {count} instruction(s)." if result else "Step over failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def skip_instruction(count: int = 1) -> str:
    """Skip instructions without executing them.

    Args:
        count: Number of instructions to skip
    """
    try:
        client = _require_client()
        result = client.skip(skip_count=count)
        return f"Skipped {count} instruction(s)." if result else "Skip failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def run_to_return(frames: int = 1) -> str:
    """Run until a return instruction is encountered.

    Args:
        frames: Number of return frames to seek
    """
    try:
        client = _require_client()
        result = client.ret(frames=frames)
        return "Ran to return." if result else "Run to return failed."
    except Exception as e:
        return f"Error: {e}"


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
) -> str:
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
        return "Trace into completed." if result else "Trace into failed."
    except Exception as e:
        return f"Error: {e}"


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
) -> str:
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
        return "Trace over completed." if result else "Trace over failed."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------

@mcp.tool()
def read_memory(address: str, size: int = 256) -> str:
    """Read memory from the debuggee. Returns hex dump with ASCII sidebar.

    Args:
        address: Address — hex ('0x7FF6A0001000'), register ('RSP'), symbol, or expression ('rsp+0x20')
        size: Number of bytes to read (max 4096)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        size = min(size, 4096)
        data = client.read_memory(addr, size)
        return _format_memory(data, addr)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def write_memory(address: str, hex_data: str) -> str:
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
        return f"Wrote {len(data)} bytes to {_format_address(addr)}." if result else "Write failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def allocate_memory(size: int = 4096, address: str = "0") -> str:
    """Allocate memory in the debuggee's address space (VirtualAlloc).

    Args:
        size: Number of bytes to allocate
        address: Preferred address (0 for any)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virt_alloc(n=size, addr=addr)
        return f"Allocated {size} bytes at {_format_address(result)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def free_memory(address: str) -> str:
    """Free memory in the debuggee's address space (VirtualFree).

    Args:
        address: Address of memory to free
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        client.virt_free(addr)
        return f"Freed memory at {_format_address(addr)}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_memory_map() -> str:
    """List all memory regions in the debuggee's address space."""
    try:
        client = _require_client()
        pages = client.memmap()
        if not pages:
            return "No memory regions found."
        lines = []
        for p in pages:
            lines.append(
                f"{_format_address(p.base_address)}  Size: {_format_address(p.region_size)}  "
                f"Protect: 0x{p.protect:X}  State: 0x{p.state:X}  Info: {p.info}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Registers
# ---------------------------------------------------------------------------

@mcp.tool()
def get_register(register: str) -> str:
    """Read a single register value.

    Args:
        register: Register name (e.g. 'rax', 'eip', 'rsp', 'eflags')
    """
    try:
        client = _require_client()
        val = client.get_reg(register)
        return f"{register} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_register(register: str, value: str) -> str:
    """Write a value to a register.

    Args:
        register: Register name (e.g. 'rax', 'eip')
        value: Hex value to set
    """
    try:
        client = _require_client()
        val = _parse_address_or_expression(value)
        result = client.set_reg(register, val)
        return f"Set {register} = {_format_address(val)}." if result else "Failed to set register."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_all_registers() -> str:
    """Dump all general-purpose registers and flags."""
    try:
        client = _require_client()
        regs = client.get_regs()
        ctx = regs.context
        lines = []
        for field_name in type(ctx).model_fields:
            val = getattr(ctx, field_name)
            if isinstance(val, int):
                lines.append(f"{field_name:8s} = {_format_address(val)}")
        flags = regs.flags
        flag_strs = [f"{k}={int(v)}" for k, v in flags.model_dump().items()]
        lines.append(f"flags    = {' '.join(flag_strs)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Expressions & Commands
# ---------------------------------------------------------------------------

@mcp.tool()
def eval_expression(expression: str) -> str:
    """Evaluate an x64dbg expression. Supports symbols, registers, arithmetic.

    Args:
        expression: Expression to evaluate (e.g. 'kernel32:CreateFileA', 'rax+0x10')
    """
    try:
        client = _require_client()
        val, success = client.eval_sync(expression)
        if not success:
            return f"Evaluation failed for: {expression}"
        return f"{expression} = {_format_address(val)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def execute_command(command: str) -> str:
    """Execute a raw x64dbg command.

    See https://help.x64dbg.com/en/latest/commands/ for available commands.

    Args:
        command: x64dbg command string
    """
    try:
        client = _require_client()
        result = client.cmd_sync(command)
        return f"Command executed. Success: {result}"
    except Exception as e:
        return f"Error: {e}"


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
) -> str:
    """Set a breakpoint (software, hardware, or memory).

    Args:
        address_or_symbol: Hex address or symbol name
        bp_type: 'software', 'hardware', or 'memory'
        name: Optional breakpoint name (software only)
        hardware_mode: Hardware BP mode: 'r' (read), 'w' (write), 'x' (execute)
        memory_mode: Memory BP mode: 'r', 'w', 'x', 'a' (access)
        singleshot: Single-shot breakpoint
    """
    try:
        client = _require_client()
        # Parse address; if it fails, treat as symbol name
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
            result = client.set_breakpoint(addr, name=name, singleshoot=singleshot)

        return f"Breakpoint set at {address_or_symbol}." if result else "Failed to set breakpoint."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def clear_breakpoint(address: str | None = None, bp_type: str = "software") -> str:
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

        return "Breakpoint(s) cleared." if result else "Failed to clear breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def toggle_breakpoint(address: str | None = None, bp_type: str = "software", enable: bool = True) -> str:
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

        action = "Enabled" if enable else "Disabled"
        return f"{action} breakpoint(s)." if result else f"Failed to {action.lower()} breakpoint(s)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def list_breakpoints(bp_type: str = "software") -> str:
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
        if not bps:
            return f"No {bp_type} breakpoints set."
        lines = []
        for bp in bps:
            status = "ON" if bp.enabled else "OFF"
            lines.append(
                f"{_format_address(bp.addr)}  [{status}]  Name: {bp.name}  "
                f"Module: {bp.mod}  Hits: {bp.hitCount}  Singleshot: {bp.singleshoot}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

@mcp.tool()
def disassemble(address: str, count: int = 10) -> str:
    """Disassemble instructions at an address.

    Args:
        address: Address — hex ('0x401000'), register ('RIP'), symbol, or expression
        count: Number of instructions to disassemble (max 100)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        count = min(count, 100)
        lines = []
        current = addr
        for _ in range(count):
            ins = client.disassemble_at(current)
            if ins is None:
                lines.append(f"{_format_address(current)}  ???")
                break
            lines.append(f"{_format_address(current)}  {ins.instruction}")
            current += ins.instr_size
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def assemble(address: str, instruction: str) -> str:
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
            return f"Failed to assemble '{instruction}' at {_format_address(addr)}."
        return f"Assembled '{instruction}' at {_format_address(addr)} ({size} bytes)."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Annotations & Symbols
# ---------------------------------------------------------------------------

@mcp.tool()
def set_label(address: str, text: str) -> str:
    """Set a label at an address.

    Args:
        address: Hex address
        text: Label text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_label_at(addr, text)
        return f"Label set at {_format_address(addr)}." if result else "Failed to set label."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_label(address: str) -> str:
    """Get the label at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        label = client.get_label_at(addr)
        if not label:
            return f"No label at {_format_address(addr)}."
        return f"{_format_address(addr)}: {label}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_comment(address: str, text: str) -> str:
    """Set a comment at an address.

    Args:
        address: Hex address
        text: Comment text
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.set_comment_at(addr, text)
        return f"Comment set at {_format_address(addr)}." if result else "Failed to set comment."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_comment(address: str) -> str:
    """Get the comment at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        comment = client.get_comment_at(addr)
        if not comment:
            return f"No comment at {_format_address(addr)}."
        return f"{_format_address(addr)}: {comment}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_symbol(address: str) -> str:
    """Look up the symbol at an address.

    Args:
        address: Hex address
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        sym = client.get_symbol_at(addr)
        if sym is None:
            return f"No symbol at {_format_address(addr)}."
        return (
            f"Address: {_format_address(sym.addr)}\n"
            f"Decorated: {sym.decoratedSymbol}\n"
            f"Undecorated: {sym.undecoratedSymbol}\n"
            f"Type: {sym.type}  Ordinal: {sym.ordinal}"
        )
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------

@mcp.tool()
def create_thread(entry_address: str, argument: str = "0") -> str:
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
            return "Failed to create thread."
        return f"Thread created. TID: {tid}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def terminate_thread(tid: int) -> str:
    """Terminate a thread in the debuggee.

    Args:
        tid: Thread ID to terminate
    """
    try:
        client = _require_client()
        result = client.thread_terminate(tid)
        return f"Thread {tid} terminated." if result else f"Failed to terminate thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def pause_resume_thread(tid: int, action: str = "pause") -> str:
    """Pause or resume a thread.

    Args:
        tid: Thread ID
        action: 'pause' or 'resume'
    """
    try:
        client = _require_client()
        if action == "resume":
            result = client.thread_resume(tid)
            return f"Thread {tid} resumed." if result else f"Failed to resume thread {tid}."
        else:
            result = client.thread_pause(tid)
            return f"Thread {tid} paused." if result else f"Failed to pause thread {tid}."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def switch_thread(tid: int) -> str:
    """Switch the debugger's active thread context.

    Args:
        tid: Thread ID to switch to
    """
    try:
        client = _require_client()
        result = client.switch_thread(tid)
        return f"Switched to thread {tid}." if result else f"Failed to switch to thread {tid}."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

@mcp.tool()
def get_latest_event() -> str:
    """Pop the latest debug event from the event queue."""
    try:
        client = _require_client()
        event = client.get_latest_debug_event()
        if event is None:
            return "No events in queue."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def wait_for_event(event_type: str, timeout: int = 5) -> str:
    """Wait for a specific debug event type.

    Args:
        event_type: Event type name (e.g. 'EVENT_BREAKPOINT', 'EVENT_LOAD_DLL')
        timeout: Max seconds to wait
    """
    try:
        client = _require_client()
        et = EventType(event_type)
        event = client.wait_for_debug_event(et, timeout=timeout)
        if event is None:
            return f"Timed out waiting for {event_type}."
        data_str = ""
        if event.event_data is not None:
            data_str = "\n" + "\n".join(
                f"  {k}: {v}" for k, v in event.event_data.model_dump().items()
            )
        return f"Event: {event.event_type}{data_str}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@mcp.tool()
def get_setting(section: str, name: str, type: str = "string") -> str:
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
            return f"Setting [{section}]{name} not found."
        return f"[{section}]{name} = {val}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def set_setting(section: str, name: str, value: str, type: str = "string") -> str:
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
        return f"Setting [{section}]{name} updated." if result else "Failed to update setting."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

@mcp.tool()
def log_message(message: str) -> str:
    """Log a message to the x64dbg log window.

    Args:
        message: Message text to log
    """
    try:
        client = _require_client()
        result = client.log(message)
        return "Message logged." if result else "Failed to log message."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def refresh_gui() -> str:
    """Refresh all x64dbg GUI views."""
    try:
        client = _require_client()
        result = client.gui_refresh_views()
        return "GUI refreshed." if result else "Failed to refresh GUI."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Memory Analysis — offline (no x64dbg required)
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_entropy(address: str, size: int = 4096, window_size: int = 0) -> str:
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

        if window_size > 0:
            results = sliding_entropy(data, window_size)
            lines = [f"Sliding entropy (window={window_size}):"]
            for offset, ent in results:
                marker = "ENCRYPTED" if ent > 7.0 else ("CODE" if 4.5 <= ent <= 6.5 else "DATA")
                lines.append(f"  {_format_address(addr + offset)}: {ent:.4f} [{marker}]")
            return "\n".join(lines)

        ent = shannon_entropy(data)
        verdict = (
            "ENCRYPTED/COMPRESSED" if ent > 7.0
            else "LIKELY CODE" if 4.5 <= ent <= 6.5
            else "LIKELY DATA"
        )
        return f"Region {_format_address(addr)}–{_format_address(addr + size)}: entropy={ent:.4f} — {verdict}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def find_strings(address: str, size: int = 65536, min_length: int = 4, encoding: str = "both") -> str:
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

        if not results:
            return "No strings found."

        lines = [f"Strings in {_format_address(addr)} ({len(results)} found):"]
        for offset, s in results[:100]:
            lines.append(f"  {_format_address(addr + offset)}: {s}")
        if len(results) > 100:
            lines.append(f"  ... and {len(results) - 100} more")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def scan_hex_pattern(address: str, size: int, pattern: str) -> str:
    """Scan a debuggee memory region for a hex pattern with ?? wildcards.

    Example: '55 8B EC' (x86 function prologue)
    Example: 'E8 ?? ?? ?? ?? 83 C4 04' (call + add esp, 4)
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)
        matches = scan_pattern(data, pattern)

        if not matches:
            return f"No matches for pattern '{pattern}' in {_format_address(addr)}–{_format_address(addr + size)}"

        lines = [f"Pattern '{pattern}' — {len(matches)} matches:"]
        for off in matches[:50]:
            lines.append(f"  {_format_address(addr + off)}")
        if len(matches) > 50:
            lines.append(f"  ... and {len(matches) - 50} more")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def find_x86_prologues(address: str, size: int = 65536) -> str:
    """Find x86 function prologues in a debuggee memory region.

    Detects 'push ebp; mov ebp, esp' patterns.
    High density indicates decrypted machine code.
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)

        prologues = scan_pattern(data, "55 8B EC") + scan_pattern(data, "55 89 E5")
        all_prologues = sorted(set(prologues))

        if not all_prologues:
            return f"No x86 function prologues found in region."

        pages = max(1, len(data) / 4096)
        density = len(all_prologues) / pages
        verdict = "DECRYPTED CODE (high confidence)" if density > 1.0 else ("POSSIBLE CODE" if density > 0.1 else "SPARSE")

        lines = [
            f"Found {len(all_prologues)} function prologues",
            f"Density: {density:.1f} per 4KB page",
            f"Interpretation: {verdict}",
        ]
        for off in all_prologues[:20]:
            lines.append(f"  {_format_address(addr + off)}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def analyze_region_full(address: str, size: int = 65536) -> str:
    """Run comprehensive analysis on a debuggee memory region.

    Returns: entropy, string count, known SecuROM/Torque engine strings,
    function prologue density, and a code/data/encrypted verdict.
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        data = client.read_memory(addr, size)
        result = _analyze_region(data, addr)

        lines = [
            f"=== Region {_format_address(addr)} ({result['size']} bytes) ===",
            f"Entropy: {result['entropy']:.4f}",
            f"Likely code: {'YES' if result['is_likely_code'] else 'NO'}",
            f"ASCII strings: {result['string_count']}",
            f"Function prologues: {result['prologue_count']}",
            "",
            "Known SecuROM strings found:",
        ]
        for offset, s in result["known_strings"]:
            lines.append(f"  '{s}' @ {_format_address(offset)}")
        if not result["known_strings"]:
            lines.append("  (none)")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def compare_memory(address_a: str, address_b: str, size: int = 4096) -> str:
    """Compare two debuggee memory regions byte-by-byte."""
    try:
        client = _require_client()
        a = _parse_address_or_expression(address_a)
        b = _parse_address_or_expression(address_b)
        data_a = client.read_memory(a, size)
        data_b = client.read_memory(b, size)

        if data_a == data_b:
            return f"Regions are identical ({_format_address(a)} and {_format_address(b)}, {size} bytes)"

        diffs = [(i, data_a[i], data_b[i]) for i in range(size) if data_a[i] != data_b[i]]
        lines = [f"Differences ({len(diffs)} bytes differ):"]
        for offset, va, vb in diffs[:50]:
            lines.append(f"  {_format_address(a + offset)}: {va:02X} vs {vb:02X}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# External Process — no debugger required
# ---------------------------------------------------------------------------

@mcp.tool()
def launch_process_no_debug(exe_path: str, args: str = "", cwd: str = "", wait: bool = False) -> str:
    """Launch a process WITHOUT debugger attachment. Returns the PID.

    Use this to run SecuROM-protected targets normally,
    then dump them after decryption completes.
    """
    import subprocess
    try:
        cmd = [exe_path]
        if args.strip():
            cmd.extend(args.split())
        proc = subprocess.Popen(cmd, cwd=cwd or None, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if wait:
            proc.wait()
            return f"Process completed with exit code {proc.returncode}"
        return f"Process launched. PID={proc.pid}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def dump_process_no_debugger(pid: int, output_dir: str = "", method: str = "procdump") -> str:
    """Dump process memory WITHOUT debugger attachment.

    Methods:
      - procdump: ProcDump -r (clone via PssCaptureSnapshot, never pauses)
      - comsvcs: Built-in comsvcs.dll MiniDump (always available)
      - minidump: Python ctypes call to MiniDumpWriteDump
    """
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "dumps")
        os.makedirs(output_dir, exist_ok=True)
        dump_path = os.path.join(output_dir, f"dump_{pid}.dmp")

        if method == "procdump":
            ok = dump_via_procdump_clone(pid, dump_path)
        elif method == "comsvcs":
            ok = dump_via_comsvcs(pid, dump_path)
        elif method == "minidump":
            ok = dump_via_minidumpwritedump(pid, dump_path)
        else:
            return f"ERROR: Unknown method '{method}'. Use: procdump, comsvcs, minidump."

        if ok and os.path.exists(dump_path):
            size = os.path.getsize(dump_path)
            return f"Dump: {dump_path} ({size:,} bytes)"
        return "Dump failed. Run as Administrator?"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def wait_for_window_title(pid: int, title_substring: str, timeout_sec: int = 120) -> str:
    """Wait until a process window with a specific title appears.

    For SecuROM: wait for 'Serial' dialog = Stext decrypted in memory.
    """
    if wait_for_window(pid, title_substring, timeout_sec):
        return f"Window containing '{title_substring}' found for PID {pid}."
    return f"TIMEOUT: Window '{title_substring}' not found within {timeout_sec}s."


@mcp.tool()
def list_running_processes(filter_name: str = "") -> str:
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
                procs.append((info["pid"], name))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if not procs:
            return "No matching processes." if filter_name else "No processes found."
        return "\n".join(f"{pid:>8}  {name}" for pid, name in sorted(procs))
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def terminate_process(pid: int) -> str:
    """Terminate a process by PID."""
    import psutil
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        return f"Process {pid} terminated."
    except psutil.NoSuchProcess:
        return f"Process {pid} not found."
    except psutil.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        return f"Process {pid} killed (terminate timed out)."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def suspend_process(pid: int) -> str:
    """Suspend all threads in a process WITHOUT debugger attachment."""
    if nt_suspend_process(pid):
        return f"Process {pid} suspended."
    return f"Failed to suspend process {pid}. Run as Administrator?"


# ---------------------------------------------------------------------------
# PE Analysis — read-only, no x64dbg required
# ---------------------------------------------------------------------------

@mcp.tool()
def analyze_pe(pe_path: str) -> str:
    """Parse PE headers, sections, entry point, TLS callbacks (read-only).

    NO patching — SecuROM CRC32 check blocks modified executables.
    """
    try:
        sections = get_sections(pe_path)
        tls = get_tls_callbacks(pe_path)
        ep = get_entry_point(pe_path)
        base = get_image_base(pe_path)
        bits = get_bitness(pe_path)

        lines = [
            f"=== {os.path.basename(pe_path)} ===",
            f"Bitness: {bits}-bit",
            f"Image Base: {_format_address(base)}",
            f"Entry Point: {_format_address(base + ep)} (RVA 0x{ep:X})",
            f"TLS Callbacks: {len(tls)}",
        ]
        for i, cb in enumerate(tls):
            lines.append(f"  [{i}] RVA 0x{cb:X}")

        lines.append(f"\nSections ({len(sections)}):")
        fmt = "{:<14} {:<14} {:<10} {:<10}"
        lines.append(fmt.format("Name", "VA", "VSize", "RawSize"))
        for sec in sections:
            lines.append(fmt.format(sec["name"], _format_address(sec["virtual_address"]), hex(sec["virtual_size"]), hex(sec["size_of_raw_data"])))
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_pe_imports(pe_path: str, dll_filter: str = "") -> str:
    """List imported functions from a PE file."""
    try:
        imports = get_imports(pe_path, dll_filter)
        by_dll: dict[str, list[str]] = {}
        for imp in imports:
            dll = imp["dll"]
            by_dll.setdefault(dll, []).append(imp["function_name"])

        lines = [f"=== Imports ({os.path.basename(pe_path)}) ==="]
        for dll, funcs in sorted(by_dll.items()):
            lines.append(f"\n{dll} ({len(funcs)} functions):")
            for f in funcs[:20]:
                lines.append(f"  {f}")
            if len(funcs) > 20:
                lines.append(f"  ... and {len(funcs) - 20} more")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def check_pe_security(pe_path: str) -> str:
    """Check PE security mitigations: NX, ASLR, CFG, Integrity Check."""
    try:
        result = check_security(pe_path)
        lines = [f"=== Security: {os.path.basename(pe_path)} ==="]
        for k, v in result.items():
            lines.append(f"  {k}: {'YES' if v else 'NO'}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def locate_securom_sections(pe_path: str) -> str:
    """Locate SecuROM-specific sections: Stext, Sdata, .securom."""
    try:
        sections = get_sections(pe_path)
        target = {"stext", "sdata", ".securom", "srdata"}
        lines = ["=== SecuROM Sections ==="]
        found = False
        for sec in sections:
            name_lower = sec["name"].lower().strip("\x00").rstrip("\x00")
            if name_lower in target or any(t in name_lower for t in target):
                found = True
                lines.append(f"  {sec['name']}: VA={_format_address(sec['virtual_address'])}  Size=0x{sec['virtual_size']:X} ({sec['virtual_size']:,} bytes)")
        if not found:
            lines.append("  No SecuROM sections found.")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def get_pe_tls_callbacks(pe_path: str) -> str:
    """List TLS callback addresses from a PE file."""
    try:
        callbacks = get_tls_callbacks(pe_path)
        if not callbacks:
            return f"No TLS callbacks in {os.path.basename(pe_path)}."
        lines = [f"TLS Callbacks in {os.path.basename(pe_path)}:"]
        for i, cb in enumerate(callbacks):
            lines.append(f"  [{i}] RVA 0x{cb:X}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Section Extraction — dump file analysis
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_section_from_dump(dump_path: str, section_va: str, size: int, output_path: str) -> str:
    """Extract raw bytes at a VA from a process minidump file.

    Uses memprocfs if available, falls back to pefile-based raw search.
    Use this to extract Stext/Sdata/.securom from a process dump.
    """
    try:
        va = _parse_address_or_expression(section_va)

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
            return f"Could not extract bytes at VA {_format_address(va)} from dump."

        with open(output_path, "wb") as f:
            f.write(extracted)
        return f"Extracted {len(extracted):,} bytes to {output_path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def validate_extracted_binary(binary_path: str, expected_va: int = 0) -> str:
    """Validate an extracted section: entropy, prologues, known strings.

    Scores 0–100. >=70 = VALID, >=40 = SUSPECT, <40 = INVALID.
    """
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
        result = validate_extracted_section(data, os.path.basename(binary_path))
        lines = [
            f"=== Validation: {os.path.basename(binary_path)} ===",
            f"Size: {result['size']:,} bytes",
            f"Entropy: {result['entropy']:.4f}",
            f"Prologues: {result['prologue_count']}",
            f"Score: {result['score']}/100 — {result['verdict']}",
        ]
        for check in result["checks"]:
            lines.append(f"  {check}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def extract_securom_sections(dump_path: str, output_dir: str = "") -> str:
    """Extract all known SecuROM sections from a dump file.

    Extracts Stext (0x67A000), Sdata (0x1122000), .securom (0x146D000).
    """
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")
        os.makedirs(output_dir, exist_ok=True)

        results = []
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
                results.append(f"  {name}: FAILED to extract")
                continue

            with open(output, "wb") as f:
                f.write(extracted)

            ent = shannon_entropy(extracted)
            prologues = len(scan_pattern(extracted, "55 8B EC")) + len(scan_pattern(extracted, "55 89 E5"))
            results.append(f"  {name}: {output} ({len(extracted):,}b, entropy={ent:.2f}, {prologues} prologues)")

        return "\n".join(results)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Master Workflow — SecuROM extraction
# ---------------------------------------------------------------------------

@mcp.tool()
def workflow_extract_securom(
    target_exe: str,
    timeout_sec: int = 120,
    dump_method: str = "procdump",
    output_dir: str = "",
    validate: bool = True,
) -> str:
    """Extract decrypted Stext/Sdata/.securom from BoneCrafterModKit.exe.

    Steps: launch -> wait for serial dialog -> dump process -> extract sections -> validate.

    NO debugger, NO PE patching. Works against SecuROM v7-v8 integrity checks.

    Args:
        target_exe: Full path to BoneCrafterModKit.exe
        timeout_sec: Max wait for serial dialog (default 120)
        dump_method: 'procdump' (recommended), 'comsvcs', or 'minidump'
        output_dir: Output directory (default: ./extracted/)
        validate: Run entropy + string analysis after extraction
    """
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")

        result = workflow_extract_securom(
            target_exe=target_exe,
            timeout_sec=timeout_sec,
            dump_method=dump_method,
            output_dir=output_dir,
            validate=validate,
            terminate_after=True,
        )

        lines = [f"=== Extraction {'SUCCESS' if result.success else 'FAILED'} ==="]
        lines.append(f"PID: {result.pid}  Method: {result.dump_method}")
        lines.append(f"Dump: {result.dump_path}")
        lines.append(f"Elapsed: {result.elapsed_sec:.1f}s")

        for section, path in result.sections_extracted.items():
            size = os.path.getsize(path) if os.path.exists(path) else 0
            analysis = result.analysis.get(section, {})
            lines.append(f"\n  {section}: {path} ({size:,} bytes)")
            if analysis:
                lines.append(f"    Score: {analysis['score']}/100 — {analysis['verdict']}")
                for check in analysis.get("checks", []):
                    lines.append(f"      {check}")

        if result.errors:
            lines.append("\nErrors:")
            for err in result.errors:
                lines.append(f"  X {err}")

        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def workflow_batch_cold_dump(
    target_exe: str,
    iterations: int = 5,
    dump_method: str = "procdump",
    output_dir: str = "",
) -> str:
    """Run extraction multiple times, compare dumps for consistency."""
    try:
        if not output_dir:
            output_dir = os.path.join(Path.cwd(), "extracted")

        results_data = []
        for i in range(iterations):
            iteration_dir = os.path.join(output_dir, f"run_{i + 1:02d}")
            result = workflow_extract_securom(
                target_exe=target_exe,
                dump_method=dump_method,
                output_dir=iteration_dir,
                sections=["Stext"],
                validate=True,
                terminate_after=True,
            )
            results_data.append(result)

        lines = [f"=== Batch Results ({iterations} runs) ==="]
        for i, r in enumerate(results_data):
            status = "OK" if r.success else "FAIL"
            analysis = r.analysis.get("Stext", {})
            lines.append(f"  [{i + 1}] {status}  score={analysis.get('score', 0)}/100  entropy={analysis.get('entropy', '?')}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Phase 2 — New debugger commands
# ---------------------------------------------------------------------------

@mcp.tool()
def get_debugee_tls_callbacks() -> str:
    """Get TLS callback RVAs from the debuggee's PE file on disk."""
    try:
        client = _require_client()
        callbacks = client.get_tls_callbacks()
        if not callbacks:
            return "No TLS callbacks found in debuggee."
        lines = [f"TLS Callbacks ({len(callbacks)}):"]
        for i, cb in enumerate(callbacks):
            lines.append(f"  [{i}] RVA 0x{cb:X}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def debuggee_virtual_protect_ex(address: str, size: int, new_protection: int = 0x20) -> str:
    """Change memory protection on a debuggee region.
    
    Uses VirtualProtectEx. Common values:
    0x20 = PAGE_EXECUTE_READ, 0x04 = PAGE_READWRITE, 0x40 = PAGE_EXECUTE_READWRITE
    """
    try:
        client = _require_client()
        addr = _parse_address_or_expression(address)
        result = client.virtual_protect_ex(addr, size, new_protection)
        return f"Page protection changed at {_format_address(addr)}." if result else "VirtualProtectEx failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def debuggee_suspend_all_threads() -> str:
    """Suspend all threads in the debuggee via ToolHelp snapshot."""
    try:
        client = _require_client()
        ok = client.suspend_all_threads()
        return "All threads suspended." if ok else "Suspend failed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def debuggee_get_peb() -> str:
    """Read the debuggee's PEB: BeingDebugged, NtGlobalFlag, HeapFlags."""
    try:
        client = _require_client()
        peb = client.get_peb()
        lines = [
            f"BeingDebugged: {peb.being_debugged}",
            f"NtGlobalFlag: 0x{peb.nt_global_flag:08X}",
            f"HeapFlags: 0x{peb.heap_flags:08X}",
            f"HeapForceFlags: 0x{peb.heap_force_flags:08X}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def debuggee_get_process_info() -> str:
    """Get debuggee process metadata: PID, entry point, image base, size, path."""
    try:
        client = _require_client()
        info = client.get_process_info()
        lines = [
            f"PID: {info.pid}",
            f"Main Thread: {info.main_thread_id}",
            f"Entry Point: {_format_address(info.image_base + info.entry_point)}",
            f"Image Base: {_format_address(info.image_base)}",
            f"Image Size: {info.image_size:,} bytes",
            f"64-bit: {info.is_64bit}",
            f"Path: {info.exe_path}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Phase 6 — x64dbg SecuROM fallback tools
# ---------------------------------------------------------------------------

@mcp.tool()
def debug_securom_tls_callbacks(target_exe: str) -> str:
    """Launch target in x64dbg with ScyllaHide, enumerate TLS callbacks."""
    try:
        client = _require_client()
        client.load_executable(target_exe)
        client.wait_until_debugging(timeout=30)
        callbacks = client.get_tls_callbacks()
        peb = client.get_peb()
        info = client.get_process_info()

        lines = [
            f"=== TLS Analysis: {target_exe} ===",
            f"Entry Point: {_format_address(info.image_base + info.entry_point)}",
            f"Image Base: {_format_address(info.image_base)}",
            f"PEB.BeingDebugged: {peb.being_debugged}",
            f"PEB.NtGlobalFlag: 0x{peb.nt_global_flag:08X}",
            f"TLS Callbacks ({len(callbacks)}):",
        ]
        for i, cb in enumerate(callbacks):
            lines.append(f"  [{i}] RVA 0x{cb:X} (VA {_format_address(info.image_base + cb)})")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def bypass_securom_execute_protect(section_name: str = "Stext") -> str:
    """Change Stext/Sdata/.securom from PAGE_EXECUTE to PAGE_EXECUTE_READ."""
    section_map = {
        "Stext": (0x00A7A000, 0x00A18DF0),
        "Sdata": (0x01522000, 0x0034381C),
        ".securom": (0x0186D000, 0x00172A4C),
    }
    if section_name not in section_map:
        return f"Unknown section '{section_name}'. Known: {list(section_map.keys())}"
    va, size = section_map[section_name]
    PAGE_EXECUTE_READ = 0x20
    try:
        client = _require_client()
        ok = client.virtual_protect_ex(va, size, PAGE_EXECUTE_READ)
        if ok:
            return f"Changed {section_name} ({_format_address(va)}, {size:,}b) to PAGE_EXECUTE_READ"
        return f"VirtualProtectEx failed for {section_name}"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# DEPRECATED legacy tools — superseded by api_runtime equivalents
# These are kept for backward compatibility but agents should prefer:
#   configure_scyllahide  →  configure_scyllahide (runtime API)
#   check_peb_after_hide  →  check_antidebug_status (runtime API)
#   freeze_debugee_for_dump  →  sandbox_dump (runtime API)
# ---------------------------------------------------------------------------

@mcp.tool()
def freeze_debugee_for_dump() -> str:
    """[DEPRECATED] Use sandbox_dump instead. Suspend all debugee threads, dump via comsvcs, then resume."""
    try:
        client = _require_client()
        pid = client.get_process_info().pid
        if not client.suspend_all_threads():
            return "[DEPRECATED → use sandbox_dump] Failed to suspend threads."
        from x64dbg_automate.external.process_dumper import dump_via_comsvcs
        output = os.path.join(Path.cwd(), "dumps", f"frozen_dump_{pid}.dmp")
        os.makedirs(os.path.dirname(output), exist_ok=True)
        ok = dump_via_comsvcs(pid, output)
        return f"[DEPRECATED → use sandbox_dump] Dump: {output} ({'OK' if ok else 'FAILED'})"
    except Exception as e:
        return f"[DEPRECATED → use sandbox_dump] Error: {e}"


@mcp.tool()
def configure_scyllahide_for_securom() -> str:
    """[DEPRECATED] Use configure_scyllahide(sandbox_id) instead. Configure ScyllaHide settings for SecuROM v8 anti-debug."""
    try:
        client = _require_client()
        settings = [
            ("ScyllaHide", "PEBBeingDebugged", 0),
            ("ScyllaHide", "PEBHeapFlags", 0),
            ("ScyllaHide", "NtQueryInformationProcess", 1),
            ("ScyllaHide", "NtSetInformationThread", 1),
            ("ScyllaHide", "NtQuerySystemInformation", 1),
            ("ScyllaHide", "GetTickCount", 1),
            ("ScyllaHide", "NtClose", 1),
        ]
        for section, key, val in settings:
            client.set_setting_int(section, key, val)
        return "[DEPRECATED → use configure_scyllahide(sandbox_id)] ScyllaHide configured for SecuROM (7 settings)"
    except Exception as e:
        return f"[DEPRECATED → use configure_scyllahide(sandbox_id)] Error: {e}"


@mcp.tool()
def check_peb_after_hide() -> str:
    """[DEPRECATED] Use check_antidebug_status(sandbox_id) instead. Verify PEB patches are active after ScyllaHide configuration."""
    try:
        client = _require_client()
        peb = client.get_peb()
        lines = [
            "[DEPRECATED → use check_antidebug_status(sandbox_id)]",
            f"BeingDebugged: {peb.being_debugged} (expect False)",
            f"NtGlobalFlag: 0x{peb.nt_global_flag:08X} (expect 0x00)",
            f"HeapFlags: 0x{peb.heap_flags:08X} (expect 0x02)",
            f"HeapForceFlags: 0x{peb.heap_force_flags:08X} (expect 0x00)",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"[DEPRECATED → use check_antidebug_status(sandbox_id)] Error: {e}"


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
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the MCP server with stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
