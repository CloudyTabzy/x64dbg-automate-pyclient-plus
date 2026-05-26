"""Sandbox lifecycle management for the AI-native runtime API.

A **sandbox** here is a *disposable debugged session*: one ``X64DbgClient`` bound to
one launched-or-attached target under x64dbg/x32dbg. The on-disk binary is never
patched, so each debugged instance is freely killable — that is the isolation
guarantee. This deliberately does **not** try to clone a running process into a
separately-runnable copy (a ``PssCaptureSnapshot`` VA-clone is a frozen read-only
snapshot, not an executable process). Three safety primitives instead:

1. ``create_sandbox`` / ``destroy_sandbox`` — disposable debugged instances.
2. ``checkpoint`` / ``restore_checkpoint`` — best-effort userland state snapshots
   (active-thread registers + caller-chosen memory regions). Not a kernel-level
   fork: handles, new threads, and kernel object state are NOT restored.
3. Read-only forensic dumps (ProcDump/PssCaptureSnapshot) live in the existing
   ``external.process_dumper`` and are surfaced by the sandbox tool layer.

The manager keys multiple sandboxes by ``sandbox_id``, mirroring Synapse's
``IDASessionManager``.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from x64dbg_automate.dbg_paths import (
    pe_bitness,
    resolve_debugger_path,
    resolve_x64dbg_path_with_env,
)

if TYPE_CHECKING:
    from x64dbg_automate import X64DbgClient

# Curated general-purpose register sets captured/restored by checkpoints.
_GP_REGS_64 = [
    "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
]
_GP_REGS_32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip", "eflags"]


@dataclass
class Checkpoint:
    """A best-effort userland snapshot of a debugged target's state."""

    name: str
    created_at: datetime
    arch: str                                   # "x64" or "x32"
    registers: dict[str, int] = field(default_factory=dict)
    memory: dict[int, bytes] = field(default_factory=dict)   # addr -> captured bytes
    thread_count: int = 0
    debuggee_pid: int | None = None
    warnings: list[str] = field(default_factory=list)
    # Semantic diff fields — always captured; not used by restore.
    threads_snapshot: list[dict] = field(default_factory=list)
    modules_snapshot: list[dict] = field(default_factory=list)
    breakpoints_snapshot: list[dict] = field(default_factory=list)
    patches_snapshot: list[dict] = field(default_factory=list)
    peb_snapshot: dict | None = None
    # Regions that were requested but failed to read (addr, size pairs).
    failed_regions: list[tuple[int, int]] = field(default_factory=list)

    def to_info(self) -> dict:
        """JSON-safe summary (no raw bytes)."""
        region_count = len(self.memory)
        failed_count = len(self.failed_regions)
        info: dict = {
            "name": self.name,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "arch": self.arch,
            "register_count": len(self.registers),
            "region_count": region_count,
            "region_attempts": region_count + failed_count,
            "total_bytes": sum(len(b) for b in self.memory.values()),
            "thread_count": self.thread_count,
            "module_count": len(self.modules_snapshot),
            "breakpoint_count": len(self.breakpoints_snapshot),
            "patch_count": len(self.patches_snapshot),
            "peb": self.peb_snapshot,
            "warnings": self.warnings,
        }
        if failed_count:
            info["region_read_failures"] = [
                {"address": f"0x{addr:X}", "size": size}
                for addr, size in self.failed_regions
            ]
        return info


def _auto_regions(registers: dict[str, int], arch: str) -> list[tuple[int, int]]:
    """Return auto-capture regions: stack (256 B from SP) + instruction window (96 B around IP)."""
    sp_key = "rsp" if arch == "x64" else "esp"
    ip_key = "rip" if arch == "x64" else "eip"
    regions: list[tuple[int, int]] = []
    sp = registers.get(sp_key, 0)
    ip = registers.get(ip_key, 0)
    if sp:
        regions.append((sp, 256))
    if ip:
        regions.append((max(0, ip - 16), 96))
    return regions


def _capture_threads(client) -> list[dict]:
    try:
        return [
            {"thread_id": t.thread_id, "cip": t.cip, "suspend_count": t.suspend_count,
             "priority": t.priority, "name": t.name}
            for t in (client.get_threads() or [])
        ]
    except Exception:
        return []


def _capture_modules(client) -> list[dict]:
    try:
        return [{"base": m.base, "name": m.name, "size": m.size}
                for m in (client.get_modules() or [])]
    except Exception:
        return []


def _capture_breakpoints(client) -> list[dict]:
    try:
        from x64dbg_automate.models import BreakpointType
        bps: list[dict] = []
        for bt in (BreakpointType.BpNormal, BreakpointType.BpHardware, BreakpointType.BpMemory):
            for bp in (client.get_breakpoints(bt) or []):
                bps.append({"addr": bp.addr, "type": bt.value, "enabled": bp.enabled,
                             "hit_count": bp.hitCount, "name": bp.name})
        return bps
    except Exception:
        return []


def _capture_peb(client) -> dict | None:
    try:
        peb = client.get_peb()
        return {"being_debugged": peb.being_debugged, "nt_global_flag": peb.nt_global_flag,
                "heap_flags": peb.heap_flags, "heap_force_flags": peb.heap_force_flags}
    except Exception:
        return None


@dataclass
class ProcessSandbox:
    """A disposable debugged session managed by :class:`SandboxManager`."""

    sandbox_id: str
    debugger_pid: int                           # PID of the x64dbg/x32dbg process
    debugger_arch: str                          # "x64" or "x32"
    created_at: datetime
    target_exe: str | None = None
    attach_pid: int | None = None               # source PID when created via attach
    debuggee_pid: int | None = None             # the actual target PID
    state: str = "created"                       # created|running|stopped|detached|destroyed|crashed
    anti_debug_applied: bool = False
    last_error: str | None = None
    checkpoints: dict[str, Checkpoint] = field(default_factory=dict)
    patches: list[dict] = field(default_factory=list)   # in-memory patch records
    client: "X64DbgClient | None" = None

    def to_info(self) -> dict:
        """JSON-safe metadata for tool responses (never includes the client)."""
        return {
            "sandbox_id": self.sandbox_id,
            "debugger_pid": self.debugger_pid,
            "debuggee_pid": self.debuggee_pid,
            "debugger_arch": self.debugger_arch,
            "target_exe": self.target_exe,
            "attach_pid": self.attach_pid,
            "state": self.state,
            "anti_debug_applied": self.anti_debug_applied,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "checkpoints": [cp.to_info() for cp in self.checkpoints.values()],
            "patch_count": len(self.patches),
            "last_error": self.last_error,
        }


class SandboxError(Exception):
    """Raised for sandbox lifecycle failures (creation, lookup, teardown)."""


class SandboxManager:
    """Tracks and operates on multiple disposable debugged sessions."""

    def __init__(self) -> None:
        self._sandboxes: dict[str, ProcessSandbox] = {}
        self._active_session_id: str | None = None
        self._lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------

    def create_sandbox(
        self,
        target_exe: str | None = None,
        attach_pid: int | None = None,
        cmdline: str = "",
        current_dir: str = "",
        x64dbg_path: str = "",
    ) -> ProcessSandbox:
        """Launch (or attach) a target under a fresh debugger and register it.

        Exactly one of ``target_exe`` or ``attach_pid`` must be provided.
        """
        if bool(target_exe) == bool(attach_pid):
            raise ValueError("Provide exactly one of target_exe or attach_pid")

        from x64dbg_automate import X64DbgClient  # local import avoids import cycle

        base_path = resolve_x64dbg_path_with_env(x64dbg_path)
        bitness_exe = target_exe or self._exe_path_for_pid(attach_pid) or ""
        resolved = resolve_debugger_path(base_path, bitness_exe)

        client = X64DbgClient(resolved)
        try:
            if target_exe:
                debugger_pid = client.start_session(target_exe, cmdline, current_dir)
            else:
                debugger_pid = client.start_session_attach(int(attach_pid))  # type: ignore[arg-type]
        except Exception as exc:
            self._safe_terminate(client)
            raise SandboxError(f"Failed to create sandbox: {exc}") from exc

        arch = self._detect_arch(client, bitness_exe)
        sandbox = ProcessSandbox(
            sandbox_id=uuid.uuid4().hex[:8],
            debugger_pid=debugger_pid,
            debugger_arch=arch,
            created_at=datetime.now(),
            target_exe=target_exe,
            attach_pid=attach_pid,
            debuggee_pid=self._safe_debuggee_pid(client),
            state="stopped" if self._safe_is_debugging(client) else "created",
            client=client,
        )
        with self._lock:
            self._sandboxes[sandbox.sandbox_id] = sandbox
        return sandbox

    def destroy_sandbox(self, sandbox_id: str) -> bool:
        """Terminate the sandbox's debugger process and forget it."""
        with self._lock:
            sandbox = self._sandboxes.pop(sandbox_id, None)
            if self._active_session_id == sandbox_id:
                self._active_session_id = None
        if sandbox is None:
            raise KeyError(f"No sandbox with id '{sandbox_id}'")
        ok = self._safe_terminate(sandbox.client)
        sandbox.state = "destroyed"
        sandbox.client = None
        return ok

    def get_sandbox(self, sandbox_id: str | None = None) -> ProcessSandbox:
        with self._lock:
            if sandbox_id is None:
                sandbox_id = self._active_session_id
            sandbox = self._sandboxes.get(sandbox_id) if sandbox_id else None
        if sandbox is None:
            if sandbox_id:
                raise KeyError(f"No sandbox with id '{sandbox_id}'")
            raise KeyError(
                "No active session. Start a session with start_session() or sandbox_create() first."
            )
        return sandbox

    def get_client(self, sandbox_id: str | None = None) -> "X64DbgClient":
        sandbox = self.get_sandbox(sandbox_id)
        if sandbox.client is None:
            raise SandboxError(
                f"Sandbox '{sandbox.sandbox_id}' has no active debugger client"
            )
        return sandbox.client

    def set_active_session(self, sandbox_id: str) -> None:
        with self._lock:
            if sandbox_id not in self._sandboxes:
                raise KeyError(f"No sandbox with id '{sandbox_id}'")
            self._active_session_id = sandbox_id

    def get_active_session_id(self) -> str | None:
        with self._lock:
            return self._active_session_id

    def register_legacy_session(
        self, client: "X64DbgClient", debugger_pid: int, debugger_arch: str
    ) -> ProcessSandbox:
        """Wrap an existing legacy X64DbgClient as a sandbox for unified access."""
        sandbox = ProcessSandbox(
            sandbox_id=uuid.uuid4().hex[:8],
            debugger_pid=debugger_pid,
            debugger_arch=debugger_arch,
            created_at=datetime.now(),
            target_exe=None,
            attach_pid=None,
            debuggee_pid=self._safe_debuggee_pid(client),
            state="stopped" if self._safe_is_debugging(client) else "created",
            client=client,
        )
        with self._lock:
            self._sandboxes[sandbox.sandbox_id] = sandbox
            self._active_session_id = sandbox.sandbox_id
        return sandbox

    def list_sandboxes(self) -> list[ProcessSandbox]:
        with self._lock:
            return list(self._sandboxes.values())

    def refresh_state(self, sandbox: ProcessSandbox) -> str:
        """Re-query the live debugger state, updating ``sandbox.state``."""
        client = sandbox.client
        if client is None:
            sandbox.state = "destroyed"
            return sandbox.state
        try:
            is_debugging = client.is_debugging()
            is_running = client.is_running() if is_debugging else False
        except Exception as exc:  # RPC dead → debugger likely gone
            sandbox.state = "crashed"
            sandbox.last_error = str(exc)
            return sandbox.state

        # Sync state machine if available
        sm = getattr(client, "_axon_state_machine", None)
        if sm is not None:
            from x64dbg_automate.api_runtime.debugger_state import DebuggerState
            if not is_debugging:
                sm.transition(DebuggerState.DISCONNECTED, reason="refresh_state: not debugging")
            elif is_running:
                if sm.current_state != DebuggerState.RUNNING:
                    sm.transition(DebuggerState.RUNNING, reason="refresh_state: is_running")
            else:
                if sm.current_state == DebuggerState.RUNNING:
                    sm.transition(DebuggerState.PAUSED_EVENT, reason="refresh_state: unexpected pause")
                elif sm.current_state == DebuggerState.DISCONNECTED:
                    sm.transition(DebuggerState.STOPPED, reason="refresh_state: debugging but stopped")
            sandbox.state = str(sm.current_state)
            return sandbox.state

        # Fallback crude state
        if not is_debugging:
            sandbox.state = "detached"
        elif is_running:
            sandbox.state = "running"
        else:
            sandbox.state = "stopped"
        return sandbox.state

    # -- checkpoint / restore ---------------------------------------------

    def _count_threads(self, pid: int | None) -> int:
        if not pid:
            return 0
        try:
            import psutil
            return psutil.Process(pid).num_threads()
        except Exception:
            return 0

    def checkpoint(
        self,
        sandbox_id: str,
        name: str,
        regions: list[tuple[int, int]] | None = None,
    ) -> Checkpoint:
        """Capture a best-effort userland snapshot.

        Captures GP registers, semantic state (threads, modules, breakpoints, patches,
        PEB), and memory regions. When *regions* is ``None``, the current stack window
        (SP to SP+256) and instruction window (IP-16 to IP+80) are auto-captured so
        zero-configuration checkpoints are useful for diffing. Pass *regions=[]* to
        skip memory capture entirely.
        """
        sandbox = self.get_sandbox(sandbox_id)
        client = self.get_client(sandbox_id)
        self._ensure_stopped(client)

        cp_warnings: list[str] = [
            "Restore writes GP registers + memory only; threads/modules/PEB are not restored."
        ]

        reg_names = self._reg_names(sandbox)
        registers: dict[str, int] = {}
        reg_failures: list[str] = []
        for reg in reg_names:
            try:
                registers[reg] = client.get_reg(reg)
            except Exception as exc:
                reg_failures.append(f"{reg}: {exc}")

        if reg_failures:
            read_count = len(registers)
            total_count = len(reg_names)
            first_err = reg_failures[0]
            if read_count == 0:
                cp_warnings.append(
                    f"CAPTURE FAILURE: 0/{total_count} registers read — all reads failed. "
                    f"First error: {first_err}. "
                    "Likely cause: process was running during capture (ensure_stopped race) "
                    "or the RPC connection was lost."
                )
            else:
                cp_warnings.append(
                    f"Partial register capture: {read_count}/{total_count} registers read. "
                    f"First failure: {first_err}"
                )

        # None → auto-capture stack + instruction window; [] → no memory
        if regions is None:
            regions = _auto_regions(registers, sandbox.debugger_arch)

        memory: dict[int, bytes] = {}
        failed_regions: list[tuple[int, int]] = []
        for addr, size in regions:
            try:
                memory[addr] = client.read_memory(addr, size)
            except Exception as exc:
                failed_regions.append((addr, size))
                cp_warnings.append(f"Memory read failed at 0x{addr:X} ({size} B): {exc}")

        threads_snapshot = _capture_threads(client)
        modules_snapshot = _capture_modules(client)
        breakpoints_snapshot = _capture_breakpoints(client)
        patches_snapshot = list(sandbox.patches)
        peb_snapshot = _capture_peb(client)
        thread_count = len(threads_snapshot) if threads_snapshot else self._count_threads(sandbox.debuggee_pid)

        cp = Checkpoint(
            name=name,
            created_at=datetime.now(),
            arch=sandbox.debugger_arch,
            registers=registers,
            memory=memory,
            thread_count=thread_count,
            debuggee_pid=sandbox.debuggee_pid,
            warnings=cp_warnings,
            threads_snapshot=threads_snapshot,
            modules_snapshot=modules_snapshot,
            breakpoints_snapshot=breakpoints_snapshot,
            patches_snapshot=patches_snapshot,
            peb_snapshot=peb_snapshot,
            failed_regions=failed_regions,
        )
        sandbox.checkpoints[name] = cp
        return cp

    def restore_checkpoint(self, sandbox_id: str, name: str) -> tuple[int, int, list[str]]:
        """Restore a checkpoint. Returns (registers_restored, regions_restored, warnings)."""
        sandbox = self.get_sandbox(sandbox_id)
        client = self.get_client(sandbox_id)
        cp = sandbox.checkpoints.get(name)
        if cp is None:
            raise KeyError(f"No checkpoint '{name}' in sandbox '{sandbox_id}'")
        self._ensure_stopped(client)

        warnings: list[str] = list(cp.warnings)
        current_threads = self._count_threads(sandbox.debuggee_pid)
        if current_threads != cp.thread_count:
            warnings.append(
                f"Thread count changed: {cp.thread_count} at checkpoint → {current_threads} now. "
                "New threads will continue running with stale register state."
            )

        regions_restored = 0
        for addr, data in cp.memory.items():
            try:
                if client.write_memory(addr, data):
                    regions_restored += 1
            except Exception:
                pass

        regs_restored = 0
        for reg, val in cp.registers.items():
            try:
                if client.set_reg(reg, val):
                    regs_restored += 1
            except Exception:
                pass

        return regs_restored, regions_restored, warnings

    # -- helpers -----------------------------------------------------------

    def _reg_names(self, sandbox: ProcessSandbox) -> list[str]:
        return _GP_REGS_64 if sandbox.debugger_arch == "x64" else _GP_REGS_32

    @staticmethod
    def ensure_stopped(client: "X64DbgClient") -> None:
        """Pause the debuggee if it is currently running.

        Raises:
            SandboxError: if the running state cannot be determined, or if the
                pause command fails to stop the process. All callers have an
                outer ``except (KeyError, SandboxError)`` or
                ``except Exception`` guard, so the error surfaces as a
                structured ``INVALID_STATE`` response rather than propagating.
        """
        try:
            running = client.is_running()
        except Exception as exc:
            raise SandboxError(
                f"Cannot determine running state before capture: {exc}. "
                "Check sandbox_info() and retry."
            ) from exc

        if not running:
            return

        try:
            paused = client.pause()
        except Exception as exc:
            raise SandboxError(
                f"Pause command raised an error: {exc}. "
                "Call sandbox_pause() manually and retry."
            ) from exc

        if not paused:
            raise SandboxError(
                "Debuggee did not stop after pause command — it may be in a "
                "transitional or undebuggable state. "
                "Call sandbox_pause() explicitly and retry sandbox_checkpoint()."
            )

    # Backward-compatibility alias — external callers should use ensure_stopped().
    _ensure_stopped = ensure_stopped

    @staticmethod
    def _detect_arch(client: "X64DbgClient", bitness_exe: str) -> str:
        try:
            bits = client.debugee_bitness()
            if bits in (32, 64):
                return "x64" if bits == 64 else "x32"
        except Exception:
            pass
        if bitness_exe:
            try:
                return "x64" if pe_bitness(bitness_exe) == 64 else "x32"
            except Exception:
                pass
        return "x64"

    @staticmethod
    def _exe_path_for_pid(pid: int | None) -> str:
        if not pid:
            return ""
        try:
            import psutil

            return psutil.Process(int(pid)).exe() or ""
        except Exception:
            return ""

    @staticmethod
    def _safe_debuggee_pid(client: "X64DbgClient") -> int | None:
        try:
            return client.debugee_pid()
        except Exception:
            return None

    @staticmethod
    def _safe_is_debugging(client: "X64DbgClient") -> bool:
        try:
            return bool(client.is_debugging())
        except Exception:
            return False

    @staticmethod
    def _safe_terminate(client: "X64DbgClient | None") -> bool:
        if client is None:
            return True
        try:
            client.terminate_session()
            return True
        except Exception:
            try:
                client.detach_session()
            except Exception:
                pass
            return False


# Module-level singleton (mirrors the existing mcp_server global-client pattern).
_manager: SandboxManager | None = None
_manager_lock = threading.Lock()


def get_manager() -> SandboxManager:
    """Return the process-wide SandboxManager, creating it on first use."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = SandboxManager()
    return _manager
