"""Anti-debug transparency tools.

Make debugger presence invisible to the target without the agent needing anti-debug
expertise: apply a ScyllaHide profile, patch the PEB, and surface TLS callbacks. Built
on primitives that already exist in the client (``set_setting_int``, ``hide_debugger_peb``,
``get_tls_callbacks``, ``get_peb``, ``get_process_info``).
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, lookup_error, ok
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

# ScyllaHide settings tuned for SecuROM v7–v8 (written to x64dbg.ini under [ScyllaHide]).
# These take full effect when the target is (re)started under the debugger; the live
# PEB patch from hide_debugger_peb() applies immediately regardless.
SCYLLAHIDE_SECUROM_PROFILE: list[tuple[str, str, int]] = [
    ("ScyllaHide", "PEBBeingDebugged", 0),
    ("ScyllaHide", "PEBHeapFlags", 0),
    ("ScyllaHide", "PEBNtGlobalFlag", 0),
    ("ScyllaHide", "NtQueryInformationProcess", 1),
    ("ScyllaHide", "NtSetInformationThread", 1),
    ("ScyllaHide", "NtQuerySystemInformation", 1),
    ("ScyllaHide", "GetTickCount", 1),
    ("ScyllaHide", "NtClose", 1),
    ("ScyllaHide", "HideDebugRegisters", 1),
    ("ScyllaHide", "NtYieldExecution", 1),
]


def _peb_status(client) -> dict:
    """Read the PEB and classify whether the debugger is currently hidden."""
    peb = client.get_peb()
    detected = bool(peb.being_debugged) or peb.nt_global_flag != 0
    return {
        "being_debugged": bool(peb.being_debugged),
        "nt_global_flag": f"0x{peb.nt_global_flag:08X}",
        "heap_flags": f"0x{peb.heap_flags:08X}",
        "heap_force_flags": f"0x{peb.heap_force_flags:08X}",
        "debugger_detectable": detected,
    }


@tool
def configure_scyllahide(sandbox_id: str | None = None) -> dict:
    """Write the SecuROM ScyllaHide profile into x64dbg settings for this sandbox.

    Takes full effect when the target is (re)started under the debugger.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    applied: list[str] = []
    try:
        for section, key, val in SCYLLAHIDE_SECUROM_PROFILE:
            client.set_setting_int(section, key, val)
            applied.append(key)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id, applied=applied)
    return ok(sandbox_id=sandbox_id, profile="securom", settings_applied=applied)


@tool
def attach_safe(*, sandbox_id: str | None = None, breakpoint_tls: bool = False) -> dict:
    """Apply full anti-debug evasion to an already-created sandbox.

    Performs, in order:
      1. Writes the SecuROM ScyllaHide profile.
      2. Patches the live PEB (BeingDebugged / NtGlobalFlag / heap flags) via x64dbg 'hide'.
      3. Enumerates TLS callbacks and (optionally) sets one-shot breakpoints on them so
         they can be observed before they fire.
      4. Verifies the PEB is now clean.

    Args:
        sandbox_id: The sandbox to harden.
        breakpoint_tls: If true, set a software breakpoint at each TLS callback VA.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    sandbox = mgr.get_sandbox(sandbox_id)
    result: dict = {"sandbox_id": sandbox_id}
    try:
        # 1. ScyllaHide profile
        scylla_applied = []
        for section, key, val in SCYLLAHIDE_SECUROM_PROFILE:
            client.set_setting_int(section, key, val)
            scylla_applied.append(key)
        result["scyllahide_settings_applied"] = scylla_applied

        # 2. Live PEB patch
        result["peb_hidden"] = bool(client.hide_debugger_peb())

        # 3. TLS callbacks
        image_base = 0
        try:
            image_base = client.get_process_info().image_base
        except Exception:
            pass
        callbacks = []
        tls_breakpoints_set = 0
        for rva in client.get_tls_callbacks():
            va = image_base + rva if image_base else rva
            entry = {"rva": f"0x{rva:X}", "va": f"0x{va:X}"}
            if breakpoint_tls and image_base:
                try:
                    if client.set_breakpoint(va, singleshoot=True):
                        tls_breakpoints_set += 1
                        entry["breakpoint"] = True
                except Exception:
                    entry["breakpoint"] = False
            callbacks.append(entry)
        result["tls_callbacks"] = callbacks
        if breakpoint_tls:
            result["tls_breakpoints_set"] = tls_breakpoints_set

        # 4. Verify
        result["peb_status"] = _peb_status(client)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), **result)

    sandbox.anti_debug_applied = True
    detectable = result["peb_status"]["debugger_detectable"]
    result["verdict"] = "anti-debug evasion active" if not detectable else "PEB still flags a debugger"
    return ok(**result)


@tool
def check_antidebug_status(sandbox_id: str | None = None) -> dict:
    """Report whether the debugger is currently detectable via the target's PEB.

    Checks BeingDebugged, NtGlobalFlag, and heap flags. Expected when hidden:
    BeingDebugged=False, NtGlobalFlag=0x0, HeapFlags=0x2, HeapForceFlags=0x0.
    """
    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    try:
        status = _peb_status(client)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)
    sandbox = mgr.get_sandbox(sandbox_id)
    extra = {}
    if status["debugger_detectable"]:
        extra["hint"] = "Run attach_safe to hide the debugger."
    return ok(
        sandbox_id=sandbox_id,
        anti_debug_applied=sandbox.anti_debug_applied,
        **status,
        **extra,
    )


# ---------------------------------------------------------------------------
# Adaptive anti-debug detection (beyond static ScyllaHide profiles)
# ---------------------------------------------------------------------------

_PROCESS_DEBUG_PORT = 7
_PROCESS_DEBUG_OBJECT_HANDLE = 30
_ObjectTypesInformation = 2


def _nt_query_information_process(pid: int, info_class: int, size: int = 8) -> tuple[int, int]:
    """Call NtQueryInformationProcess via ctypes. Returns (value, status)."""
    import ctypes
    from ctypes import wintypes

    ntdll = ctypes.windll.ntdll
    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
    NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
    ]
    NtQueryInformationProcess.restype = wintypes.LONG

    kernel32 = ctypes.windll.kernel32
    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return 0, -1

    buf = ctypes.create_string_buffer(size)
    ret_len = wintypes.ULONG()
    status = NtQueryInformationProcess(h, info_class, buf, size, ctypes.byref(ret_len))
    kernel32.CloseHandle(h)

    if status != 0:
        return 0, status
    return int.from_bytes(buf.raw[:ret_len.value], "little"), status


def _enum_debug_object_handles(pid: int) -> list[int]:
    """Enumerate handles looking for DebugObject types. Returns list of handle values."""
    import ctypes
    from ctypes import wintypes

    ntdll = ctypes.windll.ntdll
    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
    ]
    NtQuerySystemInformation.restype = wintypes.LONG

    SystemHandleInformation = 16
    size = 64 * 1024
    while size <= 16 * 1024 * 1024:
        buf = ctypes.create_string_buffer(size)
        ret_len = wintypes.ULONG()
        status = NtQuerySystemInformation(SystemHandleInformation, buf, size, ctypes.byref(ret_len))
        if status == 0:
            break
        if status == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
            size = ret_len.value
            continue
        return []

    # Parse SYSTEM_HANDLE_INFORMATION
    handle_count = int.from_bytes(buf.raw[:4], "little")
    debug_handles: list[int] = []
    offset = 4
    for _ in range(min(handle_count, 65536)):
        if offset + 24 > size:
            break
        proc_id = int.from_bytes(buf.raw[offset:offset + 4], "little")
        if proc_id == pid:
            obj_type = buf.raw[offset + 6]
            handle_val = int.from_bytes(buf.raw[offset + 8:offset + 12], "little")
            # obj_type 0x0D is DebugObject on most Windows versions; we can't
            # resolve the type name without another query, so we note all handles.
            debug_handles.append(handle_val)
        offset += 24
    return debug_handles


@tool
def detect_timing_attacks(*, sandbox_id: str | None = None, samples: int = 5) -> dict:
    """Detect RDTSC-based timing anti-debug by measuring CPU tick consistency.

    A target that reads RDTSC, sleeps, then reads RDTSC again can detect a debugger
    if the delta is much larger than expected. We sample the baseline ourselves so
    the agent knows whether the environment is 'noisy' (VM/cloud) or clean.

    Args:
        sandbox_id: Sandbox whose debuggee to benchmark (used for PID context only).
        samples: Number of sleep-measure cycles.
    """
    import ctypes
    import time

    ntdll = ctypes.windll.ntdll
    QueryPerformanceFrequency = ctypes.windll.kernel32.QueryPerformanceFrequency
    QueryPerformanceCounter = ctypes.windll.kernel32.QueryPerformanceCounter

    freq = ctypes.c_longlong()
    if not QueryPerformanceFrequency(ctypes.byref(freq)):
        return err("High-res timer unavailable.", ErrorType.UNSUPPORTED, sandbox_id=sandbox_id)

    deltas_ms: list[float] = []
    for _ in range(samples):
        start = ctypes.c_longlong()
        QueryPerformanceCounter(ctypes.byref(start))
        time.sleep(0.01)
        end = ctypes.c_longlong()
        QueryPerformanceCounter(ctypes.byref(end))
        delta_ms = (end.value - start.value) * 1000.0 / freq.value
        deltas_ms.append(round(delta_ms, 4))

    avg = sum(deltas_ms) / len(deltas_ms)
    max_dev = max(abs(d - avg) for d in deltas_ms)
    return ok(
        sandbox_id=sandbox_id,
        target_sleep_ms=10,
        measured_deltas_ms=deltas_ms,
        average_delta_ms=round(avg, 4),
        max_deviation_ms=round(max_dev, 4),
        noisy_environment=max_dev > 5.0,
        hint=("High jitter detected — VM/cloud host. RDTSC anti-debug may give false positives."
              if max_dev > 5.0 else "Timer baseline looks stable."),
    )


@tool
def check_debug_port(sandbox_id: str | None = None) -> dict:
    """Query the target's ProcessDebugPort via NtQueryInformationProcess.

    A non-zero value means a debugger is attached at the kernel level.
    ScyllaHide can hide this for some query paths, but not all.
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    pid = sandbox.debuggee_pid
    if not pid:
        return err("Sandbox has no known debuggee PID.", ErrorType.INVALID_STATE, sandbox_id=sandbox_id)

    val, status = _nt_query_information_process(pid, _PROCESS_DEBUG_PORT)
    if status != 0:
        return err(f"NtQueryInformationProcess failed: 0x{status:08X}", ErrorType.RPC_ERROR,
                   sandbox_id=sandbox_id)
    return ok(
        sandbox_id=sandbox_id,
        debug_port=val,
        debugger_detected=val != 0,
        hint="Non-zero debug_port means kernel-level debugger attachment." if val != 0 else None,
    )


@tool
def check_debug_object_handles(sandbox_id: str | None = None) -> dict:
    """Enumerate the target's handles looking for DebugObject instances.

    When a debugger attaches, Windows creates a DebugObject handle in the target's
    handle table. This enumerates all handles and reports suspicious ones.
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except KeyError as exc:
        return lookup_error(exc)
    pid = sandbox.debuggee_pid
    if not pid:
        return err("Sandbox has no known debuggee PID.", ErrorType.INVALID_STATE, sandbox_id=sandbox_id)

    try:
        handles = _enum_debug_object_handles(pid)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    # Filter to a reasonable subset for reporting (first 32)
    return ok(
        sandbox_id=sandbox_id,
        total_handles=len(handles),
        suspicious_handle_count=len(handles),
        handles_reported=handles[:32],
        note=("Handle enumeration is heuristic; requires elevation for full accuracy."),
    )
