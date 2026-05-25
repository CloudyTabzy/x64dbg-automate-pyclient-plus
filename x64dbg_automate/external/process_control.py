"""Process suspend/resume — no debugger attachment required.

Uses NtSuspendProcess / NtResumeProcess from ntdll.dll.
These are undocumented but stable kernel APIs that suspend ALL threads
atomically without creating a debug port.
"""

import ctypes
from ctypes import wintypes

_kernel32 = ctypes.windll.kernel32
_ntdll = ctypes.windll.ntdll

_NtSuspendProcess = _ntdll.NtSuspendProcess
_NtSuspendProcess.argtypes = [wintypes.HANDLE]
_NtSuspendProcess.restype = ctypes.c_long

_NtResumeProcess = _ntdll.NtResumeProcess
_NtResumeProcess.argtypes = [wintypes.HANDLE]
_NtResumeProcess.restype = ctypes.c_long


def nt_suspend_process(pid: int) -> bool:
    PROCESS_SUSPEND_RESUME = 0x0800
    h_process = _kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h_process:
        return False
    try:
        status = _NtSuspendProcess(wintypes.HANDLE(h_process))
        return status >= 0  # STATUS_SUCCESS or STATUS_SUSPEND_COUNT_EXCEEDED
    except OSError:
        return False
    finally:
        _kernel32.CloseHandle(h_process)


def nt_resume_process(pid: int) -> bool:
    PROCESS_SUSPEND_RESUME = 0x0800
    h_process = _kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if not h_process:
        return False
    try:
        status = _NtResumeProcess(wintypes.HANDLE(h_process))
        return status >= 0
    except OSError:
        return False
    finally:
        _kernel32.CloseHandle(h_process)
