"""Process memory dumper. No debugger attachment required.

Methods:
  dump_via_comsvcs     — rundll32 comsvcs.dll,MiniDump (built-in Windows, zero deps)
  dump_via_procdump    — ProcDump -r (clone via PssCaptureSnapshot, no pause)
  dump_via_minidump    — ctypes call to dbghelp!MiniDumpWriteDump
  poll_for_window_title — Enumerate windows looking for substring in title
  wait_for_window      — Block until window with title appears
"""

import ctypes
import os
import subprocess
import time
from ctypes import wintypes


EXT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "ext")

# -----------------------------------------------------------------------
# Type-safe MiniDumpWriteDump
# -----------------------------------------------------------------------
_kernel32 = ctypes.windll.kernel32

_minidump_write_dump = ctypes.windll.dbghelp.MiniDumpWriteDump
_minidump_write_dump.argtypes = [
    wintypes.HANDLE,   # hProcess
    wintypes.DWORD,    # ProcessId
    wintypes.HANDLE,   # hFile
    wintypes.DWORD,    # DumpType
    ctypes.c_void_p,   # ExceptionParam (NULL)
    ctypes.c_void_p,   # UserStreamParam (NULL)
    ctypes.c_void_p,   # CallbackParam (NULL)
]
_minidump_write_dump.restype = wintypes.BOOL


# -----------------------------------------------------------------------
# Dump: comsvcs.dll (built-in Windows, zero external tools)
# -----------------------------------------------------------------------
def dump_via_comsvcs(pid: int, output_path: str) -> bool:
    cmdline = f'rundll32.exe comsvcs.dll, MiniDump {pid} "{output_path}" full'
    try:
        result = subprocess.run(cmdline, shell=True, capture_output=True, text=True, timeout=120)
        return result.returncode == 0 and os.path.exists(output_path) and os.path.getsize(output_path) > 0
    except (subprocess.TimeoutExpired, OSError):
        return False


# -----------------------------------------------------------------------
# Dump: ProcDump -r (clone mode, process never paused)
# -----------------------------------------------------------------------
def dump_via_procdump_clone(pid: int, output_path: str) -> bool:
    procdump_path = os.path.join(EXT_DIR, "procdump64.exe")
    if not os.path.exists(procdump_path):
        procdump_path = os.path.join(EXT_DIR, "procdump.exe")
    if not os.path.exists(procdump_path):
        procdump_path = "procdump64.exe"

    base = os.path.splitext(output_path)[0]
    cmd = [procdump_path, "-r", "-ma", "-accepteula", str(pid), base]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0 and os.path.exists(output_path)
    except (subprocess.TimeoutExpired, OSError):
        return False


# -----------------------------------------------------------------------
# Dump: MiniDumpWriteDump via ctypes (no subprocess)
# -----------------------------------------------------------------------
def dump_via_minidumpwritedump(pid: int, output_path: str) -> bool:
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MiniDumpWithFullMemory = 0x00000002

    h_process = _kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h_process:
        return False

    try:
        h_file = _kernel32.CreateFileW(
            output_path, 0x40000000, 0, None, 2, 0, None  # GENERIC_WRITE, CREATE_ALWAYS
        )
        if h_file == wintypes.HANDLE(-1).value:
            return False

        try:
            return bool(_minidump_write_dump(
                wintypes.HANDLE(h_process),
                wintypes.DWORD(pid),
                wintypes.HANDLE(h_file),
                wintypes.DWORD(MiniDumpWithFullMemory),
                None, None, None,
            ))
        finally:
            _kernel32.CloseHandle(h_file)
    finally:
        _kernel32.CloseHandle(h_process)



# -----------------------------------------------------------------------
# Window polling via pywin32
# -----------------------------------------------------------------------
def _poll_for_window_title(pid: int, title_substring: str) -> bool:
    import win32gui
    import win32process

    title_lower = title_substring.lower()
    found = False

    def _callback(hwnd, _lparam):
        nonlocal found
        try:
            _, wnd_pid = win32process.GetWindowThreadProcessId(hwnd)
            if wnd_pid == pid:
                text = win32gui.GetWindowText(hwnd)
                if title_lower in text.lower():
                    found = True
                    return 0
        except Exception:
            pass
        return 1

    win32gui.EnumWindows(_callback, 0)
    return found


def wait_for_window(pid: int, title_substring: str, timeout_sec: float = 120.0) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        if _poll_for_window_title(pid, title_substring):
            return True
        time.sleep(0.5)
    return False


def find_process_by_window_title(title_substring: str) -> list[int]:
    import win32gui
    import win32process
    pids: list[int] = []
    title_lower = title_substring.lower()

    def _callback(hwnd, _lparam):
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid:
                text = win32gui.GetWindowText(hwnd)
                if title_lower in text.lower() and pid not in pids:
                    pids.append(pid)
        except Exception:
            pass
        return 1

    win32gui.EnumWindows(_callback, 0)
    return pids
