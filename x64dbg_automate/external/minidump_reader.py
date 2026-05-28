"""Robust, agent-friendly reader over Windows minidump (.dmp) files.

Wraps the third-party ``minidump`` library behind a single ``DumpInspector`` that:

* parses a dump **once** (results cached per file path + mtime),
* lazily imports ``minidump`` so environments without it fail with a clear hint
  rather than an ImportError at module load,
* exposes clean dict-shaped accessors (exception, modules, threads, registers,
  stack, VA reads) that **degrade to None/[] instead of raising** when a stream
  is absent — so downstream MCP tools never crash on a partial dump.

This is the shared foundation for the dump_* MCP tools (dump_registers,
dump_stack_walk, compare_dump_to_live). The library's raw object model is messy
and stream-specific; everything here normalizes it to the same structured-dict
contract the live debugger tools use.

The ``raw_provider`` seam (``(rva, size) -> bytes``) makes the inspector fully
unit-testable without a real .dmp on disk: ``from_file`` wires it to a
file-backed reader, while tests inject an in-memory provider.
"""

from __future__ import annotations

import io
import os
import threading
from typing import Any, Callable

# Architecture codes from MINIDUMP SystemInfo (PROCESSOR_ARCHITECTURE).
_ARCH_AMD64 = 9
_ARCH_INTEL = 0
_ARCH_ARM64 = 32771

# Common NTSTATUS / exception codes → readable names (not exhaustive; unknowns
# are reported by their hex value so the agent still has something actionable).
_EXCEPTION_CODE_NAMES = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC0000025: "NONCONTINUABLE_EXCEPTION",
    0xC0000026: "INVALID_DISPOSITION",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "INTEGER_OVERFLOW",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0x80000003: "BREAKPOINT",
    0x80000004: "SINGLE_STEP",
    0xC0000409: "STACK_BUFFER_OVERRUN",
    0xC0000374: "HEAP_CORRUPTION",
}

# Access-violation ExceptionInformation[0] operation codes.
_AV_OPERATION = {0: "read", 1: "write", 8: "execute"}


class DumpError(Exception):
    """Raised only for unrecoverable dump problems (missing lib, unparseable file)."""


def exception_code_name(code: int | None) -> str | None:
    if code is None:
        return None
    return _EXCEPTION_CODE_NAMES.get(code & 0xFFFFFFFF, f"0x{code & 0xFFFFFFFF:08X}")


class DumpInspector:
    """Normalized read-only view over a parsed minidump.

    Construct via :meth:`from_file` in production (cached, file-backed) or
    directly with a pre-parsed ``mf`` object + ``raw_provider`` in tests.
    """

    def __init__(self, mf: Any, path: str, *, raw_provider: Callable[[int, int], bytes] | None = None):
        self._mf = mf
        self._path = path
        self._raw_provider = raw_provider or self._file_raw_provider

    # ── construction ──────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, path: str) -> "DumpInspector":
        if not path or not os.path.isfile(path):
            raise DumpError(f"Dump file not found: {path!r}")
        try:
            from minidump.minidumpfile import MinidumpFile
        except Exception as exc:  # noqa: BLE001
            raise DumpError(
                "The 'minidump' package is required to read .dmp files but is not "
                f"importable: {exc}. Install it (pip install minidump)."
            ) from exc
        try:
            mf = MinidumpFile.parse(path)
        except Exception as exc:  # noqa: BLE001
            raise DumpError(f"Failed to parse minidump {path!r}: {exc}") from exc
        return cls(mf, path)

    def _file_raw_provider(self, rva: int, size: int) -> bytes:
        with open(self._path, "rb") as f:
            f.seek(rva)
            return f.read(size)

    # ── architecture ──────────────────────────────────────────────────────

    def arch(self) -> str:
        """Return 'x64' | 'x32'. Defaults to x64 when sysinfo is unavailable."""
        try:
            raw = self._mf.sysinfo.ProcessorArchitecture
            code = getattr(raw, "value", raw)
        except Exception:
            return "x64"
        if code == _ARCH_INTEL:
            return "x32"
        return "x64"  # AMD64/ARM64/unknown → 64-bit register layout

    # ── exception ─────────────────────────────────────────────────────────

    def exception(self) -> dict | None:
        """Return the crash exception record, or None if the dump has no exception stream."""
        try:
            records = self._mf.exception.exception_records
        except Exception:
            return None
        if not records:
            return None
        es = records[0]
        rec = getattr(es, "ExceptionRecord", None)
        if rec is None:
            return None
        code_raw = getattr(rec, "ExceptionCode_raw", None)
        if code_raw is None:
            # ExceptionCode may be an enum; fall back to its value.
            code_enum = getattr(rec, "ExceptionCode", None)
            code_raw = getattr(code_enum, "value", code_enum)
        params = list(getattr(rec, "ExceptionInformation", []) or [])
        out = {
            "thread_id": getattr(es, "ThreadId", None),
            "code": code_raw,
            "code_name": exception_code_name(code_raw),
            "address": getattr(rec, "ExceptionAddress", None),
            "parameter_count": getattr(rec, "NumberParameters", None),
            "parameters": params,
        }
        # For access violations, decode the faulting operation + address.
        if (code_raw & 0xFFFFFFFF) == 0xC0000005 and len(params) >= 2:
            out["access_violation"] = {
                "operation": _AV_OPERATION.get(params[0], f"0x{params[0]:X}"),
                "fault_address": params[1],
            }
        return out

    # ── modules ───────────────────────────────────────────────────────────

    def modules(self) -> list[dict]:
        try:
            mods = self._mf.modules.modules
        except Exception:
            return []
        out = []
        for m in mods:
            base = getattr(m, "baseaddress", None)
            size = getattr(m, "size", None) or 0
            name = getattr(m, "name", None)
            out.append({
                "name": os.path.basename(name) if name else None,
                "path": name,
                "base": base,
                "size": size,
                "end": (base + size) if base is not None else None,
            })
        return out

    def module_for_va(self, va: int) -> dict | None:
        """Return {name, path, base, rva} for the module containing ``va``."""
        for m in self.modules():
            base, end = m.get("base"), m.get("end")
            if base is not None and end is not None and base <= va < end:
                return {"name": m["name"], "path": m["path"], "base": base, "rva": va - base}
        return None

    # ── threads ───────────────────────────────────────────────────────────

    def _raw_threads(self) -> list:
        try:
            return list(self._mf.threads.threads)
        except Exception:
            return []

    def threads(self) -> list[dict]:
        out = []
        for t in self._raw_threads():
            stack = getattr(t, "Stack", None)
            out.append({
                "thread_id": getattr(t, "ThreadId", None),
                "suspend_count": getattr(t, "SuspendCount", None),
                "priority": getattr(t, "Priority", None),
                "teb": getattr(t, "Teb", None),
                "stack_base": getattr(stack, "StartOfMemoryRange", None) if stack else None,
                "stack_size": getattr(stack, "DataSize", None) if stack else None,
            })
        return out

    def _resolve_thread(self, thread_id: int | None):
        """Return the raw thread for ``thread_id`` (or the crash thread, or first)."""
        raw = self._raw_threads()
        if not raw:
            return None
        if thread_id is None:
            exc = self.exception()
            if exc and exc.get("thread_id") is not None:
                thread_id = exc["thread_id"]
        if thread_id is None:
            return raw[0]
        for t in raw:
            if getattr(t, "ThreadId", None) == thread_id:
                return t
        return None

    # ── registers ─────────────────────────────────────────────────────────

    def thread_context(self, thread_id: int | None = None) -> dict | None:
        """Return the register state for a thread (crash thread by default).

        Auto-selects the 64-bit ``CONTEXT`` or 32-bit ``WOW64_CONTEXT`` layout
        based on the dump's processor architecture. Returns ``{thread_id, arch,
        registers:{name:int}}`` or None if the context can't be read/parsed.
        """
        t = self._resolve_thread(thread_id)
        if t is None:
            return None
        loc = getattr(t, "ThreadContext", None)
        if loc is None or getattr(loc, "Rva", None) is None:
            return None
        try:
            raw = self._raw_provider(loc.Rva, loc.DataSize or 0)
        except Exception:
            return None
        if not raw:
            return None

        arch = self.arch()
        regs = self._parse_context(raw, arch)
        if regs is None:
            return None
        return {"thread_id": getattr(t, "ThreadId", None), "arch": arch, "registers": regs}

    @staticmethod
    def _parse_context(raw: bytes, arch: str) -> dict | None:
        try:
            from minidump.streams.ContextStream import CONTEXT, WOW64_CONTEXT
        except Exception:
            return None
        try:
            buff = io.BytesIO(raw)
            if arch == "x64":
                ctx = CONTEXT.parse(buff)
                names = ["Rax", "Rbx", "Rcx", "Rdx", "Rsi", "Rdi", "Rbp", "Rsp",
                         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                         "Rip", "EFlags", "SegCs", "SegSs", "SegDs", "SegEs", "SegFs", "SegGs"]
            else:
                ctx = WOW64_CONTEXT.parse(buff)
                names = ["Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp",
                         "Eip", "EFlags", "SegCs", "SegSs", "SegDs", "SegEs", "SegFs", "SegGs"]
        except Exception:
            return None
        regs: dict[str, int] = {}
        for n in names:
            v = getattr(ctx, n, None)
            if v is not None:
                regs[n.lower()] = v
        return regs or None

    # ── memory ────────────────────────────────────────────────────────────

    def read_va(self, va: int, size: int) -> bytes | None:
        """Read ``size`` bytes at virtual address ``va`` from the dump, or None."""
        if size <= 0:
            return b""
        try:
            reader = self._mf.get_reader()
            data = reader.read(va, size)
            return bytes(data) if data else None
        except Exception:
            return None

    def read_stack(self, thread_id: int | None = None, max_bytes: int = 0x4000) -> dict | None:
        """Read a thread's stack memory window. Returns {base, size, data} or None."""
        t = self._resolve_thread(thread_id)
        if t is None:
            return None
        stack = getattr(t, "Stack", None)
        if stack is None:
            return None
        base = getattr(stack, "StartOfMemoryRange", None)
        size = min(getattr(stack, "DataSize", 0) or 0, max_bytes)
        if base is None or size <= 0:
            return None
        data = self.read_va(base, size)
        if data is None:
            # Fall back to reading the stack bytes straight from the file RVA.
            try:
                data = self._raw_provider(stack.Rva, size)
            except Exception:
                data = None
        if not data:
            return None
        return {"base": base, "size": len(data), "data": data}


# ---------------------------------------------------------------------------
# Parse-once cache (keyed by path + mtime) so repeated tool calls on the same
# dump don't re-parse the whole file.
# ---------------------------------------------------------------------------
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, DumpInspector]] = {}


def get_inspector(path: str) -> DumpInspector:
    """Return a cached :class:`DumpInspector` for ``path`` (re-parses if the file changed)."""
    try:
        mtime = os.path.getmtime(path)
    except OSError as exc:
        raise DumpError(f"Dump file not found: {path!r}") from exc
    with _cache_lock:
        hit = _cache.get(path)
        if hit and hit[0] == mtime:
            return hit[1]
    inspector = DumpInspector.from_file(path)
    with _cache_lock:
        _cache[path] = (mtime, inspector)
    return inspector
