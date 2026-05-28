"""Low-level helpers shared by the composite / memory / workflow tool layers.

These operate directly on an ``X64DbgClient`` and contain no MCP/response concerns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_GP_REGS_64 = [
    "rax", "rbx", "rcx", "rdx", "rbp", "rsp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
]
_GP_REGS_32 = ["eax", "ebx", "ecx", "edx", "ebp", "esp", "esi", "edi", "eip", "eflags"]

# Common function prologues, used by the heuristic boundary scanner when
# x64dbg's own analysis hasn't run on the target yet.
_PROLOGUE_PATTERNS = (
    # ── x64 prologues ───────────────────────────────────────────────────────
    b"\x48\x89\x5C\x24",  # mov [rsp+x], rbx                 (x64 reg save)
    b"\x48\x89\x4C\x24",  # mov [rsp+x], rcx                 (x64 home rcx)
    b"\x4C\x89\x44\x24",  # mov [rsp+x], r8                  (x64 home r8)
    b"\x4C\x89\x4C\x24",  # mov [rsp+x], r9                  (x64 home r9)
    b"\x48\x8B\xC4",      # mov rax, rsp                     (MSVC x64 home)
    b"\x40\x55",          # push rbp                         (x64 REX prefix)
    b"\x48\x83\xEC",      # sub rsp, imm8                    (x64 stack alloc)
    b"\x48\x81\xEC",      # sub rsp, imm32                   (x64 big frame)
    # ── x86 prologues ───────────────────────────────────────────────────────
    b"\x55\x8B\xEC",      # push ebp; mov ebp, esp           (MSVC x86 frame)
    b"\x55\x89\xE5",      # push ebp; mov ebp, esp           (GCC x86 frame)
    b"\x83\xEC",          # sub esp, imm8                    (x86 stack alloc)
    b"\x81\xEC",          # sub esp, imm32                   (x86 big frame)
    b"\x8B\xFF",          # mov edi, edi                     (hot-patch 2-byte NOP, W32 DLLs)
    b"\x55\x53",          # push ebp; push ebx               (x86 multi-reg save)
    b"\x55\x56",          # push ebp; push esi
    b"\x55\x57",          # push ebp; push edi
    b"\x53\x56\x57",      # push ebx; push esi; push edi
    b"\x56\x57",          # push esi; push edi
    b"\x57\x56",          # push edi; push esi
    b"\x57\x55",          # push edi; push ebp
)
_RET_BYTES = (b"\xC3", b"\xC2")  # ret / ret imm16

# Inter-function padding bytes that compilers emit for alignment.
# A run of 2+ consecutive CC or 90 bytes marks an inter-function boundary;
# the byte immediately after is the (non-standard) function entry.
_PADDING_BYTE_VALUES = (0xCC, 0x90)  # INT3, NOP

# Windows PAGE_* protection constants (base values; GUARD/NOCACHE are modifiers).
_PAGE_PROTECT_NAMES = {
    0x01: "NOACCESS", 0x02: "READONLY", 0x04: "READWRITE", 0x08: "WRITECOPY",
    0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY",
}
_PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80


def protect_name(protect: int) -> str:
    """Human-readable name for a Windows PAGE_* protection value (e.g. EXECUTE_READ|GUARD)."""
    name = _PAGE_PROTECT_NAMES.get(protect & 0xFF, f"0x{protect:X}")
    flags = []
    if protect & 0x100:
        flags.append("GUARD")
    if protect & 0x200:
        flags.append("NOCACHE")
    return name + ("|" + "|".join(flags) if flags else "")


def region_info(mgr, sandbox_id, address: int, *, ttl: float = 2.0) -> dict | None:
    """Cheap region metadata for ``address`` via the manager's cached memory map.

    Returns ``{region_base, region_size, protection, executable, section}`` or
    None when the address isn't in any mapped region. Uses the short-TTL memmap
    cache so it adds no RPC in tight read loops.
    """
    try:
        page = mgr.region_for_address(sandbox_id, address=address, ttl=ttl)
    except Exception:
        return None
    if page is None:
        return None
    return {
        "region_base": f"0x{page.base_address:X}",
        "region_size": page.region_size,
        "protection": protect_name(page.protect),
        "executable": bool(page.protect & _PAGE_EXECUTE_ANY),
        "section": page.info or None,
    }


@dataclass
class FunctionBounds:
    """Result of :func:`detect_function_bounds`.

    ``method`` records how the bounds were found and ``confidence`` reflects how
    much an agent should trust them — agents need this to decide whether to act
    on the disassembly or fall back to manual inspection.
    """
    start: int
    end: int
    method: str          # "x64dbg" | "prologue_scan" | "ret_scan" | "fallback"
    confidence: str      # "high" | "medium" | "low"
    note: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)


def detect_function_bounds(
    client: Any,
    addr: int,
    *,
    max_back: int = 0x2000,
    max_forward: int = 0x8000,
) -> FunctionBounds:
    """Find the (start, end) of the function containing ``addr``.

    Layered strategy, most-trusted first:

    1. **x64dbg analysis** (``get_function``) — authoritative when auto-analysis
       has run. ``confidence="high"``.
    2. **Prologue + RET scan** — walk backward for a known prologue byte sequence,
       then forward for a RET. Works on un-analyzed images. ``confidence="medium"``.
    2b. **Padding/alignment scan** — when no classic prologue is found, look for
       inter-function ``CC``/``NOP`` padding (2+ consecutive bytes) as a boundary
       marker. Catches MSVC-optimized entries (``jnz``, early-exit) that have no
       push-ebp preamble. ``confidence="low"``.
    3. **RET-only scan** — no prologue/padding found; bound forward to the next
       RET from ``addr``. ``confidence="low"``.
    4. **Fixed window** — last resort 4 KiB span so callers always get *some*
       range to disassemble rather than nothing. ``confidence="low"``.

    Never raises and never returns ``None`` — a usable range is always produced.
    """
    # 1. x64dbg's own analysis — authoritative *only if* it actually contains the
    #    queried address. On relocated/un-rebased images x64dbg can return bounds
    #    in the wrong frame (preferred-base RVAs) that don't contain ``addr``;
    #    trusting those produced confidently-wrong results. Reject and fall back.
    try:
        fb = client.get_function(addr)
        if fb and fb.start <= addr < fb.end:
            return FunctionBounds(fb.start, fb.end, "x64dbg", "high")
    except Exception:
        pass

    # 2. Backward prologue scan, then forward RET scan.
    scan_start = max(0, addr - max_back)
    for off in range(addr, scan_start, -1):
        try:
            data = client.read_memory(off, 8)
        except Exception:
            continue
        if not data:
            continue
        if any(data.startswith(p) for p in _PROLOGUE_PATTERNS):
            func_start = off
            for foff in range(addr, min(addr + max_forward, off + 0x20000)):
                try:
                    b = client.read_memory(foff, 1)
                except Exception:
                    break
                if b in _RET_BYTES:
                    return FunctionBounds(func_start, foff + 1, "prologue_scan", "medium")
            return FunctionBounds(
                func_start, addr + 0x1000, "prologue_scan", "low",
                note="Prologue found but no RET within scan window; end is approximate.",
            )

    # 2b. Padding/alignment scan — catches non-standard entries (jnz, early-exit
    #     patterns) where no classic prologue bytes appear. Read the entire backward
    #     window in one bulk call so this adds only a single RPC, then scan the
    #     buffer in Python for CC/NOP padding runs (2+ consecutive bytes) that
    #     compilers emit between functions for alignment.
    look_back = min(max_back, addr)
    if look_back >= 4:
        try:
            bulk = client.read_memory(addr - look_back, look_back)
        except Exception:
            bulk = b""
        if bulk and len(bulk) >= 4:
            # Scan right-to-left for the nearest 2+ padding-byte run.
            i = len(bulk) - 1
            while i >= 1:
                curr = bulk[i]
                prev = bulk[i - 1]
                if curr in _PADDING_BYTE_VALUES and curr == prev:
                    # Extend the run leftward to find its full extent.
                    j = i - 1
                    while j >= 0 and bulk[j] == curr:
                        j -= 1
                    # Function starts at the byte immediately after the run.
                    func_start = (addr - look_back) + i + 1
                    if 0 < func_start < addr:
                        for foff in range(func_start, min(func_start + max_forward, func_start + 0x10000)):
                            try:
                                b = client.read_memory(foff, 1)
                            except Exception:
                                break
                            if b in _RET_BYTES:
                                return FunctionBounds(
                                    func_start, foff + 1, "padding_scan", "low",
                                    note="Non-standard prologue; function start inferred from "
                                         "inter-function alignment padding (CC/NOP run).",
                                )
                        return FunctionBounds(
                            func_start, func_start + 0x1000, "padding_scan", "low",
                            note="Non-standard prologue inferred from padding. End is approximate.",
                        )
                    i = j  # skip past this run and continue scanning further back
                else:
                    i -= 1

    # 3. RET-only scan forward from addr.
    for foff in range(addr, addr + (max_forward // 2)):
        try:
            b = client.read_memory(foff, 1)
        except Exception:
            break
        if b in _RET_BYTES:
            return FunctionBounds(
                addr, foff + 1, "ret_scan", "low",
                note="No prologue found; start assumed at the queried address.",
            )

    # 4. Absolute fallback — fixed window so callers never get nothing.
    return FunctionBounds(
        addr, addr + 0x1000, "fallback", "low",
        note="Could not determine bounds; using a fixed 4 KiB window.",
    )


def resolve_addr(client: Any, value: Any) -> int:
    """Resolve a hex literal or x64dbg expression to an integer address.

    Bare numbers are treated as hex (matching the existing server). Non-hex strings
    (symbols, ``rsp+0x20``, ``kernel32:CreateFileA``) fall back to the expression
    evaluator. Raises ValueError if unresolvable.
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        val, success = client.eval_sync(s)
        if not success:
            raise ValueError(f"Cannot resolve address/expression: {value!r}")
        return val


def gp_regs(arch: str) -> list[str]:
    """General-purpose register names for the architecture ('x64' or 'x32')."""
    return _GP_REGS_64 if arch == "x64" else _GP_REGS_32


def capture_registers(client: Any, arch: str) -> dict[str, str]:
    """Snapshot the general-purpose registers as ``{name: '0x...'}`` (debuggee must be stopped)."""
    out: dict[str, str] = {}
    for reg in gp_regs(arch):
        try:
            out[reg] = f"0x{client.get_reg(reg):X}"
        except Exception:
            pass
    return out


def read_pointer(client: Any, arch: str, addr: int) -> int:
    """Read a pointer-sized value at ``addr`` (qword on x64, dword on x32)."""
    return client.read_qword(addr) if arch == "x64" else client.read_dword(addr)


def disasm_instructions(client: Any, addr: int, count: int) -> list[dict]:
    """Disassemble ``count`` instructions starting at ``addr``, stopping at RET.

    Returns a list of ``{address, bytes, mnemonic, size}`` dicts (bytes hex-encoded).
    This is the shared core used by both :func:`api_memory.disassemble_range` and
    the inline disassembly path in :func:`api_composite.capture_function_context`.
    """
    instructions: list[dict] = []
    cur = addr
    for _ in range(max(1, min(count, 512))):
        ins = client.disassemble_at(cur)
        if ins is None:
            break
        try:
            raw = client.read_memory(cur, ins.instr_size)
        except Exception:
            raw = b""
        instructions.append({
            "address": f"0x{cur:X}",
            "bytes": raw.hex(),
            "mnemonic": ins.instruction,
            "size": ins.instr_size,
        })
        cur += ins.instr_size
        if ins.instruction.strip().lower().startswith("ret"):
            break
    return instructions


def diff_bytes(before: bytes, after: bytes, max_runs: int = 64) -> list[dict]:
    """Group differing bytes into contiguous runs ``{offset, before, after}`` (hex strings)."""
    runs: list[dict] = []
    n = min(len(before), len(after))
    i = 0
    while i < n and len(runs) < max_runs:
        if before[i] != after[i]:
            j = i
            while j < n and before[j] != after[j]:
                j += 1
            runs.append({"offset": i, "before": before[i:j].hex(), "after": after[i:j].hex()})
            i = j
        else:
            i += 1
    return runs
