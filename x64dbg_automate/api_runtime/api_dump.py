"""Crash-dump inspection tools — bring minidump (.dmp) analysis into the live MCP.

Before these, answering "what does this crash dump say?" meant dropping out of the
debugger toolset into a separate Python ``minidump`` workflow and hand-parsing
streams. These tools expose the dump through the same structured-dict contract as
the live debugger, and ``compare_dump_to_live`` correlates the two in a single call.

All three build on :class:`x64dbg_automate.external.minidump_reader.DumpInspector`,
which parses once (cached) and degrades gracefully on partial dumps.
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, lookup_error, ok,
)
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager
from x64dbg_automate.external.minidump_reader import DumpError, get_inspector

# EFLAGS bit positions → short names.
_EFLAGS_BITS = [
    (0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"),
    (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF"),
]

# Call opcodes used to verify a stack value is a real return address
# (the byte(s) immediately preceding it should encode a CALL).
#   E8 cd            call rel32          (return addr = site+5)
#   9A cp            call far            (return addr = site+7, rare)
#   FF /2 (modrm)    call r/m            (1–7 bytes; we check the FF byte)
_CALL_NEAR_REL = 0xE8


def _decode_eflags(value: int) -> dict:
    return {name: bool(value & (1 << bit)) for bit, name in _EFLAGS_BITS}


def _hexregs(registers: dict) -> dict:
    out = {}
    for k, v in registers.items():
        out[k] = f"0x{v:X}" if isinstance(v, int) else v
    return out


def _open_dump(dump_path: str):
    """Return (inspector, None) or (None, error_dict)."""
    try:
        return get_inspector(dump_path), None
    except DumpError as exc:
        return None, err(str(exc), ErrorType.NOT_FOUND,
                         hint="Verify the .dmp path and that the 'minidump' package is installed.")
    except Exception as exc:  # noqa: BLE001
        return None, err(str(exc), classify_exception(exc))


@tool
def dump_registers(*, dump_path: str, thread_id: int | None = None) -> dict:
    """Read the CPU register state of a thread from a crash dump.

    Defaults to the faulting (exception) thread, so a single call answers
    "what were the registers at the crash?" — e.g. seeing ``eax: 0x0`` next to a
    ``mov ecx, [eax]`` fault. Auto-selects the 64-bit or 32-bit register layout.

    Args:
        dump_path: Path to the .dmp file.
        thread_id: Specific thread to read; omit for the crash thread (or the
                   first thread if the dump has no exception record).

    Returns ``arch``, ``thread_id``, ``registers`` (hex strings), decoded
    ``eflags``, and an ``exception`` summary when the dump has one.
    """
    inspector, error = _open_dump(dump_path)
    if error:
        return error

    try:
        ctx = inspector.thread_context(thread_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc))

    if ctx is None:
        return err(
            "Could not read a register context from the dump"
            + (f" for thread {thread_id}." if thread_id is not None else "."),
            ErrorType.NOT_FOUND,
            hint="The dump may lack a thread/context stream, or the thread_id is wrong. "
                 "Use dump_stack_walk or list threads to find valid ids.",
        )

    regs = ctx["registers"]
    eflags_val = regs.get("eflags")
    result = ok(
        dump_path=dump_path,
        arch=ctx["arch"],
        thread_id=ctx["thread_id"],
        registers=_hexregs(regs),
    )
    if eflags_val is not None:
        result["eflags"] = _decode_eflags(eflags_val)

    exc = inspector.exception()
    if exc:
        result["exception"] = {
            "thread_id": exc["thread_id"],
            "code": (f"0x{exc['code']:08X}" if isinstance(exc.get("code"), int) else exc.get("code")),
            "code_name": exc.get("code_name"),
            "address": (f"0x{exc['address']:X}" if isinstance(exc.get("address"), int) else None),
            "access_violation": _fmt_av(exc.get("access_violation")),
        }
        result["is_crash_thread"] = (exc["thread_id"] == ctx["thread_id"])
    return result


def _fmt_av(av: dict | None) -> dict | None:
    if not av:
        return None
    return {
        "operation": av.get("operation"),
        "fault_address": (f"0x{av['fault_address']:X}" if isinstance(av.get("fault_address"), int) else None),
    }


@tool
def dump_stack_walk(
    *,
    dump_path: str,
    thread_id: int | None = None,
    max_frames: int = 64,
) -> dict:
    """Reconstruct a thread's call stack from a crash dump.

    Minidumps don't store a ready-made call stack, and full unwind-info walking
    isn't available offline. This uses the robust technique RE analysts apply by
    hand: frame 0 is the instruction pointer from the thread context, then the
    thread's stack memory is scanned for values that point into a loaded module
    and are immediately preceded by a CALL instruction (verified by reading the
    dump). ``call_verified`` flags each frame's confidence.

    Args:
        dump_path: Path to the .dmp file.
        thread_id: Thread to walk; omit for the crash thread.
        max_frames: Cap on frames returned (default 64).

    Returns ``frames`` (each: address-on-stack, return_address, module, rva,
    call_verified) with frame 0 being the current instruction pointer.
    """
    inspector, error = _open_dump(dump_path)
    if error:
        return error

    try:
        ctx = inspector.thread_context(thread_id)
        stack = inspector.read_stack(thread_id)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc))

    if ctx is None or stack is None:
        return err(
            "Could not read thread context/stack from the dump.",
            ErrorType.NOT_FOUND,
            hint="The dump may not include this thread's stack memory.",
        )

    arch = ctx["arch"]
    ptr_size = 8 if arch == "x64" else 4
    regs = ctx["registers"]
    ip = regs.get("rip") if arch == "x64" else regs.get("eip")
    sp = regs.get("rsp") if arch == "x64" else regs.get("esp")

    frames: list[dict] = []

    # Frame 0 — current instruction pointer.
    if ip is not None:
        mod = inspector.module_for_va(ip)
        frames.append({
            "frame": 0,
            "return_address": f"0x{ip:X}",
            "module": mod["name"] if mod else None,
            "rva": (f"0x{mod['rva']:X}" if mod else None),
            "stack_address": None,
            "call_verified": None,  # frame 0 is live IP, not a return address
        })

    base, data = stack["base"], stack["data"]
    # Only scan from SP upward (toward higher addresses) — below SP is dead space.
    start_off = 0
    if sp is not None and base <= sp < base + len(data):
        start_off = sp - base
    start_off -= start_off % ptr_size  # align

    n = len(data)
    off = start_off
    while off + ptr_size <= n and len(frames) < max_frames:
        value = int.from_bytes(data[off:off + ptr_size], "little")
        mod = inspector.module_for_va(value)
        if mod is not None:
            verified = _verify_return_address(inspector, value, arch)
            if verified is not False:  # True (verified) or None (couldn't read)
                frames.append({
                    "frame": len(frames),
                    "return_address": f"0x{value:X}",
                    "module": mod["name"],
                    "rva": f"0x{mod['rva']:X}",
                    "stack_address": f"0x{base + off:X}",
                    "call_verified": bool(verified),
                })
        off += ptr_size

    return ok(
        dump_path=dump_path,
        arch=arch,
        thread_id=ctx["thread_id"],
        frames=frames,
        frame_count=len(frames),
        method="heuristic_scan",
        note="Frames after 0 are heuristic: stack values pointing into a module and "
             "preceded by a CALL. call_verified=false/null means lower confidence.",
    )


def _verify_return_address(inspector, addr: int, arch: str) -> bool | None:
    """True if the bytes before ``addr`` encode a CALL; None if unreadable; False otherwise."""
    data = inspector.read_va(addr - 8, 8)
    if not data or len(data) < 8:
        return None
    # E8 rel32 → return addr is site+5, so site is addr-5 → data[3] == 0xE8.
    if data[3] == _CALL_NEAR_REL:
        return True
    # FF /2 register/memory-indirect call: the FF can sit 2–7 bytes before addr.
    # Check the plausible window for an 0xFF that could begin a CALL r/m.
    for back in range(2, 8):
        if data[8 - back] == 0xFF:
            return True
    return False


@tool
def compare_dump_to_live(
    *,
    dump_path: str,
    sandbox_id: str | None = None,
    address: str = "",
    instructions: int = 8,
) -> dict:
    """Verify a crash-dump code site against the live debuggee — in one call.

    Extracts the crash address from the dump (or uses ``address`` if given),
    maps it to its module + RVA, finds the same module in the live process,
    computes the live VA, disassembles both sides, and diffs them. This collapses
    the former ~30-call cross-ecosystem workflow ("does the dump crash site match
    the live binary?") into a single tool with a clear verdict.

    Args:
        dump_path: Path to the .dmp file.
        sandbox_id: Live sandbox to compare against (omit for active session).
        address: Optional explicit dump VA to compare; defaults to the crash address.
        instructions: How many instructions to disassemble on each side (default 8).

    Verdict is one of: ``MATCH`` (bytes identical), ``MISMATCH`` (bytes differ),
    ``MODULE_NOT_LOADED`` (dump module absent live), ``CODE_NOT_IN_DUMP``
    (bytes not captured in the dump), ``NO_CRASH_ADDRESS`` (no exception + no
    address given).
    """
    from x64dbg_automate.external.decompiler import disassemble_bytes

    inspector, error = _open_dump(dump_path)
    if error:
        return error

    mgr = get_manager()
    try:
        client = mgr.get_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    # Resolve the dump-side address: explicit arg wins, else the exception address.
    dump_va: int | None = None
    if address.strip():
        try:
            dump_va = int(address, 16) if not address.lower().startswith("0x") else int(address, 16)
        except ValueError:
            return err(f"Invalid address {address!r}; expected a hex VA like '0x88729D'.",
                       ErrorType.BAD_ARGUMENT)
    else:
        exc = inspector.exception()
        if exc and isinstance(exc.get("address"), int):
            dump_va = exc["address"]
    if dump_va is None:
        return err(
            "No crash address: the dump has no exception record and no address was given.",
            ErrorType.NOT_FOUND, hint="Pass address= to compare a specific VA.",
            verdict="NO_CRASH_ADDRESS",
        )

    arch = inspector.arch()
    count = max(1, min(instructions, 64))

    # Map dump VA → module + RVA, then to the live VA via the same module.
    dump_mod = inspector.module_for_va(dump_va)
    live_va = None
    live_module = None
    if dump_mod is not None:
        try:
            for m in client.get_modules():
                if m.name.lower() == dump_mod["name"].lower():
                    live_module = m
                    live_va = m.base + dump_mod["rva"]
                    break
        except Exception as exc:  # noqa: BLE001
            if is_bug(exc):
                raise
            return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    # Read + disassemble the dump side.
    read_size = count * 16  # generous upper bound; x86 insns ≤ 15 bytes
    dump_bytes = inspector.read_va(dump_va, read_size)
    dump_disasm = _safe_disasm(disassemble_bytes, dump_bytes, dump_va, arch, count)

    base_result = {
        "dump_path": dump_path,
        "sandbox_id": sandbox_id,
        "arch": arch,
        "dump_address": f"0x{dump_va:X}",
        "module": dump_mod["name"] if dump_mod else None,
        "module_rva": (f"0x{dump_mod['rva']:X}" if dump_mod else None),
        "dump_disasm": dump_disasm,
    }

    if dump_bytes is None:
        return ok(verdict="CODE_NOT_IN_DUMP", **base_result,
                  note="The crash address is not backed by memory in the dump; cannot compare.")
    if dump_mod is None:
        return ok(verdict="MODULE_NOT_LOADED", **base_result,
                  note="Crash address is not inside any module recorded in the dump.")
    if live_va is None:
        return ok(verdict="MODULE_NOT_LOADED", **base_result,
                  note=f"Module '{dump_mod['name']}' is not loaded in the live process.")

    # Read + disassemble the live side (debuggee must be stopped).
    try:
        mgr.ensure_stopped(client)
    except Exception:
        pass
    try:
        live_bytes = client.read_memory(live_va, read_size)
    except Exception as exc:  # noqa: BLE001
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id,
                   **{k: base_result[k] for k in ("dump_address", "module", "module_rva")})
    live_disasm = _safe_disasm(disassemble_bytes, live_bytes, live_va, arch, count)

    # Compare the leading bytes that both sides actually have.
    cmp_len = min(len(dump_bytes), len(live_bytes or b""), count * 16)
    bytes_match = bool(live_bytes) and dump_bytes[:cmp_len] == live_bytes[:cmp_len]
    first_diff = None
    if live_bytes:
        for i in range(cmp_len):
            if dump_bytes[i] != live_bytes[i]:
                first_diff = i
                break

    return ok(
        verdict="MATCH" if bytes_match else "MISMATCH",
        **base_result,
        live_address=f"0x{live_va:X}",
        live_module_base=f"0x{live_module.base:X}",
        live_disasm=live_disasm,
        bytes_compared=cmp_len,
        first_diff_offset=first_diff,
        note=("Dump and live code are byte-identical at the crash site."
              if bytes_match else
              "Dump and live code DIFFER — the live binary is not what crashed "
              "(patched/relocated/different build)."),
    )


def _safe_disasm(disassemble_bytes, data: bytes | None, base: int, arch: str, count: int) -> list[dict]:
    if not data:
        return []
    try:
        insns = disassemble_bytes(data, base, arch)
    except Exception:
        return []
    out = []
    for ins in insns[:count]:
        out.append({
            "address": f"0x{ins.address:X}",
            "bytes": ins.bytes.hex(),
            "mnemonic": (ins.mnemonic + (" " + ins.raw_op_str if ins.raw_op_str else "")).strip(),
        })
    return out
