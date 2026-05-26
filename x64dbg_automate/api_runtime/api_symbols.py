"""Symbol and type-information tools for the AI-native runtime API.

Provides three capabilities:

1. **Ordinal resolution** — convert ``(dll_path, ordinal)`` to an export name using
   the existing PE analyzer. Fills the gap where SecuROM calls imports by ordinal.

2. **Type layout** — static field schema for common Windows structures (PEB, TEB,
   UNICODE_STRING, LDR_DATA_TABLE_ENTRY, LIST_ENTRY, IMAGE_DOS_HEADER, …).
   Returns field definitions without touching process memory.

3. **Type interpretation** — read process memory and display it as a named
   Windows type with labeled, hex-formatted field values. Builds on the static
   type library; augments pointer fields with best-effort symbol resolution.

Type field format (each element in ``fields`` list)::

    {"name": str, "offset": "0xNN", "type": str, "size": int, "value": "0x...", "description": str}

Supported primitive types: ``u8``, ``u16``, ``u32``, ``u64``, ``ptr``
(pointer-sized: 4 B on x32, 8 B on x64).
"""

from __future__ import annotations

import struct as _struct

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, lookup_error, ok,
)
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

# ---------------------------------------------------------------------------
# Static type library
# Each entry: (name, offset, type_str, description)
# type_str: u8 | u16 | u32 | u64 | ptr
# ---------------------------------------------------------------------------

_TYPES: dict[str, dict[str, list]] = {
    # arch-independent (same offsets on x64; x32 variants keyed separately)
    "IMAGE_DOS_HEADER": {
        "x64": [
            ("e_magic",    0x00, "u16", "MZ signature (0x5A4D)"),
            ("e_cblp",     0x02, "u16", "Bytes on last page"),
            ("e_cp",       0x04, "u16", "Pages in file"),
            ("e_crlc",     0x06, "u16", "Relocations"),
            ("e_cparhdr",  0x08, "u16", "Size of header in paragraphs"),
            ("e_minalloc", 0x0A, "u16", "Minimum extra paragraphs"),
            ("e_maxalloc", 0x0C, "u16", "Maximum extra paragraphs"),
            ("e_ss",       0x0E, "u16", "Initial SS value"),
            ("e_sp",       0x10, "u16", "Initial SP value"),
            ("e_lfanew",   0x3C, "u32", "Offset to PE header"),
        ],
        "x32": None,  # same layout
    },
    "IMAGE_FILE_HEADER": {
        "x64": [
            ("Machine",              0x00, "u16", "Target architecture (0x8664=x64, 0x14C=x86)"),
            ("NumberOfSections",     0x02, "u16", "Section count"),
            ("TimeDateStamp",        0x04, "u32", "Link timestamp (Unix epoch)"),
            ("PointerToSymbolTable", 0x08, "u32", "COFF symbol table offset"),
            ("NumberOfSymbols",      0x0C, "u32", "COFF symbol count"),
            ("SizeOfOptionalHeader", 0x10, "u16", "Optional header size"),
            ("Characteristics",      0x12, "u16", "Flags"),
        ],
        "x32": None,
    },
    "UNICODE_STRING": {
        "x64": [
            ("Length",        0x00, "u16", "String byte length (not including null)"),
            ("MaximumLength", 0x02, "u16", "Buffer capacity in bytes"),
            ("Buffer",        0x08, "ptr", "Pointer to wide-character string data"),
        ],
        "x32": [
            ("Length",        0x00, "u16", "String byte length (not including null)"),
            ("MaximumLength", 0x02, "u16", "Buffer capacity in bytes"),
            ("Buffer",        0x04, "ptr", "Pointer to wide-character string data"),
        ],
    },
    "LIST_ENTRY": {
        "x64": [
            ("Flink", 0x00, "ptr", "Forward link (next element)"),
            ("Blink", 0x08, "ptr", "Backward link (previous element)"),
        ],
        "x32": [
            ("Flink", 0x00, "ptr", "Forward link (next element)"),
            ("Blink", 0x04, "ptr", "Backward link (previous element)"),
        ],
    },
    "LDR_DATA_TABLE_ENTRY": {
        "x64": [
            ("InLoadOrderLinks",      0x00, "ptr", "LIST_ENTRY Flink (load-order chain)"),
            ("InMemoryOrderLinks",    0x10, "ptr", "LIST_ENTRY Flink (memory-order chain)"),
            ("InInitializationOrderLinks", 0x20, "ptr", "LIST_ENTRY Flink (init-order chain)"),
            ("DllBase",               0x30, "ptr", "Module base address"),
            ("EntryPoint",            0x38, "ptr", "DLL entry point"),
            ("SizeOfImage",           0x40, "u32", "Module size in bytes"),
            ("FullDllName_Len",        0x48, "u16", "Full path length (bytes)"),
            ("FullDllName_Buffer",     0x50, "ptr", "Full path buffer pointer"),
            ("BaseDllName_Len",        0x58, "u16", "Short name length (bytes)"),
            ("BaseDllName_Buffer",     0x60, "ptr", "Short name buffer pointer"),
        ],
        "x32": [
            ("InLoadOrderLinks",      0x00, "ptr", "LIST_ENTRY Flink (load-order chain)"),
            ("InMemoryOrderLinks",    0x08, "ptr", "LIST_ENTRY Flink (memory-order chain)"),
            ("InInitializationOrderLinks", 0x10, "ptr", "LIST_ENTRY Flink (init-order chain)"),
            ("DllBase",               0x18, "ptr", "Module base address"),
            ("EntryPoint",            0x1C, "ptr", "DLL entry point"),
            ("SizeOfImage",           0x20, "u32", "Module size in bytes"),
            ("FullDllName_Len",        0x24, "u16", "Full path length (bytes)"),
            ("FullDllName_Buffer",     0x28, "ptr", "Full path buffer pointer"),
            ("BaseDllName_Len",        0x2C, "u16", "Short name length (bytes)"),
            ("BaseDllName_Buffer",     0x30, "ptr", "Short name buffer pointer"),
        ],
    },
    "PEB": {
        "x64": [
            ("InheritedAddressSpace",    0x000, "u8",  ""),
            ("ReadImageFileExecOptions", 0x001, "u8",  ""),
            ("BeingDebugged",            0x002, "u8",  "1 when process is attached to a debugger"),
            ("BitField",                 0x003, "u8",  "Bit flags (ImageUsedLargePages, IsProtectedProcess, …)"),
            ("Mutant",                   0x008, "ptr", "Process mutex handle"),
            ("ImageBaseAddress",         0x010, "ptr", "PE image base address"),
            ("Ldr",                      0x018, "ptr", "PEB_LDR_DATA pointer (module list)"),
            ("ProcessParameters",        0x020, "ptr", "RTL_USER_PROCESS_PARAMETERS pointer"),
            ("SubSystemData",            0x028, "ptr", ""),
            ("ProcessHeap",              0x030, "ptr", "Default process heap handle"),
            ("FastPebLock",              0x038, "ptr", "RTL_CRITICAL_SECTION for PEB access"),
            ("NtGlobalFlag",             0x0BC, "u32", "Debug flags (0x70 = heap validation etc.)"),
            ("NumberOfProcessors",       0x0B8, "u32", "Logical CPU count"),
            ("OSMajorVersion",           0x118, "u32", "Windows major version"),
            ("OSMinorVersion",           0x11C, "u32", "Windows minor version"),
            ("OSBuildNumber",            0x120, "u16", "Windows build number"),
        ],
        "x32": [
            ("InheritedAddressSpace",    0x000, "u8",  ""),
            ("ReadImageFileExecOptions", 0x001, "u8",  ""),
            ("BeingDebugged",            0x002, "u8",  "1 when process is attached to a debugger"),
            ("BitField",                 0x003, "u8",  "Bit flags"),
            ("Mutant",                   0x004, "ptr", "Process mutex handle"),
            ("ImageBaseAddress",         0x008, "ptr", "PE image base address"),
            ("Ldr",                      0x00C, "ptr", "PEB_LDR_DATA pointer (module list)"),
            ("ProcessParameters",        0x010, "ptr", "RTL_USER_PROCESS_PARAMETERS pointer"),
            ("SubSystemData",            0x014, "ptr", ""),
            ("ProcessHeap",              0x018, "ptr", "Default process heap handle"),
            ("FastPebLock",              0x01C, "ptr", "RTL_CRITICAL_SECTION for PEB access"),
            ("NtGlobalFlag",             0x068, "u32", "Debug flags (0x70 = heap validation etc.)"),
            ("NumberOfProcessors",       0x064, "u32", "Logical CPU count"),
            ("OSMajorVersion",           0x0A4, "u32", "Windows major version"),
            ("OSMinorVersion",           0x0A8, "u32", "Windows minor version"),
            ("OSBuildNumber",            0x0AC, "u16", "Windows build number"),
        ],
    },
    "TEB": {
        "x64": [
            ("NtTib_ExceptionList", 0x000, "ptr", "SEH exception list head"),
            ("NtTib_StackBase",     0x008, "ptr", "Top of thread stack"),
            ("NtTib_StackLimit",    0x010, "ptr", "Bottom of thread stack"),
            ("NtTib_Self",          0x018, "ptr", "Self pointer (= TEB base)"),
            ("EnvironmentPointer",  0x038, "ptr", ""),
            ("ClientId_Pid",        0x040, "ptr", "Process ID"),
            ("ClientId_Tid",        0x048, "ptr", "Thread ID"),
            ("TlsStoragePointer",   0x058, "ptr", "TLS pointer"),
            ("PEB_Pointer",         0x060, "ptr", "Pointer to the PEB"),
            ("LastErrorValue",      0x068, "u32", "GetLastError() value"),
            ("LastStatusValue",     0x1250, "u32", "NTSTATUS last set by NT call"),
        ],
        "x32": [
            ("NtTib_ExceptionList", 0x000, "ptr", "SEH exception list head"),
            ("NtTib_StackBase",     0x004, "ptr", "Top of thread stack"),
            ("NtTib_StackLimit",    0x008, "ptr", "Bottom of thread stack"),
            ("NtTib_Self",          0x018, "ptr", "Self pointer (= TEB base)"),
            ("EnvironmentPointer",  0x01C, "ptr", ""),
            ("ClientId_Pid",        0x020, "ptr", "Process ID"),
            ("ClientId_Tid",        0x024, "ptr", "Thread ID"),
            ("TlsStoragePointer",   0x02C, "ptr", "TLS pointer"),
            ("PEB_Pointer",         0x030, "ptr", "Pointer to the PEB"),
            ("LastErrorValue",      0x034, "u32", "GetLastError() value"),
            ("LastStatusValue",     0x0BF4, "u32", "NTSTATUS last set by NT call"),
        ],
    },
}

# Canonical sizes (for get_type_layout total_size field; conservative estimates)
_TYPE_SIZES: dict[str, dict[str, int]] = {
    "IMAGE_DOS_HEADER":        {"x64": 0x40, "x32": 0x40},
    "IMAGE_FILE_HEADER":       {"x64": 0x14, "x32": 0x14},
    "UNICODE_STRING":          {"x64": 0x10, "x32": 0x08},
    "LIST_ENTRY":              {"x64": 0x10, "x32": 0x08},
    "LDR_DATA_TABLE_ENTRY":    {"x64": 0x80, "x32": 0x48},
    "PEB":                     {"x64": 0x130, "x32": 0x0B0},
    "TEB":                     {"x64": 0x1260, "x32": 0xBFC},
}


def _ptr_size(arch: str) -> int:
    return 8 if arch == "x64" else 4


def _field_size(type_str: str, arch: str) -> int:
    if type_str == "ptr":
        return _ptr_size(arch)
    return {"u8": 1, "u16": 2, "u32": 4, "u64": 8}.get(type_str, 0)


def _field_fmt(type_str: str, arch: str) -> str:
    """Return struct.unpack format for a field."""
    sizes = {"u8": "B", "u16": "H", "u32": "I", "u64": "Q", "ptr": "Q" if arch == "x64" else "I"}
    return "<" + sizes.get(type_str, "B")


def _resolve_fields(type_name: str, arch: str) -> list[tuple] | None:
    """Return field list for type_name+arch, handling None (same-as-x64) aliases."""
    entry = _TYPES.get(type_name)
    if entry is None:
        return None
    fields = entry.get(arch)
    if fields is None and arch == "x32":
        fields = entry.get("x64")  # same-layout type (e.g. IMAGE_DOS_HEADER)
    return fields


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@tool
def resolve_ordinal(dll_path: str, ordinal: int) -> dict:
    """Resolve a DLL ordinal number to its exported function name.

    Uses the on-disk PE export table — no live debugger required.

    Args:
        dll_path: Full path to the DLL (e.g. ``"C:\\Windows\\System32\\ws2_32.dll"``).
        ordinal: The numeric ordinal to look up (as it appears in the IAT entry).
    """
    if ordinal < 0:
        return err("ordinal must be >= 0.", ErrorType.BAD_ARGUMENT)

    from x64dbg_automate.external.pe_analyzer import get_exports
    try:
        exports = get_exports(dll_path)
    except Exception as exc:
        return err(str(exc), classify_exception(exc),
                   hint="Verify the path is a valid PE file and is readable.")

    match = next((e for e in exports if e.get("ordinal") == ordinal), None)
    if match is None:
        return err(
            f"No export with ordinal {ordinal} in {dll_path!r}.",
            ErrorType.NOT_FOUND,
            hint="Use get_pe_exports to see all available ordinals.",
        )
    return ok(
        ordinal=ordinal,
        name=match.get("name") or "<unnamed>",
        virtual_address=f"0x{match.get('virtual_address', 0):X}",
        dll_path=dll_path,
    )


@tool
def get_type_layout(type_name: str, arch: str = "x64") -> dict:
    """Return the static field schema for a Windows structure.

    Does not read process memory — useful for understanding a type before
    calling ``get_type_info``.

    Supported types: ``IMAGE_DOS_HEADER``, ``IMAGE_FILE_HEADER``,
    ``UNICODE_STRING``, ``LIST_ENTRY``, ``LDR_DATA_TABLE_ENTRY``, ``PEB``, ``TEB``.

    Args:
        type_name: Case-sensitive Windows structure name.
        arch: ``"x64"`` (default) or ``"x32"``.
    """
    arch = arch.lower().strip()
    if arch not in ("x64", "x32"):
        return err("arch must be 'x64' or 'x32'.", ErrorType.BAD_ARGUMENT)

    fields_raw = _resolve_fields(type_name, arch)
    if fields_raw is None:
        available = sorted(_TYPES.keys())
        return err(
            f"Unknown type '{type_name}'.",
            ErrorType.NOT_FOUND,
            hint=f"Available types: {', '.join(available)}.",
        )

    ptr_sz = _ptr_size(arch)
    fields = []
    for name, offset, tstr, desc in fields_raw:
        fields.append({
            "name": name,
            "offset": f"0x{offset:03X}",
            "type": "ptr64" if (tstr == "ptr" and arch == "x64") else
                    "ptr32" if (tstr == "ptr") else tstr,
            "size": _field_size(tstr, arch),
            "description": desc,
        })

    total = _TYPE_SIZES.get(type_name, {}).get(arch, 0)
    return ok(
        type_name=type_name,
        arch=arch,
        pointer_size=ptr_sz,
        total_size=total,
        field_count=len(fields),
        fields=fields,
    )


@tool
def get_type_info(
    *,
    sandbox_id: str | None = None,
    address: str,
    type_name: str,
    arch: str = "",
) -> dict:
    """Read process memory and interpret it as a named Windows structure.

    Returns labeled field values (hex-formatted). Pointer fields include a
    best-effort symbol resolution. UNICODE_STRING ``Buffer`` pointers are
    dereferenced and the wide string content is returned when readable.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        address: Base address of the structure.
        type_name: Windows structure name — see ``get_type_layout`` for the list.
        arch: Architecture override (``"x64"`` or ``"x32"``). Defaults to the
              sandbox's debugger architecture.
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
        client = sandbox.client
        if client is None:
            raise SandboxError(f"Sandbox '{sandbox.sandbox_id}' has no active client")
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    effective_arch = (arch.lower().strip() or sandbox.debugger_arch or "x64")
    if effective_arch not in ("x64", "x32"):
        return err("arch must be 'x64' or 'x32'.", ErrorType.BAD_ARGUMENT)

    fields_raw = _resolve_fields(type_name, effective_arch)
    if fields_raw is None:
        available = sorted(_TYPES.keys())
        return err(
            f"Unknown type '{type_name}'.",
            ErrorType.NOT_FOUND,
            hint=f"Available types: {', '.join(available)}. Call get_type_layout for field details.",
        )

    try:
        base = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    total_size = _TYPE_SIZES.get(type_name, {}).get(effective_arch, 0)
    if not total_size and fields_raw:
        # Compute minimum read: last field offset + field size
        last = max(fields_raw, key=lambda f: f[1])
        total_size = last[1] + _field_size(last[2], effective_arch)

    try:
        mgr.ensure_stopped(client)
        raw = client.read_memory(base, total_size)
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(
            f"Cannot read {total_size} bytes at {address}: {exc}",
            classify_exception(exc),
            sandbox_id=sandbox_id,
        )

    ptr_sz = _ptr_size(effective_arch)
    fields_out = []
    for fname, offset, tstr, desc in fields_raw:
        fsize = _field_size(tstr, effective_arch)
        if offset + fsize > len(raw):
            break
        raw_val = raw[offset: offset + fsize]
        fmt = _field_fmt(tstr, effective_arch)
        try:
            value_int = _struct.unpack(fmt, raw_val)[0]
        except Exception:
            value_int = 0

        field_entry: dict = {
            "name": fname,
            "offset": f"0x{offset:03X}",
            "value": f"0x{value_int:X}",
            "size": fsize,
            "description": desc,
        }

        # Best-effort symbol and string resolution for pointer fields
        if tstr == "ptr" and value_int:
            try:
                sym = client.get_symbol_at(value_int)
                if sym and sym.undecoratedSymbol:
                    field_entry["symbol"] = sym.undecoratedSymbol
            except Exception:
                pass

            # If this looks like a UNICODE_STRING Buffer, try reading the string
            if "Buffer" in fname:
                try:
                    # Get the corresponding Length field (immediately before Buffer)
                    len_fname = fname.replace("_Buffer", "_Len")
                    len_field = next(
                        (f for f in fields_raw if f[0] == len_fname), None
                    )
                    str_bytes = 0
                    if len_field:
                        loff, ltype = len_field[1], len_field[2]
                        lsize = _field_size(ltype, effective_arch)
                        if loff + lsize <= len(raw):
                            str_bytes = _struct.unpack(_field_fmt(ltype, effective_arch),
                                                       raw[loff: loff + lsize])[0]
                    if not str_bytes:
                        str_bytes = 64  # fallback: try 32 wide chars
                    wstr_raw = client.read_memory(value_int, min(str_bytes, 512))
                    decoded = wstr_raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                    if decoded:
                        field_entry["string_value"] = decoded
                except Exception:
                    pass

        fields_out.append(field_entry)

    return ok(
        sandbox_id=sandbox.sandbox_id,
        type_name=type_name,
        arch=effective_arch,
        address=f"0x{base:X}",
        total_size=total_size,
        fields=fields_out,
    )
