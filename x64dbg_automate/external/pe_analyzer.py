"""Read-only PE file analysis via LIEF (primary) or pefile (fallback).

CRITICAL: Never modify the PE. PE integrity checks at runtime
detects any on-disk modification and kills the process.

API Notes
---------
LIEF 0.17+ scoped MACHINE_TYPES into lief.PE.Header (not lief.PE directly).
This module auto-detects and falls back to numeric constants (0x8664 = AMD64).
"""

import os

try:
    import lief as _lief_primary
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    import pefile as _pefile_primary
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


_EXT_TOOL = "LIEF" if HAS_LIEF else "pefile"

# -----------------------------------------------------------------------
# LIEF machine type detection — scoped correctly for 0.15+ versions
# -----------------------------------------------------------------------
_AMD64_VALUE = 0x8664
if HAS_LIEF:
    try:
        _AMD64_VALUE = _lief_primary.PE.Header.MACHINE_TYPES.AMD64
    except AttributeError:
        try:
            _AMD64_VALUE = _lief_primary.PE.MACHINE_TYPES.AMD64
        except AttributeError:
            pass  # keep 0x8664


def _resolve_pe(pe_path: str):
    if not os.path.isfile(pe_path):
        raise FileNotFoundError(pe_path)
    if HAS_LIEF:
        return _lief_primary.parse(pe_path)
    if HAS_PEFILE:
        return _pefile_primary.PE(pe_path)
    raise RuntimeError("No PE parser available — install lief or pefile")


# ── Sections ─────────────────────────────────────────────────────────
def get_sections(pe_path: str) -> list[dict]:
    pe = _resolve_pe(pe_path)
    sections: list[dict] = []
    if HAS_LIEF:
        for sec in pe.sections:
            sections.append({
                "name": sec.name,
                "virtual_address": sec.virtual_address,
                "virtual_size": sec.virtual_size,
                "size_of_raw_data": sec.sizeof_raw_data,
                "characteristics": sec.characteristics,
            })
    else:
        for sec in pe.sections:
            name = sec.Name.decode(errors="replace").strip("\x00")
            sections.append({
                "name": name,
                "virtual_address": sec.VirtualAddress,
                "virtual_size": sec.Misc_VirtualSize,
                "size_of_raw_data": sec.SizeOfRawData,
                "characteristics": sec.Characteristics,
            })
    return sections


# ── TLS Callbacks ────────────────────────────────────────────────────
def get_tls_callbacks(pe_path: str) -> list[int]:
    pe = _resolve_pe(pe_path)
    callbacks: list[int] = []

    if HAS_LIEF:
        if pe.has_tls and pe.tls:
            for cb in pe.tls.callbacks:
                if cb != 0:
                    callbacks.append(cb)
    elif HAS_PEFILE:
        try:
            tls = pe.DIRECTORY_ENTRY_TLS
            if tls and tls.struct and tls.struct.AddressOfCallBacks:
                cb_rva = tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
                try:
                    raw = pe.get_data(cb_rva, 256)
                except Exception:
                    raw = pe.get_data(tls.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase, 256)
                offset = 0
                while offset + 4 <= len(raw):
                    rva = int.from_bytes(raw[offset:offset + 4], "little")
                    if rva == 0:
                        break
                    callbacks.append(rva)
                    offset += 4
        except AttributeError:
            pass

    return callbacks


# ── Entry Point / Image Base / Bitness ───────────────────────────────
def get_entry_point(pe_path: str) -> int:
    pe = _resolve_pe(pe_path)
    if HAS_LIEF:
        return pe.optional_header.addressof_entrypoint
    return pe.OPTIONAL_HEADER.AddressOfEntryPoint


def get_image_base(pe_path: str) -> int:
    pe = _resolve_pe(pe_path)
    if HAS_LIEF:
        return pe.optional_header.imagebase
    return pe.OPTIONAL_HEADER.ImageBase


def get_bitness(pe_path: str) -> int:
    pe = _resolve_pe(pe_path)
    if HAS_LIEF:
        return 64 if pe.header.machine == _AMD64_VALUE else 32
    return 64 if pe.FILE_HEADER.Machine == 0x8664 else 32


# ── Imports ──────────────────────────────────────────────────────────
def get_imports(pe_path: str, dll_filter: str = "") -> list[dict]:
    pe = _resolve_pe(pe_path)
    imports: list[dict] = []
    dll_lower = dll_filter.lower()
    if HAS_LIEF:
        for imp in pe.imports:
            if dll_lower and dll_lower not in imp.name.lower():
                continue
            for entry in imp.entries:
                name = entry.name or (f"ord_{entry.ordinal}" if hasattr(entry, "ordinal") and entry.ordinal else f"iat_{entry.iat_value:x}")
                imports.append({
                    "dll": imp.name,
                    "function_name": name,
                    "iat_address": entry.iat_value if hasattr(entry, "iat_value") else 0,
                })
    else:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll_name = entry.dll.decode(errors="replace") if isinstance(entry.dll, bytes) else entry.dll
            if dll_lower and dll_lower not in dll_name.lower():
                continue
            for imp in entry.imports:
                func_name = imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}"
                imports.append({
                    "dll": dll_name,
                    "function_name": func_name,
                    "iat_address": imp.address,
                })
    return imports


# ── Exports ──────────────────────────────────────────────────────────
def get_exports(pe_path: str, pattern: str = "") -> list[dict]:
    pe = _resolve_pe(pe_path)
    exports: list[dict] = []
    pat_lower = pattern.lower()
    if HAS_LIEF:
        export = pe.get_export() if hasattr(pe, "get_export") else None
        if export:
            for entry in export.entries:
                name = entry.name or f"ord_{entry.ordinal}"
                if pat_lower and pat_lower not in name.lower():
                    continue
                exports.append({"name": name, "ordinal": entry.ordinal, "address": entry.address})
    else:
        for exp in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", ""), "symbols", []):
            name = exp.name.decode(errors="replace") if exp.name else f"ord_{exp.ordinal}"
            if pat_lower and pat_lower not in name.lower():
                continue
            exports.append({"name": name, "ordinal": exp.ordinal, "address": exp.address})
    return exports


# ── Security ─────────────────────────────────────────────────────────
def check_security(pe_path: str) -> dict:
    pe = _resolve_pe(pe_path)
    if HAS_LIEF:
        nx = pe.has_nx
        aslr = pe.optional_header.dll_characteristics & 0x40  # DYNAMIC_BASE
        cfg = pe.optional_header.dll_characteristics & 0x4000  # CFG
        return {
            "NX": bool(nx),
            "ASLR": bool(aslr),
            "CFG": bool(cfg),
            "integrity_check": bool(pe.optional_header.dll_characteristics & 0x8000),
            "high_entropy_va": bool(pe.optional_header.dll_characteristics & 0x20),
        }
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    return {
        "NX": bool(dll_chars & 0x100),
        "ASLR": bool(dll_chars & 0x40),
        "CFG": bool(dll_chars & 0x4000),
        "integrity_check": bool(dll_chars & 0x8000),
        "high_entropy_va": bool(dll_chars & 0x20),
    }
