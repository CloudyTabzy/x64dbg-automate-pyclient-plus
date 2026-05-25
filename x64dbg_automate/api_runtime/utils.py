"""Shared helpers for the runtime API: argument parsing and crypto-constant detection.

The crypto detectors recognize well-known constant tables that survive in memory at
runtime, which is exactly what lets an agent *interpret* a buffer ("this is an AES
S-box") instead of staring at raw bytes.
"""

from __future__ import annotations

import struct
from typing import Any


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_int(value: Any, *, hex_default: bool = True) -> int:
    """Parse an int from an int or string.

    ``0x``-prefixed strings are always hex. Otherwise ``hex_default`` decides the
    base — True for addresses (bare ``448300`` => 0x448300), False for sizes/counts
    (bare ``4096`` => 4096).
    """
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty integer value")
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    if s.lower().startswith("0x"):
        v = int(s, 16)
    elif hex_default:
        v = int(s, 16)
    else:
        v = int(s, 10)
    return -v if neg else v


def parse_region(spec: str) -> tuple[int, int]:
    """Parse an ``'addr:size'`` region spec into ``(addr, size)``.

    Address is hex by default (``0x448300`` or ``448300``); size is decimal by
    default (``4096``) but honors a ``0x`` prefix. Address must be numeric here —
    resolve symbols/expressions in the tool layer before calling.
    """
    text = str(spec)
    if ":" not in text:
        raise ValueError(f"Region must be 'addr:size' (e.g. '0x448300:4096'), got: {spec!r}")
    addr_s, size_s = text.split(":", 1)
    addr = parse_int(addr_s, hex_default=True)
    size = parse_int(size_s, hex_default=False)
    if size <= 0:
        raise ValueError(f"Region size must be positive: {spec!r}")
    return addr, size


# ---------------------------------------------------------------------------
# Crypto-constant detection
# ---------------------------------------------------------------------------

# 16-byte heads are statistically unique enough to identify the full table.
_AES_SBOX_HEAD = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
])
_AES_INV_SBOX_HEAD = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
])

_BYTE_SIGNATURES: list[tuple[str, str, bytes, float]] = [
    ("AES", "forward S-box", _AES_SBOX_HEAD, 0.97),
    ("AES", "inverse S-box", _AES_INV_SBOX_HEAD, 0.97),
]

# Word-based constant runs. Searched in both little- and big-endian dword packings
# because storage order varies by implementation/architecture.
_WORD_SIGNATURES: list[tuple[str, str, list[int], float]] = [
    ("SHA-256", "round constants K[0..3]",
     [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5], 0.95),
    ("SHA-256", "init hash H[0..3]",
     [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a], 0.9),
    ("SHA-512", "init hash H[0..1] (low words)",
     [0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85], 0.85),
    ("SHA-1", "init state H[0..4]",
     [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], 0.9),
    ("MD5", "T-table K[0..3] (sine constants)",
     [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee], 0.92),
    ("MD5/SHA-1", "init state A,B,C,D (ambiguous)",
     [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], 0.6),
    ("CRC32", "lookup table head (poly 0xEDB88320)",
     [0x77073096, 0xee0d7308, 0x990951ba, 0x076dc419], 0.9),
    ("CRC32C", "Castagnoli table head",
     [0xf26b8303, 0xe13b70f7, 0x1350f3f4, 0xe235446c], 0.9),
]


def _pack(words: list[int], endian: str) -> bytes:
    return struct.pack(f"{endian}{len(words)}I", *words)


def _find_all(data: bytes, needle: bytes, limit: int = 16) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        idx = data.find(needle, start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def _find_rc4_identity(data: bytes, limit: int = 8) -> list[int]:
    """Locate pristine RC4 identity permutations (bytes 0x00..0xFF in order)."""
    target = bytes(range(256))
    return _find_all(data, target, limit=limit)


def detect_crypto_constants(
    data: bytes,
    base_addr: int = 0,
    scan_mode: str = "all",
) -> list[dict]:
    """Scan ``data`` for known cryptographic constant tables.

    Args:
        data: Buffer to scan.
        base_addr: Virtual address of ``data[0]`` so findings carry an absolute address.
        scan_mode: ``'all'`` or a substring filter like ``'aes'``, ``'sha256'``, ``'rc4'``.

    Returns:
        Findings sorted by offset, each:
        ``{algorithm, detail, offset, address, confidence}``.
    """
    mode = (scan_mode or "all").strip().lower()

    def _wanted(algorithm: str) -> bool:
        if mode in ("", "all"):
            return True
        return mode.replace("-", "") in algorithm.lower().replace("-", "")

    findings: list[dict] = []

    for algorithm, detail, needle, conf in _BYTE_SIGNATURES:
        if not _wanted(algorithm):
            continue
        for off in _find_all(data, needle):
            findings.append(_finding(algorithm, detail, off, base_addr, conf))

    for algorithm, detail, words, conf in _WORD_SIGNATURES:
        if not _wanted(algorithm):
            continue
        seen: set[int] = set()
        for endian in ("<", ">"):
            needle = _pack(words, endian)
            for off in _find_all(data, needle):
                if off in seen:
                    continue
                seen.add(off)
                label = f"{detail} ({'LE' if endian == '<' else 'BE'})"
                findings.append(_finding(algorithm, label, off, base_addr, conf))

    if _wanted("RC4"):
        for off in _find_rc4_identity(data):
            findings.append(_finding("RC4", "identity S-box (pre-KSA permutation)", off, base_addr, 0.75))

    findings.sort(key=lambda f: f["offset"])
    return findings


def _finding(algorithm: str, detail: str, offset: int, base_addr: int, confidence: float) -> dict:
    return {
        "algorithm": algorithm,
        "detail": detail,
        "offset": offset,
        "address": f"0x{base_addr + offset:X}",
        "confidence": confidence,
    }
