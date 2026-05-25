"""Byte pattern scanner with IDA/x64dbg-style ?? wildcards.

Pure Python — no yara-python dependency required.
"""


def scan_pattern(data: bytes, pattern: str) -> list[int]:
    hex_str = pattern.replace(" ", "").upper()
    if len(hex_str) % 2 != 0:
        raise ValueError("Pattern must have even number of hex chars")

    pattern_bytes: list[int] = []
    pattern_mask: list[int] = []
    i = 0
    while i < len(hex_str):
        if hex_str[i : i + 2] == "??":
            pattern_bytes.append(0)
            pattern_mask.append(0)  # 0 = wildcard
        else:
            pattern_bytes.append(int(hex_str[i : i + 2], 16))
            pattern_mask.append(1)  # 1 = must match
        i += 2

    plen = len(pattern_bytes)
    matches: list[int] = []
    for offset in range(len(data) - plen + 1):
        match = True
        for j in range(plen):
            if pattern_mask[j] and data[offset + j] != pattern_bytes[j]:
                match = False
                break
        if match:
            matches.append(offset)
    return matches


def scan_multiple(data: bytes, patterns: dict[str, str]) -> dict[str, list[int]]:
    return {name: scan_pattern(data, pat) for name, pat in patterns.items()}
