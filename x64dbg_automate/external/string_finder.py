"""String extraction from binary data — ASCII + UTF-16LE."""

import re


def find_strings(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    pattern = rb"[\x20-\x7E]{%d,}" % min_length
    return [(m.start(), m.group().decode("ascii")) for m in re.finditer(pattern, data)]


def find_strings_utf16le(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    i = 0
    while i < len(data) - 1:
        run: list[str] = []
        start = i
        while i < len(data) - 1:
            char = data[i] | (data[i + 1] << 8)
            if 0x20 <= char <= 0x7E:
                run.append(chr(char))
                i += 2
            else:
                break
        if len(run) >= min_length:
            results.append((start, "".join(run)))
        i += 2
    return results


def find_specific_strings(data: bytes, targets: list[str]) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []
    for target in targets:
        encoded_ascii = target.encode("ascii")
        offset = 0
        while True:
            idx = data.find(encoded_ascii, offset)
            if idx == -1:
                break
            results.append((idx, target))
            offset = idx + 1
        encoded_utf16 = target.encode("utf-16-le")
        offset = 0
        while True:
            idx = data.find(encoded_utf16, offset)
            if idx == -1:
                break
            results.append((idx, target))
            offset = idx + 1
    return results
