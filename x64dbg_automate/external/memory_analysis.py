"""Composite memory region analysis — entropy + strings + patterns.

One-pass analysis over a buffer, used for validating extracted code sections.
"""

from .entropy import shannon_entropy, is_likely_code
from .string_finder import find_strings, find_specific_strings
from .pattern_scanner import scan_multiple


DEFAULT_TARGET_STRINGS = [
    "malloc", "free", "memcpy", "strlen",
    "kernel32", "ntdll", "msvcrt",
    "game", "server", "error",
]

KNOWN_X86_PATTERNS = {
    "x86_prologue": "55 8B EC",            # push ebp; mov ebp, esp
    "x86_prologue_at": "55 89 E5",         # push ebp; mov ebp, esp (AT&T)
    "x86_ret": "C3",                       # ret
    "x86_call": "E8 ?? ?? ?? ??",          # call rel32
    "x86_jmp": "E9 ?? ?? ?? ??",           # jmp rel32
}


def analyze_region(data: bytes, base_va: int = 0) -> dict:
    prologue1 = scan_multiple(data, {"x86_prologue": KNOWN_X86_PATTERNS["x86_prologue"]})
    prologue2 = scan_multiple(data, {"x86_prologue_at": KNOWN_X86_PATTERNS["x86_prologue_at"]})
    all_prologues = len(prologue1.get("x86_prologue", [])) + len(prologue2.get("x86_prologue_at", []))

    sig_matches = scan_multiple(data, KNOWN_X86_PATTERNS)
    sig_counts = {name: len(matches) for name, matches in sig_matches.items()}

    strings = find_strings(data, min_length=4)
    known = find_specific_strings(data, DEFAULT_TARGET_STRINGS)

    return {
        "size": len(data),
        "entropy": round(shannon_entropy(data), 4),
        "is_likely_code": is_likely_code(data),
        "string_count": len(strings),
        "known_strings": [(base_va + offset, s) for offset, s in known],
        "prologue_count": all_prologues,
        "page_count": max(1, len(data) // 4096),
        "prologue_density": round(all_prologues / max(1, len(data) / 4096), 2),
        "signature_counts": sig_counts,
    }


def validate_extracted_section(data: bytes, section_name: str = "") -> dict:
    result = analyze_region(data)
    score = 0
    checks: list[str] = []

    if result["is_likely_code"]:
        score += 40
        checks.append(f"entropy={result['entropy']} (code range)")
    elif result["entropy"] > 7.5:
        checks.append(f"entropy={result['entropy']} (encrypted — FAIL)")
    else:
        score += 10
        checks.append(f"entropy={result['entropy']} (ambiguous)")

    if result["prologue_density"] > 0.5:
        score += 30
        checks.append(f"{result['prologue_count']} prologues (dense)")
    elif result["prologue_count"] > 0:
        score += 15
        checks.append(f"{result['prologue_count']} prologues (sparse)")
    else:
        checks.append("no prologues — FAIL")

    if result["known_strings"]:
        score += 30
        unique = sorted(set(s for _, s in result["known_strings"]))
        checks.append(f"found: {', '.join(unique)}")
    else:
        checks.append("no known strings")

    verdict = "VALID" if score >= 70 else ("SUSPECT" if score >= 40 else "INVALID")
    return {
        "section": section_name,
        **result,
        "score": score,
        "verdict": verdict,
        "checks": checks,
    }
