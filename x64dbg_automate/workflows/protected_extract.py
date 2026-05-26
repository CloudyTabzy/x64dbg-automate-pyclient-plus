"""Protected binary extraction workflow.

Generic approach: launch original exe, wait for initialization signal,
dump process via non-debugger method, extract and validate sections.
"""

import os
import time
import subprocess
from dataclasses import dataclass, field

from x64dbg_automate.external.entropy import shannon_entropy, is_likely_code
from x64dbg_automate.external.string_finder import find_specific_strings
from x64dbg_automate.external.pattern_scanner import scan_pattern
from x64dbg_automate.external.process_dumper import (
    dump_via_comsvcs,
    dump_via_procdump_clone,
    dump_via_minidumpwritedump,
    wait_for_window,
)


TARGET_SECTIONS = {
    ".text": (0x1000, 0x10000),
    ".data": (0x11000, 0x5000),
    ".rsrc": (0x16000, 0x2000),
}

# Generic strings useful for validating extracted code/data.
# Override via the ``strings`` parameter in ``workflow_extract_binary``.
DEFAULT_KNOWN_STRINGS = [
    "malloc", "free", "memcpy", "strlen",
    "kernel32", "ntdll", "msvcrt",
]


@dataclass
class ExtractionResult:
    success: bool
    pid: int
    dump_path: str
    dump_method: str
    sections_extracted: dict[str, str]
    analysis: dict[str, dict]
    errors: list[str] = field(default_factory=list)
    elapsed_sec: float = 0.0


def workflow_extract_binary(
    target_exe: str,
    timeout_sec: int = 120,
    dump_method: str = "procdump",
    output_dir: str = "",
    sections: list[str] | None = None,
    validate: bool = True,
    terminate_after: bool = True,
    window_title: str = "Ready",
) -> ExtractionResult:
    start_time = time.time()
    result = ExtractionResult(
        success=False, pid=0, dump_path="", dump_method=dump_method,
        sections_extracted={}, analysis={}, errors=[],
    )

    if sections is None:
        sections = list(TARGET_SECTIONS.keys())

    if not os.path.isfile(target_exe):
        result.errors.append(f"Target not found: {target_exe}")
        return result

    if not output_dir:
        output_dir = os.path.join(os.getcwd(), "extracted")
    os.makedirs(output_dir, exist_ok=True)

    # Step 1: Launch original unpatched executable
    try:
        proc = subprocess.Popen(
            [target_exe],
            cwd=os.path.dirname(target_exe) or None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        result.pid = proc.pid
    except Exception as e:
        result.errors.append(f"Launch failed: {e}")
        return result

    # Step 2: Wait for initialization signal (window title substring)
    if not wait_for_window(result.pid, window_title, timeout_sec):
        result.errors.append(f"Initialization window not found within {timeout_sec}s")
        if terminate_after:
            proc.terminate()
        return result

    # Step 3: Dump process
    dump_path = os.path.join(output_dir, f"dump_{result.pid}.dmp")
    if dump_method == "procdump":
        success = dump_via_procdump_clone(result.pid, dump_path)
    elif dump_method == "comsvcs":
        success = dump_via_comsvcs(result.pid, dump_path)
    elif dump_method == "minidump":
        success = dump_via_minidumpwritedump(result.pid, dump_path)
    else:
        result.errors.append(f"Unknown dump method: {dump_method}")
        proc.terminate()
        return result

    if not success:
        result.errors.append("Memory dump failed")
        proc.terminate()
        return result

    result.dump_path = dump_path

    # Step 4: Extract sections
    for section_name in sections:
        va, size = TARGET_SECTIONS[section_name]
        output = os.path.join(output_dir, f"{section_name.lower()}_{result.pid}.bin")
        try:
            extracted = _extract_region_from_dump(dump_path, va, size)
            if extracted:
                with open(output, "wb") as f:
                    f.write(extracted)
                result.sections_extracted[section_name] = output
            else:
                result.errors.append(f"Could not extract {section_name}")
        except Exception as e:
            result.errors.append(f"Extract {section_name}: {e}")

    if not result.sections_extracted:
        proc.terminate()
        return result

    # Step 5: Validate
    if validate:
        for section_name, section_path in result.sections_extracted.items():
            with open(section_path, "rb") as f:
                data = f.read()
            result.analysis[section_name] = _validate_section(section_name, data)

    # Step 6: Cleanup
    if terminate_after:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    result.success = len(result.sections_extracted) > 0
    result.elapsed_sec = time.time() - start_time
    return result


def _extract_region_from_dump(dump_path: str, va: int, size: int) -> bytes | None:
    try:
        import memprocfs
        vmm = memprocfs.Vmm(["-device", dump_path])
        for proc in vmm.process_list():
            try:
                data = proc.memory.read(va, size)
                if data and len(data) == size:
                    return bytes(data)
            except Exception:
                continue
    except Exception:
        pass

    try:
        import pefile
        with open(dump_path, "rb") as f:
            raw = f.read()
        offset = 0
        while offset < len(raw) - 2:
            if raw[offset:offset + 2] == b"MZ":
                try:
                    pe = pefile.PE(data=raw[offset:])
                    image_base = pe.OPTIONAL_HEADER.ImageBase
                    for section in pe.sections:
                        sec_va = image_base + section.VirtualAddress
                        sec_end = sec_va + section.Misc_VirtualSize
                        if sec_va <= va < sec_end:
                            section_offset = va - sec_va
                            section_data = section.get_data()
                            return section_data[section_offset:section_offset + size]
                except Exception:
                    pass
            offset += 1
    except ImportError:
        pass

    return None


def _validate_section(name: str, data: bytes, known_strings: list[str] | None = None) -> dict:
    entropy = shannon_entropy(data)
    prologues = scan_pattern(data, "55 8B EC") + scan_pattern(data, "55 89 E5")
    found = find_specific_strings(data, known_strings or DEFAULT_KNOWN_STRINGS)
    pages = max(1, len(data) / 4096)
    density = len(prologues) / pages

    score = 0
    checks = []

    if is_likely_code(data):
        score += 40
        checks.append(f"entropy OK ({entropy:.2f})")
    elif entropy > 7.5:
        checks.append(f"entropy too high ({entropy:.2f})")
    else:
        score += 10
        checks.append(f"entropy ambiguous ({entropy:.2f})")

    if density > 0.5:
        score += 30
        checks.append(f"{len(prologues)} prologues ({density:.1f}/page)")
    elif len(prologues) > 0:
        score += 15
        checks.append(f"{len(prologues)} prologues (sparse)")
    else:
        checks.append("no prologues")

    if found:
        score += 30
        unique = sorted(set(s for _, s in found))
        checks.append(f"strings: {', '.join(unique)}")
    else:
        checks.append("no known strings")

    return {
        "section": name, "size": len(data),
        "entropy": round(entropy, 4), "prologue_count": len(prologues),
        "known_strings": [s for _, s in found], "score": score,
        "verdict": "VALID" if score >= 70 else ("SUSPECT" if score >= 40 else "INVALID"),
        "checks": checks,
    }


def _print_result(result: ExtractionResult):
    print(f"\n{'=' * 60}")
    print(f"Extraction {'SUCCESS' if result.success else 'FAILED'}")
    print(f"PID: {result.pid}  Method: {result.dump_method}")
    print(f"Dump: {result.dump_path}")
    print(f"Elapsed: {result.elapsed_sec:.1f}s")

    for section, path in result.sections_extracted.items():
        size = os.path.getsize(path) if os.path.exists(path) else 0
        analysis = result.analysis.get(section, {})
        print(f"\n  {section}: {path} ({size:,} bytes)")
        if analysis:
            print(f"    Score: {analysis['score']}/100 — {analysis['verdict']}")
            for check in analysis.get("checks", []):
                print(f"      {check}")

    if result.errors:
        print(f"\nErrors:")
        for err in result.errors:
            print(f"  ✗ {err}")


def main():
    """CLI entry point: automate-extract <target_exe> [options]"""
    import argparse
    parser = argparse.ArgumentParser(
        description="Generic binary section extractor from process dumps"
    )
    parser.add_argument("target_exe", help="Path to target executable")
    parser.add_argument("--method", default="procdump", choices=["procdump", "comsvcs", "minidump"])
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output", default="")
    parser.add_argument("--batch", type=int, default=1, help="Run N iterations")
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--no-terminate", action="store_true")
    args = parser.parse_args()

    if args.batch > 1:
        results = []
        for i in range(args.batch):
            print(f"\n=== Iteration {i + 1}/{args.batch} ===")
            iteration_dir = os.path.join(args.output or "./extracted", f"run_{i + 1:02d}")
            r = workflow_extract_binary(
                target_exe=args.target_exe,
                dump_method=args.method,
                output_dir=iteration_dir,
                sections=list(TARGET_SECTIONS.keys()),
                validate=not args.no_validate,
                terminate_after=not args.no_terminate,
            )
            results.append(r)
            _print_result(r)
        print(f"\n{'=' * 60}")
        print(f"Batch complete — {len(results)} runs")
    else:
        result = workflow_extract_binary(
            target_exe=args.target_exe,
            timeout_sec=args.timeout,
            dump_method=args.method,
            output_dir=args.output,
            validate=not args.no_validate,
            terminate_after=not args.no_terminate,
        )
        _print_result(result)


if __name__ == "__main__":
    main()
