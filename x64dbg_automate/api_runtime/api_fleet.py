"""Fleet-wide concurrent sandbox inspection tools.

Operates on multiple sandboxes in parallel using a thread pool. Every tool accepts
an optional ``sandbox_ids`` list; omitting it targets *all* active sandboxes.

These are the cross-sandbox / multi-sandbox counterparts to the per-sandbox tools
in :mod:`api_sandbox`, :mod:`api_memory`, and :mod:`api_analysis`.
"""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, classify_exception, err, lookup_error, ok
from x64dbg_automate.api_runtime.runtime_helpers import capture_registers, diff_bytes
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager

_MAX_WORKERS = 8


def _resolve_sandbox_ids(mgr, sandbox_ids: list[str] | None) -> list[str]:
    """Return the list of sandbox IDs to operate on."""
    if sandbox_ids is None:
        with mgr._lock:
            return list(mgr._sandboxes.keys())
    return sandbox_ids


def _parallel_map(
    fn,
    items: list,
    max_workers: int = _MAX_WORKERS,
    timeout: float | None = None,
) -> list[tuple[Any, Exception | None]]:
    """Run ``fn(item)`` for each item in a thread pool.

    Returns a list of ``(result, exception)`` pairs in the same order as *items*.
    Exceptions are captured, not raised.
    """
    if not items:
        return []
    results: list[tuple[Any, Exception | None]] = [(None, None)] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as ex:
        futures = {ex.submit(fn, item): i for i, item in enumerate(items)}
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            try:
                results[idx] = (future.result(timeout=timeout), None)
            except Exception as exc:  # noqa: BLE001
                results[idx] = (None, exc)
    return results


# ---------------------------------------------------------------------------
# 1. Fleet health
# ---------------------------------------------------------------------------

@tool
def sandbox_fleet_health(sandbox_ids: list[str] | None = None) -> dict:
    """Health-check multiple sandboxes in parallel.

    Refreshes the live state of each sandbox and returns a per-snapshot status
    plus an aggregate summary (healthy / crashed / detached counts).

    Args:
        sandbox_ids: List of sandbox IDs to check. Omit to check all active sandboxes.
    """
    mgr = get_manager()
    ids = _resolve_sandbox_ids(mgr, sandbox_ids)
    if not ids:
        return ok(sandboxes=[], total=0, summary="No sandboxes to inspect.")

    def _check_one(sid: str) -> dict:
        try:
            sandbox = mgr.get_sandbox(sid)
            state = mgr.refresh_state(sandbox)
            return {
                "sandbox_id": sid,
                "state": state,
                "target_exe": sandbox.target_exe,
                "debuggee_pid": sandbox.debuggee_pid,
                "arch": sandbox.debugger_arch,
                "error": sandbox.last_error,
            }
        except Exception as exc:
            return {
                "sandbox_id": sid,
                "state": "unknown",
                "error": str(exc),
            }

    t0 = time.perf_counter()
    checked = [r for r, _ in _parallel_map(_check_one, ids)]
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    healthy = sum(1 for c in checked if c["state"] in ("stopped", "running", "created"))
    crashed = sum(1 for c in checked if c["state"] == "crashed")
    detached = sum(1 for c in checked if c["state"] == "detached")

    return ok(
        sandboxes=checked,
        total=len(checked),
        healthy=healthy,
        crashed=crashed,
        detached=detached,
        elapsed_ms=elapsed_ms,
        summary=f"{healthy} healthy, {crashed} crashed, {detached} detached",
    )


# ---------------------------------------------------------------------------
# 2. Batch inspection
# ---------------------------------------------------------------------------

@tool
def sandbox_batch_inspect(
    sandbox_ids: list[str] | None = None,
    capture_stack: int = 64,
    capture_modules: bool = True,
    capture_breakpoints: bool = True,
) -> dict:
    """Run a uniform inspection across multiple sandboxes in parallel.

    Captures registers, top-of-stack bytes, module list, breakpoint count, and
    thread count from each sandbox. Returns per-sandbox results plus a divergence
    summary highlighting where the fleet differs.

    Args:
        sandbox_ids: List of sandbox IDs to inspect. Omit to inspect all.
        capture_stack: Bytes to read from the stack pointer (0 to skip).
        capture_modules: Include module list in results.
        capture_breakpoints: Include breakpoint count in results.
    """
    mgr = get_manager()
    ids = _resolve_sandbox_ids(mgr, sandbox_ids)
    if not ids:
        return ok(sandboxes=[], total=0, divergence={})

    def _inspect_one(sid: str) -> dict:
        try:
            client = mgr.get_client(sid)
            sandbox = mgr.get_sandbox(sid)
            arch = sandbox.debugger_arch
            regs = capture_registers(client, arch)
            sp_key = "rsp" if arch == "x64" else "esp"
            sp = int(regs.get(sp_key, "0x0"), 16) if isinstance(regs.get(sp_key), str) else regs.get(sp_key, 0)
            stack_hex = ""
            if capture_stack > 0 and sp:
                try:
                    stack_bytes = client.read_memory(sp, capture_stack)
                    stack_hex = stack_bytes.hex()
                except Exception:
                    pass

            modules: list[dict] = []
            if capture_modules:
                try:
                    for m in client.get_modules():
                        modules.append({
                            "base": f"0x{m.base:X}",
                            "size": m.size,
                            "name": m.name,
                        })
                except Exception:
                    pass

            bp_count = 0
            if capture_breakpoints:
                try:
                    bps = client.get_breakpoints()
                    bp_count = len(bps) if bps else 0
                except Exception:
                    pass

            threads = 0
            try:
                threads = len(client.get_threads())
            except Exception:
                pass

            return {
                "sandbox_id": sid,
                "success": True,
                "state": sandbox.state,
                "arch": arch,
                "registers": regs,
                "stack_top": stack_hex,
                "thread_count": threads,
                "module_count": len(modules),
                "modules": modules,
                "breakpoint_count": bp_count,
            }
        except Exception as exc:
            return {
                "sandbox_id": sid,
                "success": False,
                "error": str(exc),
                "error_type": classify_exception(exc),
            }

    t0 = time.perf_counter()
    results = [r for r, _ in _parallel_map(_inspect_one, ids)]
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    # --- divergence analysis ---
    successful = [r for r in results if r.get("success")]
    divergence: dict[str, Any] = {}

    if len(successful) > 1:
        # Register divergence: which regs differ across sandboxes
        all_reg_names = set()
        for r in successful:
            all_reg_names.update(r["registers"].keys())
        reg_divergence = {}
        for reg in sorted(all_reg_names):
            vals = {r["registers"].get(reg) for r in successful if reg in r["registers"]}
            if len(vals) > 1:
                reg_divergence[reg] = list(sorted(vals, key=lambda v: str(v)))
        if reg_divergence:
            divergence["registers"] = reg_divergence

        # Module divergence: which modules are present in some but not all
        module_names_sets = []
        for r in successful:
            module_names_sets.append({m["name"] for m in r["modules"]})
        all_modules = set().union(*module_names_sets)
        common_modules = all_modules.intersection(*module_names_sets) if module_names_sets else set()
        missing_modules = {}
        for r in successful:
            missing = all_modules - {m["name"] for m in r["modules"]}
            if missing:
                missing_modules[r["sandbox_id"]] = sorted(missing)
        if missing_modules:
            divergence["modules_not_common"] = missing_modules
        if common_modules:
            divergence["common_modules"] = sorted(common_modules)

        # Thread count divergence
        thread_counts = {r["thread_count"] for r in successful}
        if len(thread_counts) > 1:
            divergence["thread_counts"] = sorted(thread_counts)

    return ok(
        sandboxes=results,
        total=len(results),
        successful=len(successful),
        failed=len(results) - len(successful),
        elapsed_ms=elapsed_ms,
        divergence=divergence if divergence else None,
    )


# ---------------------------------------------------------------------------
# 3. Synchronized execution control
# ---------------------------------------------------------------------------

@tool
def sandbox_sync_execution(
    action: str,
    sandbox_ids: list[str] | None = None,
) -> dict:
    """Apply the same execution control action to multiple sandboxes in parallel.

    Actions: ``pause``, ``continue``, ``step_into``, ``step_over``.

    Args:
        action: Execution control action to apply.
        sandbox_ids: Target sandboxes. Omit to target all.
    """
    action = action.strip().lower()
    valid_actions = {"pause", "continue", "step_into", "step_over"}
    if action not in valid_actions:
        return err(
            f"Invalid action '{action}'.",
            ErrorType.BAD_ARGUMENT,
            hint=f"Valid actions: {', '.join(sorted(valid_actions))}.",
        )

    mgr = get_manager()
    ids = _resolve_sandbox_ids(mgr, sandbox_ids)
    if not ids:
        return ok(results=[], total=0, applied=0, summary="No sandboxes to control.")

    def _apply_one(sid: str) -> dict:
        try:
            client = mgr.get_client(sid)
            sandbox = mgr.get_sandbox(sid)
            if action == "pause":
                result = client.pause()
            elif action == "continue":
                result = client.go()
            elif action == "step_into":
                result = client.step_into()
            else:  # step_over
                result = client.step_over()
            state = mgr.refresh_state(sandbox)
            return {
                "sandbox_id": sid,
                "success": True,
                "action": action,
                "result": result,
                "state": state,
            }
        except Exception as exc:
            return {
                "sandbox_id": sid,
                "success": False,
                "action": action,
                "error": str(exc),
                "error_type": classify_exception(exc),
            }

    t0 = time.perf_counter()
    results = [r for r, _ in _parallel_map(_apply_one, ids)]
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    applied = sum(1 for r in results if r.get("success"))

    return ok(
        results=results,
        total=len(results),
        applied=applied,
        failed=len(results) - applied,
        action=action,
        elapsed_ms=elapsed_ms,
        summary=f"{applied}/{len(results)} sandboxes '{action}' applied",
    )


# ---------------------------------------------------------------------------
# 4. Cross-sandbox memory correlation
# ---------------------------------------------------------------------------

@tool
def sandbox_correlate_memory(
    sandbox_a_id: str,
    sandbox_b_id: str,
    address_a: str,
    address_b: str,
    size: int = 4096,
) -> dict:
    """Read the same-sized region from two sandboxes and produce a structured diff.

    This is useful when the same executable is loaded at different bases, or when
    comparing state before/after a mutation across two separate debugged sessions.

    Args:
        sandbox_a_id: First sandbox.
        sandbox_b_id: Second sandbox.
        address_a: Region start in sandbox A (hex literal or expression).
        address_b: Region start in sandbox B (hex literal or expression).
        size: Bytes to read from each (default 4 KiB, max 1 MiB).
    """
    _MAX_SIZE = 1024 * 1024
    if size <= 0:
        return err("size must be > 0.", ErrorType.BAD_ARGUMENT)
    if size > _MAX_SIZE:
        return err(f"size exceeds 1 MiB limit ({size} bytes).", ErrorType.BAD_ARGUMENT)

    mgr = get_manager()
    try:
        client_a = mgr.get_client(sandbox_a_id)
        client_b = mgr.get_client(sandbox_b_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr

    try:
        base_a = resolve_addr(client_a, address_a)
        base_b = resolve_addr(client_b, address_b)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    def _read_a() -> bytes:
        return client_a.read_memory(base_a, size)

    def _read_b() -> bytes:
        return client_b.read_memory(base_b, size)

    t0 = time.perf_counter()
    data_a = data_b = b""
    exc_a = exc_b = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_a = ex.submit(_read_a)
        f_b = ex.submit(_read_b)
        try:
            data_a = f_a.result(timeout=30)
        except Exception as exc:
            exc_a = exc
        try:
            data_b = f_b.result(timeout=30)
        except Exception as exc:
            exc_b = exc

    if exc_a:
        return err(f"Read from sandbox A failed: {exc_a}", classify_exception(exc_a), sandbox_a_id=sandbox_a_id)
    if exc_b:
        return err(f"Read from sandbox B failed: {exc_b}", classify_exception(exc_b), sandbox_b_id=sandbox_b_id)

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

    runs = diff_bytes(data_a, data_b)
    changed_bytes = sum(len(r["before"]) // 2 for r in runs)

    # Align modules for rebasing hint
    modules_a: list[dict] = []
    modules_b: list[dict] = []
    try:
        for m in client_a.get_modules():
            modules_a.append({"base": m.base, "size": m.size, "name": m.name})
    except Exception:
        pass
    try:
        for m in client_b.get_modules():
            modules_b.append({"base": m.base, "size": m.size, "name": m.name})
    except Exception:
        pass

    rebase_hint = None
    if modules_a and modules_b:
        # Find first module common to both with different base
        names_a = {m["name"]: m["base"] for m in modules_a}
        for mb in modules_b:
            if mb["name"] in names_a and names_a[mb["name"]] != mb["base"]:
                delta = mb["base"] - names_a[mb["name"]]
                rebase_hint = {
                    "module": mb["name"],
                    "base_a": f"0x{names_a[mb['name']]:X}",
                    "base_b": f"0x{mb['base']:X}",
                    "delta": f"0x{abs(delta):X}{'+' if delta >= 0 else '-'}",
                }
                break

    return ok(
        sandbox_a_id=sandbox_a_id,
        sandbox_b_id=sandbox_b_id,
        address_a=f"0x{base_a:X}",
        address_b=f"0x{base_b:X}",
        size=size,
        identical=changed_bytes == 0,
        changed_bytes=changed_bytes,
        diff_runs=runs,
        elapsed_ms=elapsed_ms,
        rebase_hint=rebase_hint,
    )
