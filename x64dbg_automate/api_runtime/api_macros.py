"""Macro record-replay system for Axon MCP (Category C4).

Macros are reusable multi-tool workflows stored in semantic memory.
They enable AI agents to define, save, and replay sequences of tool calls,
dramatically reducing repetitive multi-step operations.

Recording model (Synapse-inspired dispatch-level interception):
  - The FastMCP ``call_tool`` method is monkey-patched at server start-up.
  - Every MCP-mediated tool call is captured while a recording is active.
  - Macro execution does NOT recursively record its inner steps.

Parameter interpolation:
  - ``{key}`` in string param values is replaced from ``params_override``.
  - Direct keys in ``params_override`` are merged into every step's params.
  - ``{saved:name}`` references results from earlier steps (when save_as is used).

Example workflow:
    macro_create("capture_func", "Capture function at entry")
    macro_add_step("capture_func", "set_breakpoint",
                   {"address_or_symbol": "{addr}", "singleshot": True})
    macro_add_step("capture_func", "go", {"pass_exceptions": True})
    macro_add_step("capture_func", "get_all_registers", {}, save_as="entry_regs")
    macro_run("capture_func", {"addr": "0x1496B60"})
"""

from __future__ import annotations

import copy
import functools
import json
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from x64dbg_automate.api_runtime.registry import (
    _REGISTERED,
    _UNSAFE_NAMES,
    read_only_enabled,
    tool,
    unsafe,
)
from x64dbg_automate.api_runtime.responses import ErrorType, err, ok
from x64dbg_automate.api_runtime.semantic_memory import _get_store

# ── Constants ───────────────────────────────────────────────────────────────

_MACRO_CATEGORY = "macro"
_PARAM_REF = re.compile(r"\{(\w+)\}")
_SAVED_REF = re.compile(r"\{saved:([^}]+)\}")

# ── Global state ────────────────────────────────────────────────────────────

# Active recordings: macro_id -> {"steps": [...], "allow_unsafe": bool}
_ACTIVE_RECORDINGS: dict[str, dict] = {}
_recordings_lock = threading.Lock()

# Macro-running guard (prevents recursive recording during macro execution).
_MACRO_RUNNING_DEPTH = 0

# Stored MCP instance for unified tool dispatch.
_STORED_MCP: Any | None = None


# ── Internal helpers ────────────────────────────────────────────────────────


def set_mcp_instance(mcp: Any) -> None:
    """Store the FastMCP instance so macros can dispatch to legacy tools."""
    global _STORED_MCP
    _STORED_MCP = mcp


def get_mcp_instance() -> Any | None:
    return _STORED_MCP


def set_macro_running(running: bool) -> None:
    """Bump or drop the macro-running reference counter."""
    global _MACRO_RUNNING_DEPTH
    if running:
        _MACRO_RUNNING_DEPTH += 1
    else:
        _MACRO_RUNNING_DEPTH = max(0, _MACRO_RUNNING_DEPTH - 1)


def start_recording(macro_id: str, allow_unsafe: bool = False) -> None:
    with _recordings_lock:
        _ACTIVE_RECORDINGS[macro_id] = {
            "steps": [],
            "allow_unsafe": allow_unsafe,
        }


def stop_recording(macro_id: str) -> list[dict] | None:
    with _recordings_lock:
        rec = _ACTIVE_RECORDINGS.pop(macro_id, None)
    return rec["steps"] if rec is not None else None


def _maybe_record_call(tool_name: str, arguments: dict[str, Any]) -> None:
    """Capture a tool call into all active recordings."""
    if _MACRO_RUNNING_DEPTH > 0:
        return
    if tool_name.startswith("macro_"):
        return
    with _recordings_lock:
        for rec in _ACTIVE_RECORDINGS.values():
            if not rec.get("allow_unsafe", False) and tool_name in _UNSAFE_NAMES:
                continue
            rec["steps"].append({
                "tool": tool_name,
                "params": copy.deepcopy(arguments or {}),
            })


def install_macro_recorder(mcp: Any) -> bool:
    """Monkey-patch ``mcp.call_tool`` to intercept every tool call for recording.

    Idempotent: safe to call multiple times. Returns True if installed (or
    already installed), False on error.
    """
    try:
        original = mcp.call_tool
        if getattr(original, "_axon_macro_recorder", False):
            return True

        @functools.wraps(original)
        async def recorded_call_tool(
            name: str, arguments: dict[str, Any], **kwargs: Any
        ) -> Any:
            _maybe_record_call(name, arguments)
            return await original(name, arguments, **kwargs)

        recorded_call_tool._axon_macro_recorder = True  # type: ignore[attr-defined]
        mcp.call_tool = recorded_call_tool
        return True
    except Exception:
        return False


# ── Tool resolution ─────────────────────────────────────────────────────────


def _get_tool_fn(name: str) -> Callable[..., Any] | None:
    """Resolve a tool function by name.

    First checks the FastMCP tool manager (covers legacy + runtime tools with
    read-only stubs), then falls back to the runtime ``_REGISTERED`` list.
    """
    mcp = _STORED_MCP
    if mcp is not None:
        try:
            tm = getattr(mcp, "_tool_manager", None)
            if tm is not None:
                t = tm.get_tool(name)
                if t is not None and hasattr(t, "fn"):
                    return t.fn
        except Exception:
            pass
    for func in _REGISTERED:
        if func.__name__ == name:
            return func
    return None


def _interpolate_params(params: dict, override: dict, saved: dict | None = None) -> dict:
    """Apply template substitution to step parameters.

    1. ``{key}`` in string values → replaced from ``override``.
    2. ``{saved:name}`` in string values → replaced from ``saved``.
    """
    result = dict(params)
    saved = saved or {}

    for k, v in result.items():
        if isinstance(v, str):
            v = _PARAM_REF.sub(
                lambda m: str(override.get(m.group(1), m.group(0))), v
            )
            v = _SAVED_REF.sub(
                lambda m: str(saved.get(m.group(1), m.group(0))), v
            )
            result[k] = v

    return result


# ── Persistence helpers ─────────────────────────────────────────────────────


def _save_macro(macro_id: str, data: dict) -> None:
    _get_store().record(
        category=_MACRO_CATEGORY,
        key=macro_id,
        value=data,
        tags=["macro", "workflow"],
    )


def _load_macro(macro_id: str) -> dict | None:
    entry = _get_store().get_latest(macro_id)
    if entry is None or entry.get("category") != _MACRO_CATEGORY:
        return None
    return entry.get("value", {})


def _list_macros() -> list[dict]:
    return _get_store().query(category=_MACRO_CATEGORY)


# ── Tool definitions ────────────────────────────────────────────────────────


@tool
def macro_create(
    macro_id: str,
    description: str = "",
    steps: list[dict] | None = None,
) -> dict:
    """Create a new reusable macro.

    Args:
        macro_id: Unique identifier for the macro (e.g. ``capture_func``).
        description: Human-readable description of what this macro does.
        steps: Optional initial list of steps. Each step is a dict with
            ``tool`` (str), ``params`` (dict), and optional ``description``
            and ``save_as`` keys.

    Returns:
        Structured dict with ``macro_id``, ``description``, and ``step_count``.
    """
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)
    macro_id = macro_id.strip()
    if _load_macro(macro_id) is not None:
        return err(
            f"Macro '{macro_id}' already exists.",
            ErrorType.INVALID_STATE,
            hint="Use macro_delete first, or choose a different ID.",
        )
    data = {
        "description": description,
        "steps": list(steps or []),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_macro(macro_id, data)
    return ok(macro_id=macro_id, description=description, step_count=len(data["steps"]))


@tool
def macro_delete(macro_id: str) -> dict:
    """Delete a macro from the semantic memory store."""
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)
    entry = _load_macro(macro_id)
    if entry is None:
        return err(f"Macro '{macro_id}' not found.", ErrorType.NOT_FOUND)
    removed = _get_store().delete_by_key(macro_id)
    return ok(macro_id=macro_id, removed=removed)


@tool
def macro_get(macro_id: str) -> dict:
    """Retrieve a macro by ID including all steps and metadata."""
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)
    macro = _load_macro(macro_id)
    if macro is None:
        return err(f"Macro '{macro_id}' not found.", ErrorType.NOT_FOUND)
    return ok(macro_id=macro_id, **macro)


@tool
def macro_list() -> dict:
    """List all saved macros with summary metadata."""
    macros = _list_macros()
    return ok(
        macros=[
            {
                "macro_id": m.get("key", ""),
                "description": m.get("value", {}).get("description", ""),
                "step_count": len(m.get("value", {}).get("steps", [])),
                "created_at": m.get("value", {}).get("created_at", ""),
            }
            for m in macros
        ],
        total=len(macros),
    )


@tool
def macro_add_step(
    macro_id: str,
    tool_name: str,
    params: dict,
    description: str = "",
    save_as: str = "",
) -> dict:
    """Append a step to an existing macro.

    Args:
        macro_id: The macro to modify.
        tool_name: Name of the tool to call (e.g. ``set_breakpoint``).
        params: Dict of parameters. Use ``{key}`` for runtime interpolation.
        description: Optional note about what this step does.
        save_as: Optional name to save the step's result under during execution.
    """
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)
    macro = _load_macro(macro_id)
    if macro is None:
        return err(f"Macro '{macro_id}' not found.", ErrorType.NOT_FOUND)

    step: dict[str, Any] = {
        "tool": tool_name,
        "params": copy.deepcopy(params),
        "description": description,
    }
    if save_as:
        step["save_as"] = save_as

    macro["steps"].append(step)
    _save_macro(macro_id, macro)
    return ok(macro_id=macro_id, step_count=len(macro["steps"]))


@tool
def macro_remove_step(macro_id: str, step_index: int) -> dict:
    """Remove a step from a macro by its zero-based index."""
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)
    macro = _load_macro(macro_id)
    if macro is None:
        return err(f"Macro '{macro_id}' not found.", ErrorType.NOT_FOUND)
    steps = macro.get("steps", [])
    if step_index < 0 or step_index >= len(steps):
        return err(
            f"Invalid step_index {step_index} (macro has {len(steps)} steps).",
            ErrorType.BAD_ARGUMENT,
        )
    steps.pop(step_index)
    _save_macro(macro_id, macro)
    return ok(macro_id=macro_id, step_count=len(steps))


@tool
def macro_run(
    macro_id: str,
    params_override: dict | None = None,
    stop_on_error: bool = True,
) -> dict:
    """Execute a macro, running each step sequentially.

    Args:
        macro_id: The macro to execute.
        params_override: Values for ``{key}`` templates and direct param keys.
            Example: ``{"addr": "0x401000", "sandbox_id": "abc123"}``.
        stop_on_error: If ``True`` (default), abort on the first failed step.

    Returns:
        Dict with ``results`` array, ``saved`` dict, ``total_steps``,
        ``executed_steps``, and ``all_success``.
    """
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)

    macro = _load_macro(macro_id)
    if macro is None:
        return err(
            f"Macro '{macro_id}' not found.",
            ErrorType.NOT_FOUND,
            hint="Use macro_list to see available macros.",
        )

    steps = macro.get("steps", [])
    if not steps:
        return err(
            f"Macro '{macro_id}' has no steps.",
            ErrorType.INVALID_STATE,
            hint="Use macro_add_step to add steps before running.",
        )

    override = dict(params_override or {})
    results: list[dict] = []
    saved: dict[str, Any] = {}

    set_macro_running(True)
    try:
        for i, step in enumerate(steps):
            tool_name = step.get("tool", "")
            raw_params = step.get("params", {})
            params = _interpolate_params(raw_params, override, saved)

            # Read-only safety: block @unsafe tools when server is in read-only mode.
            if read_only_enabled() and tool_name in _UNSAFE_NAMES:
                results.append({
                    "step": i,
                    "tool": tool_name,
                    "success": False,
                    "error": (
                        f"Tool '{tool_name}' is @unsafe and the server is in "
                        "read-only mode (X64DBG_MCP_READ_ONLY)."
                    ),
                })
                if stop_on_error:
                    break
                continue

            func = _get_tool_fn(tool_name)
            if func is None:
                results.append({
                    "step": i,
                    "tool": tool_name,
                    "success": False,
                    "error": f"Tool '{tool_name}' not found in runtime or legacy registry.",
                })
                if stop_on_error:
                    break
                continue

            try:
                result = func(**params)
            except Exception as exc:
                results.append({
                    "step": i,
                    "tool": tool_name,
                    "success": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                if stop_on_error:
                    break
                continue

            save_as = step.get("save_as")
            if save_as:
                saved[save_as] = result

            success = bool(result.get("success", True)) if isinstance(result, dict) else True
            results.append({
                "step": i,
                "tool": tool_name,
                "success": success,
                "result": result,
                "save_as": save_as or "",
            })
            if not success and stop_on_error:
                break
    finally:
        set_macro_running(False)

    all_success = all(r["success"] for r in results)
    return ok(
        results=results,
        saved=saved,
        total_steps=len(steps),
        executed_steps=len(results),
        all_success=all_success,
        macro_id=macro_id,
    )


@tool
def macro_export(macro_id: str) -> dict:
    """Export a macro as a portable JSON string."""
    macro = _load_macro(macro_id)
    if macro is None:
        return err(f"Macro '{macro_id}' not found.", ErrorType.NOT_FOUND)

    export_data = {
        "macro_id": macro_id,
        **macro,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "format_version": "1.0",
    }
    return ok(export=json.dumps(export_data, indent=2), macro_id=macro_id)


@tool
def macro_import(macro_json: str) -> dict:
    """Import a macro from a JSON string.

    The JSON must contain at least a ``macro_id`` field and a ``steps`` list.
    Each step must have a ``tool`` string and optionally ``params``, ``description``,
    and ``save_as``.
    """
    try:
        data = json.loads(macro_json)
    except json.JSONDecodeError as exc:
        return err(f"Invalid JSON: {exc}", ErrorType.BAD_ARGUMENT)

    macro_id = data.get("macro_id", "")
    if not macro_id:
        return err(
            "macro_json missing 'macro_id' field.", ErrorType.BAD_ARGUMENT
        )

    if _load_macro(macro_id) is not None:
        return err(
            f"Macro '{macro_id}' already exists.",
            ErrorType.INVALID_STATE,
            hint="Delete the existing macro first, or choose a different ID.",
        )

    steps = data.get("steps", [])
    if not isinstance(steps, list):
        return err("'steps' must be a list.", ErrorType.BAD_ARGUMENT)

    for i, step in enumerate(steps):
        if not isinstance(step, dict) or "tool" not in step:
            return err(
                f"Step {i} missing required 'tool' field.", ErrorType.BAD_ARGUMENT
            )

    _save_macro(macro_id, {
        "description": data.get("description", ""),
        "steps": steps,
        "created_at": data.get("created_at", datetime.now(timezone.utc).isoformat()),
    })
    return ok(macro_id=macro_id, step_count=len(steps))


@tool
def macro_record_start(
    macro_id: str,
    description: str = "",
    allow_unsafe: bool = False,
) -> dict:
    """Start recording all subsequent tool calls into a macro.

    While recording is active, every MCP-mediated call to a runtime or legacy
    tool is captured as a step. Recording stops when ``macro_record_stop`` is
    called. The captured steps are saved to semantic memory.

    Args:
        macro_id: Identifier for the new macro.
        description: What this macro will do.
        allow_unsafe: If ``True``, @unsafe tools (write_memory, patch_apply,
            etc.) are also recorded. Default ``False`` for safety.

    Returns:
        Dict confirming recording has started.
    """
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)

    with _recordings_lock:
        if macro_id in _ACTIVE_RECORDINGS:
            return err(
                f"Already recording macro '{macro_id}'.",
                ErrorType.INVALID_STATE,
                hint="Call macro_record_stop first.",
            )

    start_recording(macro_id, allow_unsafe=allow_unsafe)
    return ok(
        macro_id=macro_id,
        status="recording",
        allow_unsafe=allow_unsafe,
        hint="Call tools normally. Each call will be captured as a macro step.",
    )


@tool
def macro_record_stop(macro_id: str, save: bool = True) -> dict:
    """Stop recording and optionally persist the captured steps.

    Args:
        macro_id: The macro being recorded.
        save: If ``True`` (default), persist captured steps to semantic memory.
            If ``False``, discard them.

    Returns:
        Dict with captured ``steps``, ``step_count``, and ``saved`` flag.
    """
    if not macro_id or not macro_id.strip():
        return err("macro_id must not be empty.", ErrorType.BAD_ARGUMENT)

    steps = stop_recording(macro_id)
    if steps is None:
        return err(
            f"No active recording for '{macro_id}'.",
            ErrorType.NOT_FOUND,
            hint="Call macro_record_start first.",
        )

    if not save:
        return ok(
            macro_id=macro_id,
            saved=False,
            step_count=len(steps),
            hint="Recording discarded.",
        )

    # Remove existing macro with same ID before saving
    existing = _load_macro(macro_id)
    if existing is not None:
        _get_store().delete_by_key(macro_id)

    _save_macro(macro_id, {
        "description": f"Recorded macro {macro_id}",
        "steps": steps,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return ok(macro_id=macro_id, saved=True, step_count=len(steps))
