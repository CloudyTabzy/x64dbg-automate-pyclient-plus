"""In-memory patch lifecycle management for disposable sandbox sessions.

Tracks original and patched bytes for every write, enabling clean rollback and
a persistent audit trail. Patches target live process memory only — the on-disk
PE is NEVER modified (SecuROM CRC32 integrity constraint).

Patch record shape (stored in ``ProcessSandbox.patches``)::

    {
        "patch_id":       "a1b2c3d4",
        "address":        "0x401000",
        "original_bytes": "5589ec...",
        "patched_bytes":  "909090...",
        "description":    "NOP anti-debug timing check",
        "applied_at":     "2026-05-26T01:00:00+00:00",
    }
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from x64dbg_automate.api_runtime.registry import tool, unsafe
from x64dbg_automate.api_runtime.responses import (
    ErrorType, classify_exception, err, is_bug, lookup_error, ok,
)
from x64dbg_automate.api_runtime.runtime_helpers import resolve_addr
from x64dbg_automate.api_runtime.supervisor import SandboxError, get_manager


def _get_sandbox_and_client(sandbox_id):
    """Return (sandbox, client) or raise KeyError/SandboxError."""
    mgr = get_manager()
    sandbox = mgr.get_sandbox(sandbox_id)
    if sandbox.client is None:
        raise SandboxError(f"Sandbox '{sandbox.sandbox_id}' has no active debugger client")
    return sandbox, sandbox.client


@tool
@unsafe
def patch_apply(
    *,
    sandbox_id: str | None = None,
    address: str,
    hex_bytes: str = "",
    asm: str = "",
    description: str = "",
) -> dict:
    """Apply an in-memory patch and record it for rollback.

    Exactly one of ``hex_bytes`` or ``asm`` must be supplied.
    Original bytes are saved automatically so the patch can be reversed with
    ``patch_rollback`` or ``patch_rollback_all``.

    The on-disk PE is NEVER modified — writes target live process memory only.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        address: Patch location — address, symbol, or x64dbg expression.
        hex_bytes: Raw bytes as a hex string, e.g. ``"90 90 90"`` or ``"909090"``.
        asm: Assembly instruction to assemble and write, e.g. ``"nop"`` or ``"jmp 0x401020"``.
        description: Optional human-readable label shown in ``patch_list``.
    """
    if bool(hex_bytes) == bool(asm):
        return err(
            "Provide exactly one of hex_bytes or asm.",
            ErrorType.BAD_ARGUMENT,
            hint="Use hex_bytes for raw bytes (e.g. '90 90') or asm for assembly (e.g. 'nop').",
        )

    try:
        sandbox, client = _get_sandbox_and_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    try:
        addr = resolve_addr(client, address)
    except ValueError as exc:
        return err(str(exc), ErrorType.BAD_ARGUMENT)

    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)

        if hex_bytes:
            clean = hex_bytes.replace(" ", "").replace("\t", "")
            try:
                patch_data = bytes.fromhex(clean)
            except ValueError:
                return err(
                    f"Invalid hex string: {hex_bytes!r}",
                    ErrorType.BAD_ARGUMENT,
                    hint="Use two-hex-digit pairs, optionally space-separated (e.g. '90 90 90').",
                )
            original = client.read_memory(addr, len(patch_data))
            client.write_memory(addr, patch_data)
            patched = patch_data

        else:  # asm path
            # Read up to 15 bytes (max x86/x64 instruction length) before overwriting.
            try:
                original_buf = client.read_memory(addr, 15)
            except Exception:
                original_buf = b""
            byte_count = client.assemble_at(addr, asm)
            if not byte_count:
                return err(
                    f"Assembly failed for '{asm}' at {address}.",
                    ErrorType.RPC_ERROR,
                    hint="Check the mnemonic syntax and that the address is executable/writable.",
                )
            original = original_buf[:byte_count] if len(original_buf) >= byte_count else original_buf
            try:
                patched = client.read_memory(addr, byte_count)
            except Exception:
                patched = b""

    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    patch_id = uuid.uuid4().hex[:8]
    entry = {
        "patch_id": patch_id,
        "address": f"0x{addr:X}",
        "original_bytes": original.hex() if original else "",
        "patched_bytes": patched.hex() if patched else "",
        "description": description,
        "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    sandbox.patches.append(entry)
    return ok(sandbox_id=sandbox.sandbox_id, **entry)


@tool
def patch_list(*, sandbox_id: str | None = None) -> dict:
    """List all in-memory patches applied in a sandbox.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)
    return ok(
        sandbox_id=sandbox.sandbox_id,
        patches=list(sandbox.patches),
        total=len(sandbox.patches),
    )


@tool
@unsafe
def patch_rollback(*, sandbox_id: str | None = None, patch_id: str) -> dict:
    """Revert a single patch by restoring its original bytes.

    Args:
        sandbox_id: Target sandbox (omit for active session).
        patch_id: The ``patch_id`` returned by ``patch_apply``.
    """
    if not patch_id or not patch_id.strip():
        return err("patch_id must not be empty.", ErrorType.BAD_ARGUMENT)

    try:
        sandbox, client = _get_sandbox_and_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    entry = next((p for p in sandbox.patches if p["patch_id"] == patch_id.strip()), None)
    if entry is None:
        return err(
            f"No patch with id '{patch_id}'.",
            ErrorType.NOT_FOUND,
            hint="Use patch_list to see active patch ids.",
        )

    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        original = bytes.fromhex(entry["original_bytes"])
        addr = int(entry["address"], 16)
        client.write_memory(addr, original)
        sandbox.patches.remove(entry)
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    return ok(
        sandbox_id=sandbox.sandbox_id,
        patch_id=patch_id,
        address=entry["address"],
        original_bytes_restored=entry["original_bytes"],
        description=entry.get("description", ""),
    )


@tool
@unsafe
def patch_rollback_all(*, sandbox_id: str | None = None) -> dict:
    """Revert all patches in reverse-application order.

    Patches are undone newest-first so overlapping writes are handled correctly.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    try:
        sandbox, client = _get_sandbox_and_client(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    if not sandbox.patches:
        return ok(sandbox_id=sandbox.sandbox_id, restored=0, patches=[])

    mgr = get_manager()
    try:
        mgr.ensure_stopped(client)
        restored_ids: list[str] = []
        failed: list[dict] = []
        for entry in reversed(list(sandbox.patches)):
            try:
                original = bytes.fromhex(entry["original_bytes"])
                addr = int(entry["address"], 16)
                client.write_memory(addr, original)
                restored_ids.append(entry["patch_id"])
            except Exception as exc:
                failed.append({"patch_id": entry["patch_id"], "error": str(exc)})
        sandbox.patches = [p for p in sandbox.patches if p["patch_id"] not in set(restored_ids)]
    except Exception as exc:
        if is_bug(exc):
            raise
        return err(str(exc), classify_exception(exc), sandbox_id=sandbox_id)

    result = ok(sandbox_id=sandbox.sandbox_id, restored=len(restored_ids), restored_ids=restored_ids)
    if failed:
        result["failed"] = failed
    return result


@tool
def patch_export(*, sandbox_id: str | None = None) -> dict:
    """Export all patches as a portable JSON structure.

    The returned ``patches`` list can be stored in semantic memory or used to
    re-apply the same set of modifications in a fresh sandbox session.

    Args:
        sandbox_id: Target sandbox (omit for active session).
    """
    mgr = get_manager()
    try:
        sandbox = mgr.get_sandbox(sandbox_id)
    except (KeyError, SandboxError) as exc:
        return lookup_error(exc)

    return ok(
        sandbox_id=sandbox.sandbox_id,
        target_exe=sandbox.target_exe,
        patches=list(sandbox.patches),
        total=len(sandbox.patches),
    )
