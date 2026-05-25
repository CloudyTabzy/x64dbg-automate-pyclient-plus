"""Cross-session semantic memory for runtime analysis findings.

A lightweight JSONL-backed store that persists conclusions across sandbox
lifetimes. When an AI identifies that ``sub_2ADEB7`` is the decryption entry
point, that finding is written here and can be queried by the next session
without relying on the AI's context window.

Storage layout (one JSON object per line):

    {
        "timestamp": "2026-05-26T01:46:39",
        "sandbox_id": "a1b2c3d4",
        "category": "function_identification",
        "target_exe": "BoneCrafterModKit.exe",
        "key": "sub_2ADEB7",
        "value": {
            "role": "decryption_entry",
            "confidence": 0.92,
            "evidence": ["0x2ADEB7 called before Stext XOR loop", "..."]
        },
        "tags": ["securom", "crypto"]
    }
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from x64dbg_automate.api_runtime.registry import tool
from x64dbg_automate.api_runtime.responses import ErrorType, err, ok

_DEFAULT_MEMORY_PATH = os.path.join(Path.home(), ".x64dbg_automate", "semantic_memory.jsonl")


class _SemanticMemoryStore:
    """Thread-safe JSONL append-only store with in-memory index."""

    def __init__(self, path: str = "") -> None:
        self._path = path or _DEFAULT_MEMORY_PATH
        self._lock = threading.Lock()
        self._entries: list[dict] = []
        self._index: dict[str, list[int]] = {}  # key -> list of entry indices
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        self._append_to_index(entry, len(self._entries))
                        self._entries.append(entry)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    def _append_to_index(self, entry: dict, idx: int) -> None:
        key = entry.get("key", "")
        if key:
            self._index.setdefault(key, []).append(idx)
        for tag in entry.get("tags", []):
            self._index.setdefault(f"_tag:{tag}", []).append(idx)
        cat = entry.get("category", "")
        if cat:
            self._index.setdefault(f"_cat:{cat}", []).append(idx)

    def _persist(self, entry: dict) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")))
            f.write("\n")

    def record(
        self,
        category: str,
        key: str,
        value: dict,
        target_exe: str = "",
        sandbox_id: str = "",
        tags: list[str] | None = None,
    ) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sandbox_id": sandbox_id,
            "category": category,
            "target_exe": target_exe,
            "key": key,
            "value": value,
            "tags": list(tags or []),
        }
        with self._lock:
            self._append_to_index(entry, len(self._entries))
            self._entries.append(entry)
            self._persist(entry)
        return entry

    def query(
        self,
        key: str = "",
        category: str = "",
        tag: str = "",
        target_exe: str = "",
        limit: int = 50,
    ) -> list[dict]:
        with self._lock:
            if key:
                indices = self._index.get(key, [])
                candidates = [self._entries[i] for i in indices]
            elif tag:
                indices = self._index.get(f"_tag:{tag}", [])
                candidates = [self._entries[i] for i in indices]
            elif category:
                indices = self._index.get(f"_cat:{category}", [])
                candidates = [self._entries[i] for i in indices]
            else:
                candidates = list(self._entries)

            if target_exe:
                candidates = [e for e in candidates if e.get("target_exe") == target_exe]
            return candidates[-limit:]

    def get_latest(self, key: str) -> dict | None:
        with self._lock:
            indices = self._index.get(key, [])
            if not indices:
                return None
            return self._entries[indices[-1]]

    def keys(self) -> list[str]:
        with self._lock:
            return sorted(
                k for k in self._index if not k.startswith(("_tag:", "_cat:"))
            )

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_entries": len(self._entries),
                "unique_keys": len([k for k in self._index if not k.startswith(("_tag:", "_cat:"))]),
                "store_path": self._path,
            }


# Module-level singleton
_store: _SemanticMemoryStore | None = None
_store_lock = threading.Lock()


def _get_store() -> _SemanticMemoryStore:
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = _SemanticMemoryStore()
    return _store


@tool
def memory_record_finding(
    category: str,
    key: str,
    value: dict,
    target_exe: str = "",
    sandbox_id: str = "",
    tags: list[str] | None = None,
) -> dict:
    """Persist an analysis finding to the cross-session semantic memory.

    Args:
        category: Logical category, e.g. 'function_identification', 'crypto_key', 'iat_resolution'.
        key: Unique identifier for the finding, e.g. 'sub_2ADEB7' or 'des_key_table'.
        value: Arbitrary dict with the finding's details (confidence, evidence, etc.).
        target_exe: Optional executable this finding relates to.
        sandbox_id: Optional sandbox that produced it.
        tags: Optional tags for filtering, e.g. ['securom', 'crypto'].
    """
    try:
        entry = _get_store().record(
            category=category,
            key=key,
            value=value,
            target_exe=target_exe,
            sandbox_id=sandbox_id,
            tags=tags,
        )
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), ErrorType.UNKNOWN)
    return ok(recorded=entry)


@tool
def memory_query_findings(
    key: str = "",
    category: str = "",
    tag: str = "",
    target_exe: str = "",
    limit: int = 50,
) -> dict:
    """Query previously recorded findings from the semantic memory.

    Args:
        key: Exact key to look up (most specific).
        category: Filter by category.
        tag: Filter by tag.
        target_exe: Filter by target executable.
        limit: Max results to return.
    """
    try:
        results = _get_store().query(
            key=key, category=category, tag=tag, target_exe=target_exe, limit=limit
        )
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), ErrorType.UNKNOWN)
    return ok(findings=results, total=len(results))


@tool
def memory_get_latest(key: str) -> dict:
    """Get the most recent finding for a specific key."""
    try:
        entry = _get_store().get_latest(key)
    except Exception as exc:  # noqa: BLE001
        return err(str(exc), ErrorType.UNKNOWN)
    if entry is None:
        return err(f"No finding for key '{key}'.", ErrorType.NOT_FOUND,
                   hint="Use memory_query_findings to browse available keys.")
    return ok(finding=entry)


@tool
def memory_list_keys() -> dict:
    """List all unique keys stored in semantic memory."""
    return ok(keys=_get_store().keys())


@tool
def memory_stats() -> dict:
    """Return statistics about the semantic memory store."""
    return ok(**_get_store().stats())
