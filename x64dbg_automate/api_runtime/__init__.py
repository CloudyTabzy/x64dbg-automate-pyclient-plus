"""AI-native runtime analysis API for x64dbg-automate (Phase 7).

A Synapse-style structured tool layer over the existing high-level client. It adds:

* **Sandboxes** — disposable debugged sessions with best-effort userland checkpoints.
* **Anti-debug transparency** — one call applies ScyllaHide + PEB hiding + TLS surfacing.
* **Composite capture** — function context, memory-change tracing, crypto discovery.
* **Semantic memory** — typed struct reads, entropy discovery, IAT resolution, diffs.
* **Workflows** — one-call SecuROM runtime extraction.

Every tool returns a JSON-serializable structured dict (see :mod:`responses`), is
read-only unless flagged ``@unsafe``, and operates on a ``sandbox_id``.
"""

from __future__ import annotations

from x64dbg_automate.api_runtime.registry import is_unsafe, register_all, registered_tools
from x64dbg_automate.api_runtime.supervisor import SandboxManager, get_manager

__all__ = [
    "register_runtime_tools",
    "register_all",
    "registered_tools",
    "is_unsafe",
    "get_manager",
    "SandboxManager",
]


def register_runtime_tools(mcp) -> int:
    """Import every runtime API module (populating the registry) and bind tools onto ``mcp``.

    Returns the number of tools registered.
    """
    # Importing these modules runs their @tool decorators.
    from x64dbg_automate.api_runtime import (  # noqa: F401
        api_analysis,
        api_antidebug,
        api_composite,
        api_memory,
        api_sandbox,
        api_workflow,
        semantic_memory,
    )

    return register_all(mcp)
