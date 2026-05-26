# Axon-MCP: Production Priority List

**Date:** 2026-05-26  
**Audit Source:** Full codebase review across archived Phase 1–3 plans, Phase 4–5 deliverables, Phase 9 NextGen spec, and live code audit (162 tools verified).  
**Current Score:** 8.0 / 10 — Production-ready with minor gaps.

---

## Legend

| Priority | Meaning |
|----------|---------|
| **P0** | Blocks production deployment or breaks existing workflows |
| **P1** | Significantly impairs agent autonomy; high ROI fix |
| **P2** | Nice-to-have; improves UX or fills capability gaps |
| **P3** | Future work; requires architectural changes or new C++ commands |
| **P4** | Research / speculative; depends on lower-priority infrastructure |

| Effort | Meaning |
|--------|---------|
| Trivial | < 5 min, single file |
| Low | < 30 min, pure Python, no tests needed |
| Medium | 30–120 min, may need tests |
| High | 2–6 hours, cross-file changes or algorithmic work |
| Very High | 6+ hours or requires C++ plugin changes |

---

## P0 — Critical (Nothing currently in this bucket)

All P0 items from the Phase 9 assessment were resolved in the 2026-05-26 fix batch:
- ✅ State machine wired to unified sessions
- ✅ Sandbox execution control idempotent
- ✅ Macro recording captures steps
- ✅ `trace_execution` uses `stepi()`
- ✅ `extract_section_from_dump` uses proper minidump parsing
- ✅ `macro_list` deduplicated

---

## P1 — High ROI / Agent Autonomy Blockers

These items are pure Python, require no C++ changes, and directly improve an AI agent's ability to operate independently.

| # | Item | Category | Effort | Impact | Why It Matters |
|---|------|----------|--------|--------|----------------|
| 1.1 | **`tool_search`** — keyword search across all 166 tool names + docstrings | C15 Orchestration | Low | **Critical** | Agents cannot discover tools. A search tool collapses discovery from minutes to seconds. | ✅ Done |
| 1.2 | **`suggest_next_actions`** — rule-based suggestion engine given context | C15 Orchestration | Medium | **Critical** | Agents repeat the same discovery mistakes. "Found AES S-box → suggest `find_crypto_material`" prevents wasted tool calls. | ✅ Done |
| 1.3 | **`report_generate`** — auto-compile session findings into markdown | C13 Reporting | Medium | High | Enables agent handoffs and audit trails. A session with 20 findings is opaque without a structured report. | ✅ Done |
| 1.4 | **`resume_process`** MCP tool — pair with `suspend_process` | Legacy Gap | Trivial | Medium | `suspend_process` exists but `resume_process` did not. Now implemented. | ✅ Done |
| 1.5 | **`validate_address`** — resolve + classify expression type | C15 Orchestration | Low | **Critical** | Pre-validates addresses before memory/BP ops. Returns `valid`, `resolved`, `type`. | ✅ Done |
| 1.6 | **`set_conditional_breakpoint`** + `list_breakpoints` structured | Legacy Gap | Low | High | Dedicated conditional BP tool with `condition_applied` flag; legacy BP tools now return dicts. | ✅ Done |
| 1.7 | **`list_tools_by_group`** — heuristic grouping of all 169 tools | C15 Orchestration | Low | Medium | 13 categories (session, memory, register, breakpoint, analysis, antidebug, execution, trace, workflow, offline, semantic, macro, infrastructure). | ✅ Done |
| 1.8 | **Dependency hardening** — `pyproject.toml` cleanup | Phase 1 Debt | Trivial | Low | Removed `memprocfs` (AGPL), `construct` (unused), `yara-python` extra. Added `minidump` (MIT). Updated `LICENSE` and `README`. | ✅ Done |

### P1 Implementation Notes

**`tool_search` pseudocode:**
```python
@tool
def tool_search(query: str, category: str = "", limit: int = 10) -> dict:
    """Search available tools by keyword or natural language query."""
    # Search across _REGISTERED runtime tools + legacy mcp.tools
    # Match against name, docstring, parameter names
    # Return ranked list with description + parameter schema
```

**`suggest_next_actions` rule tree (hardcoded, no LLM):**
```python
RULES = [
    ("crypto_found", ["find_crypto_material", "find_initialized_data", "resolve_iat_slot"]),
    ("breakpoint_hit", ["get_all_registers", "read_memory", "disassemble_range", "capture_function_context"]),
    ("dump_extracted", ["analyze_entropy", "find_x86_prologues", "find_strings", "validate_extracted_binary"]),
    ...
]
```

**`report_generate` sections:**
1. Target info (PE analysis, modules, bitness)
2. Key findings (semantic memory, top 10 by confidence)
3. Crypto material detected
4. Patches applied
5. Coverage summary (if tracked)
6. Execution log summary (last N transitions)
7. Call stack / thread snapshot
8. Recommended next steps

---

## P2 — Capability Gaps

These fill missing RE capabilities that are well-defined and implementable without C++ changes.

| # | Item | Category | Effort | Impact | Note |
|---|------|----------|--------|--------|------|
| 2.1 | **`trace_until_call` / `trace_until_write` / `trace_until_register_equals`** | C6 Execution Trees | Medium | High | Composite trace abstractions hiding x64dbg expression DSL. 500-step limit, structured trace log. | ✅ Done |
| 2.2 | **`read_memory_raw`** — structured hex without ASCII sidebar | C2 Data Flow | Low | High | Returns `{"bytes": "hexstring", "size": N}` up to 64KB. No ASCII art. | ✅ Done |
| 2.3 | **`memory_export` / `memory_import`** — JSONL round-trip | C12 Collaboration | Low | Medium | Semantic memory persistence for cross-agent handoffs. | ✅ Done |
| 2.4 | **`find_x86_prologues` flexibility** — multiple signatures | C4 Static Analysis | Low | Medium | 8 built-in prologue patterns (55 8B EC, 55 89 E5, 48 89 5C 24, etc.). Accepts custom `patterns`. | ✅ Done |
| 2.5 | **`watch_memory_writes`** — persistent memory-write BP with record limit | C2 Data Flow | Medium | High | Better version of `trace_until_memory_change` (timeout → record-limit). | ⏳ Pending |
| 2.6 | **`trace_call_tree`** — record call hierarchy during `trace_execution` | C6 Execution Trees | Medium | High | Filters `trace_execution` to `call` instructions, builds nested tree with depth counter. | ⏳ Pending |
| 2.7 | **`graph_call_graph`** — structured node-edge call graph from entry point | C13 Visualization | Medium | Medium | Returns JSON graph data; agent or downstream tool renders. | ✅ Done |
| 2.7a | **`checkpoint_diff`** — structured semantic diff between two checkpoints (registers, memory, threads, modules, breakpoints, patches, PEB) | C13 Visualization | Medium | High | Same-sandbox checkpoint comparison with human-readable summary. | ✅ Done |
| 2.7b | **`sandbox_cross_diff`** — live cross-sandbox diff (registers, modules, threads, optional memory) | C13 Visualization | Medium | High | Compare two running sandboxes side-by-side. | ✅ Done |
| 2.7c | **Concurrent sandbox inspection** — `sandbox_fleet_health`, `sandbox_batch_inspect`, `sandbox_sync_execution`, `sandbox_correlate_memory` | C16 Infrastructure | Medium | High | Parallel fleet-wide ops with divergence detection and rebase hints. | ✅ Done |
| 2.8 | **`graph_memory_layout`** — structured memory map with anomaly highlights | C13 Visualization | Medium | Medium | Groups adjacent regions, flags high-entropy / RWX / non-module regions. | ✅ Done |
| 2.9 | **`workflow_template_list` / `workflow_template_apply`** | C12 Collaboration | Medium | Medium | Reusable macro templates tagged with metadata (e.g., "capture_func_entry"). | ⏳ Pending |
| 2.10 | **`tool_usage_stats`** — per-tool call counts, success rates, latency | C15 Orchestration | Low | Medium | Telemetry counter in MCP server. Helps optimize agent behavior. | ✅ Done |
| 2.11 | **`workflow_batch_cold_dump` as importable function** | Phase 5 Debt | Low | Low | Removed from MCP server — launches external subprocesses that can hang indefinitely on protected targets, blocking the entire tool suite. Remains available as standalone CLI: `python -m x64dbg_automate.workflows.protected_extract`. | ❌ Removed |

---

## P3 — Architectural / Requires C++ or Complex Runtime

These need new C++ RPC commands, complex runtime infrastructure, or significant design work.

| # | Item | Category | Effort | Impact | Blocker |
|---|------|----------|--------|--------|---------|
| 3.1 | **`hook_iat` / `hook_inline` / `hook_bridge`** | C10 Hooking | Very High | Medium | Needs `VirtualProtectEx` + trampoline generation + register save/restore shellcode. |
| 3.2 | **`inject_dll` / `inject_shellcode`** | C9 Multi-Process | High | Medium | Needs `CreateRemoteThread` + `LoadLibrary` shellcode. Can reuse `allocate_memory` + `write_memory`. |
| 3.3 | **`set_child_process_debug`** + `list_process_tree` | C9 Multi-Process | Very High | Medium | C++ plugin must handle `CREATE_PROCESS_DEBUG_EVENT` and spawn child sandboxes. |
| 3.4 | **`start_telemetry` / `stop_telemetry`** | C14 Telemetry | High | Low | Needs background sampling thread + metric aggregation. Low priority until C2/C6 trace infra exists. |
| 3.5 | **`recover_sandbox`** — reconnect to orphaned x64dbg instance | C16 Infrastructure | High | Medium | Needs session lockfile parsing + ZMQ reconnect without restarting target. |
| 3.6 | **`set_tool_timeout` / `get_tool_timeout`** | C16 Infrastructure | Medium | Medium | Client-side config in kilo.jsonc; server-side is advisory only. |
| 3.7 | **Externalize `COMPAT_VERSION`** | Phase 2 Debt | Medium | Low | Shared text file consumed at C++ build time and Python import time. |

---

## P4 — Research / Speculative

These are intentionally ambitious and depend on P2/P3 infrastructure being in place first.

| # | Item | Category | Effort | Impact | Dependency |
|---|------|----------|--------|--------|------------|
| 4.1 | **`trace_value_origin`** — backward data-flow from register/memory | C2 Data Flow | Very High | High | Requires execution trace log (C2/C6). |
| 4.2 | **`reverse_step` / `reverse_continue_until`** | C11 Time-Travel | Very High | High | Needs checkpoint recording every N instructions or Intel PT. |
| 4.3 | **`finding_link` / `finding_graph`** — semantic memory knowledge graph | C12 Collaboration | High | Medium | Extends semantic memory with edge types; graph traversal queries. |
| 4.4 | **`session_share_state`** — cross-agent state sync | C12 Collaboration | Very High | Medium | Needs serialization format + sync protocol. Start with same-machine JSON export/import. |
| 4.5 | **MM register support in `get_all_registers`** | Phase 3 Debt | Medium | Low | `models.py:279` TODO. Requires x64dbg `movdqu` command for XMM/YMM/ZMM reads. |

---

## Resolved Items (Do Not Revisit)

| Item | Status | Resolution |
|------|--------|------------|
| `_extract_via_raw_pe` stub | ✅ Superseded | `minidump` library handles proper stream parsing |
| `MemoryAnalysis` / `PESection` / `PEInfo` models | ✅ Not Needed | Functions return dicts; formal Pydantic models add no value |
| `ext/MemProcFS/` directory | ✅ Not Needed | `memprocfs` pip package + `procdump` + `comsvcs` cover all dump needs |
| C1 Decompilation | ✅ Done | `api_decompiler.py` + 9 tests |
| C3 Coverage | ✅ Done | `api_coverage.py` + C++ TRACEEXECUTE callback |
| C4 Macros | ✅ Done | `api_macros.py` + dispatch-level recorder |
| C5 Patches | ✅ Done | `api_patches.py` |
| C7 Exceptions | ✅ Done | `api_exceptions.py` |
| C8 Symbols | ✅ Done | `api_symbols.py` |
| B4 MCP 10s timeout | ⚠️ Out-of-scope | Client-side `kilo.jsonc` config |
| B6 `capture_function_context` at system BP | ⚠️ By-design | Agent must check EIP first |
| B8 PEB format inconsistency | ⚠️ By-design | Cosmetic; both formats usable |
| B13 `execute_command` silent failure | ⚠️ Out-of-scope | Needs new C++ RPC command for x64dbg log |
| B18 `get_breakpoints()` missing `bp_type` | ✅ Fixed | Added `_get_all_breakpoints()` helper; all call sites updated |
| S1 Stale workflow tool in search results | ✅ Fixed | Removed hardcoded target-specific workflow; registry now clean |
| S2 Generic BP diagnostics at system BP | ✅ Fixed | `_diagnose_bp_failure` detects ntdll loader breakpoint and gives concrete hint |
| D1 Dual response format | ⚠️ Deferred | Breaking change; `set_breakpoint` pilot done |

---

## Recommended Implementation Order

```
Week 1 (P1 batch — pure Python, no tests blockers):
  ├─ 1.5 construct in pyproject.toml           [5 min]
  ├─ 1.4 resume_process MCP tool               [10 min]
  ├─ 1.1 tool_search                           [20 min]
  ├─ 1.2 suggest_next_actions (rule tree)      [30 min]
  ├─ 1.3 report_generate                       [45 min]
  └─ 2.6 tool_usage_stats                      [15 min]

Week 2 (P2 batch — capability expansion):
  ├─ 2.1 watch_memory_writes                   [60 min]
  ├─ 2.2 trace_call_tree                       [90 min]
  ├─ 2.3 graph_call_graph                      [60 min]
  ├─ 2.4 graph_memory_layout                   [45 min]
  └─ 2.5 workflow_template_list/apply          [45 min]

Week 3+ (P3/P4 — architectural):
  ├─ 3.7 Externalize COMPAT_VERSION            [30 min]
  ├─ 3.1 Function hooking (hook_inline PoC)    [4 hours]
  └─ 3.2 DLL/shellcode injection               [3 hours]
```

---

## Metrics

| Metric | Value |
|--------|-------|
| Total unique tools | 166 (82 legacy + 84 runtime) |
| P0 resolved in 2026-05-26 batch | 6 / 6 |
| P1 items resolved | 8 / 8 |
| P2 items resolved | 11 / 15 |
| P2 items pending | 3 |
| P2 items removed | 1 |
| P3 items pending | 7 |
| P4 items pending | 5 |
| **Current score with P1+P2a done** | **8.9 / 10** |
| **Target score with all P2 done** | **9.0 / 10** |
| **Target score with P2+P3 done** | **9.2 / 10** |
