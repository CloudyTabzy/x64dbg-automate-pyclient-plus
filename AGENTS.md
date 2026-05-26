# Project: Axon MCP (x64dbg-automate-plus)

## What This Is

A fork-and-extension of [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate) to create a comprehensive MCP (Model Context Protocol) orchestrator for defeating SecuROM v7-v8 DRM on **BoneCrafterModKit.exe** — a developer-consented legacy software preservation project.

**New mission (2026-05-26):** Transform x64dbg from a manual debugger into an **AI-native runtime analysis platform** — making runtime reverse engineering as safe and deterministic as static analysis with IDA Pro. See `Plans/NextGen_x64dbg_MCP_AI_Native_Architecture.md` for the full architectural specification.

## Architecture

Two repos work together:
- **`x64dbg-automate-plus/`** — C++ x64dbg plugin (ZMQ RPC server, ~43 commands) ✅ **COMPLETE**
- **`x64dbg-automate-pyclient-plus/`** — Python client + FastMCP server (82 legacy + 84 runtime = 166 tools)

## Primary Strategy (Dual-Path)

### Path A: Cold Dump (Phase 5 — VALIDATED)
1. Launch original **unpatched** BoneCrafterModKit.exe (subprocess, **no debugger**)
2. Wait for "Serial" window dialog (Stext decrypted in RAM by this point)
3. Dump process via ProcDump `-r` (clone mode) or comsvcs.dll MiniDump
4. Extract Stext section (VA `0x00A7A000`, ~10MB) from dump
5. Validate via entropy (4.5–6.5 = code), function prologues, known strings

### Path B: AI-Native Runtime Analysis (Phase 7 — NEW PRIORITY)
1. Launch target normally → wait for Serial dialog
2. **`sandbox_create(pid)`** → disposable debugged session
3. **`attach_safe(sandbox_id)`** → automatic anti-debug evasion (ScyllaHide + PEB + TLS)
4. **`trace_execution(sandbox_id, max_steps=50)`** → step-by-step instruction history
5. **`trace_until_memory_change("0x448300", 4096)`** → capture identity array
6. **`get_call_stack(sandbox_id)`** → see where you are in the call graph
7. **`resolve_iat_slot("0x43D070")`** → identify crypto function
8. **`find_crypto_material(sandbox_id)`** → discover keys/tables
9. **`capture_function_context("sub_2ADEB7", sandbox_id)`** → full pipeline analysis
10. **`memory_record_finding(...)`** → persist conclusion across sessions
11. **`sandbox_destroy(sandbox_id)`** → original process untouched

**Why both paths:** Cold dump gives us decrypted code. Runtime analysis gives us initialized data. Together they give us the complete algorithm.

## Critical Constraint — READ BEFORE ADDING CODE

- **NEVER modify the PE on disk.** SecuROM CRC32 integrity check kills any patched executable.
- **LIEF/pefile are read-only tools** in this project.
- **The ORIGINAL process is sacred.** Use `sandbox_create()` to clone before any debugger attachment.
- **Sandbox clones are disposable.** Crash them, patch them, trace them — the original lives on.

## C++ Plugin Build & Deploy Rule (x64 + x32)

**ALWAYS build AND deploy BOTH architectures after ANY C++ source change.** The compat version string lives in the compiled binary — if one arch is stale, agents debugging x86 targets will hit a version mismatch.

### Build method — use `build.ps1` (preferred) or `build.bat` via Bash

**Preferred — PowerShell tool (`build.ps1`):**
```powershell
# Full rebuild + deploy both architectures:
powershell.exe -ExecutionPolicy Bypass -File "C:\Dev\x64dbg_MCP_Automate_Plus\x64dbg-automate-plus\build.ps1" -Arch x64 -Deploy
powershell.exe -ExecutionPolicy Bypass -File "C:\Dev\x64dbg_MCP_Automate_Plus\x64dbg-automate-plus\build.ps1" -Arch x86 -Deploy

# Skip cmake reconfigure (faster, when CMakeCache already exists):
powershell.exe -ExecutionPolicy Bypass -File "...\build.ps1" -Arch x64 -NoConfigure -Deploy
```

The script auto-detects vcvarsall.bat, imports the MSVC environment into PowerShell, finds cmake, configures + builds, and copies to x64dbg plugins. Works out of the box from the PowerShell tool.

**Alternative — Bash tool with `//c` (double-slash workaround):**

Direct `cmd /c` from Git Bash interprets `/c` as a path; double-slash `//c` prevents this:
```bash
cmd //c "C:\Dev\x64dbg_MCP_Automate_Plus\x64dbg-automate-plus\build.bat x64 Release copy"
cmd //c "C:\Dev\x64dbg_MCP_Automate_Plus\x64dbg-automate-plus\build.bat x86 Release copy"
```

Known `build.bat` quirks to avoid:
- `PowerShell cmd /c "build.bat"` → "not recognized" (needs `.\` prefix)
- `PowerShell .\build.bat` via `Start-Process` → goes to background, empty output
- Bash tool `cmd /c "..."` → opens interactive session, never returns

**Verify:** Both binaries must contain `Axon_MCP` and zero occurrences of `kilo_alpha`.
```powershell
foreach ($p in @(
    "C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x64\plugins\x64dbg-automate.dp64",
    "C:\Dev\RE_Tools\snapshot_2025-08-19_19-40\release\x32\plugins\x64dbg-automate.dp32"
)) {
    $bytes = [System.IO.File]::ReadAllBytes($p)
    $str = [System.Text.Encoding]::ASCII.GetString($bytes)
    $hasAxon = $str -match "Axon_MCP"
    $hasKilo = $str -match "kilo_alpha"
    $hasCov  = $str -match "XAUTO_REQ_COVERAGE"
    "$(Split-Path $p -Leaf): Axon=$hasAxon Kilo=$hasKilo Coverage=$hasCov"
}
```

## Implementation Phases

| Phase | File | What | Status |
|-------|------|------|--------|
| 1 | `Implementation/Phase_1_Environment_Setup.md` | Dependencies, external tools | ✅ |
| 2 | `Implementation/Phase_2_Cpp_Plugin_Commands.md` | 5 new C++ RPC commands | ✅ |
| 3 | `Implementation/Phase_3_Python_Core_Wrappers.md` | `external/` package (entropy, strings, pattern, dumper) | ✅ |
| 4 | `Implementation/Phase_4_MCP_Server_Tools.md` | 27 new MCP tools (78 total) | ✅ |
| 5 | `Implementation/Phase_5_Master_Workflow.md` | `workflow_extract_securom()` orchestrator | ✅ |
| 6 | `Implementation/Phase_6_x64dbg_Integration.md` | x64dbg fallback tools (ScyllaHide, PEB, TLS) | ✅ |
| 7 | `Plans/NextGen_x64dbg_MCP_AI_Native_Architecture.md` | AI-native runtime analysis: 42 tools, call stack, CFG, xrefs, threads, modules, trace, semantic memory, adaptive anti-debug | ✅ |
| **8** | **`Implementation/Phase_8_Axon_MCP_Comprehensive_Assessment.md`** | **Bug fixes (B1–B3, B5, B9), 3 new tools (`read_memory_range`, `memory_delete_key`, `get_pe_exports`), conditional BP support, `is_bug()` guard, `ensure_stopped` public, `disasm_instructions` shared helper, 15 new tests (200 total)** | **✅** |
| **9a** | **`Implementation/Phase_9_NextGen_AI_Native_RE_Tools.md`** | **P0/P1 items: patch management (C5), symbol/type info (C8), health/version infra (C16), session summary (C15 partial) — 16 new tests (216 total)** | **✅ (P0/P1)** |
| **9b** | **`Implementation/Phase_9_NextGen_AI_Native_RE_Tools.md`** | **C3 coverage tracking (C++ TRACEEXECUTE callback + 4 RPC commands + api_coverage.py), C7 exception control (api_exceptions.py pure Python) — 12 new tests (228 total)** | **✅ (C3/C7)** |
| **9c** | **`docs_custom/AXON_EXECUTION_ARCHITECTURE.md`** | **Hardened execution architecture: DebuggerStateMachine, ExecutionContextManager, `@guarded` tool gateway, non-blocking ZMQ PUB, `running_guard` v2, 4 infrastructure tools (`get_debugger_state`, `wait_for_stable_state`, `force_resume`, `get_execution_log`), ScyllaHide PEB bypass, 23 new tests (312 total)** | **✅ (Hardening)** |
| **9d** | **`api_runtime/api_analysis.py`** | **Call graph construction (`graph_call_graph`): Capstone-based BFS traversal with direct/indirect/import/tail call resolution, cycle detection, unresolved call metadata. 43 new tests (379 total). A1/A2/A3 stress-test anomaly fixes.** | **✅ (C13)** |
| **9e** | **`api_runtime/api_memory.py` + `api_runtime/api_fleet.py`** | **Semantic diff (`checkpoint_diff`), cross-sandbox diff (`sandbox_cross_diff`), concurrent sandbox inspection (`sandbox_fleet_health`, `sandbox_batch_inspect`, `sandbox_sync_execution`, `sandbox_correlate_memory`). ThreadPoolExecutor-based parallelism, divergence detection, rebase hints. 22 new tests (401 total).** | **✅ (C13/C16)** |

## Phase 9c: Hardened Execution Architecture — DELIVERED

### The Problem Solved

x64dbg is an **interactive** debugger. When it catches an event, it **freezes all threads**. AI agents have no eyes to see the pause and no hands to click "Run". The original upstream test suite assumed human operators.

Four critical edge cases threatened reliability:
1. **Missed-Message Race** — Event arrives before monitor hook is active
2. **Cascading Event Deadlock** — Guard resumes on Event A, but Event B pauses immediately after
3. **ZMQ Slow Joiner** — SUB socket not ready when PUB sends
4. **ScyllaHide Reversion** — Anti-debug plugin patches `PEB.BeingDebugged=0`, making `OutputDebugStringA` a no-op

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (FastMCP Client)                 │
│  @guarded Tool Call → running_guard { } → get_debugger_state │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌─────────────────┐    ┌──────────────┐
│  Tool Gateway │    │ ExecutionContext │    │ StateMachine │
│  (@guarded)   │───►│  (running_guard) │───►│  (tracking)  │
│  pre-flight   │    │  auto-resume     │    │  transitions │
│  post-flight  │    │  nested guards   │    │  health      │
└───────────────┘    └─────────────────┘    └──────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │  ZMQ SUB Thread │
                    │  (persistent)   │
                    └─────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
           ┌─────────────┐     ┌────────────────┐
           │ C++ Plugin  │     │  x64dbg Engine │
           │ safe_pub_   │     │  (pauses on    │
           │   send()    │     │   events)      │
           │ SNDHWM=10K  │     │                │
           └─────────────┘     └────────────────┘
```

### Components

| Component | File | What It Does |
|-----------|------|--------------|
| **DebuggerStateMachine** | `debugger_state.py` | Explicit state tracking (DISCONNECTED→CONNECTING→STOPPED→RUNNING→PAUSED_EVENT→PAUSED_BREAKPOINT→ERROR). Transition log with timestamps, reasons, event types. Health monitor detects stalls. |
| **ExecutionContextManager** | `execution_context.py` | Hardened `running_guard` v2. Four resume policies (NEVER, TRACKED_EVENTS, ALL_NON_BREAKPOINT, FORCE). Nested guard support. Untracked pause detection. Timeout enforcement. |
| **Tool Gateway** | `tool_gateway.py` | `@guarded` decorator. Pre-flight `ensure_running()`. Post-flight state validation. Read-only safety. Structured errors with recovery hints. |
| **Timeout & Retry** | `timeout_retry.py` | `@timeout_retry` decorator. Exponential backoff. Circuit breaker (5 failures → 10s recovery window). |
| **Infrastructure Tools** | `api_infrastructure.py` | 4 MCP tools: `get_debugger_state`, `wait_for_stable_state`, `force_resume`, `get_execution_log`. |
| **ZMQ Hardening** | `plugin.cpp`, `xauto_server.cpp` | `safe_pub_send()` with `zmq::send_flags::dontwait`. `ZMQ_SNDHWM=10000`. Prevents x64dbg callback thread from stalling. |

### Test Hardening

| Test | Before | After |
|------|--------|-------|
| `test_event_output_dbg_str` | `_queue.Empty` (ScyllaHide + INFINITE wait) | **PASS** — PEB patch + null terminator + `running_guard` + finite timeout |
| `test_api_runtime.py` | 117 tests | **131 tests** (+14) |
| Full suite | 303 tests | **312 tests** (+9) |
| C++ build | N/A | **Success** (VS 18 2026) |

### Agent Usage Pattern

```python
# 1. Check state before acting
state = get_debugger_state()
if state["is_paused"]:
    force_resume()

# 2. Guarded execution — auto-resumes on OutputDebugString
with client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
    hThread = CreateRemoteThread(...)
    WaitForSingleObject(hThread, 5000)

# 3. Every tool is implicitly protected by @guarded
read_memory(address="0x401000", size=64)  # ensure_running() called automatically
```

### Full Documentation

See **`docs_custom/AXON_EXECUTION_ARCHITECTURE.md`** for complete architecture diagrams, state machine transitions, API reference, and troubleshooting matrix.

See **`docs_custom/STRESS_TEST_PROTOCOL.md`** for the agent-verification stress test suite (10 tests, ~15-20 minutes).

## Key Files

| File | Purpose |
|------|---------|
| `x64dbg-automate-plus/src/xauto_server.h` | C++ command constants (43 commands including threads, xrefs, CFG, modules, SEH, handles) |
| `x64dbg_automate/api_runtime/debugger_state.py` | **NEW** — DebuggerStateMachine + HealthMonitor (explicit state tracking) |
| `x64dbg_automate/api_runtime/execution_context.py` | **NEW** — ExecutionContextManager with hardened `running_guard` v2 (nested guards, catch-all pause detection, 4 resume policies) |
| `x64dbg_automate/api_runtime/tool_gateway.py` | **NEW** — `@guarded` decorator (pre-flight `ensure_running()`, post-flight validation, structured errors with recovery hints) |
| `x64dbg_automate/api_runtime/timeout_retry.py` | **NEW** — `@timeout_retry` decorator + CircuitBreaker (exponential backoff, failure threshold, recovery window) |
| `x64dbg_automate/api_runtime/api_infrastructure.py` | **NEW** — 4 MCP tools: `get_debugger_state`, `wait_for_stable_state`, `force_resume`, `get_execution_log` |
| `x64dbg-automate-plus/src/xauto_cmd.cpp` | C++ command implementations |
| `x64dbg-automate-plus/src/xauto_server.cpp` | C++ dispatch (`_dispatch_cmd()`) |
| `x64dbg-automate-plus/build64/Release/x64dbg-automate.dp64` | **Built plugin** |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/commands_xauto.py` | Python RPC command enum + wrappers for all 43 commands |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/mcp_server.py` | MCP tools dispatcher (legacy 82 + runtime 84) |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/hla_xauto.py` | High-level abstractions |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/models.py` | Pydantic models (`CallStackEntry`, `BreakpointEntry` added) |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/external/` | Phase 3 analysis libraries |
| `x64dbg-automate-pyclient-plus/x64dbg_automate/workflows/` | Phase 5 workflows |
| **`x64dbg-automate-pyclient-plus/x64dbg_automate/api_runtime/`** | **Phase 7 AI-native runtime API** |

## Phase 7: AI-Native Runtime API (`api_runtime`) — DELIVERED

```
x64dbg_automate/
├── dbg_paths.py           # Shared x64/x32 debugger-path resolution
├── api_runtime/           # AI-native runtime analysis (Synapse-style structured tools)
│   ├── __init__.py        # register_runtime_tools(mcp) — imports modules + binds tools
│   ├── responses.py       # Structured response shape: ok()/err()/ErrorType/to_hex/lookup_error
│   ├── registry.py        # @tool / @unsafe decorators; ToolAnnotations for MCP protocol safety
│   ├── supervisor.py      # SandboxManager + ProcessSandbox + Checkpoint (with thread-count warnings)
│   ├── runtime_helpers.py # resolve_addr, capture_registers, diff_bytes, read_pointer
│   ├── utils.py           # parse_region, parse_int, detect_crypto_constants
│   ├── api_sandbox.py     # sandbox_create/destroy/list/info/continue/pause/checkpoint/restore/dump
│   ├── api_antidebug.py   # attach_safe, check_antidebug_status, configure_scyllahide,
│   │                      #   detect_timing_attacks, check_debug_port, check_debug_object_handles
│   ├── api_composite.py   # capture_function_context, trace_until_memory_change,
│   │                      #   find_crypto_material, trace_execution
│   ├── api_memory.py      # read_struct, find_initialized_data, memory_diff, resolve_iat_slot,
│   │                      #   memory_search_pattern, disassemble_range, get_call_stack,
│   │                      #   read_memory_range (chunked up to 64 MiB, paginated),
│   │                      #   checkpoint_diff (semantic diff: registers, memory, threads, modules, breakpoints, patches, PEB),
│   │                      #   sandbox_cross_diff (live cross-sandbox comparison with optional memory diff)
│   ├── api_analysis.py    # get_threads, get_xrefs, get_function_boundaries, analyze_function_cfg,
│   │                      #   get_string_at, get_patches, get_modules, get_seh_chain, get_handles,
│   │                      #   graph_call_graph (Capstone BFS with cycle detection, max_depth/max_nodes limits)
│   ├── api_patches.py     # patch_apply, patch_list, patch_rollback, patch_rollback_all,
│   │                      #   patch_export — in-memory patch lifecycle, rollback, audit (Phase 9 C5)
│   ├── api_symbols.py     # resolve_ordinal, get_type_layout, get_type_info — static Windows type
│   │                      #   library (PEB/TEB/LDR/UNICODE_STRING/IMAGE_*), struct field reader (Phase 9 C8)
│   ├── api_coverage.py    # coverage_start, coverage_stop, coverage_query, coverage_clear —
│   │                      #   in-memory address set via TRACEEXECUTE callback (Phase 9 C3)
│   ├── api_exceptions.py  # exception_set_handler, exception_clear_handler, exception_list_known,
│   │                      #   exception_configure_securom — x64dbg exception BP control (Phase 9 C7)
│   ├── api_workflow.py    # workflow_capture_securom_state, workflow_trace_crypto_pipeline
│   ├── api_fleet.py       # **NEW** — Concurrent sandbox inspection:
│   │                      #   sandbox_fleet_health (parallel health check all sandboxes),
│   │                      #   sandbox_batch_inspect (uniform inspection + divergence detection),
│   │                      #   sandbox_sync_execution (pause/continue/step all sandboxes),
│   │                      #   sandbox_correlate_memory (cross-sandbox memory diff + rebase hint)
│   └── semantic_memory.py # memory_record_finding, memory_query_findings, memory_get_latest,
│                          #   memory_list_keys, memory_stats, memory_delete_key (JSONL cross-session persistence)
```

### Corrected sandbox model (IMPORTANT — differs from the original plan)

A **sandbox is a disposable debugged session**, not a runnable `PssCaptureSnapshot`
clone (a PSS VA-clone is a frozen read-only snapshot, not an executable process).
Three safety primitives:
1. **`sandbox_create` / `sandbox_destroy`** — launch or attach a target under x64dbg/x32dbg
   (auto arch-select), freely killable since the on-disk binary is never patched.
2. **`sandbox_checkpoint` / `sandbox_restore`** — *best-effort userland* snapshot
   (active-thread registers + chosen memory regions). NOT a kernel fork — handles/new
   threads are not restored. **Restore now warns if thread count changed.**
   Ideal for "retry this trace from a known point".
3. **`sandbox_dump`** — read-only forensic clone/minidump for offline extraction.

### Tool conventions & safety
- Every runtime tool returns a **JSON-serilizable structured dict** (`success` + fields,
  or `success:false` + `error`/`error_type`/`hint`). Bytes are hex-encoded.
- All tools take a `sandbox_id`. Read-only by default; state-mutating tools are flagged
  `@unsafe` (`sandbox_destroy`, `sandbox_restore`). Set `X64DBG_MCP_READ_ONLY=1` to block
  `@unsafe` tools at the transport boundary.
- **Protocol-level safety:** `ToolAnnotations` (`readOnlyHint`, `destructiveHint`) are
  passed to FastMCP so AI clients can see safety metadata before calling.

### Gap closure summary (developer assessment addressed)

| Gap | Mitigation | Status |
|-----|-----------|--------|
| No execution trace / instruction history | `trace_execution()` — software single-step trace with configurable steps, register recording, stop conditions | ✅ |
| No call stack tool | **C++ command added:** `XAUTO_REQ_DBG_GET_CALLSTACK` using `GetCallStackEx`. Python `get_call_stack()` tool with symbol resolution | ✅ |
| No call graph construction | `graph_call_graph()` — Capstone-based BFS from entry point, direct/indirect/import/tail call resolution, cycle detection, JSON node/edge output | ✅ Phase 9d |
| No disassembly tool | `disassemble_range()` — disassemble N instructions with bytes + mnemonic + size | ✅ |
| Userland checkpoint limits | Checkpoint now captures thread count; restore warns if threads changed. Warnings explicitly document kernel handles / mapped files not restored | ✅ |
| Anti-debug is profile-based, not adaptive | Added `detect_timing_attacks` (RDTSC baseline), `check_debug_port` (NtQueryInformationProcess), `check_debug_object_handles` (NtQuerySystemInformation handle enumeration) | ✅ |
| No cross-session persistence | `semantic_memory.py` — JSONL-backed store with `memory_record_finding`, `memory_query_findings`, `memory_get_latest`, `memory_list_keys`, `memory_delete_key` (rewrite-on-delete) | ✅ |
| No checkpoint semantic diff | `checkpoint_diff` — compares two checkpoints across registers, memory, threads, modules, breakpoints, patches, PEB with human-readable summary | ✅ Phase 9e |
| No cross-sandbox comparison | `sandbox_cross_diff` — live diff between two sandboxes (registers, modules, threads, optional memory) | ✅ Phase 9e |
| No fleet-wide operations | `api_fleet.py` — parallel health, batch inspect, sync execution, memory correlation with divergence detection | ✅ Phase 9e |
| Requires live Windows + x64dbg | **Fundamental constraint.** Mitigated by enhanced offline dump tools (`sandbox_dump`, `workflow_extract_securom`) and semantic memory for multi-session campaigns | ⚠️ Documented |
| read_memory capped at 4 KB | `read_memory_range(address, size, chunk_size, offset)` — reads up to 64 MiB in configurable chunks; zero-fills unreadable sub-regions; `unreadable_chunks` key lists failed addresses | ✅ Phase 8 |
| No PE exports tool | `get_pe_exports(pe_path, filter_name)` — wraps existing `pe_analyzer.get_exports`; supports substring filter; truncates at 200 with overflow notice | ✅ Phase 8 |
| Conditional breakpoints | `set_breakpoint(condition="expr")` — applies `SetBreakpointCondition` via `cmd_sync`; failure path returns structured dict with `_diagnose_bp_failure()` hint | ✅ Phase 8 |
| trace_execution broken (B1) | `client.stepi()` used instead of non-existent `client.step_into()` | ✅ Phase 8 |
| Semantic memory no delete (D7) | `memory_delete_key(key)` — in-memory index rebuilt, JSONL rewritten to remove entries permanently | ✅ Phase 8 |
| Programming errors silently swallowed | `is_bug(exc)` guard added to all bare excepts — re-raises `AttributeError`, `NameError`, `NotImplementedError` | ✅ Phase 8 |
| No in-memory patch lifecycle | `api_patches.py` — `patch_apply` (hex or asm), `patch_list`, `patch_rollback`, `patch_rollback_all`, `patch_export`; original bytes saved for clean rollback; never modifies PE on disk | ✅ Phase 9 C5 |
| No Windows struct introspection | `api_symbols.py` — `get_type_layout` (PEB/TEB/LDR/UNICODE_STRING/IMAGE_* field map, x64/x32), `get_type_info` (live struct read + symbol hint per pointer field), `resolve_ordinal` (DLL ordinal → name) | ✅ Phase 9 C8 |
| No agent health/version check | `mcp_server.health_check` — RTT measurement, plugin compat check, structured result; `get_plugin_version` — version/compat summary | ✅ Phase 9 C16 |
| No single-call session orientation | `mcp_server.session_summary` — sandbox info + debugger state + module count + BP count + semantic memory stats in one call | ✅ Phase 9 C15 |
| No code coverage tracking | `api_coverage.py` — `coverage_start/stop/query/clear`; C++ `PLUGCB_TRACEEXECUTE` callback collects CIPs into `std::unordered_set<size_t>`; 4 new RPC commands; group-by-module query | ✅ Phase 9 C3 |
| No fine-grained exception control | `api_exceptions.py` — `exception_set_handler` (break/pass/second/all via `SetExceptionBPX`/`DeleteExceptionBPX`), `exception_configure_securom` (SecuROM baseline), `exception_list_known` | ✅ Phase 9 C7 |

### Deprecated legacy tools (kept for compatibility, agents should prefer runtime API)
- `configure_scyllahide_for_securom()` → `configure_scyllahide(sandbox_id)`
- `check_peb_after_hide()` → `check_antidebug_status(sandbox_id)`
- `freeze_debugee_for_dump()` → `sandbox_dump(sandbox_id)`

### Runtime API tests
```powershell
cd x64dbg-automate-pyclient-plus
python -m pytest tests/test_api_runtime.py -q   # 200 tests, no x64dbg required
python -m pytest tests/test_mcp_server.py -q    # 109 tests (legacy tools + new tools)
python -m pytest tests/test_xauto_commands.py -q  # 73 tests
python -m pytest --ignore=tests/test_hla_commands.py -q  # 401 total non-integration tests
```

## External Tools (download to `ext/`)

- **WinPMEM** (signed) — physical memory read via kernel driver
- **ProcDump** (Sysinternals) — process clone + dump, no debugger
- **MemProcFS** — optional advanced forensics

## Python Dependencies

`lief`, `pefile`, `capstone`, `pywin32`, `memprocfs`, `construct`, `yara-python`(optional)

**No new dependencies for Phase 7.** All Windows API calls use `ctypes` or `pywin32`, already in `pyproject.toml`.

## Compat Version

`"Axon_MCP"` (bumped from upstream `"green_pepe"`)

## Test Commands

```powershell
# Unit tests (no x64dbg required)
cd x64dbg-automate-pyclient-plus
python -m pytest tests/ -k "not integration" -v

# Build C++ plugin (Phase 7+ added get_callstack, threads, xrefs, CFG, modules, SEH, handles, strings, patches)
cd x64dbg-automate-plus
cmake -B build64 -G "Visual Studio 18 2026" -A x64 -DCMAKE_TOOLCHAIN_FILE="C:/Dev/x64dbg_MCP_Automate_Plus/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build build64 --config Release

# Run MCP server
x64dbg-automate-mcp
```

## Environment Prerequisites (Confirmed)

| Component | Path | Status |
|-----------|------|--------|
| x64dbg | `C:/Dev/RE_Tools/snapshot_2025-08-19_19-40/release/x64/x64dbg.exe` | ✅ |
| x32dbg | `C:/Dev/RE_Tools/snapshot_2025-08-19_19-40/release/x32/x32dbg.exe` | ✅ |
| ScyllaHide (x64) | `.../x64/plugins/ScyllaHideX64DBGPlugin.dp64` | ✅ |
| ScyllaHide (x32) | `.../x32/plugins/ScyllaHideX64DBGPlugin.dp32` | ✅ |
| Target binary | `C:/Dev/BoneCrafterModKit/BoneCraft/BoneCrafterModKit.exe` | ✅ |
| Python | 3.13.12 (Windows 10 build 26100) | ✅ |
| PssCaptureSnapshot | Available via `ctypes.windll.kernel32` | ✅ |

## Git Remotes

- **origin** → `https://github.com/CloudyTabzy/x64dbg-automate-plus` (C++) / `...-pyclient-plus` (Python)
- **upstream** → `https://github.com/dariushoule/x64dbg-automate` / `...-pyclient`
