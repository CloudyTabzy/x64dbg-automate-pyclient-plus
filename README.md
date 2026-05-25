# x64dbg Automate Plus — AI-Native Runtime Analysis Platform

> A fork-and-extension of [x64dbg-automate](https://github.com/dariushoule/x64dbg-automate) that transforms x64dbg into an **AI-controllable runtime analysis engine** via the Model Context Protocol (MCP).

Instead of typing debugger commands by hand, LLM agents drive the entire reverse engineering workflow through **120+ structured tools** — from memory inspection and control-flow graph analysis to anti-debug evasion and cross-session semantic memory.

---

## What's New (Plus Edition)

| Capability | Description |
|-----------|-------------|
| **120+ MCP Tools** | 42 new runtime API tools + 78 upstream tools, all exposed via FastMCP 3.2.4 with `readOnlyHint`/`destructiveHint` annotations |
| **Sandbox Model** | Isolate every debugging session with automatic checkpoint/restore, read-only safety mode, and lifecycle management |
| **Full CFG Analysis** | Extract control-flow graphs with basic blocks, branch targets, and instruction bytes via `analyze_function_cfg()` |
| **Execution Tracing** | Software single-step trace (up to 500 steps) with register snapshots and configurable stop conditions |
| **Cross-Session Memory** | JSONL-backed semantic memory — record findings, query history, and resume multi-day campaigns across process restarts |
| **Adaptive Anti-Debug** | Beyond static ScyllaHide profiles: RDTSC timing detection, `NtQueryInformationProcess` debug-port checks, and debug-object handle enumeration |
| **Structured Data** | Every tool returns Pydantic-validated JSON — no regex-parsing command output |
| **Call Stack & Threads** | Full thread inventory, call stack with symbol resolution, SEH chain, and open handle enumeration |
| **Offline Dump Tools** | Entropy analysis, pattern search, string extraction, and PE section forensics via LIEF/Capstone — no debugger required |

---

## Architecture

```
┌─────────────────┐     ZMQ/msgpack      ┌─────────────────────────┐
│   LLM Agent     │◄────────────────────►│  x64dbg Automate Plugin │
│  (Claude Code   │                      │   (C++ RPC Server)      │
│   Cursor, etc.) │                      │      x64dbg GUI         │
└─────────────────┘                      └─────────────────────────┘
         ▲                                        │
         │          120+ MCP tools                │
         └────────────────────────────────────────┘
```

**Two repos work together:**
- [`x64dbg-automate-plus`](https://github.com/CloudyTabzy/x64dbg-automate-plus) — C++ x64dbg plugin (ZMQ RPC server)
- [`x64dbg-automate-pyclient-plus`](https://github.com/CloudyTabzy/x64dbg-automate-pyclient-plus) — Python client + FastMCP server (this repo)

---

## Installation

Requires **Python 3.10+** on Windows.

```sh
pip install x64dbg_automate[mcp] --upgrade
```

For YARA rule support (optional):
```sh
pip install x64dbg_automate[mcp,yara] --upgrade
```

---

## MCP Configuration

Add to your `.mcp.json` (project or user level):

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "x64dbg-automate-mcp",
      "env": {
        "X64DBG_PATH": "C:\\path\\to\\x96dbg.exe"
      }
    }
  }
}
```

Setting `X64DBG_PATH` lets the MCP tools resolve x64dbg automatically — no need to pass the path on every `start_session` or `connect_to_session` call.

**For local development**, use `uv` to run from source:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "uv",
      "args": [
        "run",
        "--directory", "C:\\path\\to\\x64dbg-automate-pyclient-plus",
        "--extra", "mcp",
        "x64dbg-automate-mcp"
      ],
      "env": {
        "X64DBG_PATH": "C:\\path\\to\\x96dbg.exe"
      }
    }
  }
}
```

---

## Tool Categories

### Runtime Analysis (`api_analysis`)
- `get_threads` — thread inventory with CIP, priority, wait reason
- `get_xrefs` — typed cross-references (CALL, JMP, DATA)
- `get_function_boundaries` — function start/end from any interior address
- `analyze_function_cfg` — **full control-flow graph** with nodes, exits, instruction bytes
- `get_string_at` — auto-detected ASCII/Unicode strings
- `get_patches` — track all debugger memory modifications
- `get_modules` — loaded module list with base/size/entry/path
- `get_seh_chain` — structured exception handler chain
- `get_handles` — open handle enumeration with type and access
- `get_call_stack` — call stack with symbol resolution

### Memory & Disassembly (`api_memory`)
- `read_memory`, `write_memory`, `read_struct` — structured memory access
- `disassemble_range` — N instructions with bytes, mnemonic, size; auto-stops on `ret`
- `memory_search_pattern` — byte-pattern / regex search across regions

### Anti-Debug (`api_antidebug`)
- `get_peb` — full PEB dump with heap/being-debugged flags
- `detect_timing_attacks` — RDTSC baseline + variance detection
- `check_debug_port` — `NtQueryInformationProcess` ProcessDebugPort
- `check_debug_object_handles` — `NtQuerySystemInformation` debug-object enumeration

### Execution Control (`api_composite`)
- `trace_execution` — software single-step trace with register capture
- `capture_function_context` — snapshot registers + stack around a call
- `crypto_material_search` — entropy-based key/material detection

### Sandbox Management (`api_sandbox`)
- `sandbox_create`, `sandbox_destroy`, `sandbox_list`, `sandbox_info`
- `sandbox_checkpoint`, `sandbox_restore` — full memory/register snapshots with thread-safety warnings
- `read_only_mode` — prevents destructive tools at the protocol level

### Semantic Memory (`semantic_memory`)
- `memory_record_finding` — append-only JSONL persistence
- `memory_query_findings`, `memory_get_latest`, `memory_list_keys`, `memory_stats`

### Offline Forensics (`external/`)
- `calculate_entropy`, `find_function_prologues`, `extract_strings`
- `search_pattern`, `dump_process_section` — ProcDump + PE analysis without a debugger

### Legacy Tools (`mcp_server.py`)
- 78 upstream tools for breakpoints, labels, comments, assembly, direct command execution, etc.

---

## Example: SecuROM Extraction Workflow

One validated use-case from this project is extracting decrypted code from SecuROM v7–v8 protected binaries without patching the on-disk PE (integrity checks would kill it):

1. Launch original **unpatched** executable as a subprocess (**no debugger**)
2. Wait for the "Serial" dialog (decrypted section now in RAM)
3. Dump process via ProcDump `-r` (clone mode)
4. Extract `.stext` section (VA `0x0067A000`, ~10 MB)
5. Validate via entropy, function prologues, and known strings

The `automate-extract` CLI command wraps this entire pipeline:
```sh
automate-extract --target "C:\\path\\to\\BoneCrafterModKit.exe" --output-dir ./dump
```

---

## Development

The project uses [Poetry](https://python-poetry.org/docs/).

```powershell
cd x64dbg-automate-pyclient-plus
poetry install --extras "mcp"
poetry env activate
```

### Testing

```powershell
# Unit tests (no x64dbg required)
python -m pytest tests/ -k "not integration" -v

# Full test suite (requires x64dbg)
python -m pytest tests/ -v
```

**Current status:** 156 tests passing, 0 failures.

### Running Examples

```powershell
python examples\\assemble_and_disassemble.py C:\\path\\to\\x64dbg.exe
```

### Documentation

Built with MkDocs:
```powershell
python -m mkdocs serve  # dev
python -m mkdocs build  # publish
```

---

## Compatibility

| Component | Version |
|-----------|---------|
| Python | 3.10+ |
| x64dbg | Latest release (Oct 2024+) |
| Plugin Compat | `"Axon_MCP"` |
| FastMCP | 3.2.4+ (ToolAnnotations support) |
| C++ Build | Visual Studio 2022, CMake 3.20+ |

---

## Contributing

Issues, feature requests, and pull requests are welcome. For major additions, please open an issue to discuss design first.

Upstream: [dariushoule/x64dbg-automate](https://github.com/dariushoule/x64dbg-automate) / [dariushoule/x64dbg-automate-pyclient](https://github.com/dariushoule/x64dbg-automate-pyclient)

---

## License

This project extends the upstream x64dbg-automate ecosystem. All original upstream code retains its respective license. New contributions in the Plus edition follow the same open-source spirit.
