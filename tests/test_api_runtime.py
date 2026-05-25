"""Unit tests for the Phase 7 AI-native runtime API. No running x64dbg required.

Uses mocked X64DbgClient instances injected into a fresh SandboxManager.
"""

from __future__ import annotations

import os
import struct
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from x64dbg_automate.api_runtime import responses, supervisor
from x64dbg_automate.api_runtime.responses import ErrorType
from x64dbg_automate.api_runtime.supervisor import Checkpoint, ProcessSandbox, SandboxManager
from x64dbg_automate.api_runtime.utils import (
    _AES_SBOX_HEAD,
    detect_crypto_constants,
    parse_int,
    parse_region,
)


# ---------------------------------------------------------------------------
# utils: parsing
# ---------------------------------------------------------------------------

class TestParseInt:
    def test_int_passthrough(self):
        assert parse_int(0x1000) == 0x1000

    def test_hex_prefixed(self):
        assert parse_int("0x448300") == 0x448300

    def test_bare_hex_default(self):
        assert parse_int("448300") == 0x448300

    def test_decimal_default_for_size(self):
        assert parse_int("4096", hex_default=False) == 4096

    def test_negative(self):
        assert parse_int("-0x10") == -16

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_int("  ")


class TestParseRegion:
    def test_hex_addr_decimal_size(self):
        assert parse_region("0x448300:4096") == (0x448300, 4096)

    def test_hex_size(self):
        assert parse_region("0x448300:0x1000") == (0x448300, 0x1000)

    def test_missing_colon(self):
        with pytest.raises(ValueError):
            parse_region("0x448300")

    def test_nonpositive_size(self):
        with pytest.raises(ValueError):
            parse_region("0x448300:0")


# ---------------------------------------------------------------------------
# utils: crypto detection
# ---------------------------------------------------------------------------

class TestCryptoDetection:
    def test_aes_sbox(self):
        buf = b"\x00" * 64 + _AES_SBOX_HEAD + b"\xff" * 64
        findings = detect_crypto_constants(buf, base_addr=0x1000)
        aes = [f for f in findings if f["algorithm"] == "AES"]
        assert aes and aes[0]["offset"] == 64
        assert aes[0]["address"] == "0x1040"

    def test_sha256_round_constants_le(self):
        words = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]
        buf = struct.pack("<4I", *words)
        findings = detect_crypto_constants(buf)
        assert any(f["algorithm"] == "SHA-256" for f in findings)

    def test_crc32_table_head(self):
        words = [0x77073096, 0xee0d7308, 0x990951ba, 0x076dc419]
        buf = b"\x00\x00\x00\x00" + struct.pack("<4I", *words)
        findings = detect_crypto_constants(buf)
        assert any(f["algorithm"] == "CRC32" for f in findings)

    def test_rc4_identity(self):
        buf = bytes(range(256))
        findings = detect_crypto_constants(buf)
        assert any(f["algorithm"] == "RC4" for f in findings)

    def test_scan_mode_filter(self):
        buf = _AES_SBOX_HEAD + bytes(range(256))
        only_rc4 = detect_crypto_constants(buf, scan_mode="rc4")
        assert all(f["algorithm"] == "RC4" for f in only_rc4)


# ---------------------------------------------------------------------------
# responses
# ---------------------------------------------------------------------------

class TestResponses:
    def test_ok(self):
        r = responses.ok(value=1)
        assert r["success"] is True and r["value"] == 1

    def test_err(self):
        r = responses.err("boom", ErrorType.TIMEOUT, hint="wait")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.TIMEOUT
        assert r["hint"] == "wait"

    def test_to_hex(self):
        assert responses.to_hex(b"\x00\xff") == "00ff"
        assert responses.to_hex(b"") == ""

    def test_lookup_error_keyerror(self):
        r = responses.lookup_error(KeyError("no sandbox"))
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_classify_timeout(self):
        assert responses.classify_exception(TimeoutError("x")) == ErrorType.TIMEOUT


# ---------------------------------------------------------------------------
# SandboxManager bookkeeping
# ---------------------------------------------------------------------------

def _mock_sandbox(mgr: SandboxManager, arch: str = "x64", sid: str = "aa11") -> ProcessSandbox:
    client = MagicMock()
    sb = ProcessSandbox(
        sandbox_id=sid,
        debugger_pid=999,
        debugger_arch=arch,
        created_at=datetime.now(),
        debuggee_pid=1234,
        client=client,
        state="stopped",
    )
    mgr._sandboxes[sid] = sb
    return sb


class TestSandboxManager:
    def test_create_sandbox_launch(self, monkeypatch):
        import x64dbg_automate

        monkeypatch.setattr(supervisor, "resolve_x64dbg_path_with_env", lambda p: "x64dbg.exe")
        monkeypatch.setattr(supervisor, "resolve_debugger_path", lambda p, e="": "x64dbg.exe")
        fake = MagicMock()
        fake.start_session.return_value = 4321
        fake.debugee_bitness.return_value = 64
        fake.debugee_pid.return_value = 1234
        fake.is_debugging.return_value = True
        monkeypatch.setattr(x64dbg_automate, "X64DbgClient", lambda path: fake)

        mgr = SandboxManager()
        sb = mgr.create_sandbox(target_exe="foo.exe")
        assert sb.debugger_pid == 4321
        assert sb.debugger_arch == "x64"
        assert sb.debuggee_pid == 1234
        fake.start_session.assert_called_once()

    def test_create_requires_exactly_one(self):
        mgr = SandboxManager()
        with pytest.raises(ValueError):
            mgr.create_sandbox()
        with pytest.raises(ValueError):
            mgr.create_sandbox(target_exe="a", attach_pid=1)

    def test_get_missing_raises(self):
        mgr = SandboxManager()
        with pytest.raises(KeyError):
            mgr.get_sandbox("nope")

    def test_checkpoint_and_restore(self):
        mgr = SandboxManager()
        sb = _mock_sandbox(mgr)
        client = sb.client
        client.is_running.return_value = False
        client.get_reg.side_effect = lambda r: 0x10
        client.read_memory.return_value = b"\xaa\xbb\xcc\xdd"

        cp = mgr.checkpoint("aa11", "cp1", regions=[(0x448300, 4)])
        assert isinstance(cp, Checkpoint)
        assert cp.memory[0x448300] == b"\xaa\xbb\xcc\xdd"
        assert "rax" in cp.registers

        client.set_reg.return_value = True
        client.write_memory.return_value = True
        regs, regions, warnings = mgr.restore_checkpoint("aa11", "cp1")
        assert regions == 1
        assert regs >= 1
        assert warnings

    def test_destroy(self):
        mgr = SandboxManager()
        sb = _mock_sandbox(mgr)
        sb.client.terminate_session.return_value = None
        assert mgr.destroy_sandbox("aa11") is True
        with pytest.raises(KeyError):
            mgr.get_sandbox("aa11")


# ---------------------------------------------------------------------------
# Tool-level tests (manager singleton replaced per test)
# ---------------------------------------------------------------------------

@pytest.fixture
def manager(monkeypatch):
    mgr = SandboxManager()
    monkeypatch.setattr(supervisor, "_manager", mgr)
    return mgr


class TestSandboxTools:
    def test_sandbox_info_not_found(self, manager):
        from x64dbg_automate.api_runtime.api_sandbox import sandbox_info

        r = sandbox_info("ghost")
        assert r["success"] is False and r["error_type"] == ErrorType.NOT_FOUND

    def test_sandbox_list(self, manager):
        from x64dbg_automate.api_runtime.api_sandbox import sandbox_list

        sb = _mock_sandbox(manager)
        sb.client.is_debugging.return_value = True
        sb.client.is_running.return_value = False
        r = sandbox_list()
        assert r["success"] and r["total"] == 1
        assert r["sandboxes"][0]["sandbox_id"] == "aa11"

    def test_sandbox_checkpoint_bad_region(self, manager):
        from x64dbg_automate.api_runtime.api_sandbox import sandbox_checkpoint

        _mock_sandbox(manager)
        r = sandbox_checkpoint("aa11", "cp", regions=["not-a-region"])
        assert r["success"] is False and r["error_type"] == ErrorType.BAD_ARGUMENT


class TestAntiDebugTools:
    def test_check_status_clean(self, manager):
        from x64dbg_automate.api_runtime.api_antidebug import check_antidebug_status

        sb = _mock_sandbox(manager)
        sb.client.get_peb.return_value = SimpleNamespace(
            being_debugged=False, nt_global_flag=0, heap_flags=2, heap_force_flags=0
        )
        r = check_antidebug_status("aa11")
        assert r["success"] and r["debugger_detectable"] is False

    def test_check_status_detected(self, manager):
        from x64dbg_automate.api_runtime.api_antidebug import check_antidebug_status

        sb = _mock_sandbox(manager)
        sb.client.get_peb.return_value = SimpleNamespace(
            being_debugged=True, nt_global_flag=0x70, heap_flags=0x40000060, heap_force_flags=0x40000060
        )
        r = check_antidebug_status("aa11")
        assert r["debugger_detectable"] is True
        assert "hint" in r


class TestMemoryTools:
    def test_read_struct_rc4_identity(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_struct

        sb = _mock_sandbox(manager)
        sb.client.read_memory.return_value = bytes(range(256))
        r = read_struct("aa11", "rc4_state", "0x500000")
        assert r["success"] and r["is_identity"] is True

    def test_read_struct_peb(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_struct

        sb = _mock_sandbox(manager, arch="x64")
        blob = bytearray(0xC0)
        blob[0x02] = 1
        struct.pack_into("<Q", blob, 0x10, 0xDEAD0000)
        struct.pack_into("<I", blob, 0xBC, 0x70)
        sb.client.read_memory.return_value = bytes(blob)
        sb.client.eval_sync.return_value = (0x7FF00000, True)
        r = read_struct("aa11", "peb")
        assert r["success"]
        assert r["fields"]["BeingDebugged"] is True
        assert r["fields"]["NtGlobalFlag"] == "0x70"
        assert r["fields"]["ImageBaseAddress"] == "0xDEAD0000"

    def test_read_struct_unknown(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_struct

        _mock_sandbox(manager)
        r = read_struct("aa11", "bogus", "0x1000")
        assert r["success"] is False and r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_memory_search_pattern(self, manager):
        from x64dbg_automate.api_runtime.api_memory import memory_search_pattern

        sb = _mock_sandbox(manager)
        sb.client.read_memory.return_value = b"\x90\x55\x8b\xec\x90"
        r = memory_search_pattern("aa11", "0x401000", 5, "55 8B EC")
        assert r["success"] and r["total"] == 1
        assert r["matches"] == ["0x401001"]


class TestCompositeTools:
    def test_find_crypto_material_default_region(self, manager):
        from x64dbg_automate.api_runtime.api_composite import find_crypto_material

        sb = _mock_sandbox(manager)
        buf = b"\x00" * 32 + _AES_SBOX_HEAD + b"\x00" * 32
        sb.client.is_running.return_value = False
        sb.client.get_process_info.return_value = SimpleNamespace(
            image_base=0x400000, image_size=len(buf)
        )
        sb.client.read_memory.return_value = buf
        r = find_crypto_material("aa11")
        assert r["success"]
        assert any(f["algorithm"] == "AES" for f in r["findings"])

    def test_trace_until_memory_change_detects(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_memory_change

        sb = _mock_sandbox(manager)
        c = sb.client
        c.is_running.return_value = False
        c.read_memory.side_effect = [b"\x00\x00\x00\x00", b"\x11\x22\x33\x44"]
        c.set_memory_breakpoint.return_value = True
        c.go.return_value = True
        c.wait_until_stopped.return_value = True
        c.get_reg.return_value = 0x401234
        r = trace_until_memory_change("aa11", "0x448300", 4, timeout_sec=5)
        assert r["success"] and r["before"] == "00000000" and r["after"] == "11223344"
        assert r["changed_by_instruction"] == "0x401234"

    def test_capture_function_context_entry_and_return(self, manager):
        from x64dbg_automate.api_runtime.api_composite import capture_function_context

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        c.set_breakpoint.return_value = True
        c.go.return_value = True
        c.wait_until_stopped.return_value = True
        c.get_symbol_at.return_value = None

        def _get_reg(reg):
            if reg == "cip":
                return 0x401000
            if reg == "rsp":
                return 0x500000
            return 0x11

        c.get_reg.side_effect = _get_reg
        c.read_qword.return_value = 0x402000  # return address
        r = capture_function_context("aa11", "0x401000")
        assert r["success"]
        assert r["entry_hit"] is True
        assert r["return_hit"] is True
        assert "register_inputs" in r and "register_outputs" in r


class TestWorkflowGuards:
    def test_bad_region_before_launch(self):
        from x64dbg_automate.api_runtime.api_workflow import workflow_capture_securom_state

        r = workflow_capture_securom_state(target_exe="x.exe", regions=["bogus"])
        assert r["success"] is False and r["error_type"] == ErrorType.BAD_ARGUMENT


# ---------------------------------------------------------------------------
# read-only safety mode
# ---------------------------------------------------------------------------

class TestReadOnlyMode:
    def test_unsafe_tool_blocked(self, monkeypatch):
        from x64dbg_automate.api_runtime import register_runtime_tools
        from x64dbg_automate.api_runtime.registry import is_unsafe

        monkeypatch.setenv("X64DBG_MCP_READ_ONLY", "1")

        class Stub:
            def __init__(self):
                self.funcs = {}

            def tool(self, **kwargs):
                def dec(f):
                    self.funcs[f.__name__] = f
                    return f

                return dec

        s = Stub()
        register_runtime_tools(s)
        assert is_unsafe("sandbox_destroy")
        res = s.funcs["sandbox_destroy"]("anything")
        assert res["success"] is False and res["error_type"] == ErrorType.READ_ONLY


# ---------------------------------------------------------------------------
# New tools: disassemble_range, get_call_stack, trace_execution
# ---------------------------------------------------------------------------

class TestDisassembleRange:
    def test_disassemble_range(self, manager):
        from x64dbg_automate.api_runtime.api_memory import disassemble_range

        sb = _mock_sandbox(manager, arch="x64")
        ins = type("Ins", (), {"instruction": "mov rax, rbx", "instr_size": 3})()
        sb.client.disassemble_at.return_value = ins
        sb.client.read_memory.return_value = b"\x48\x89\xD8"
        r = disassemble_range("aa11", "0x401000", count=2)
        assert r["success"]
        assert r["total"] == 2
        assert r["instructions"][0]["mnemonic"] == "mov rax, rbx"

    def test_disassemble_range_invalid_addr(self, manager):
        from x64dbg_automate.api_runtime.api_memory import disassemble_range

        _mock_sandbox(manager)
        r = disassemble_range("aa11", "not_an_addr", count=2)
        assert r["success"] is False


class TestGetCallStack:
    def test_get_call_stack(self, manager):
        from x64dbg_automate.api_runtime.api_memory import get_call_stack
        from x64dbg_automate.models import CallStackEntry

        sb = _mock_sandbox(manager, arch="x64")
        sb.client.get_call_stack.return_value = [
            CallStackEntry(address=0x401000, from_addr=0x402000, to_addr=0x403000, comment="main"),
            CallStackEntry(address=0x402000, from_addr=0x404000, to_addr=0x405000, comment="caller"),
        ]
        sb.client.get_symbol_at.return_value = None
        r = get_call_stack("aa11")
        assert r["success"]
        assert r["depth"] == 2
        assert r["frames"][0]["address"] == "0x401000"


class TestTraceExecution:
    def test_trace_execution_steps(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_execution

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        c.get_reg.return_value = 0x401000
        ins = type("Ins", (), {"instruction": "nop", "instr_size": 1})()
        c.disassemble_at.return_value = ins
        c.read_memory.return_value = b"\x90"
        c.step_into.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_execution("aa11", max_steps=3)
        assert r["success"]
        assert r["steps_recorded"] == 3
        assert len(r["trace"]) == 3


# ---------------------------------------------------------------------------
# Adaptive anti-debug
# ---------------------------------------------------------------------------

class TestAdaptiveAntiDebug:
    def test_detect_timing_attacks(self):
        from x64dbg_automate.api_runtime.api_antidebug import detect_timing_attacks

        r = detect_timing_attacks("dummy", samples=3)
        assert r["success"]
        assert len(r["measured_deltas_ms"]) == 3
        assert "noisy_environment" in r

    def test_check_debug_port_no_pid(self, manager):
        from x64dbg_automate.api_runtime.api_antidebug import check_debug_port

        sb = _mock_sandbox(manager)
        sb.debuggee_pid = None
        r = check_debug_port("aa11")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.INVALID_STATE


# ---------------------------------------------------------------------------
# Semantic memory
# ---------------------------------------------------------------------------

class TestAnalysisTools:
    def test_get_threads(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_threads
        from x64dbg_automate.models import ThreadInfo

        sb = _mock_sandbox(manager)
        sb.client.get_threads.return_value = [
            ThreadInfo(thread_id=1234, start_address=0x1000, local_base=0x2000, cip=0x3000,
                       suspend_count=0, priority=8, wait_reason=0, last_error=0, name="main"),
        ]
        r = get_threads("aa11")
        assert r["success"] and r["total"] == 1
        assert r["threads"][0]["thread_id"] == 1234

    def test_get_xrefs(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_xrefs
        from x64dbg_automate.models import XrefRecord

        sb = _mock_sandbox(manager)
        sb.client.get_xrefs.return_value = [
            XrefRecord(address=0x401000, xref_type=3),
            XrefRecord(address=0x402000, xref_type=2),
        ]
        r = get_xrefs("aa11", "0x400000")
        assert r["success"] and r["total"] == 2
        assert r["xrefs"][0]["type"] == "CALL"

    def test_get_function_boundaries(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_function_boundaries
        from x64dbg_automate.models import FunctionBoundaries

        sb = _mock_sandbox(manager)
        sb.client.get_function.return_value = FunctionBoundaries(start=0x401000, end=0x401100, instruction_count=42, manual=False)
        r = get_function_boundaries("aa11", "0x401050")
        assert r["success"]
        assert r["start"] == "0x401000"
        assert r["instruction_count"] == 42

    def test_get_function_boundaries_not_found(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_function_boundaries

        sb = _mock_sandbox(manager)
        sb.client.get_function.return_value = None
        r = get_function_boundaries("aa11", "0x401050")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_get_modules(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_modules
        from x64dbg_automate.models import ModuleInfo

        sb = _mock_sandbox(manager)
        sb.client.get_modules.return_value = [
            ModuleInfo(base=0x400000, size=0x10000, entry=0x401000, section_count=5, name="test.exe", path="C:/test.exe"),
        ]
        r = get_modules("aa11")
        assert r["success"] and r["total"] == 1
        assert r["modules"][0]["name"] == "test.exe"

    def test_get_seh_chain(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_seh_chain
        from x64dbg_automate.models import SehRecord

        sb = _mock_sandbox(manager)
        sb.client.get_seh_chain.return_value = [
            SehRecord(address=0x0012FF00, handler=0x401000),
        ]
        r = get_seh_chain("aa11")
        assert r["success"] and r["total"] == 1

    def test_get_patches(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_patches
        from x64dbg_automate.models import PatchInfo

        sb = _mock_sandbox(manager)
        sb.client.get_patches.return_value = [
            PatchInfo(address=0x401000, old_byte=0x55, new_byte=0x90),
        ]
        r = get_patches("aa11")
        assert r["success"] and r["total"] == 1
        assert r["patches"][0]["new"] == "0x90"

    def test_get_string_at(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_string_at

        sb = _mock_sandbox(manager)
        sb.client.get_string_at.return_value = "Hello World"
        r = get_string_at("aa11", "0x404000")
        assert r["success"]
        assert r["string"] == "Hello World"

    def test_get_string_at_none(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_string_at

        sb = _mock_sandbox(manager)
        sb.client.get_string_at.return_value = ""
        r = get_string_at("aa11", "0x404000")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND


class TestSemanticMemory:
    def test_record_and_query(self, monkeypatch):
        from x64dbg_automate.api_runtime.semantic_memory import (
            memory_record_finding, memory_query_findings, memory_get_latest, memory_list_keys,
        )

        tmp = os.path.join(os.getcwd(), "test_semantic_memory.jsonl")
        monkeypatch.setattr(
            "x64dbg_automate.api_runtime.semantic_memory._DEFAULT_MEMORY_PATH", tmp
        )
        monkeypatch.setattr(
            "x64dbg_automate.api_runtime.semantic_memory._store", None
        )

        r1 = memory_record_finding(
            category="function_identification",
            key="sub_2ADEB7",
            value={"role": "decryption_entry", "confidence": 0.92},
            target_exe="test.exe",
            tags=["securom"],
        )
        assert r1["success"]

        r2 = memory_query_findings(key="sub_2ADEB7")
        assert r2["success"] and r2["total"] == 1

        r3 = memory_get_latest("sub_2ADEB7")
        assert r3["success"]
        assert r3["finding"]["value"]["confidence"] == 0.92

        r4 = memory_list_keys()
        assert r4["success"] and "sub_2ADEB7" in r4["keys"]

        if os.path.exists(tmp):
            os.remove(tmp)
