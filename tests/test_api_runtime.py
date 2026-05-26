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
        assert parse_int("0x7FF6A0001000") == 0x7FF6A0001000

    def test_bare_hex_default(self):
        assert parse_int("7FF6A0001000") == 0x7FF6A0001000

    def test_decimal_default_for_size(self):
        assert parse_int("4096", hex_default=False) == 4096

    def test_negative(self):
        assert parse_int("-0x10") == -16

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_int("  ")


class TestParseRegion:
    def test_hex_addr_decimal_size(self):
        assert parse_region("0x7FF6A0001000:4096") == (0x7FF6A0001000, 4096)

    def test_hex_size(self):
        assert parse_region("0x7FF6A0001000:0x1000") == (0x7FF6A0001000, 0x1000)

    def test_missing_colon(self):
        with pytest.raises(ValueError):
            parse_region("0x7FF6A0001000")

    def test_nonpositive_size(self):
        with pytest.raises(ValueError):
            parse_region("0x7FF6A0001000:0")


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
    client.debugee_bitness.return_value = 64 if arch == "x64" else 32
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

        cp = mgr.checkpoint("aa11", "cp1", regions=[(0x7FF6A0001000, 4)])
        assert isinstance(cp, Checkpoint)
        assert cp.memory[0x7FF6A0001000] == b"\xaa\xbb\xcc\xdd"
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
        r = sandbox_checkpoint(sandbox_id="aa11", name="cp", regions=["not-a-region"])
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
        r = read_struct(sandbox_id="aa11", schema="rc4_state", address="0x500000")
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
        r = read_struct(sandbox_id="aa11", schema="peb")
        assert r["success"]
        assert r["fields"]["BeingDebugged"] is True
        assert r["fields"]["NtGlobalFlag"] == "0x70"
        assert r["fields"]["ImageBaseAddress"] == "0xDEAD0000"

    def test_read_struct_unknown(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_struct

        _mock_sandbox(manager)
        r = read_struct(sandbox_id="aa11", schema="bogus", address="0x1000")
        assert r["success"] is False and r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_memory_search_pattern(self, manager):
        from x64dbg_automate.api_runtime.api_memory import memory_search_pattern

        sb = _mock_sandbox(manager)
        sb.client.read_memory.return_value = b"\x90\x55\x8b\xec\x90"
        r = memory_search_pattern(sandbox_id="aa11", address="0x401000", size=5, pattern="55 8B EC")
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
        r = trace_until_memory_change(sandbox_id="aa11", address="0x7FF6A0001000", size=4, timeout_sec=5)
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
        r = capture_function_context(sandbox_id="aa11", addr="0x401000")
        assert r["success"]
        assert r["entry_hit"] is True
        assert r["return_hit"] is True
        assert "register_inputs" in r and "register_outputs" in r


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
        r = disassemble_range(sandbox_id="aa11", address="0x401000", count=2)
        assert r["success"]
        assert r["total"] == 2
        assert r["instructions"][0]["mnemonic"] == "mov rax, rbx"

    def test_disassemble_range_invalid_addr(self, manager):
        from x64dbg_automate.api_runtime.api_memory import disassemble_range

        _mock_sandbox(manager)
        r = disassemble_range(sandbox_id="aa11", address="not_an_addr", count=2)
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


class TestTraceAbstractions:
    def test_trace_until_call_hit(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_call

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        # Step 0: nop at 0x401000, Step 1: call 0x402000 at 0x401001
        reg_vals = [0x401000, 0x401001]
        c.get_reg.side_effect = lambda r: reg_vals.pop(0)
        ins_nop = type("Ins", (), {"instruction": "nop", "instr_size": 1})()
        ins_call = type("Ins", (), {"instruction": "call 0x402000", "instr_size": 5})()
        c.disassemble_at.side_effect = lambda addr: ins_nop if addr == 0x401000 else ins_call
        c.eval_sync.return_value = (0x402000, True)
        c.step_into.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_until_call(target_addr="0x402000", sandbox_id="aa11", max_steps=10)
        assert r["success"]
        assert r["hit_at"] == "0x401001"
        assert r["steps_recorded"] == 2

    def test_trace_until_call_miss(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_call

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        c.get_reg.return_value = 0x401000
        ins = type("Ins", (), {"instruction": "nop", "instr_size": 1})()
        c.disassemble_at.return_value = ins
        c.step_into.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_until_call(target_addr="0x402000", sandbox_id="aa11", max_steps=3)
        assert r["success"]  # returns ok with hit_at=None
        assert r["hit_at"] is None
        assert r["steps_recorded"] == 3

    def test_trace_until_register_equals_hit(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_register_equals

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        # Return cip values for steps, then rax values interleaved
        call_count = 0
        def _get_reg(reg_name):
            nonlocal call_count
            call_count += 1
            if reg_name.lower() == "cip":
                return 0x401000 + (call_count // 2)  # cip advances each step
            return 0x42 if (call_count // 2) >= 2 else 0x0  # rax hits 0x42 on step 2
        c.get_reg.side_effect = _get_reg
        ins = type("Ins", (), {"instruction": "mov rax, 0x42", "instr_size": 5})()
        c.disassemble_at.return_value = ins
        c.step_into.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_until_register_equals(register="rax", value="0x42", sandbox_id="aa11", max_steps=5)
        assert r["success"]
        assert r["hit_at"] == "0x401001"  # step 2 (0-indexed), cip = 0x401001
        assert r["steps_recorded"] == 2

    def test_trace_until_register_equals_miss(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_register_equals

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        c.get_reg.return_value = 0x0
        ins = type("Ins", (), {"instruction": "nop", "instr_size": 1})()
        c.disassemble_at.return_value = ins
        c.step_into.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_until_register_equals(register="rax", value="0x42", sandbox_id="aa11", max_steps=3)
        assert r["success"]  # returns ok with hit_at=None
        assert r["hit_at"] is None
        assert r["steps_recorded"] == 3

    def test_trace_until_write_delegates(self, manager):
        from x64dbg_automate.api_runtime.api_composite import trace_until_write

        sb = _mock_sandbox(manager, arch="x64")
        c = sb.client
        c.is_running.return_value = False
        c.read_memory.return_value = b"\x00" * 16
        c.set_memory_breakpoint.return_value = True
        c.clear_memory_breakpoint.return_value = True
        c.go.return_value = True
        c.wait_until_stopped.return_value = True
        r = trace_until_write(address="0x404000", size=16, sandbox_id="aa11", timeout_sec=1)
        assert r["success"] is False  # timeout because memory never changes
        assert r["error_type"] == ErrorType.TIMEOUT


# ---------------------------------------------------------------------------
# Adaptive anti-debug
# ---------------------------------------------------------------------------

class TestAdaptiveAntiDebug:
    def test_detect_timing_attacks(self):
        from x64dbg_automate.api_runtime.api_antidebug import detect_timing_attacks

        r = detect_timing_attacks(sandbox_id="dummy", samples=3)
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
        r = get_xrefs(sandbox_id="aa11", address="0x400000")
        assert r["success"] and r["total"] == 2
        assert r["xrefs"][0]["type"] == "CALL"

    def test_get_function_boundaries(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_function_boundaries
        from x64dbg_automate.models import FunctionBoundaries

        sb = _mock_sandbox(manager)
        sb.client.get_function.return_value = FunctionBoundaries(start=0x401000, end=0x401100, instruction_count=42, manual=False)
        r = get_function_boundaries(sandbox_id="aa11", address="0x401050")
        assert r["success"]
        assert r["start"] == "0x401000"
        assert r["instruction_count"] == 42

    def test_get_function_boundaries_not_found(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_function_boundaries

        sb = _mock_sandbox(manager)
        sb.client.get_function.return_value = None
        r = get_function_boundaries(sandbox_id="aa11", address="0x401050")
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
        r = get_string_at(sandbox_id="aa11", address="0x404000")
        assert r["success"]
        assert r["string"] == "Hello World"

    def test_get_string_at_none(self, manager):
        from x64dbg_automate.api_runtime.api_analysis import get_string_at

        sb = _mock_sandbox(manager)
        sb.client.get_string_at.return_value = ""
        r = get_string_at(sandbox_id="aa11", address="0x404000")
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
            tags=["protected"],
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

    def test_delete_key(self, monkeypatch):
        from x64dbg_automate.api_runtime.semantic_memory import (
            memory_delete_key, memory_list_keys, memory_record_finding,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_semantic_delete.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        memory_record_finding(
            category="function_identification",
            key="sub_DELETE",
            value={"role": "test"},
        )
        assert "sub_DELETE" in memory_list_keys()["keys"]

        r = memory_delete_key("sub_DELETE")
        assert r["success"]
        assert r["removed"] == 1
        assert "sub_DELETE" not in memory_list_keys()["keys"]

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_delete_key_not_found(self, monkeypatch):
        from x64dbg_automate.api_runtime.semantic_memory import memory_delete_key
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_semantic_delete2.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        r = memory_delete_key("nonexistent_key")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_delete_key_empty_rejected(self, monkeypatch):
        from x64dbg_automate.api_runtime.semantic_memory import memory_delete_key
        import x64dbg_automate.api_runtime.semantic_memory as sem

        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", "unused.jsonl")
        monkeypatch.setattr(sem, "_store", None)

        r = memory_delete_key("")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_export_import(self, monkeypatch):
        from x64dbg_automate.api_runtime.semantic_memory import (
            memory_record_finding, memory_export, memory_import, memory_list_keys,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp_store = os.path.join(os.getcwd(), "test_semantic_export.jsonl")
        tmp_export = os.path.join(os.getcwd(), "test_export.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp_store)
        monkeypatch.setattr(sem, "_store", None)

        memory_record_finding(
            category="crypto",
            key="aes_key",
            value={"bytes": "deadbeef"},
            tags=["protected"],
        )
        keys_before = memory_list_keys()["keys"]
        assert "aes_key" in keys_before

        r1 = memory_export(tmp_export)
        assert r1["success"]
        assert r1["entries_exported"] >= 1
        assert os.path.exists(tmp_export)

        # Clear store by deleting the backing file and resetting singleton
        monkeypatch.setattr(sem, "_store", None)
        if os.path.exists(tmp_store):
            os.remove(tmp_store)
        keys_after_clear = memory_list_keys()["keys"]
        assert "aes_key" not in keys_after_clear

        r2 = memory_import(tmp_export)
        assert r2["success"]
        assert r2["entries_imported"] >= 1

        keys_after_import = memory_list_keys()["keys"]
        assert "aes_key" in keys_after_import

        for f in [tmp_store, tmp_export]:
            if os.path.exists(f):
                os.remove(f)


# ---------------------------------------------------------------------------
# read_memory_range (chunked large reads)
# ---------------------------------------------------------------------------

class TestReadMemoryRange:
    def test_basic_read(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\xde\xad\xbe\xef" * 4
        r = read_memory_range(sandbox_id="aa11", address="0x401000", size=16)
        assert r["success"]
        assert r["address"] == "0x401000"
        assert r["requested"] == 16
        assert r["read"] == 16
        assert r["hex"] == "deadbeef" * 4

    def test_size_zero_rejected(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        _mock_sandbox(manager)
        r = read_memory_range(sandbox_id="aa11", address="0x401000", size=0)
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_size_exceeds_cap(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        _mock_sandbox(manager)
        r = read_memory_range(sandbox_id="aa11", address="0x401000", size=64 * 1024 * 1024 + 1)
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT
        assert "hint" in r

    def test_offset_slices_result(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\xaa\xbb\xcc\xdd"
        r = read_memory_range(sandbox_id="aa11", address="0x401000", size=4, offset=2)
        assert r["success"]
        assert r["returned"] == 2
        assert r["hex"] == "ccdd"

    def test_unreadable_chunk_fills_zeros(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.side_effect = OSError("access denied")
        r = read_memory_range(sandbox_id="aa11", address="0x401000", size=4)
        assert r["success"]
        assert r["hex"] == "00000000"
        assert "unreadable_chunks" in r

    def test_sandbox_not_found(self, manager):
        from x64dbg_automate.api_runtime.api_memory import read_memory_range

        r = read_memory_range(sandbox_id="ghost", address="0x401000", size=16)
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND


# ---------------------------------------------------------------------------
# Patch management (C5)
# ---------------------------------------------------------------------------

class TestPatchManagement:
    def test_patch_apply_hex(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply, patch_list

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\x55\x89\xEC"
        sb.client.write_memory.return_value = True
        r = patch_apply(sandbox_id="aa11", address="0x401000", hex_bytes="90 90 90",
                        description="NOP prologue")
        assert r["success"]
        assert r["original_bytes"] == "5589ec"
        assert r["patched_bytes"] == "909090"
        assert len(r["patch_id"]) == 8
        # Verify stored in sandbox
        pl = patch_list(sandbox_id="aa11")
        assert pl["total"] == 1
        assert pl["patches"][0]["description"] == "NOP prologue"

    def test_patch_apply_asm(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.side_effect = [b"\x90" * 15, b"\x90"]  # original_buf, readback
        sb.client.assemble_at.return_value = 1
        r = patch_apply(sandbox_id="aa11", address="0x401000", asm="nop")
        assert r["success"]
        assert r["patched_bytes"] == "90"

    def test_patch_apply_both_rejected(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply

        _mock_sandbox(manager)
        r = patch_apply(sandbox_id="aa11", address="0x401000",
                        hex_bytes="90", asm="nop")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_patch_apply_neither_rejected(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply

        _mock_sandbox(manager)
        r = patch_apply(sandbox_id="aa11", address="0x401000")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_patch_apply_invalid_hex(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        r = patch_apply(sandbox_id="aa11", address="0x401000", hex_bytes="ZZ ZZ")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_patch_rollback(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply, patch_rollback, patch_list

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\x55\x89\xEC"
        sb.client.write_memory.return_value = True
        pr = patch_apply(sandbox_id="aa11", address="0x401000", hex_bytes="909090")
        pid = pr["patch_id"]

        # Rollback
        r = patch_rollback(sandbox_id="aa11", patch_id=pid)
        assert r["success"]
        assert r["original_bytes_restored"] == "5589ec"
        # Patch list should now be empty
        assert patch_list(sandbox_id="aa11")["total"] == 0

    def test_patch_rollback_not_found(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_rollback

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        r = patch_rollback(sandbox_id="aa11", patch_id="deadbeef")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_patch_rollback_all(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply, patch_rollback_all, patch_list

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\x90"
        sb.client.write_memory.return_value = True
        patch_apply(sandbox_id="aa11", address="0x401000", hex_bytes="90")
        patch_apply(sandbox_id="aa11", address="0x401001", hex_bytes="90")
        r = patch_rollback_all(sandbox_id="aa11")
        assert r["success"]
        assert r["restored"] == 2
        assert patch_list(sandbox_id="aa11")["total"] == 0

    def test_patch_export(self, manager):
        from x64dbg_automate.api_runtime.api_patches import patch_apply, patch_export

        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.read_memory.return_value = b"\x55"
        sb.client.write_memory.return_value = True
        patch_apply(sandbox_id="aa11", address="0x401000", hex_bytes="90", description="test")
        r = patch_export(sandbox_id="aa11")
        assert r["success"]
        assert r["total"] == 1
        assert r["patches"][0]["description"] == "test"


# ---------------------------------------------------------------------------
# Symbol and type information (C8)
# ---------------------------------------------------------------------------

class TestSymbolTools:
    def test_resolve_ordinal_found(self, tmp_path):
        from unittest.mock import patch as mpatch
        from x64dbg_automate.api_runtime.api_symbols import resolve_ordinal

        with mpatch("x64dbg_automate.external.pe_analyzer.get_exports") as mock_exp:
            mock_exp.return_value = [
                {"name": "CreateFileA", "ordinal": 1, "virtual_address": 0x1000},
                {"name": "CloseHandle", "ordinal": 2, "virtual_address": 0x2000},
            ]
            r = resolve_ordinal("kernel32.dll", 2)
        assert r["success"]
        assert r["name"] == "CloseHandle"
        assert r["ordinal"] == 2

    def test_resolve_ordinal_not_found(self, tmp_path):
        from unittest.mock import patch as mpatch
        from x64dbg_automate.api_runtime.api_symbols import resolve_ordinal

        with mpatch("x64dbg_automate.external.pe_analyzer.get_exports") as mock_exp:
            mock_exp.return_value = [{"name": "Foo", "ordinal": 1, "virtual_address": 0x1000}]
            r = resolve_ordinal("test.dll", 99)
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_get_type_layout_unicode_string_x64(self):
        from x64dbg_automate.api_runtime.api_symbols import get_type_layout

        r = get_type_layout("UNICODE_STRING", arch="x64")
        assert r["success"]
        assert r["type_name"] == "UNICODE_STRING"
        assert r["pointer_size"] == 8
        names = [f["name"] for f in r["fields"]]
        assert "Length" in names
        assert "Buffer" in names

    def test_get_type_layout_unknown_type(self):
        from x64dbg_automate.api_runtime.api_symbols import get_type_layout

        r = get_type_layout("BOGUS_STRUCT")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_get_type_layout_bad_arch(self):
        from x64dbg_automate.api_runtime.api_symbols import get_type_layout

        r = get_type_layout("PEB", arch="arm64")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_get_type_info_unicode_string(self, manager):
        from x64dbg_automate.api_runtime.api_symbols import get_type_info

        sb = _mock_sandbox(manager, arch="x64")
        sb.client.is_running.return_value = False
        # UNICODE_STRING x64: Length(u16)=10, MaxLen(u16)=20, pad(4), Buffer(ptr)=0xDEAD0000
        import struct
        raw = struct.pack("<HH", 10, 20) + b"\x00" * 4 + struct.pack("<Q", 0xDEAD0000)
        # Extra bytes so read_memory returns enough
        raw += b"\x00" * 32
        sb.client.read_memory.return_value = raw
        sb.client.get_symbol_at.return_value = None
        r = get_type_info(sandbox_id="aa11", address="0x500000", type_name="UNICODE_STRING")
        assert r["success"]
        assert r["type_name"] == "UNICODE_STRING"
        fields = {f["name"]: f["value"] for f in r["fields"]}
        assert fields["Length"] == "0xA"
        assert fields["Buffer"] == "0xDEAD0000"

    def test_get_type_info_unknown_type(self, manager):
        from x64dbg_automate.api_runtime.api_symbols import get_type_info

        _mock_sandbox(manager)
        r = get_type_info(sandbox_id="aa11", address="0x401000", type_name="BOGUS")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND


# ---------------------------------------------------------------------------
# Coverage tools
# ---------------------------------------------------------------------------

class TestCoverageTools:
    def test_coverage_start(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_start

        sb = _mock_sandbox(manager, sid="cc11")
        sb.client.is_running.return_value = False
        sb.client.coverage_start.return_value = (True, 0)
        r = coverage_start(sandbox_id="cc11")
        assert r["success"]
        assert r["active"] is True
        assert r["existing_count"] == 0
        sb.client.coverage_start.assert_called_once()

    def test_coverage_stop(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_stop

        sb = _mock_sandbox(manager, sid="cc11")
        sb.client.is_running.return_value = False
        sb.client.coverage_stop.return_value = (False, 42)
        r = coverage_stop(sandbox_id="cc11")
        assert r["success"]
        assert r["active"] is False
        assert r["total_count"] == 42

    def test_coverage_query_flat(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_query

        sb = _mock_sandbox(manager, sid="cc11")
        addrs = [0x401000, 0x401010, 0x401020]
        sb.client.coverage_get.return_value = addrs
        r = coverage_query(sandbox_id="cc11")
        assert r["success"]
        assert r["total"] == 3
        assert "0x401000" in r["addresses"]

    def test_coverage_query_with_filter(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_query
        from unittest.mock import patch as mpatch

        sb = _mock_sandbox(manager, sid="cc11")
        sb.client.coverage_get.return_value = [0x401000]
        with mpatch("x64dbg_automate.api_runtime.runtime_helpers.resolve_addr") as mock_ra:
            mock_ra.side_effect = lambda c, expr: int(expr, 16)
            r = coverage_query(
                sandbox_id="cc11",
                start_address="0x401000",
                end_address="0x402000",
            )
        assert r["success"]
        sb.client.coverage_get.assert_called_with(0x401000, 0x402000)

    def test_coverage_clear(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_clear

        sb = _mock_sandbox(manager, sid="cc11")
        sb.client.coverage_clear.return_value = True
        r = coverage_clear(sandbox_id="cc11")
        assert r["success"]
        assert r["cleared"] is True

    def test_coverage_no_client(self, manager):
        from x64dbg_automate.api_runtime.api_coverage import coverage_start

        sb = ProcessSandbox(
            sandbox_id="noconn",
            debugger_pid=0,
            debugger_arch="x64",
            created_at=__import__("datetime").datetime.now(),
            client=None,
        )
        manager._sandboxes["noconn"] = sb
        r = coverage_start(sandbox_id="noconn")
        assert r["success"] is False


# ---------------------------------------------------------------------------
# Exception handler tools
# ---------------------------------------------------------------------------

class TestExceptionTools:
    def test_set_handler_break(self, manager):
        from x64dbg_automate.api_runtime.api_exceptions import exception_set_handler

        sb = _mock_sandbox(manager, sid="ex11")
        sb.client.is_running.return_value = False
        r = exception_set_handler(
            sandbox_id="ex11",
            exception_code="0xC0000094",
            action="break",
        )
        assert r["success"]
        assert r["exception_code"] == "0xC0000094"
        assert r["action"] == "break"
        sb.client.cmd_sync.assert_called_once()
        call_arg = sb.client.cmd_sync.call_args[0][0]
        assert "SetExceptionBPX" in call_arg
        assert "C0000094" in call_arg.upper()

    def test_set_handler_pass(self, manager):
        from x64dbg_automate.api_runtime.api_exceptions import exception_set_handler

        sb = _mock_sandbox(manager, sid="ex11")
        sb.client.is_running.return_value = False
        r = exception_set_handler(
            sandbox_id="ex11",
            exception_code="0xC0000094",
            action="pass",
        )
        assert r["success"]
        call_arg = sb.client.cmd_sync.call_args[0][0]
        assert "DeleteExceptionBPX" in call_arg

    def test_set_handler_invalid_action(self, manager):
        from x64dbg_automate.api_runtime.api_exceptions import exception_set_handler

        _mock_sandbox(manager, sid="ex11")
        r = exception_set_handler(
            sandbox_id="ex11",
            exception_code="0xC0000094",
            action="nuke",
        )
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_set_handler_bad_code(self, manager):
        from x64dbg_automate.api_runtime.api_exceptions import exception_set_handler

        _mock_sandbox(manager, sid="ex11")
        r = exception_set_handler(
            sandbox_id="ex11",
            exception_code="notanumber",
            action="break",
        )
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_exception_list_known(self):
        from x64dbg_automate.api_runtime.api_exceptions import exception_list_known

        r = exception_list_known()
        assert r["success"]
        assert r["total"] > 0
        codes = [e["code"] for e in r["exceptions"]]
        assert "0xC0000094" in codes

    def test_configure_protected(self, manager):
        from x64dbg_automate.api_runtime.api_exceptions import exception_configure_protected

        sb = _mock_sandbox(manager, sid="ex11")
        sb.client.is_running.return_value = False
        r = exception_configure_protected(sandbox_id="ex11")
        assert r["success"]
        assert r["all_succeeded"]
        assert len(r["applied"]) == 3


# ---------------------------------------------------------------------------
# Macro record-replay (C4)
# ---------------------------------------------------------------------------

class TestMacroTools:
    def test_macro_create_and_get(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_get, macro_delete,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        r = macro_create("test_macro", "A test macro", steps=[
            {"tool": "get_threads", "params": {}}
        ])
        assert r["success"]
        assert r["macro_id"] == "test_macro"
        assert r["step_count"] == 1

        g = macro_get("test_macro")
        assert g["success"]
        assert g["description"] == "A test macro"
        assert len(g["steps"]) == 1

        macro_delete("test_macro")
        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_create_duplicate_rejected(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_create
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_dup.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("dup_macro")
        r = macro_create("dup_macro")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.INVALID_STATE

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_list(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_create, macro_list, macro_delete
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_list.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("m1", "First")
        macro_create("m2", "Second")
        r = macro_list()
        assert r["success"]
        assert r["total"] == 2
        ids = {m["macro_id"] for m in r["macros"]}
        assert ids == {"m1", "m2"}

        macro_delete("m1")
        macro_delete("m2")
        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_add_step(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_create, macro_add_step, macro_get
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_add.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("add_test")
        r = macro_add_step("add_test", "get_threads", {"sandbox_id": "aa11"})
        assert r["success"]
        assert r["step_count"] == 1

        r2 = macro_add_step("add_test", "get_modules", {}, save_as="mods")
        assert r2["step_count"] == 2

        g = macro_get("add_test")
        assert g["steps"][1].get("save_as") == "mods"

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_remove_step(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_remove_step, macro_get,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_rm.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("rm_test")
        macro_add_step("rm_test", "a", {})
        macro_add_step("rm_test", "b", {})
        macro_add_step("rm_test", "c", {})

        r = macro_remove_step("rm_test", 1)
        assert r["success"]
        assert r["step_count"] == 2

        g = macro_get("rm_test")
        assert [s["tool"] for s in g["steps"]] == ["a", "c"]

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_run_with_mock_tools(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_run,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_run.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("run_test")
        macro_add_step("run_test", "memory_stats", {})
        macro_add_step("run_test", "memory_list_keys", {}, save_as="keys")

        r = macro_run("run_test")
        assert r["success"]
        assert r["total_steps"] == 2
        assert r["executed_steps"] == 2
        assert r["all_success"] is True
        assert "keys" in r["saved"]

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_run_param_override(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_run,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_override.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("override_test")
        macro_add_step("override_test", "memory_query_findings",
                        {"key": "{target}"})

        r = macro_run("override_test", {"target": "sub_1234"})
        assert r["success"]
        assert r["results"][0]["success"] is True

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_run_stop_on_error(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_run,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_stop.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("stop_test")
        macro_add_step("stop_test", "memory_stats", {})
        macro_add_step("stop_test", "nonexistent_tool_xyz", {})
        macro_add_step("stop_test", "memory_list_keys", {})

        r = macro_run("stop_test", stop_on_error=True)
        assert r["success"]  # macro_run itself succeeds
        assert r["executed_steps"] == 2  # stopped at the failed step
        assert r["all_success"] is False

        r2 = macro_run("stop_test", stop_on_error=False)
        assert r2["executed_steps"] == 3  # continued through errors
        assert r2["all_success"] is False

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_export_import(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_export, macro_import, macro_get, macro_delete,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_ei.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("ei_test", "Export/import test")
        macro_add_step("ei_test", "memory_stats", {})

        exp = macro_export("ei_test")
        assert exp["success"]
        assert "export" in exp
        assert "format_version" in exp["export"]

        macro_delete("ei_test")

        r = macro_import(exp["export"])
        assert r["success"]
        assert r["macro_id"] == "ei_test"

        g = macro_get("ei_test")
        assert g["description"] == "Export/import test"

        macro_delete("ei_test")
        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_record_start_stop(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_record_start, macro_record_stop, macro_get,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_rec.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        r = macro_record_start("rec_test", "Test recording")
        assert r["success"]
        assert r["status"] == "recording"

        # Simulate a recorded call by injecting into active recordings directly
        from x64dbg_automate.api_runtime.api_macros import _ACTIVE_RECORDINGS
        _ACTIVE_RECORDINGS["rec_test"]["steps"].append(
            {"tool": "memory_stats", "params": {}}
        )
        _ACTIVE_RECORDINGS["rec_test"]["steps"].append(
            {"tool": "memory_list_keys", "params": {}}
        )

        s = macro_record_stop("rec_test")
        assert s["success"]
        assert s["saved"] is True
        assert s["step_count"] == 2

        g = macro_get("rec_test")
        assert len(g["steps"]) == 2

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_record_duplicate_rejected(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_record_start
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_rec_dup.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_record_start("dup_rec")
        r = macro_record_start("dup_rec")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.INVALID_STATE

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_delete_not_found(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_delete
        import x64dbg_automate.api_runtime.semantic_memory as sem

        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", "unused.jsonl")
        monkeypatch.setattr(sem, "_store", None)

        r = macro_delete("no_such_macro")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_macro_run_not_found(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_run
        import x64dbg_automate.api_runtime.semantic_memory as sem

        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", "unused.jsonl")
        monkeypatch.setattr(sem, "_store", None)

        r = macro_run("no_such_macro")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.NOT_FOUND

    def test_macro_run_empty_steps(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_create, macro_run
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_empty.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        macro_create("empty_test")
        r = macro_run("empty_test")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.INVALID_STATE

        if os.path.exists(tmp):
            os.remove(tmp)

    def test_macro_import_invalid_json(self, monkeypatch):
        from x64dbg_automate.api_runtime.api_macros import macro_import
        import x64dbg_automate.api_runtime.semantic_memory as sem

        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", "unused.jsonl")
        monkeypatch.setattr(sem, "_store", None)

        r = macro_import("not json")
        assert r["success"] is False
        assert r["error_type"] == ErrorType.BAD_ARGUMENT

    def test_macro_read_only_blocks_unsafe(self, monkeypatch, manager):
        from x64dbg_automate.api_runtime.api_macros import (
            macro_create, macro_add_step, macro_run,
        )
        # Ensure patch_apply is registered in _UNSAFE_NAMES
        from x64dbg_automate.api_runtime.api_patches import patch_apply  # noqa: F401
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_macros_ro.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)
        monkeypatch.setenv("X64DBG_MCP_READ_ONLY", "1")

        macro_create("ro_test")
        macro_add_step("ro_test", "patch_apply", {"sandbox_id": "aa11", "address": "0x401000", "hex_bytes": "90"})

        r = macro_run("ro_test")
        assert r["success"]  # macro_run succeeds
        assert r["all_success"] is False
        assert "read-only" in r["results"][0]["error"].lower()

        monkeypatch.delenv("X64DBG_MCP_READ_ONLY", raising=False)
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# Decompiler (C1)
# ---------------------------------------------------------------------------

class TestDecompiler:
    def test_simple_function(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # push rbp; mov rbp, rsp; mov eax, 1; pop rbp; ret
        code = bytes.fromhex('554889e5b8010000005dc3')
        result = decompile_function(code, 0x401000, 'x64', 'simple')
        assert result.function_name == "simple"
        assert "eax = 1;" in result.pseudocode
        assert "return;" in result.pseudocode
        # Prologue/epilogue should be suppressed
        assert "push rbp" not in result.pseudocode
        assert "pop rbp" not in result.pseudocode

    def test_if_else(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # if/else with param1 == 5
        code = bytes.fromhex('554889e583f9057507b801000000eb05b8020000005dc3')
        result = decompile_function(code, 0x401000, 'x64', 'if_test')
        assert "if (param1 == 5) {" in result.pseudocode
        assert "eax = 1;" in result.pseudocode
        assert "} else {" in result.pseudocode
        assert "eax = 2;" in result.pseudocode

    def test_prologue_detected(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # Standard prologue: push rbp; mov rbp, rsp; sub rsp, 0x10
        code = bytes.fromhex('554889e54883ec10b801000000c9c3')
        result = decompile_function(code, 0x401000, 'x64', 'prologue')
        assert result.calling_convention == "__fastcall"
        assert result.stack_frame_size == 0x10
        assert "push rbp" not in result.pseudocode

    def test_local_var_recovery(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # mov [rbp-8], rcx; mov rax, [rbp-8]  (Windows x64: rcx = param1)
        code = bytes.fromhex('554889e54883ec1048894df8488b45f8c9c3')
        result = decompile_function(code, 0x401000, 'x64', 'locals')
        assert "local_1" in result.pseudocode
        assert "param1" in result.pseudocode  # rcx mapped to param1
        assert "param1" in result.pseudocode

    def test_x86_function(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # x86: push ebp; mov ebp, esp; mov eax, 42; pop ebp; ret
        code = bytes.fromhex('5589e5b82a0000005dc3')
        result = decompile_function(code, 0x401000, 'x32', 'x86_test')
        assert result.arch == "x32"
        assert "eax = 0x2A;" in result.pseudocode
        assert "push ebp" not in result.pseudocode

    def test_max_lines_truncation(self):
        from x64dbg_automate.external.decompiler import decompile_function

        # Many nops to make a long function
        code = bytes.fromhex('554889e5') + b'\x90' * 100 + bytes.fromhex('5dc3')
        result = decompile_function(code, 0x401000, 'x64', 'long', max_lines=10)
        lines = result.pseudocode.splitlines()
        assert len(lines) <= 12  # 10 + signature + closing brace
        assert "more lines" in result.pseudocode or len(lines) <= 10

    def test_decompile_range_tool(self, manager):
        from x64dbg_automate.api_runtime.api_decompiler import decompile_range

        sb = _mock_sandbox(manager)
        # Mock memory with two functions separated by nops
        sb.client.read_memory.return_value = (
            bytes.fromhex('554889e5b8010000005dc3')  # func1 at +0
            + b'\x90' * 16
            + bytes.fromhex('554889e5b8020000005dc3')  # func2 at +32
        )
        r = decompile_range(start_address="0x401000", size=64, sandbox_id="aa11")
        assert r["success"]
        assert r["total_found"] >= 1
        assert any("0x401000" == f["address"] for f in r["functions"])

    def test_get_function_type(self, manager):
        from x64dbg_automate.api_runtime.api_decompiler import get_function_type

        sb = _mock_sandbox(manager)
        sb.client.read_memory.return_value = bytes.fromhex('554889e54883ec10b801000000c9c3')
        r = get_function_type(address="0x401000", sandbox_id="aa11")
        assert r["success"]
        assert "__fastcall" in r["signature"] or "fastcall" in r["calling_convention"]
        assert len(r["args"]) >= 1

    def test_rename_and_list(self, monkeypatch, manager):
        from x64dbg_automate.api_runtime.api_decompiler import (
            rename_local_variable, list_variable_renames,
        )
        import x64dbg_automate.api_runtime.semantic_memory as sem

        tmp = os.path.join(os.getcwd(), "test_decompiler_renames.jsonl")
        monkeypatch.setattr(sem, "_DEFAULT_MEMORY_PATH", tmp)
        monkeypatch.setattr(sem, "_store", None)

        sb = _mock_sandbox(manager)
        sb.client.read_memory.return_value = bytes.fromhex('554889e5b8010000005dc3')

        r = rename_local_variable(
            function_address="0x401000",
            old_name="local_1",
            new_name="aes_key",
            sandbox_id="aa11",
        )
        assert r["success"]
        assert r["new_name"] == "aes_key"

        r2 = list_variable_renames(function_address="0x401000", sandbox_id="aa11")
        assert r2["success"]
        assert r2["renames"].get("local_1") == "aes_key"

        if os.path.exists(tmp):
            os.remove(tmp)


class TestRunningGuard:
    """Mock tests for ensure_running() and running_guard()."""

    def test_ensure_running_when_paused(self, manager):
        sb = _mock_sandbox(manager)
        self._bind_mixin_methods(sb.client)
        sb.client.is_running.side_effect = [False, True]
        sb.client.go.return_value = True
        sb.client.wait_until_running.return_value = True

        assert sb.client.ensure_running(timeout=1.0) is True
        sb.client.go.assert_called_once()
        sb.client.wait_until_running.assert_called_once_with(timeout=1.0)

    def test_ensure_running_when_already_running(self, manager):
        sb = _mock_sandbox(manager)
        self._bind_mixin_methods(sb.client)
        sb.client.is_running.return_value = True

        assert sb.client.ensure_running(timeout=1.0) is True
        sb.client.go.assert_not_called()

    def _bind_mixin_methods(self, mock_client):
        import types
        from x64dbg_automate import X64DbgClient
        from x64dbg_automate.events import DebugEventQueueMixin
        from x64dbg_automate.api_runtime.debugger_state import DebuggerStateMachine
        from x64dbg_automate.api_runtime.execution_context import ExecutionContextManager
        mock_client._axon_state_machine = DebuggerStateMachine()
        mock_client._axon_exec_ctx = ExecutionContextManager(mock_client, mock_client._axon_state_machine)
        mock_client.ensure_running = types.MethodType(X64DbgClient.ensure_running, mock_client)
        mock_client.running_guard = types.MethodType(X64DbgClient.running_guard, mock_client)
        mock_client.debug_event_publish = types.MethodType(DebugEventQueueMixin.debug_event_publish, mock_client)

    def test_running_guard_auto_resume_fires(self, manager):
        from x64dbg_automate.events import EventType
        sb = _mock_sandbox(manager)
        self._bind_mixin_methods(sb.client)
        sb.client.go.return_value = True

        with sb.client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
            # Simulate an OutputDebugString event being published
            sb.client.debug_event_publish(["EVENT_OUTPUT_DEBUG_STRING", b"test\x00"])

        # go() should have been called from the auto-resume handler
        sb.client.go.assert_called()

    def test_running_guard_no_resume_for_untracked_events(self, manager):
        from x64dbg_automate.events import EventType
        sb = _mock_sandbox(manager)
        self._bind_mixin_methods(sb.client)
        sb.client.go.return_value = True

        with sb.client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
            # Simulate a different event type
            sb.client.debug_event_publish(["EVENT_RESUME_DEBUG"])

        sb.client.go.assert_not_called()

    def test_running_guard_restores_state_on_exit(self, manager):
        from x64dbg_automate.events import EventType
        sb = _mock_sandbox(manager)
        self._bind_mixin_methods(sb.client)
        sb.client.go.return_value = True

        original_events = sb.client._auto_resume_events.copy()
        original_fn = sb.client._auto_resume_fn

        with sb.client.running_guard({EventType.EVENT_OUTPUT_DEBUG_STRING}):
            assert EventType.EVENT_OUTPUT_DEBUG_STRING in sb.client._auto_resume_events

        assert sb.client._auto_resume_events == original_events
        assert sb.client._auto_resume_fn == original_fn


class TestInfrastructureTools:
    """Mock tests for get_debugger_state, wait_for_stable_state, force_resume, get_execution_log."""

    def test_get_debugger_state_connected(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import get_debugger_state
        from x64dbg_automate.api_runtime.debugger_state import DebuggerStateMachine, DebuggerState
        sb = _mock_sandbox(manager)
        sm = DebuggerStateMachine()
        sm.transition(DebuggerState.RUNNING, reason="test")
        sb.client._axon_state_machine = sm

        r = get_debugger_state(sandbox_id="aa11")
        assert r["success"]
        assert r["state"] == "running"
        assert r["is_healthy"] is True
        assert r["is_executing"] is True

    def test_get_debugger_state_not_connected(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import get_debugger_state
        r = get_debugger_state(sandbox_id="ghost")
        assert not r["success"]
        assert r["error_type"] == "NOT_CONNECTED"

    def test_wait_for_stable_state_reaches_running(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import wait_for_stable_state
        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = True
        sb.client.is_debugging.return_value = True

        r = wait_for_stable_state(sandbox_id="aa11", desired_state="running", timeout=1.0, poll_interval=0.05)
        assert r["success"]
        assert r["reached"] is True
        assert r["actual_state"] == "running"

    def test_wait_for_stable_state_timeout(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import wait_for_stable_state
        sb = _mock_sandbox(manager)
        sb.client.is_running.return_value = False
        sb.client.is_debugging.return_value = True

        r = wait_for_stable_state(sandbox_id="aa11", desired_state="running", timeout=0.1, poll_interval=0.05)
        assert not r["success"]
        assert r["error_type"] == "TIMEOUT"

    def test_force_resume_success(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import force_resume
        sb = _mock_sandbox(manager)
        sb.client.go.return_value = True

        r = force_resume(sandbox_id="aa11")
        assert r["success"]
        assert r["attempts"] == 1

    def test_force_resume_eventual_success(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import force_resume
        sb = _mock_sandbox(manager)
        sb.client.go.side_effect = [False, False, True]

        r = force_resume(sandbox_id="aa11")
        assert r["success"]
        assert r["attempts"] == 3

    def test_force_resume_failure(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import force_resume
        sb = _mock_sandbox(manager)
        sb.client.go.return_value = False

        r = force_resume(sandbox_id="aa11")
        assert not r["success"]

    def test_get_execution_log(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import get_execution_log
        from x64dbg_automate.api_runtime.debugger_state import DebuggerState, DebuggerStateMachine
        sb = _mock_sandbox(manager)
        sm = DebuggerStateMachine()
        sm.transition(DebuggerState.RUNNING, reason="test")
        sm.transition(DebuggerState.STOPPED, reason="test_stop")
        sb.client._axon_state_machine = sm

        r = get_execution_log(sandbox_id="aa11", n=5)
        assert r["success"]
        assert r["count"] == 2
        assert len(r["transitions"]) == 2

    def test_get_execution_log_no_state_machine(self, manager):
        from x64dbg_automate.api_runtime.api_infrastructure import get_execution_log
        from x64dbg_automate.api_runtime.supervisor import get_manager
        from unittest.mock import MagicMock
        sb = _mock_sandbox(manager)
        # Use a spec'd mock so _axon_state_machine is not auto-created
        plain = MagicMock(spec=["is_running", "is_debugging"])
        plain.is_running.return_value = True
        plain.is_debugging.return_value = True
        sb.client = plain
        mgr = get_manager()
        mgr._sandboxes["aa11"] = sb

        r = get_execution_log(sandbox_id="aa11", n=5)
        assert not r["success"]
