"""Unit tests for the MCP server. Uses mocked X64DbgClient — no running x64dbg required."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from x64dbg_automate.mcp_server import (
    _format_address,
    _format_memory,
    _parse_address_or_expression,
    _pe_bitness,
    _resolve_debugger_path,
    _resolve_x64dbg_path_with_env,
    _require_client,
)
from x64dbg_automate.models import (
    Breakpoint,
    BreakpointType,
    Context64,
    Flags,
    FpuReg,
    Instruction,
    MemPage,
    MxcsrFields,
    RegDump64,
    Symbol,
    SymbolType,
    X87ControlWordFields,
    X87Fpu,
    X87StatusWordFields,
    DisasmInstrType,
)
from x64dbg_automate.events import EventType

# We need to import tool functions — they use the module-level _client global
import x64dbg_automate.mcp_server as mcp_mod


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestParseAddress:
    def test_hex_with_prefix(self):
        assert _parse_address_or_expression("0x7FF6A000") == 0x7FF6A000

    def test_hex_without_prefix(self):
        assert _parse_address_or_expression("7FF6A000") == 0x7FF6A000

    def test_hex_uppercase_prefix(self):
        assert _parse_address_or_expression("0X1234ABCD") == 0x1234ABCD

    def test_leading_trailing_spaces(self):
        assert _parse_address_or_expression("  0xDEAD  ") == 0xDEAD

    def test_zero(self):
        assert _parse_address_or_expression("0") == 0

    def test_plain_decimal_fallback(self):
        # "10" is valid hex, so it should parse as hex (16)
        assert _parse_address_or_expression("10") == 0x10

    def test_expression_fallback(self):
        """Non-hex strings fall back to eval_sync via the connected client."""
        mock_client = MagicMock()
        mock_client.eval_sync.return_value = (0x401000, True)
        original = mcp_mod._client
        mcp_mod._client = mock_client
        try:
            assert _parse_address_or_expression("RIP") == 0x401000
            mock_client.eval_sync.assert_called_once_with("RIP")
        finally:
            mcp_mod._client = original

    def test_expression_fallback_failure(self):
        """eval_sync failure raises ValueError."""
        mock_client = MagicMock()
        mock_client.eval_sync.return_value = (0, False)
        original = mcp_mod._client
        mcp_mod._client = mock_client
        try:
            with pytest.raises(ValueError, match="Cannot resolve"):
                _parse_address_or_expression("bad_symbol")
        finally:
            mcp_mod._client = original


class TestFormatAddress:
    def test_basic(self):
        assert _format_address(0x7FF6A000) == "0x7FF6A000"

    def test_zero(self):
        assert _format_address(0) == "0x0"


class TestFormatMemory:
    def test_single_line(self):
        data = bytes(range(16))
        result = _format_memory(data, 0x1000)
        assert "0x1000" in result
        assert "00 01 02" in result
        # ASCII sidebar should contain '.' for non-printable
        assert ".." in result

    def test_multiple_lines(self):
        data = bytes(range(32))
        result = _format_memory(data, 0x2000)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        assert "0x2000" in lines[0]
        assert "0x2010" in lines[1]

    def test_partial_last_line(self):
        data = bytes(range(20))
        result = _format_memory(data, 0)
        lines = result.strip().split("\n")
        assert len(lines) == 2

    def test_empty(self):
        result = _format_memory(b"", 0)
        assert result == ""


class TestRequireClient:
    def test_raises_when_no_client(self):
        original = mcp_mod._client
        try:
            mcp_mod._client = None
            with pytest.raises(RuntimeError, match="Not connected"):
                _require_client()
        finally:
            mcp_mod._client = original


class TestPeBitness:
    def test_pe64(self, tmp_path):
        """Minimal PE with AMD64 machine type."""
        pe = _make_minimal_pe(0x8664)
        f = tmp_path / "test64.exe"
        f.write_bytes(pe)
        assert _pe_bitness(str(f)) == 64

    def test_pe32(self, tmp_path):
        """Minimal PE with i386 machine type."""
        pe = _make_minimal_pe(0x14C)
        f = tmp_path / "test32.exe"
        f.write_bytes(pe)
        assert _pe_bitness(str(f)) == 32

    def test_not_pe(self, tmp_path):
        f = tmp_path / "bad.exe"
        f.write_bytes(b"NOT_A_PE_FILE")
        with pytest.raises(ValueError, match="Not a valid PE"):
            _pe_bitness(str(f))


class TestResolveDebuggerPath:
    def test_passthrough_x64dbg(self, tmp_path):
        """x64dbg.exe is returned as-is."""
        p = tmp_path / "x64dbg.exe"
        p.write_bytes(b"")
        assert _resolve_debugger_path(str(p)) == str(p)

    def test_passthrough_x32dbg(self, tmp_path):
        p = tmp_path / "x32dbg.exe"
        p.write_bytes(b"")
        assert _resolve_debugger_path(str(p)) == str(p)

    def test_x96dbg_resolves_64(self, tmp_path):
        """x96dbg.exe + 64-bit target -> x64/x64dbg.exe (standard layout)."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x64_dir = tmp_path / "x64"
        x64_dir.mkdir()
        dbg = x64_dir / "x64dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x8664))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_resolves_32(self, tmp_path):
        """x96dbg.exe + 32-bit target -> x32/x32dbg.exe (standard layout)."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x32_dir = tmp_path / "x32"
        x32_dir.mkdir()
        dbg = x32_dir / "x32dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x14C))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_flat_layout(self, tmp_path):
        """Falls back to same-directory layout if x64/ doesn't exist."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        dbg = tmp_path / "x64dbg.exe"
        dbg.write_bytes(b"")
        target = tmp_path / "target.exe"
        target.write_bytes(_make_minimal_pe(0x8664))
        result = _resolve_debugger_path(str(launcher), str(target))
        assert result == str(dbg)

    def test_x96dbg_no_target_defaults_64(self, tmp_path):
        """No target exe defaults to 64-bit."""
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        x64_dir = tmp_path / "x64"
        x64_dir.mkdir()
        dbg = x64_dir / "x64dbg.exe"
        dbg.write_bytes(b"")
        result = _resolve_debugger_path(str(launcher))
        assert result == str(dbg)

    def test_x96dbg_not_found(self, tmp_path):
        launcher = tmp_path / "x96dbg.exe"
        launcher.write_bytes(b"")
        with pytest.raises(FileNotFoundError, match="Cannot find"):
            _resolve_debugger_path(str(launcher))


class TestResolveX64dbgPathWithEnv:
    def test_explicit_param_used(self):
        result = _resolve_x64dbg_path_with_env("C:\\x64dbg\\x64dbg.exe")
        assert result == "C:\\x64dbg\\x64dbg.exe"

    def test_explicit_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x64dbg.exe")
        result = _resolve_x64dbg_path_with_env("C:\\param\\x64dbg.exe")
        assert result == "C:\\param\\x64dbg.exe"

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        result = _resolve_x64dbg_path_with_env("")
        assert result == "C:\\env\\x96dbg.exe"

    def test_env_fallback_when_whitespace_only(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x64dbg.exe")
        result = _resolve_x64dbg_path_with_env("   ")
        assert result == "C:\\env\\x64dbg.exe"

    def test_no_param_no_env_raises(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        with pytest.raises(FileNotFoundError, match="X64DBG_PATH"):
            _resolve_x64dbg_path_with_env("")

    def test_env_whitespace_only_raises(self, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "   ")
        with pytest.raises(FileNotFoundError, match="X64DBG_PATH"):
            _resolve_x64dbg_path_with_env("")


def _make_minimal_pe(machine: int) -> bytes:
    """Build the smallest valid PE stub with a given machine type."""
    import struct
    pe_offset = 0x80
    dos_header = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", pe_offset) + b"\x00" * (pe_offset - 0x40)
    pe_sig = b"PE\x00\x00"
    machine_bytes = struct.pack("<H", machine)
    # Pad rest of COFF header (18 bytes remaining after machine)
    coff_rest = b"\x00" * 18
    return dos_header + pe_sig + machine_bytes + coff_rest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_client():
    """Provide a MagicMock client and patch it into the module global."""
    client = MagicMock()
    original = mcp_mod._client
    mcp_mod._client = client
    yield client
    mcp_mod._client = original


# ---------------------------------------------------------------------------
# Session tool tests
# ---------------------------------------------------------------------------

class TestListSessions:
    @patch.object(mcp_mod, "X64DbgClient")
    def test_no_sessions(self, mock_cls):
        mock_cls.list_sessions.return_value = []
        result = mcp_mod.list_sessions()
        assert result["success"] is True
        assert result["total"] == 0
        assert "sessions" in result

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = ["C:\\x64dbg\\x64\\x64dbg.exe", "--arg"]
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert result["success"] is True
        # Unregistered instances appear in available_unconnected, not sessions.
        assert len(result["available_unconnected"]) == 1
        assert result["available_unconnected"][0]["debugger_pid"] == 1234

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions_empty_cmdline(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = []
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert result["success"] is True
        assert len(result["available_unconnected"]) == 1

    @patch.object(mcp_mod, "X64DbgClient")
    def test_with_sessions_whitespace_cmdline(self, mock_cls):
        session = MagicMock()
        session.pid = 1234
        session.cmdline = ["   "]
        session.window_title = "x64dbg"
        session.sess_req_rep_port = 5555
        session.sess_pub_sub_port = 5556
        mock_cls.list_sessions.return_value = [session]
        result = mcp_mod.list_sessions()
        assert result["success"] is True
        assert len(result["available_unconnected"]) == 1

    @patch.object(mcp_mod, "X64DbgClient")
    def test_exception_returns_error(self, mock_cls):
        # list_sessions() swallows X64DbgClient.list_sessions() errors gracefully;
        # the tool still succeeds with zero available_unconnected entries.
        mock_cls.list_sessions.side_effect = NotImplementedError("Windows only")
        result = mcp_mod.list_sessions()
        assert result["success"] is True
        assert result["available_unconnected"] == []


class TestStartSession:
    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\x64dbg\\x64dbg.exe")
    def test_explicit_path(self, mock_resolve, mock_cls):
        mock_instance = MagicMock()
        mock_instance.start_session.return_value = 1234
        mock_cls.return_value = mock_instance
        result = mcp_mod.start_session(x64dbg_path="C:\\x64dbg\\x96dbg.exe")
        mock_resolve.assert_called_once_with("C:\\x64dbg\\x96dbg.exe", "")
        assert result["success"] is True
        assert result["debugger_pid"] == 1234

    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\env\\x64dbg.exe")
    def test_env_fallback(self, mock_resolve, mock_cls, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        mock_instance = MagicMock()
        mock_instance.start_session.return_value = 5678
        mock_cls.return_value = mock_instance
        result = mcp_mod.start_session()
        mock_resolve.assert_called_once_with("C:\\env\\x96dbg.exe", "")
        assert result["success"] is True
        assert result["debugger_pid"] == 5678

    def test_no_path_no_env_error(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        result = mcp_mod.start_session()
        assert result["success"] is False
        assert "X64DBG_PATH" in result["error"]


class TestConnectToSession:
    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\x64dbg\\x64dbg.exe")
    def test_explicit_path(self, mock_resolve, mock_cls):
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        result = mcp_mod.connect_to_session(x64dbg_path="C:\\x64dbg\\x96dbg.exe", session_pid=1234)
        mock_resolve.assert_called_once_with("C:\\x64dbg\\x96dbg.exe")
        assert result["success"] is True
        assert result["debugger_pid"] == 1234

    @patch.object(mcp_mod, "X64DbgClient")
    @patch.object(mcp_mod, "_resolve_debugger_path", return_value="C:\\env\\x64dbg.exe")
    def test_env_fallback(self, mock_resolve, mock_cls, monkeypatch):
        monkeypatch.setenv("X64DBG_PATH", "C:\\env\\x96dbg.exe")
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        result = mcp_mod.connect_to_session(session_pid=5678)
        mock_resolve.assert_called_once_with("C:\\env\\x96dbg.exe")
        assert result["success"] is True
        assert result["debugger_pid"] == 5678

    def test_no_path_no_env_error(self, monkeypatch):
        monkeypatch.delenv("X64DBG_PATH", raising=False)
        result = mcp_mod.connect_to_session(session_pid=9999)
        assert result["success"] is False
        assert "X64DBG_PATH" in result["error"]

    def test_missing_session_pid(self):
        result = mcp_mod.connect_to_session()
        assert result["success"] is False
        assert "session_pid" in result["error"]


class TestDisconnect:
    def test_no_connection(self):
        original = mcp_mod._client
        mcp_mod._client = None
        result = mcp_mod.disconnect()
        assert result["success"] is False
        mcp_mod._client = original

    def test_disconnect_success(self, mock_client):
        result = mcp_mod.disconnect()
        mock_client.detach_session.assert_called_once()
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Debug Control tool tests
# ---------------------------------------------------------------------------

class TestGetDebuggerStatus:
    def test_status(self, mock_client):
        mock_client.is_debugging.return_value = True
        mock_client.is_running.return_value = False
        mock_client.debugee_pid.return_value = 4321
        mock_client.debugee_bitness.return_value = 64
        mock_client.debugger_is_elevated.return_value = False
        result = mcp_mod.get_debugger_status()
        assert result["success"] is True
        assert result["debugging"] is True
        assert result["debuggee_pid"] == 4321
        assert result["bitness"] == 64


class TestGo:
    def test_go_success(self, mock_client):
        mock_client.go.return_value = True
        result = mcp_mod.go()
        assert result["success"] is True

    def test_go_failure(self, mock_client):
        mock_client.go.return_value = False
        result = mcp_mod.go()
        assert result["success"] is False


class TestPause:
    def test_pause_success(self, mock_client):
        mock_client.pause.return_value = True
        result = mcp_mod.pause()
        assert result["success"] is True


class TestStepInto:
    def test_step_into(self, mock_client):
        mock_client.stepi.return_value = True
        result = mcp_mod.step_into(count=3)
        mock_client.stepi.assert_called_once_with(step_count=3)
        assert result["success"] is True
        assert result["steps"] == 3


class TestStepOver:
    def test_step_over(self, mock_client):
        mock_client.stepo.return_value = True
        result = mcp_mod.step_over(count=2)
        mock_client.stepo.assert_called_once_with(step_count=2)
        assert result["success"] is True
        assert result["steps"] == 2


class TestSkipInstruction:
    def test_skip(self, mock_client):
        mock_client.skip.return_value = True
        result = mcp_mod.skip_instruction(count=1)
        assert result["success"] is True


class TestRunToReturn:
    def test_rtr(self, mock_client):
        mock_client.ret.return_value = True
        result = mcp_mod.run_to_return()
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Memory tool tests
# ---------------------------------------------------------------------------

class TestReadMemory:
    def test_read_memory(self, mock_client):
        mock_client.read_memory.return_value = b"\x90" * 16
        result = mcp_mod.read_memory("0x1000", 16)
        assert result["success"] is True
        assert result["address"] == "0x1000"
        assert "90" in result["bytes"]

    def test_size_capped(self, mock_client):
        mock_client.read_memory.return_value = b"\x00"
        mcp_mod.read_memory("0x1000", 9999)
        mock_client.read_memory.assert_called_once_with(0x1000, 4096)


class TestReadMemoryRaw:
    def test_read_memory_raw(self, mock_client):
        mock_client.read_memory.return_value = b"\x90\x91\x92\x93"
        result = mcp_mod.read_memory_raw("0x1000", 4)
        assert result["success"] is True
        assert result["address"] == "0x1000"
        assert result["size"] == 4
        assert result["bytes"] == "90919293"

    def test_read_memory_raw_size_capped(self, mock_client):
        mock_client.read_memory.return_value = b"\x00"
        mcp_mod.read_memory_raw("0x1000", 99999)
        mock_client.read_memory.assert_called_once_with(0x1000, 65536)

    def test_read_memory_raw_error(self, mock_client):
        mock_client.read_memory.side_effect = RuntimeError("unmapped")
        result = mcp_mod.read_memory_raw("0xBAD", 16)
        assert result["success"] is False
        assert "READ_FAILED" in result["error_type"]


class TestWriteMemory:
    def test_write(self, mock_client):
        mock_client.write_memory.return_value = True
        result = mcp_mod.write_memory("0x1000", "90 90 90")
        mock_client.write_memory.assert_called_once_with(0x1000, b"\x90\x90\x90")
        assert result["success"] is True
        assert result["bytes_written"] == 3


class TestAllocateMemory:
    def test_alloc(self, mock_client):
        mock_client.virt_alloc.return_value = 0xDEAD0000
        result = mcp_mod.allocate_memory(4096)
        assert result["success"] is True
        assert "0xDEAD0000" in result["address"]


class TestFreeMemory:
    def test_free(self, mock_client):
        mock_client.virt_free.return_value = True
        result = mcp_mod.free_memory("0xDEAD0000")
        assert result["success"] is True


class TestGetMemoryMap:
    def test_memmap(self, mock_client):
        page = MemPage(
            base_address=0x10000, allocation_base=0x10000, allocation_protect=0x40,
            partition_id=0, region_size=0x1000, state=0x1000, protect=0x20, type=0x20000, info="mapped"
        )
        mock_client.memmap.return_value = [page]
        result = mcp_mod.get_memory_map()
        assert result["success"] is True
        assert result["total"] == 1
        assert "0x10000" in result["regions"][0]["base_address"]
        assert result["regions"][0]["info"] == "mapped"


# ---------------------------------------------------------------------------
# Register tool tests
# ---------------------------------------------------------------------------

class TestGetRegister:
    def test_get_reg(self, mock_client):
        mock_client.get_reg.return_value = 0xDEADBEEF
        result = mcp_mod.get_register("rax")
        assert result["success"] is True
        assert "0xDEADBEEF" in result["value"]


class TestSetRegister:
    def test_set_reg(self, mock_client):
        mock_client.set_reg.return_value = True
        result = mcp_mod.set_register("rax", "0xCAFE")
        mock_client.set_reg.assert_called_once_with("rax", 0xCAFE)
        assert result["success"] is True
        assert result["register"] == "rax"


class TestGetAllRegisters:
    def test_get_all(self, mock_client):
        ctx = Context64(
            rax=1, rbx=2, rcx=3, rdx=4, rbp=5, rsp=6, rsi=7, rdi=8,
            r8=9, r9=10, r10=11, r11=12, r12=13, r13=14, r14=15, r15=16,
            rip=0x1000, eflags=0x246, cs=0x33, ds=0x2B, es=0x2B, fs=0x53, gs=0x2B, ss=0x2B,
            dr0=0, dr1=0, dr2=0, dr3=0, dr6=0, dr7=0,
            reg_area=b"\x00" * 80,
            x87_fpu=X87Fpu(ControlWord=0, StatusWord=0, TagWord=0, ErrorOffset=0,
                           ErrorSelector=0, DataOffset=0, DataSelector=0, Cr0NpxState=0),
            mxcsr=0, zmm_regs=[b"\x00" * 64] * 32,
        )
        flags = Flags(c=False, p=True, a=False, z=True, s=False, t=False, i=True, d=False, o=False)
        fpu = [FpuReg(data=b"\x00" * 10, st_value=0, tag=0)] * 8
        mxcsr_f = MxcsrFields(FZ=False, PM=False, UM=False, OM=False, ZM=False, IM=False,
                               DM=False, DAZ=False, PE=False, UE=False, OE=False, ZE=False,
                               DE=False, IE=False, RC=0)
        x87sw = X87StatusWordFields(B=False, C3=False, C2=False, C1=False, C0=False,
                                     ES=False, SF=False, P=False, U=False, O=False,
                                     Z=False, D=False, I=False, TOP=0)
        x87cw = X87ControlWordFields(IC=False, IEM=False, PM=False, UM=False, OM=False,
                                      ZM=False, DM=False, IM=False, RC=0, PC=0)
        regdump = RegDump64(
            context=ctx, flags=flags, fpu=fpu, mmx=[0] * 8,
            mxcsr_fields=mxcsr_f, x87_status_word_fields=x87sw,
            x87_control_word_fields=x87cw, last_error=(0, ""), last_status=(0, ""),
        )
        mock_client.get_regs.return_value = regdump
        result = mcp_mod.get_all_registers()
        assert result["success"] is True
        assert "rax" in result["registers"]
        assert "rip" in result["registers"]
        assert "flags" in result


# ---------------------------------------------------------------------------
# Expression & Command tool tests
# ---------------------------------------------------------------------------

class TestEvalExpression:
    def test_eval_success(self, mock_client):
        mock_client.eval_sync.return_value = (0xBEEF, True)
        result = mcp_mod.eval_expression("kernel32:CreateFileA")
        assert result["success"] is True
        assert "0xBEEF" in result["value"]

    def test_eval_failure(self, mock_client):
        mock_client.eval_sync.return_value = (0, False)
        result = mcp_mod.eval_expression("bad_expr")
        assert result["success"] is False


class TestExecuteCommand:
    def test_cmd(self, mock_client):
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.execute_command("msg hello")
        assert result["success"] is True

    def test_display_command_returns_output_note(self, mock_client):
        """P2: display-only commands (db, disasm, r, lm) must include output_note."""
        mock_client.cmd_sync.return_value = True
        for cmd in ("db 0x401000", "disasm 0x401000", "lm", "r"):
            result = mcp_mod.execute_command(cmd)
            assert result["success"] is True, f"failed for {cmd!r}"
            assert "output_note" in result, f"missing output_note for {cmd!r}"
            assert "RPC" in result["output_note"] or "GUI" in result["output_note"]

    def test_mutation_command_has_no_output_note(self, mock_client):
        """P2: state-mutation commands must NOT get an output_note."""
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.execute_command("seteip 0x401000")
        assert result["success"] is True
        assert "output_note" not in result

    def test_result_false_adds_result_note(self, mock_client):
        """P2: when result=False for a non-display command, result_note must explain it."""
        mock_client.cmd_sync.return_value = False
        result = mcp_mod.execute_command("someunknowncmd")
        assert result["success"] is True          # tool itself succeeded (RPC ran)
        assert result["result"] is False
        assert "result_note" in result
        assert "false" in result["result_note"].lower() or "rejected" in result["result_note"].lower()

    def test_output_note_hints_at_dedicated_tool(self, mock_client):
        """P2: the output_note for 'r' must direct agents to read_registers."""
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.execute_command("r")
        assert "read_registers" in result.get("output_note", "")


# ---------------------------------------------------------------------------
# Breakpoint tool tests
# ---------------------------------------------------------------------------

class TestSetBreakpoint:
    def test_software_bp(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000")
        assert result["success"] is True
        assert result["type"] == "software"

    def test_hardware_bp(self, mock_client):
        mock_client.set_hardware_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000", bp_type="hardware", hardware_mode="x")
        mock_client.set_hardware_breakpoint.assert_called_once()
        assert result["success"] is True

    def test_memory_bp(self, mock_client):
        mock_client.set_memory_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("0x401000", bp_type="memory")
        mock_client.set_memory_breakpoint.assert_called_once()
        assert result["success"] is True

    def test_symbol_name(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        result = mcp_mod.set_breakpoint("kernel32:CreateFileA")
        assert result["success"] is True

    def test_failure_returns_hint(self, mock_client):
        mock_client.set_breakpoint.return_value = False
        mock_client.virt_query.return_value = None
        result = mcp_mod.set_breakpoint("0x401000")
        assert result["success"] is False
        assert "hint" in result

    def test_duplicate_sw_bp_detected(self, mock_client):
        # x64dbg auto-creates a one-shot entry BP; setting a second one should
        # return DUPLICATE_BP before even calling set_breakpoint.
        existing = Breakpoint(
            type=BreakpointType.BpNormal, addr=0x401000, enabled=True, singleshoot=True,
            active=True, name="entry breakpoint", mod="target.exe", slot=0, typeEx=0, hwSize=0,
            hitCount=0, fastResume=False, silent=False, breakCondition="", logText="",
            logCondition="", commandText="", commandCondition="",
        )
        mock_client.get_breakpoints.return_value = [existing]
        result = mcp_mod.set_breakpoint("0x401000")
        assert result["success"] is False
        assert result["error_type"] == "DUPLICATE_BP"
        assert "existing_bp" in result
        assert result["existing_bp"]["name"] == "entry breakpoint"
        assert result["existing_bp"]["singleshot"] is True
        assert "clear_breakpoint" in result["hint"]
        mock_client.set_breakpoint.assert_not_called()

    def test_condition_applied(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.set_breakpoint("0x401000", condition="eax == 1")
        assert result["success"] is True
        mock_client.cmd_sync.assert_called_once()


class TestSetConditionalBreakpoint:
    def test_conditional_bp(self, mock_client):
        mock_client.set_breakpoint.return_value = True
        mock_client.cmd_sync.return_value = True
        result = mcp_mod.set_conditional_breakpoint("0x401000", condition="eax == 1")
        assert result["success"] is True
        assert result["condition"] == "eax == 1"
        assert result["condition_applied"] is True

    def test_conditional_bp_failure(self, mock_client):
        mock_client.set_breakpoint.return_value = False
        mock_client.virt_query.return_value = None
        result = mcp_mod.set_conditional_breakpoint("0x401000", condition="eax == 1")
        assert result["success"] is False
        assert "hint" in result


class TestClearBreakpoint:
    def test_clear_all_software(self, mock_client):
        mock_client.clear_breakpoint.return_value = True
        result = mcp_mod.clear_breakpoint()
        mock_client.clear_breakpoint.assert_called_once_with(None)
        assert result["success"] is True

    def test_clear_hardware(self, mock_client):
        mock_client.clear_hardware_breakpoint.return_value = True
        result = mcp_mod.clear_breakpoint("0x401000", bp_type="hardware")
        mock_client.clear_hardware_breakpoint.assert_called_once_with(0x401000)
        assert result["success"] is True


class TestToggleBreakpoint:
    def test_enable(self, mock_client):
        mock_client.toggle_breakpoint.return_value = True
        result = mcp_mod.toggle_breakpoint("0x401000", enable=True)
        assert result["success"] is True
        assert result["enabled"] is True

    def test_disable(self, mock_client):
        mock_client.toggle_breakpoint.return_value = True
        result = mcp_mod.toggle_breakpoint("0x401000", enable=False)
        assert result["success"] is True
        assert result["enabled"] is False


class TestListBreakpoints:
    def test_list_empty(self, mock_client):
        mock_client.get_breakpoints.return_value = []
        result = mcp_mod.list_breakpoints()
        assert result["success"] is True
        assert result["total"] == 0

    def test_list_with_bps(self, mock_client):
        bp = Breakpoint(
            type=BreakpointType.BpNormal, addr=0x401000, enabled=True, singleshoot=False,
            active=True, name="test_bp", mod="test.exe", slot=0, typeEx=0, hwSize=0,
            hitCount=5, fastResume=False, silent=False, breakCondition="", logText="",
            logCondition="", commandText="", commandCondition="",
        )
        mock_client.get_breakpoints.return_value = [bp]
        result = mcp_mod.list_breakpoints()
        assert result["success"] is True
        assert result["total"] == 1
        assert "0x401000" in result["breakpoints"][0]["address"]
        assert result["breakpoints"][0]["name"] == "test_bp"
        assert result["breakpoints"][0]["hit_count"] == 5


# ---------------------------------------------------------------------------
# Assembly tool tests
# ---------------------------------------------------------------------------

class TestDisassemble:
    def test_disassemble(self, mock_client):
        ins1 = Instruction(
            instruction="nop", argcount=0, instr_size=1,
            type=DisasmInstrType.Normal, arg=[],
        )
        ins2 = Instruction(
            instruction="ret", argcount=0, instr_size=1,
            type=DisasmInstrType.Normal, arg=[],
        )
        mock_client.disassemble_at.side_effect = [ins1, ins2]
        result = mcp_mod.disassemble("0x1000", count=2)
        assert result["success"] is True
        assert result["total"] == 2
        mnemonics = [i["mnemonic"] for i in result["instructions"]]
        assert "nop" in mnemonics
        assert "ret" in mnemonics
        assert "0x1000" in result["instructions"][0]["address"]

    def test_disassemble_failure(self, mock_client):
        mock_client.disassemble_at.return_value = None
        result = mcp_mod.disassemble("0x1000", count=1)
        assert result["success"] is True
        assert result["total"] == 0
        assert result["instructions"] == []


class TestAssemble:
    def test_assemble(self, mock_client):
        mock_client.assemble_at.return_value = 1
        result = mcp_mod.assemble("0x1000", "nop")
        assert result["success"] is True
        assert result["instruction"] == "nop"
        assert result["bytes_written"] == 1


# ---------------------------------------------------------------------------
# Annotation & Symbol tool tests
# ---------------------------------------------------------------------------

class TestLabels:
    def test_set_label(self, mock_client):
        mock_client.set_label_at.return_value = True
        result = mcp_mod.set_label("0x1000", "my_func")
        assert result["success"] is True
        assert result["text"] == "my_func"

    def test_get_label(self, mock_client):
        mock_client.get_label_at.return_value = "my_func"
        result = mcp_mod.get_label("0x1000")
        assert result["success"] is True
        assert result["label"] == "my_func"

    def test_get_label_empty(self, mock_client):
        mock_client.get_label_at.return_value = ""
        result = mcp_mod.get_label("0x1000")
        assert result["success"] is True
        assert result["label"] == ""


class TestComments:
    def test_set_comment(self, mock_client):
        mock_client.set_comment_at.return_value = True
        result = mcp_mod.set_comment("0x1000", "interesting")
        assert result["success"] is True
        assert result["text"] == "interesting"

    def test_get_comment(self, mock_client):
        mock_client.get_comment_at.return_value = "interesting"
        result = mcp_mod.get_comment("0x1000")
        assert result["success"] is True
        assert result["comment"] == "interesting"


class TestGetSymbol:
    def test_found(self, mock_client):
        sym = Symbol(addr=0x1000, decoratedSymbol="_func", undecoratedSymbol="func",
                     type=SymbolType.SymExport, ordinal=1)
        mock_client.get_symbol_at.return_value = sym
        result = mcp_mod.get_symbol("0x1000")
        assert result["success"] is True
        assert result["found"] is True
        assert "func" in result["undecorated"]
        assert "0x1000" in result["address"]

    def test_not_found(self, mock_client):
        mock_client.get_symbol_at.return_value = None
        result = mcp_mod.get_symbol("0x1000")
        assert result["success"] is True
        assert result["found"] is False


# ---------------------------------------------------------------------------
# Thread tool tests
# ---------------------------------------------------------------------------

class TestThreads:
    def test_create_thread(self, mock_client):
        mock_client.thread_create.return_value = 42
        result = mcp_mod.create_thread("0x1000", "0")
        assert result["success"] is True
        assert result["tid"] == 42

    def test_terminate_thread(self, mock_client):
        mock_client.thread_terminate.return_value = True
        result = mcp_mod.terminate_thread(42)
        assert result["success"] is True
        assert result["tid"] == 42

    def test_pause_thread(self, mock_client):
        mock_client.thread_pause.return_value = True
        result = mcp_mod.pause_resume_thread(42, "pause")
        assert result["success"] is True
        assert result["action"] == "pause"

    def test_resume_thread(self, mock_client):
        mock_client.thread_resume.return_value = True
        result = mcp_mod.pause_resume_thread(42, "resume")
        assert result["success"] is True
        assert result["action"] == "resume"

    def test_switch_thread(self, mock_client):
        mock_client.switch_thread.return_value = True
        result = mcp_mod.switch_thread(42)
        assert result["success"] is True
        assert result["tid"] == 42


# ---------------------------------------------------------------------------
# Event tool tests
# ---------------------------------------------------------------------------

class TestEvents:
    def test_get_latest_event_empty(self, mock_client):
        mock_client.get_latest_debug_event.return_value = None
        result = mcp_mod.get_latest_event()
        assert result["success"] is True
        assert result["has_event"] is False

    def test_get_latest_event(self, mock_client):
        event = MagicMock()
        event.event_type = EventType.EVENT_BREAKPOINT
        event.event_data = MagicMock()
        event.event_data.model_dump.return_value = {"addr": 0x1000, "name": "test"}
        mock_client.get_latest_debug_event.return_value = event
        result = mcp_mod.get_latest_event()
        assert result["success"] is True
        assert result["has_event"] is True
        assert "EVENT_BREAKPOINT" in result["event_type"]

    def test_wait_for_event_timeout(self, mock_client):
        mock_client.wait_for_debug_event.return_value = None
        result = mcp_mod.wait_for_event("EVENT_BREAKPOINT", timeout=1)
        assert result["success"] is False
        assert result["error_type"] == "TIMEOUT"


# ---------------------------------------------------------------------------
# Settings tool tests
# ---------------------------------------------------------------------------

class TestSettings:
    def test_get_string_setting(self, mock_client):
        mock_client.get_setting_str.return_value = "value"
        result = mcp_mod.get_setting("Gui", "Theme")
        assert result["success"] is True
        assert result["value"] == "value"

    def test_get_int_setting(self, mock_client):
        mock_client.get_setting_int.return_value = 42
        result = mcp_mod.get_setting("Gui", "FontSize", type="int")
        assert result["success"] is True
        assert result["value"] == 42

    def test_set_setting(self, mock_client):
        mock_client.set_setting_str.return_value = True
        result = mcp_mod.set_setting("Gui", "Theme", "dark")
        assert result["success"] is True
        assert result["value"] == "dark"


# ---------------------------------------------------------------------------
# GUI tool tests
# ---------------------------------------------------------------------------

class TestGui:
    def test_log_message(self, mock_client):
        mock_client.log.return_value = True
        result = mcp_mod.log_message("hello")
        assert result["success"] is True
        assert result["message"] == "hello"

    def test_refresh_gui(self, mock_client):
        mock_client.gui_refresh_views.return_value = True
        result = mcp_mod.refresh_gui()
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PE exports tool tests
# ---------------------------------------------------------------------------

class TestGetPeExports:
    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_lists_exports(self, mock_get_exports):
        mock_get_exports.return_value = [
            {"name": "CreateFileA", "ordinal": 1, "virtual_address": 0x1000},
            {"name": "CloseHandle", "ordinal": 2, "virtual_address": 0x2000},
        ]
        result = mcp_mod.get_pe_exports("C:\\Windows\\System32\\kernel32.dll")
        assert result["success"] is True
        assert result["total"] == 2
        names = [e["name"] for e in result["exports"]]
        assert "CreateFileA" in names
        assert "CloseHandle" in names
        assert "kernel32.dll" in result["file"]

    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_filter_name(self, mock_get_exports):
        mock_get_exports.return_value = [
            {"name": "CreateFileA", "ordinal": 1, "virtual_address": 0x1000},
            {"name": "CloseHandle", "ordinal": 2, "virtual_address": 0x2000},
        ]
        result = mcp_mod.get_pe_exports("kernel32.dll", filter_name="create")
        assert result["success"] is True
        names = [e["name"] for e in result["exports"]]
        assert "CreateFileA" in names
        assert "CloseHandle" not in names

    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_no_exports_message(self, mock_get_exports):
        mock_get_exports.return_value = []
        result = mcp_mod.get_pe_exports("nodll.exe")
        assert result["success"] is True
        assert result["total"] == 0

    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_filter_yields_empty(self, mock_get_exports):
        mock_get_exports.return_value = [
            {"name": "CreateFileA", "ordinal": 1, "virtual_address": 0x1000},
        ]
        result = mcp_mod.get_pe_exports("kernel32.dll", filter_name="zzz_nomatch")
        assert result["success"] is True
        assert result["total"] == 0

    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_truncates_at_200(self, mock_get_exports):
        mock_get_exports.return_value = [
            {"name": f"Func{i}", "ordinal": i, "virtual_address": 0x1000 + i}
            for i in range(250)
        ]
        result = mcp_mod.get_pe_exports("big.dll")
        assert result["success"] is True
        assert result["total"] == 250
        assert result["shown"] == 200

    @patch("x64dbg_automate.mcp_server.get_exports")
    def test_exception_returns_error(self, mock_get_exports):
        mock_get_exports.side_effect = FileNotFoundError("file not found")
        result = mcp_mod.get_pe_exports("missing.dll")
        assert result["success"] is False


class TestErrorPaths:
    def test_no_connection_raises(self):
        original = mcp_mod._client
        mcp_mod._client = None
        try:
            result = mcp_mod.go()
            assert result["success"] is False
        finally:
            mcp_mod._client = original

    def test_invalid_address(self, mock_client):
        mock_client.read_memory.side_effect = RuntimeError("invalid address")
        result = mcp_mod.read_memory("0xBAD", 16)
        assert result["success"] is False

    def test_exception_in_eval(self, mock_client):
        mock_client.eval_sync.side_effect = Exception("eval failed")
        result = mcp_mod.eval_expression("bad")
        assert result["success"] is False


class TestValidateAddress:
    def test_valid_hex(self, mock_client):
        result = mcp_mod.validate_address("0x401000")
        assert result["valid"] is True
        assert result["resolved"] == "0x401000"
        assert result["type"] == "hex_literal"

    def test_valid_register(self, mock_client):
        mock_client.eval_sync.return_value = (0x7FFF0000, True)
        result = mcp_mod.validate_address("rax")
        assert result["valid"] is True
        assert result["type"] == "register"

    def test_invalid_expression(self, mock_client):
        mock_client.eval_sync.return_value = (0, False)
        result = mcp_mod.validate_address("bogus_symbol_xyz")
        assert result["valid"] is False
        assert "hint" in result


class TestToolSearch:
    def test_search_memory(self):
        result = mcp_mod.tool_search("memory")
        assert result["success"] is True
        assert result["total"] > 0
        assert len(result["results"]) <= 10
        names = [r["name"] for r in result["results"]]
        assert any("memory" in n.lower() for n in names)

    def test_search_limit(self):
        result = mcp_mod.tool_search("a", limit=3)
        assert result["success"] is True
        assert len(result["results"]) <= 3

    def test_search_no_matches(self):
        result = mcp_mod.tool_search("xyz_nonexistent_12345")
        assert result["success"] is True
        assert result["total"] == 0
        assert result["results"] == []


class TestListToolsByGroup:
    def test_group_memory(self):
        result = mcp_mod.list_tools_by_group("memory")
        assert result["success"] is True
        assert result["total"] > 0
        names = [r["name"] for r in result["results"]]
        assert any("memory" in n.lower() for n in names)

    def test_group_breakpoint(self):
        result = mcp_mod.list_tools_by_group("breakpoint")
        assert result["success"] is True
        assert result["total"] > 0
        names = [r["name"] for r in result["results"]]
        assert any("breakpoint" in n.lower() for n in names)

    def test_unknown_group(self):
        result = mcp_mod.list_tools_by_group("xyz_nonexistent")
        assert result["success"] is True
        assert result["total"] == 0
        assert "available_groups" in result


class TestSuggestNextActions:
    def test_no_session_suggests_connect(self):
        original = mcp_mod._client
        mcp_mod._client = None
        try:
            result = mcp_mod.suggest_next_actions()
            assert result["success"] is True
            actions = [s["action"] for s in result["suggestions"]]
            assert any("start_session" in a or "connect_to_session" in a for a in actions)
        finally:
            mcp_mod._client = original

    def test_context_aware_crypto(self):
        result = mcp_mod.suggest_next_actions(context="looking for crypto keys")
        assert result["success"] is True
        actions = [s["action"] for s in result["suggestions"]]
        assert any("crypto_material_search" in a for a in actions)


class TestReportGenerate:
    def test_generates_markdown(self):
        result = mcp_mod.report_generate("Unit Test Report")
        assert result["success"] is True
        assert result["title"] == "Unit Test Report"
        assert "# Unit Test Report" in result["report"]
        assert "## Session Summary" in result["report"]

    def test_default_title(self):
        result = mcp_mod.report_generate()
        assert result["success"] is True
        assert "Axon MCP Session Report" in result["title"]


class TestResumeProcess:
    def test_invalid_pid_fails_gracefully(self):
        result = mcp_mod.resume_process(99999)
        assert isinstance(result, dict)
        assert "success" in result
