"""Capstone-based pseudocode decompiler for x86/x64.

BSD-3-Clause — Capstone Engine attribution:
    Copyright (c) 2013-2024, Nguyen Anh Quynh
    All rights reserved.
    See Capstone's full license at: https://github.com/capstone-engine/capstone

This module implements a pattern-driven assembly-to-pseudocode translator.
It is NOT a full SSA-based decompiler (that would require months of work);
instead it uses control-flow graph analysis + instruction pattern matching
to produce readable C-like pseudocode that helps AI agents understand
function logic without reading raw assembly.

Pipeline:
    Raw bytes → Capstone disassembly → Basic blocks → CFG →
    Variable recovery → Expression translation →
    Control-flow structuring → Pseudocode emission
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86_const import (
    X86_OP_REG,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX,
    X86_REG_RSP, X86_REG_RBP, X86_REG_RSI, X86_REG_RDI,
    X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
    X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    X86_REG_RIP,
    X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, X86_REG_EBX,
    X86_REG_ESP, X86_REG_EBP, X86_REG_ESI, X86_REG_EDI,
    X86_REG_EIP,
    X86_REG_AL, X86_REG_CL, X86_REG_DL, X86_REG_BL,
    X86_INS_CALL, X86_INS_JMP, X86_INS_JA, X86_INS_JAE,
    X86_INS_JB, X86_INS_JBE, X86_INS_JE, X86_INS_JG,
    X86_INS_JGE, X86_INS_JL, X86_INS_JLE, X86_INS_JNE,
    X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO,
    X86_INS_JP, X86_INS_JS, X86_INS_JCXZ, X86_INS_JECXZ,
    X86_INS_JRCXZ,
    X86_INS_RET, X86_INS_RETF, X86_INS_LEAVE,
    X86_INS_PUSH, X86_INS_POP,
    X86_INS_CMP, X86_INS_TEST,
    X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX,
    X86_INS_LEA, X86_INS_XOR, X86_INS_ADD,
    X86_INS_SUB, X86_INS_AND, X86_INS_OR,
    X86_INS_NOT, X86_INS_NEG, X86_INS_INC,
    X86_INS_DEC, X86_INS_MUL, X86_INS_IMUL,
    X86_INS_DIV, X86_INS_IDIV, X86_INS_SHL,
    X86_INS_SHR, X86_INS_SAR, X86_INS_SAL,
    X86_INS_ROL, X86_INS_ROR, X86_INS_SETE,
    X86_INS_SETNE, X86_INS_SETG, X86_INS_SETGE,
    X86_INS_SETL, X86_INS_SETLE, X86_INS_SETA,
    X86_INS_SETAE, X86_INS_SETB, X86_INS_SETBE,
    X86_INS_SETO, X86_INS_SETNO, X86_INS_SETS,
    X86_INS_SETNS, X86_INS_SETP, X86_INS_SETNP,
      X86_INS_MOVSXD,
)


# ── Register name maps ──────────────────────────────────────────────────────

_REG_ID_TO_NAME_64: dict[int, str] = {
    X86_REG_RAX: "rax", X86_REG_RCX: "rcx", X86_REG_RDX: "rdx",
    X86_REG_RBX: "rbx", X86_REG_RSP: "rsp", X86_REG_RBP: "rbp",
    X86_REG_RSI: "rsi", X86_REG_RDI: "rdi", X86_REG_R8: "r8",
    X86_REG_R9: "r9", X86_REG_R10: "r10", X86_REG_R11: "r11",
    X86_REG_R12: "r12", X86_REG_R13: "r13", X86_REG_R14: "r14",
    X86_REG_R15: "r15", X86_REG_RIP: "rip",
}

_REG_ID_TO_NAME_32: dict[int, str] = {
    X86_REG_EAX: "eax", X86_REG_ECX: "ecx", X86_REG_EDX: "edx",
    X86_REG_EBX: "ebx", X86_REG_ESP: "esp", X86_REG_EBP: "ebp",
    X86_REG_ESI: "esi", X86_REG_EDI: "edi", X86_REG_EIP: "eip",
}

# Sub-registers (8/16/32-bit views of 64-bit regs)
_SUB_REG_MAP: dict[int, str] = {
    X86_REG_AL: "al", X86_REG_CL: "cl", X86_REG_DL: "dl", X86_REG_BL: "bl",
}

# x64 fastcall parameter registers (Windows ABI)
_WIN_X64_PARAMS = ["rcx", "rdx", "r8", "r9"]
_WIN_X64_FLOAT_PARAMS = ["xmm0", "xmm1", "xmm2", "xmm3"]

# x64 System V parameter registers (Linux/macOS)
_SYSV_X64_PARAMS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# x86 stdcall/cdecl parameter order (stack-based, right-to-left)

# Callee-saved registers per ABI
_CALLEE_SAVED_64 = {"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"}
_CALLEE_SAVED_32 = {"ebx", "esi", "edi", "ebp"}

# Volatile registers (caller-saved)
_VOLATILE_64 = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
_VOLATILE_32 = {"eax", "ecx", "edx"}


# ── Data structures ─────────────────────────────────────────────────────────


@dataclasses.dataclass
class Operand:
    """Normalized operand representation."""
    type: str  # "reg", "imm", "mem"
    value: Any
    size: int = 0  # bytes

    def __str__(self) -> str:
        if self.type == "reg":
            return str(self.value)
        if self.type == "imm":
            v = self.value
            if isinstance(v, int) and v >= 0:
                return f"0x{v:X}"
            return str(v)
        if self.type == "mem":
            mem = self.value  # dict
            parts: list[str] = []
            if mem.get("segment"):
                parts.append(f"{mem['segment']}:")
            base = mem.get("base", "")
            idx = mem.get("index", "")
            scale = mem.get("scale", 1)
            disp = mem.get("disp", 0)
            inner = ""
            if base:
                inner = base
            if idx:
                if scale != 1:
                    inner += f" + {idx} * {scale}" if inner else f"{idx} * {scale}"
                else:
                    inner += f" + {idx}" if inner else idx
            if disp != 0:
                if disp > 0:
                    inner += f" + 0x{disp:X}" if inner else f"0x{disp:X}"
                else:
                    inner += f" - 0x{abs(disp):X}" if inner else f"-0x{abs(disp):X}"
            if not inner:
                inner = "0"
            ptr_size = {1: "byte", 2: "word", 4: "dword", 8: "qword"}.get(self.size, "")
            prefix = f"{ptr_size} ptr [" if ptr_size else "["
            return prefix + inner + "]"
        return "?"


@dataclasses.dataclass
class AsmInstruction:
    address: int
    bytes: bytes
    mnemonic: str
    operands: list[Operand]
    id: int
    size: int
    regs_read: list[str]
    regs_write: list[str]
    groups: list[int]
    raw_op_str: str = ""

    @property
    def is_call(self) -> bool:
        return self.id == X86_INS_CALL

    @property
    def is_jump(self) -> bool:
        return self.id == X86_INS_JMP

    @property
    def is_cond_jump(self) -> bool:
        return self.id in _COND_JUMP_IDS

    @property
    def is_ret(self) -> bool:
        return self.id in (X86_INS_RET, X86_INS_RETF)

    @property
    def is_leave(self) -> bool:
        return self.id == X86_INS_LEAVE

    @property
    def is_push(self) -> bool:
        return self.id == X86_INS_PUSH

    @property
    def is_pop(self) -> bool:
        return self.id == X86_INS_POP


_COND_JUMP_IDS: set[int] = {
    X86_INS_JA, X86_INS_JAE, X86_INS_JB, X86_INS_JBE,
    X86_INS_JE, X86_INS_JG, X86_INS_JGE, X86_INS_JL,
    X86_INS_JLE, X86_INS_JNE, X86_INS_JNO, X86_INS_JNP,
    X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JS,
    X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JRCXZ,
}

_SETCC_IDS: set[int] = {
    X86_INS_SETE, X86_INS_SETNE, X86_INS_SETG, X86_INS_SETGE,
    X86_INS_SETL, X86_INS_SETLE, X86_INS_SETA, X86_INS_SETAE,
    X86_INS_SETB, X86_INS_SETBE, X86_INS_SETO, X86_INS_SETNO,
    X86_INS_SETS, X86_INS_SETNS, X86_INS_SETP, X86_INS_SETNP,
}

# Condition for the JUMP TARGET path (when the jump is taken)
_JUMP_COND_TO_C: dict[int, str] = {
    X86_INS_JE: "==", X86_INS_JNE: "!=",
    X86_INS_JA: ">", X86_INS_JAE: ">=",
    X86_INS_JB: "<", X86_INS_JBE: "<=",
    X86_INS_JG: ">", X86_INS_JGE: ">=",
    X86_INS_JL: "<", X86_INS_JLE: "<=",
    X86_INS_JO: "overflow", X86_INS_JNO: "!overflow",
    X86_INS_JS: "sign", X86_INS_JNS: "!sign",
    X86_INS_JP: "parity", X86_INS_JNP: "!parity",
    X86_INS_JCXZ: "cx == 0", X86_INS_JECXZ: "ecx == 0",
    X86_INS_JRCXZ: "rcx == 0",
}

# Inverted condition for the FALLTHROUGH path (standard compiler convention:
# the fallthrough is the "then" block, the jump target is the "else" block)
_JUMP_COND_INVERT: dict[int, str] = {
    X86_INS_JE: "!=", X86_INS_JNE: "==",
    X86_INS_JA: "<=", X86_INS_JAE: "<",
    X86_INS_JB: ">=", X86_INS_JBE: ">",
    X86_INS_JG: "<=", X86_INS_JGE: "<",
    X86_INS_JL: ">=", X86_INS_JLE: ">",
    X86_INS_JO: "!overflow", X86_INS_JNO: "overflow",
    X86_INS_JS: "!sign", X86_INS_JNS: "sign",
    X86_INS_JP: "!parity", X86_INS_JNP: "parity",
    X86_INS_JCXZ: "cx != 0", X86_INS_JECXZ: "ecx != 0",
    X86_INS_JRCXZ: "rcx != 0",
}

_SETCC_TO_C: dict[int, str] = {
    X86_INS_SETE: "==", X86_INS_SETNE: "!=",
    X86_INS_SETG: ">", X86_INS_SETGE: ">=",
    X86_INS_SETL: "<", X86_INS_SETLE: "<=",
    X86_INS_SETA: ">", X86_INS_SETAE: ">=",
    X86_INS_SETB: "<", X86_INS_SETBE: "<=",
    X86_INS_SETO: "overflow", X86_INS_SETNO: "!overflow",
    X86_INS_SETS: "sign", X86_INS_SETNS: "!sign",
    X86_INS_SETP: "parity", X86_INS_SETNP: "!parity",
    X86_INS_SETB: "carry", X86_INS_SETAE: "!carry",
}

_ARITH_TO_C_OP: dict[int, str] = {
    X86_INS_ADD: "+", X86_INS_SUB: "-",
    X86_INS_AND: "&", X86_INS_OR: "|",
    X86_INS_XOR: "^", X86_INS_SHL: "<<",
    X86_INS_SHR: ">>", X86_INS_SAR: ">>",
    X86_INS_SAL: "<<", X86_INS_ROL: "rol",
    X86_INS_ROR: "ror",
}


# ── Capstone helper ─────────────────────────────────────────────────────────


def _get_capstone(arch: str) -> Cs:
    if arch == "x64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return md


def _capstone_reg_name(md: Cs, reg_id: int) -> str:
    name = md.reg_name(reg_id)
    return name if name else f"reg_{reg_id}"


def _capstone_operand(md: Cs, op: Any) -> Operand:
    if op.type == X86_OP_REG:
        return Operand("reg", _capstone_reg_name(md, op.reg), op.size)
    if op.type == X86_OP_IMM:
        return Operand("imm", op.imm, op.size)
    if op.type == X86_OP_MEM:
        mem = {
            "base": _capstone_reg_name(md, op.mem.base) if op.mem.base else "",
            "index": _capstone_reg_name(md, op.mem.index) if op.mem.index else "",
            "scale": op.mem.scale,
            "disp": op.mem.disp,
            "segment": _capstone_reg_name(md, op.mem.segment) if op.mem.segment else "",
        }
        return Operand("mem", mem, op.size)
    return Operand("unknown", None, op.size)


def disassemble_bytes(data: bytes, base_addr: int, arch: str = "x64") -> list[AsmInstruction]:
    """Disassemble raw bytes into a list of ``AsmInstruction``."""
    md = _get_capstone(arch)
    instructions: list[AsmInstruction] = []
    for insn in md.disasm(data, base_addr):
        ops = [_capstone_operand(md, op) for op in insn.operands]
        reads = [_capstone_reg_name(md, r) for r in insn.regs_access()[0]]
        writes = [_capstone_reg_name(md, w) for w in insn.regs_access()[1]]
        instructions.append(AsmInstruction(
            address=insn.address,
            bytes=insn.bytes,
            mnemonic=insn.mnemonic,
            operands=ops,
            id=insn.id,
            size=insn.size,
            regs_read=reads,
            regs_write=writes,
            groups=list(insn.groups),
            raw_op_str=insn.op_str,
        ))
    return instructions


# ── Basic block & CFG ───────────────────────────────────────────────────────


@dataclasses.dataclass
class BasicBlock:
    start: int
    end: int  # inclusive last instruction address
    instructions: list[AsmInstruction]
    successors: list[int] = dataclasses.field(default_factory=list)
    predecessors: list[int] = dataclasses.field(default_factory=list)

    @property
    def last_insn(self) -> AsmInstruction | None:
        return self.instructions[-1] if self.instructions else None


@dataclasses.dataclass
class CFG:
    entry: int
    blocks: dict[int, BasicBlock]


def build_cfg(instructions: list[AsmInstruction], entry: int) -> CFG:
    """Build a control-flow graph from a flat instruction list.

    Splits on every control-flow instruction (call/jmp/jcc/ret).
    """
    if not instructions:
        return CFG(entry, {})

    # Leaders = entry + targets of jumps + instructions after jumps/calls/rets
    leaders: set[int] = {entry}
    addr_to_insn: dict[int, AsmInstruction] = {}
    for insn in instructions:
        addr_to_insn[insn.address] = insn

    for insn in instructions:
        if insn.is_call or insn.is_jump or insn.is_cond_jump:
            # The fall-through address is a leader
            fallthrough = insn.address + insn.size
            if fallthrough in addr_to_insn:
                leaders.add(fallthrough)
            # Jump target (if immediate)
            for op in insn.operands:
                if op.type == "imm":
                    target = op.value
                    if target in addr_to_insn:
                        leaders.add(target)
        elif insn.is_ret:
            fallthrough = insn.address + insn.size
            if fallthrough in addr_to_insn:
                leaders.add(fallthrough)

    # Sort leaders and slice into blocks
    sorted_leaders = sorted(leaders)
    block_ranges: list[tuple[int, int]] = []
    for i, start in enumerate(sorted_leaders):
        end = sorted_leaders[i + 1] - 1 if i + 1 < len(sorted_leaders) else instructions[-1].address
        block_ranges.append((start, end))

    blocks: dict[int, BasicBlock] = {}
    for start, end in block_ranges:
        block_insns = [insn for insn in instructions if start <= insn.address <= end]
        if block_insns:
            blocks[start] = BasicBlock(start, end, block_insns)

    # Wire successors
    for block in blocks.values():
        last = block.last_insn
        if last is None:
            continue
        if last.is_ret:
            continue
        if last.is_jump:
            # Unconditional jump: single successor (the target)
            for op in last.operands:
                if op.type == "imm":
                    target = op.value
                    if target in blocks:
                        block.successors.append(target)
                    break
        elif last.is_cond_jump:
            # Conditional: brtrue + brfalse (fallthrough)
            taken_target: int | None = None
            for op in last.operands:
                if op.type == "imm":
                    taken_target = op.value
                    break
            fallthrough = last.address + last.size
            if taken_target is not None and taken_target in blocks:
                block.successors.append(taken_target)
            if fallthrough in blocks:
                block.successors.append(fallthrough)
        elif last.is_call:
            # Call falls through
            fallthrough = last.address + last.size
            if fallthrough in blocks:
                block.successors.append(fallthrough)
        else:
            fallthrough = last.address + last.size
            if fallthrough in blocks:
                block.successors.append(fallthrough)

    # Wire predecessors
    for block in blocks.values():
        for succ_addr in block.successors:
            if succ_addr in blocks and block.start not in blocks[succ_addr].predecessors:
                blocks[succ_addr].predecessors.append(block.start)

    return CFG(entry, blocks)


# ── Function analysis ───────────────────────────────────────────────────────


@dataclasses.dataclass
class FunctionInfo:
    entry: int
    arch: str
    calling_convention: str = "unknown"
    stack_frame_size: int = 0
    parameters: list[dict] = dataclasses.field(default_factory=list)
    local_vars: list[dict] = dataclasses.field(default_factory=list)
    callee_saved: list[str] = dataclasses.field(default_factory=list)
    is_naked: bool = False


def analyze_prologue(instructions: list[AsmInstruction], arch: str) -> FunctionInfo:
    """Analyze function prologue to infer calling convention, locals, params."""
    info = FunctionInfo(entry=instructions[0].address if instructions else 0, arch=arch)

    if arch == "x64":
        # Check for standard prologue: push rbp; mov rbp, rsp; sub rsp, N
        if len(instructions) >= 3:
            i0, i1, i2 = instructions[0], instructions[1], instructions[2]
            if (i0.mnemonic == "push" and i0.operands and i0.operands[0].value == "rbp"
                    and i1.mnemonic == "mov" and i1.operands
                    and i1.operands[0].value == "rbp"
                    and i1.operands[1].value == "rsp"
                    and i2.mnemonic == "sub" and i2.operands
                    and i2.operands[0].value == "rsp"
                    and i2.operands[1].type == "imm"):
                info.stack_frame_size = i2.operands[1].value
                info.calling_convention = "__fastcall"

        # Windows x64 fastcall parameters
        if info.calling_convention == "__fastcall":
            for i, reg in enumerate(_WIN_X64_PARAMS):
                info.parameters.append({
                    "name": f"param{i + 1}",
                    "reg": reg,
                    "type": "int64_t",
                    "position": i + 1,
                })
        else:
            # Try to infer from usage (registers used before being written)
            # For now, default to standard params
            for i, reg in enumerate(_WIN_X64_PARAMS):
                info.parameters.append({
                    "name": f"param{i + 1}",
                    "reg": reg,
                    "type": "int64_t",
                    "position": i + 1,
                })

        # Callee-saved registers that are pushed
        for insn in instructions[:10]:
            if insn.mnemonic == "push" and insn.operands:
                reg = insn.operands[0].value
                if reg in _CALLEE_SAVED_64:
                    info.callee_saved.append(reg)

    else:  # x86
        # Check for standard prologue: push ebp; mov ebp, esp
        if len(instructions) >= 2:
            i0, i1 = instructions[0], instructions[1]
            if (i0.mnemonic == "push" and i0.operands and i0.operands[0].value == "ebp"
                    and i1.mnemonic == "mov" and i1.operands
                    and i1.operands[0].value == "ebp"
                    and i1.operands[1].value == "esp"):
                info.calling_convention = "__stdcall_or_cdecl"

        # x86 parameters are stack-based at [ebp+8], [ebp+0xC], etc.
        for i in range(6):
            offset = 8 + i * 4
            info.parameters.append({
                "name": f"param{i + 1}",
                "stack_offset": offset,
                "type": "int32_t",
                "position": i + 1,
            })

        for insn in instructions[:10]:
            if insn.mnemonic == "push" and insn.operands:
                reg = insn.operands[0].value
                if reg in _CALLEE_SAVED_32:
                    info.callee_saved.append(reg)

    return info


def recover_local_vars(cfg: CFG, arch: str, info: FunctionInfo) -> dict[str, str]:
    """Scan all instructions for stack accesses and assign names.

    Returns a mapping of ``access_key → var_name`` where access_key is
    ``"rbp:-8"`` or ``"esp:16"``.
    """
    locals_map: dict[str, str] = {}
    seen_offsets: dict[str, int] = {}

    base_reg = "rbp" if arch == "x64" else "ebp"
    sp_reg = "rsp" if arch == "x64" else "esp"

    for block in cfg.blocks.values():
        for insn in block.instructions:
            for op in insn.operands:
                if op.type != "mem":
                    continue
                mem = op.value
                base = mem.get("base", "")
                disp = mem.get("disp", 0)
                scale = mem.get("scale", 1)
                idx = mem.get("index", "")

                if base == base_reg and not idx and scale == 1:
                    key = f"{base_reg}:{disp}"
                    if key not in locals_map:
                        if disp < 0:
                            num = seen_offsets.setdefault("local", 0) + 1
                            seen_offsets["local"] = num
                            locals_map[key] = f"local_{num}"
                        else:
                            # Positive rbp offset = parameter (already named)
                            pass
                elif base == sp_reg and not idx and scale == 1:
                    key = f"{sp_reg}:{disp}"
                    if key not in locals_map:
                        num = seen_offsets.setdefault("local", 0) + 1
                        seen_offsets["local"] = num
                        locals_map[key] = f"local_{num}"

    return locals_map


# ── Expression builder ──────────────────────────────────────────────────────


def _resolve_operand(op: Operand, arch: str, func_info: FunctionInfo,
                     locals_map: dict[str, str]) -> str:
    """Convert an AsmInstruction operand to a C-like expression string."""
    if op.type == "reg":
        reg = str(op.value)
        # Check if it's a parameter register (handle sub-registers too)
        for p in func_info.parameters:
            preg = p.get("reg", "")
            if preg == reg:
                return p["name"]
            # Sub-register matching: eax matches rax param, cx matches rcx param, etc.
            if arch == "x64" and preg:
                # Map common sub-registers to their 64-bit parent
                sub_map = {
                    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
                    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
                    "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
                    "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
                    "esi": "rsi", "si": "rsi", "sil": "rsi",
                    "edi": "rdi", "di": "rdi", "dil": "rdi",
                    "r8d": "r8", "r8w": "r8", "r8b": "r8",
                    "r9d": "r9", "r9w": "r9", "r9b": "r9",
                    "r10d": "r10", "r10w": "r10", "r10b": "r10",
                    "r11d": "r11", "r11w": "r11", "r11b": "r11",
                    "r12d": "r12", "r12w": "r12", "r12b": "r12",
                    "r13d": "r13", "r13w": "r13", "r13b": "r13",
                    "r14d": "r14", "r14w": "r14", "r14b": "r14",
                    "r15d": "r15", "r15w": "r15", "r15b": "r15",
                }
                if sub_map.get(reg) == preg:
                    return p["name"]
        return reg

    if op.type == "imm":
        v = op.value
        if isinstance(v, int):
            if v >= 0:
                return f"0x{v:X}" if v > 9 else str(v)
            return str(v)
        return str(v)

    if op.type == "mem":
        mem = op.value
        base = mem.get("base", "")
        disp = mem.get("disp", 0)
        base_reg = "rbp" if arch == "x64" else "ebp"

        # Stack local?
        if base == base_reg and disp < 0:
            key = f"{base_reg}:{disp}"
            if key in locals_map:
                return locals_map[key]

        # Parameter?
        if base == base_reg and disp > 0 and arch == "x86":
            for p in func_info.parameters:
                if p.get("stack_offset") == disp:
                    return p["name"]

        # Default: render as memory access
        return str(op)

    return "?"


def _is_prologue_insn(insn: AsmInstruction, arch: str) -> bool:
    """Return True if this instruction is part of the standard function prologue."""
    if arch == "x64":
        if insn.mnemonic == "push" and insn.operands and insn.operands[0].value == "rbp":
            return True
        if insn.mnemonic == "mov" and len(insn.operands) >= 2:
            if insn.operands[0].value == "rbp" and insn.operands[1].value == "rsp":
                return True
        if insn.mnemonic == "sub" and len(insn.operands) >= 2:
            if insn.operands[0].value == "rsp":
                return True
    else:
        if insn.mnemonic == "push" and insn.operands and insn.operands[0].value == "ebp":
            return True
        if insn.mnemonic == "mov" and len(insn.operands) >= 2:
            if insn.operands[0].value == "ebp" and insn.operands[1].value == "esp":
                return True
        if insn.mnemonic == "sub" and len(insn.operands) >= 2:
            if insn.operands[0].value == "esp":
                return True
    return False


def _is_epilogue_insn(insn: AsmInstruction, arch: str) -> bool:
    """Return True if this instruction is part of the standard function epilogue."""
    if insn.mnemonic == "leave":
        return True
    if insn.mnemonic == "pop" and insn.operands:
        reg = str(insn.operands[0].value)
        if reg in ("rbp", "ebp"):
            return True
    return False


def instruction_to_expr(insn: AsmInstruction, arch: str, func_info: FunctionInfo,
                        locals_map: dict[str, str]) -> str | None:
    """Convert a single instruction to a C-like statement (or None if not expressible)."""
    ops = insn.operands
    n = len(ops)
    mnem = insn.mnemonic

    # Suppress prologue/epilogue
    if _is_prologue_insn(insn, arch) or _is_epilogue_insn(insn, arch):
        return None

    # mov dst, src
    if insn.id in (X86_INS_MOV, X86_INS_MOVSX, X86_INS_MOVZX, X86_INS_MOVSXD) and n >= 2:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        src = _resolve_operand(ops[1], arch, func_info, locals_map)
        # Suppress mov rbp, rsp and similar prologue-like moves already handled above
        cast = ""
        if insn.id == X86_INS_MOVSX:
            cast = "(int64_t)" if arch == "x64" else "(int32_t)"
        elif insn.id == X86_INS_MOVZX:
            cast = "(uint64_t)" if arch == "x64" else "(uint32_t)"
        return f"{dst} = {cast}{src};"

    # movaps/movups xmm, xmm — skip SSE moves for now
    if mnem in ("movaps", "movups", "movss", "movsd", "movdqa", "movdqu"):
        return None

    # lea dst, [mem] → dst = &mem
    if insn.id == X86_INS_LEA and n >= 2:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        src = _resolve_operand(ops[1], arch, func_info, locals_map)
        # Strip pointer syntax: "qword ptr [rbp - 8]" → "rbp - 8"
        src_clean = src
        if "[" in src_clean and "]" in src_clean:
            src_clean = src_clean[src_clean.index("[") + 1:src_clean.rindex("]")]
        return f"{dst} = &({src_clean});"

    # Arithmetic: add/sub/and/or/xor dst, src
    if insn.id in _ARITH_TO_C_OP and n >= 2:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        src = _resolve_operand(ops[1], arch, func_info, locals_map)
        op_char = _ARITH_TO_C_OP[insn.id]
        if insn.id == X86_INS_XOR and ops[0].value == ops[1].value:
            return f"{dst} = 0;"
        return f"{dst} = {dst} {op_char} {src};"

    # inc/dec
    if insn.id == X86_INS_INC and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"{dst}++;"
    if insn.id == X86_INS_DEC and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"{dst}--;"

    # not/neg
    if insn.id == X86_INS_NOT and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"{dst} = ~{dst};"
    if insn.id == X86_INS_NEG and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"{dst} = -{dst};"

    # cmp/test → handled at block level as part of conditional logic
    if insn.id in (X86_INS_CMP, X86_INS_TEST):
        return None

    # setcc dst
    if insn.id in _SETCC_IDS and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        cond = _SETCC_TO_C.get(insn.id, "?")
        return f"{dst} = ({cond});"

    # push / pop (simplified)
    if insn.id == X86_INS_PUSH and n >= 1:
        val = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"/* push {val} */"
    if insn.id == X86_INS_POP and n >= 1:
        dst = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"/* pop {dst} */"

    # call
    if insn.is_call and n >= 1:
        target = _resolve_operand(ops[0], arch, func_info, locals_map)
        return f"{target}();"

    # jmp (unconditional) → handled at CFG level
    if insn.is_jump:
        return None

    # ret
    if insn.is_ret:
        return "return;"

    # nop
    if mnem == "nop":
        return None

    # Default: comment
    return f"/* {mnem} {insn.raw_op_str} */"


# ── Control-flow structuring ────────────────────────────────────────────────


def _find_loop_headers(cfg: CFG) -> set[int]:
    """Find block addresses that are targets of backward jumps (loop headers)."""
    headers: set[int] = set()
    for block in cfg.blocks.values():
        last = block.last_insn
        if last and (last.is_jump or last.is_cond_jump):
            for succ in block.successors:
                if succ < block.start:
                    headers.add(succ)
    return headers


@dataclasses.dataclass
class StructuredNode:
    type: str  # "block", "if", "if_else", "while", "do_while", "switch", "seq"
    blocks: list[int] = dataclasses.field(default_factory=list)
    condition: str = ""
    then_body: list["StructuredNode"] = dataclasses.field(default_factory=list)
    else_body: list["StructuredNode"] = dataclasses.field(default_factory=list)
    loop_body: list["StructuredNode"] = dataclasses.field(default_factory=list)
    switch_cases: list[dict] = dataclasses.field(default_factory=list)


def _build_condition_expr(
    block: BasicBlock,
    arch: str = "x64",
    func_info: FunctionInfo | None = None,
    locals_map: dict[str, str] | None = None,
    invert: bool = True,
) -> str:
    """Build a C-like condition from the last cmp/test + jcc in a block.

    Args:
        invert: If True (default), return the condition for the FALLTHROUGH
            path (the "then" branch in standard compiler convention).
            If False, return the condition for the jump target path.
    """
    fi = func_info or FunctionInfo(entry=0, arch=arch)
    lm = locals_map or {}

    if len(block.instructions) < 1:
        return "/* condition */"

    # Find the comparison instruction before the jump
    cmp_insn: AsmInstruction | None = None
    jcc_insn: AsmInstruction | None = None
    for insn in reversed(block.instructions):
        if insn.is_cond_jump and jcc_insn is None:
            jcc_insn = insn
        elif insn.id in (X86_INS_CMP, X86_INS_TEST) and cmp_insn is None:
            cmp_insn = insn
            break

    if jcc_insn is None:
        return "/* condition */"

    cond_op = (_JUMP_COND_INVERT if invert else _JUMP_COND_TO_C).get(jcc_insn.id, "?")

    if cmp_insn is None:
        # No explicit cmp — might be test reg, reg or a flag-checking jump
        return f"({cond_op})"

    if cmp_insn.id == X86_INS_CMP and len(cmp_insn.operands) >= 2:
        left = _resolve_operand(cmp_insn.operands[0], arch, fi, lm)
        right = _resolve_operand(cmp_insn.operands[1], arch, fi, lm)
        # Simplify zero comparisons
        try:
            if right.startswith("0x"):
                v = int(right, 16)
            else:
                v = int(right)
            if v == 0:
                if cond_op == "==":
                    return f"(!{left})"
                if cond_op == "!=":
                    return f"({left})"
        except ValueError:
            pass
        return f"({left} {cond_op} {right})"

    if cmp_insn.id == X86_INS_TEST and len(cmp_insn.operands) >= 2:
        reg = _resolve_operand(cmp_insn.operands[0], arch, fi, lm)
        if cond_op == "==":
            return f"(!{reg})"
        if cond_op == "!=":
            return f"({reg})"
        return f"({reg} {cond_op} 0)"

    return f"({cond_op})"


def _get_fallthrough(block: BasicBlock) -> int | None:
    """Return the fall-through successor (not the jump target)."""
    last = block.last_insn
    if last is None or last.is_ret or last.is_jump:
        return None
    ft = last.address + last.size
    for succ in block.successors:
        if succ == ft:
            return succ
    # If there's only one successor and it's not a jump target, it's fallthrough
    if len(block.successors) == 1:
        return block.successors[0]
    return None


def _get_jump_target(block: BasicBlock) -> int | None:
    """Return the jump target (the non-fallthrough successor for jcc)."""
    last = block.last_insn
    if last is None:
        return None
    if last.is_jump:
        for succ in block.successors:
            return succ
    if last.is_cond_jump:
        ft = _get_fallthrough(block)
        for succ in block.successors:
            if succ != ft:
                return succ
    return None


def _collect_block_addrs(nodes: list[StructuredNode]) -> set[int]:
    """Collect all block start addresses from structured nodes."""
    addrs: set[int] = set()
    for node in nodes:
        addrs.update(node.blocks)
        addrs.update(_collect_block_addrs(node.then_body))
        addrs.update(_collect_block_addrs(node.else_body))
        addrs.update(_collect_block_addrs(node.loop_body))
    return addrs


def _find_merge_point(cfg: CFG, then_addrs: set[int], else_addrs: set[int]) -> int | None:
    """Find the first block reachable from both then and else paths."""
    # BFS from then path
    then_reachable: set[int] = set()
    queue = list(then_addrs)
    while queue:
        a = queue.pop(0)
        if a in then_reachable:
            continue
        then_reachable.add(a)
        if a in cfg.blocks:
            queue.extend(cfg.blocks[a].successors)

    # BFS from else path, stop at first common block
    else_reachable: set[int] = set()
    queue = list(else_addrs)
    while queue:
        a = queue.pop(0)
        if a in else_reachable:
            continue
        else_reachable.add(a)
        if a in then_reachable:
            return a
        if a in cfg.blocks:
            queue.extend(cfg.blocks[a].successors)
    return None


def _strip_after_addr(nodes: list[StructuredNode], addr: int) -> list[StructuredNode]:
    """Remove any nodes at or after the given merge address."""
    result: list[StructuredNode] = []
    for node in nodes:
        if addr in node.blocks:
            break
        result.append(node)
    return result


def _strip_trailing_jmp(nodes: list[StructuredNode], cfg: CFG) -> list[StructuredNode]:
    """If the last node is a block containing only an unconditional jmp, strip it."""
    while nodes:
        last = nodes[-1]
        if last.type != "block" or len(last.blocks) != 1:
            break
        block = cfg.blocks.get(last.blocks[0])
        if block is None or len(block.instructions) != 1:
            break
        if not block.instructions[0].is_jump:
            break
        nodes = nodes[:-1]
    return nodes


def structure_cfg(
    cfg: CFG,
    arch: str = "x64",
    func_info: FunctionInfo | None = None,
    locals_map: dict[str, str] | None = None,
) -> list[StructuredNode]:
    """Convert a flat CFG into structured control-flow nodes.

    This is a simple recursive descent structuring that handles:
    - Sequential blocks
    - If-then
    - If-then-else
    - While loops (backward jumps)
    """
    if not cfg.blocks:
        return []

    fi = func_info or FunctionInfo(entry=0, arch=arch)
    lm = locals_map or {}

    loop_headers = _find_loop_headers(cfg)
    visited: set[int] = set()

    def struct_region(entry: int, stop_at: set[int]) -> list[StructuredNode]:
        result: list[StructuredNode] = []
        current = entry

        while current in cfg.blocks and current not in stop_at and current not in visited:
            if current in visited:
                break
            visited.add(current)
            block = cfg.blocks[current]
            last = block.last_insn

            if current in loop_headers:
                # While loop: condition block + body
                # The body is the path from the jump target back to the header
                # Simple heuristic: the backward jump target is the header;
                # the block before the backward jump is the loop latch.
                # For now, treat the header block as the condition and
                # the block(s) between as the body.
                body_nodes: list[StructuredNode] = []
                # Collect blocks that are part of this loop (simplistic)
                # Find the latch block (the one that jumps back)
                latch = None
                for b in cfg.blocks.values():
                    if b.last_insn and b.last_insn.is_cond_jump:
                        target = _get_jump_target(b)
                        if target == current:
                            latch = b
                            break

                # Body is from the fallthrough of the header up to the latch
                if last and last.is_cond_jump:
                    ft = _get_fallthrough(block)
                    if ft is not None and ft != current:
                        body_stop = {current} | stop_at
                        body_nodes = struct_region(ft, body_stop)

                cond = _build_condition_expr(block, arch, fi, lm, invert=False)
                result.append(StructuredNode(
                    type="while",
                    condition=cond,
                    blocks=[current],
                    loop_body=body_nodes,
                ))
                # After the while, continue with the exit
                current = _get_fallthrough(block) or current
                continue

            # Check for if-then or if-then-else
            if last and last.is_cond_jump:
                cond = _build_condition_expr(block, arch, fi, lm, invert=True)
                taken = _get_jump_target(block)
                not_taken = _get_fallthrough(block)

                if taken is not None and not_taken is not None:
                    # Standard compiler convention:
                    #   cmp a, b
                    #   jcc else_label    ; jump to ELSE when condition is TRUE
                    #   ; THEN block (fallthrough)
                    #   jmp end
                    #   else_label:
                    #   ; ELSE block (jump target)
                    #   end:
                    #
                    # The fallthrough is the THEN body.
                    # The jump target is the ELSE body.
                    # _build_condition_expr(..., invert=True) gives us the
                    # fallthrough condition.
                    # THEN body starts at fallthrough, stops before ELSE block
                    # ELSE body starts at jump target
                    then_body = struct_region(not_taken, {taken} | stop_at)
                    else_body = struct_region(taken, stop_at)

                    # Detect and strip the merge point (first block reachable
                    # from both then and else paths).
                    then_addrs = _collect_block_addrs(then_body)
                    else_addrs = _collect_block_addrs(else_body)
                    merge = _find_merge_point(cfg, then_addrs, else_addrs)

                    if merge is not None:
                        then_body = _strip_after_addr(then_body, merge)
                        else_body = _strip_after_addr(else_body, merge)

                    # If the then body ends with a jmp-only block that targets
                    # the merge point, strip that trailing jmp block too.
                    then_body = _strip_trailing_jmp(then_body, cfg)

                    if not else_body:
                        result.append(StructuredNode(
                            type="if",
                            condition=cond,
                            blocks=[current],
                            then_body=then_body,
                        ))
                    else:
                        result.append(StructuredNode(
                            type="if_else",
                            condition=cond,
                            blocks=[current],
                            then_body=then_body,
                            else_body=else_body,
                        ))
                    break
                elif taken is not None:
                    # Only a jump target (unusual for cond jump without fallthrough)
                    result.append(StructuredNode(
                        type="if",
                        condition=cond,
                        blocks=[current],
                        then_body=struct_region(taken, stop_at),
                    ))
                    break
                elif not_taken is not None:
                    current = not_taken
                    continue
                else:
                    break

            # Check for unconditional jump (tail of if-then-else or goto)
            if last and last.is_jump:
                # Emit the block's non-jump instructions first, then follow
                result.append(StructuredNode(type="block", blocks=[current]))
                target = _get_jump_target(block)
                if target is not None:
                    if target in stop_at or target in visited:
                        # Jump to merge point — stop here
                        break
                    # Follow the jump within the current region
                    current = target
                    continue
                break

            # Regular block
            result.append(StructuredNode(type="block", blocks=[current]))

            # Move to fallthrough
            ft = _get_fallthrough(block)
            if ft is not None:
                current = ft
            else:
                break

        return result

    return struct_region(cfg.entry, set())


# ── Pseudocode emitter ──────────────────────────────────────────────────────


def _indent(lines: list[str], level: int = 1) -> list[str]:
    prefix = "    " * level
    return [prefix + line if line.strip() else line for line in lines]


def emit_pseudocode(nodes: list[StructuredNode], cfg: CFG, arch: str,
                    func_info: FunctionInfo, locals_map: dict[str, str]) -> list[str]:
    """Emit C-like pseudocode lines from structured nodes."""
    lines: list[str] = []

    def emit_node(node: StructuredNode, indent_level: int = 1) -> list[str]:
        out: list[str] = []
        if node.type == "block":
            for addr in node.blocks:
                if addr in cfg.blocks:
                    block = cfg.blocks[addr]
                    for insn in block.instructions:
                        stmt = instruction_to_expr(insn, arch, func_info, locals_map)
                        if stmt is not None:
                            out.append(stmt)
        elif node.type == "if":
            out.append(f"if {node.condition} {{")
            for child in node.then_body:
                out.extend(emit_node(child, indent_level + 1))
            out.append("}")
        elif node.type == "if_else":
            out.append(f"if {node.condition} {{")
            for child in node.then_body:
                out.extend(emit_node(child, indent_level + 1))
            out.append("} else {")
            for child in node.else_body:
                out.extend(emit_node(child, indent_level + 1))
            out.append("}")
        elif node.type == "while":
            out.append(f"while {node.condition} {{")
            for child in node.loop_body:
                out.extend(emit_node(child, indent_level + 1))
            out.append("}")
        elif node.type == "seq":
            for child in node.blocks:
                out.extend(emit_node(child, indent_level))
        return _indent(out, indent_level) if indent_level > 0 else out

    for node in nodes:
        lines.extend(emit_node(node, indent_level=1))

    return lines


# ── Main entry point ────────────────────────────────────────────────────────


@dataclasses.dataclass
class DecompileResult:
    function_name: str
    entry_point: int
    arch: str
    pseudocode: str
    signature: str
    local_vars: list[dict]
    parameters: list[dict]
    calling_convention: str
    stack_frame_size: int = 0
    warnings: list[str] = dataclasses.field(default_factory=list)
    structured_nodes: list[StructuredNode] = dataclasses.field(default_factory=list)


def decompile_function(
    data: bytes,
    base_addr: int,
    arch: str = "x64",
    name: str = "",
    existing_cfg: CFG | None = None,
    max_lines: int = 0,
) -> DecompileResult:
    """Decompile a function from raw bytes.

    Args:
        data: Raw instruction bytes of the function.
        base_addr: Virtual address where the function starts.
        arch: "x64" or "x32".
        name: Function name (default: sub_XXXXX).
        existing_cfg: Optional pre-built CFG from x64dbg.
        max_lines: Maximum pseudocode lines (0 = unlimited).

    Returns:
        ``DecompileResult`` with pseudocode, signature, locals, params, warnings.
    """
    if not name:
        name = f"sub_{base_addr:X}"

    instructions = disassemble_bytes(data, base_addr, arch)
    if not instructions:
        return DecompileResult(
            function_name=name,
            entry_point=base_addr,
            arch=arch,
            pseudocode=f"// Could not disassemble function {name}",
            signature=f"void {name}(void);",
            local_vars=[],
            parameters=[],
            calling_convention="unknown",
            warnings=["No instructions disassembled"],
        )

    func_info = analyze_prologue(instructions, arch)
    func_info.entry = base_addr

    cfg = existing_cfg if existing_cfg else build_cfg(instructions, base_addr)
    locals_map = recover_local_vars(cfg, arch, func_info)
    func_info.local_vars = [{"name": v, "key": k} for k, v in locals_map.items()]

    structured = structure_cfg(cfg, arch, func_info, locals_map)

    # Update parameter names in locals_map for stack-based params (x86)
    if arch == "x86":
        for p in func_info.parameters:
            offset = p.get("stack_offset", 0)
            key = f"ebp:{offset}"
            if key not in locals_map:
                pass  # param is already named in func_info.parameters

    # Build function signature
    ret_type = "void" if arch == "x64" else "int32_t"
    # Try to detect return value usage
    for insn in instructions:
        if insn.is_ret:
            # Check if rax/eax is set before ret
            break

    param_strs = [f"{p.get('type', 'int64_t')} {p['name']}" for p in func_info.parameters]
    cc_prefix = ""
    if func_info.calling_convention == "__fastcall":
        cc_prefix = "__fastcall "
    elif func_info.calling_convention == "__stdcall_or_cdecl":
        cc_prefix = "__stdcall "

    signature = f"{ret_type} {cc_prefix}{name}({', '.join(param_strs)})"

    # Emit pseudocode
    body_lines = emit_pseudocode(structured, cfg, arch, func_info, locals_map)

    # Build full function text
    lines: list[str] = [signature + " {"]

    # Declare local variables
    if locals_map:
        # Group by inferred type
        seen_names: set[str] = set()
        for key, var_name in sorted(locals_map.items(), key=lambda x: x[1]):
            if var_name not in seen_names:
                seen_names.add(var_name)
                var_type = "int64_t" if arch == "x64" else "int32_t"
                lines.append(f"    {var_type} {var_name};")

    lines.append("")
    lines.extend(body_lines)
    lines.append("}")

    pseudocode = "\n".join(lines)

    # Truncate if needed
    if max_lines > 0:
        pcode_lines = pseudocode.splitlines()
        if len(pcode_lines) > max_lines:
            pcode_lines = pcode_lines[:max_lines]
            pcode_lines.append(f"\n    /* ... ({len(pcode_lines) - max_lines} more lines) ... */")
            pseudocode = "\n".join(pcode_lines)

    warnings: list[str] = []
    if func_info.calling_convention == "unknown":
        warnings.append("Could not determine calling convention from prologue")

    return DecompileResult(
        function_name=name,
        entry_point=base_addr,
        arch=arch,
        pseudocode=pseudocode,
        signature=signature,
        local_vars=func_info.local_vars,
        parameters=func_info.parameters,
        calling_convention=func_info.calling_convention,
        stack_frame_size=func_info.stack_frame_size,
        warnings=warnings,
        structured_nodes=structured,
    )


# ── Utility: decompile from x64dbg CFG dict ─────────────────────────────────


def decompile_from_x64dbg_cfg(
    cfg_dict: dict,
    data: bytes,
    base_addr: int,
    arch: str = "x64",
    name: str = "",
    max_lines: int = 0,
) -> DecompileResult:
    """Decompile using an x64dbg-provided CFG dict (from ``client.analyze_function``).

    The ``cfg_dict`` should have the same shape as the response from
    ``api_analysis.analyze_function_cfg``:
    ``{"entry_point": int, "nodes": [{"start", "end", "instructions": [...]}]}``.
    """
    instructions = disassemble_bytes(data, base_addr, arch)
    addr_to_insn = {i.address: i for i in instructions}

    blocks: dict[int, BasicBlock] = {}
    for n in cfg_dict.get("nodes", []):
        start = n["start"]
        block_insns = [addr_to_insn[i["address"]] for i in n.get("instructions", [])
                       if i["address"] in addr_to_insn]
        if block_insns:
            bb = BasicBlock(start=start, end=n.get("end", start), instructions=block_insns)
            bb.successors = n.get("exits", [])
            if n.get("brtrue"):
                bb.successors.append(n["brtrue"])
            if n.get("brfalse"):
                bb.successors.append(n["brfalse"])
            blocks[start] = bb

    # Wire predecessors
    for bb in blocks.values():
        for succ in bb.successors:
            if succ in blocks and bb.start not in blocks[succ].predecessors:
                blocks[succ].predecessors.append(bb.start)

    cfg = CFG(entry=cfg_dict.get("entry_point", base_addr), blocks=blocks)
    return decompile_function(data, base_addr, arch, name, cfg, max_lines)
