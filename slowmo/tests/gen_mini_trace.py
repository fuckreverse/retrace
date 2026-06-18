#!/usr/bin/env python3
"""Generate a minimal but valid AArch64 trace file for e2e testing.

Produces ~5000 instructions with:
  - Proper v4 header (magic QBDT, REG_DIFF | HAS_CODE | HAS_MEM | HAS_NZCV)
  - Anchor records every 256 instructions
  - Code records for each unique PC
  - Reg diffs, memory accesses
  - A simple loop + function call pattern
"""

import struct
import sys
import os

# ─── Constants from TraceFormat.h ────────────────────────────────────────────

MAGIC = 0x51424454  # "QBDT"
VERSION = 4
ARCH_AARCH64 = 1
NUM_GPR = 34
HEADER_SIZE = 512

HF_HAS_MEM  = 1 << 0
HF_HAS_NZCV = 1 << 1
HF_REG_DIFF = 1 << 2
HF_HAS_CODE = 1 << 3

REC_INST   = 0
REC_ANCHOR = 1
REC_THREAD = 2
REC_EVENT  = 3
REC_SVC    = 4
REC_OBJC   = 5
REC_CODE   = 6

MODULE_BASE  = 0x100000000
MODULE_SLIDE = 0x4000
CODE_BASE    = MODULE_BASE + MODULE_SLIDE

# AArch64 opcode helpers
def movz(rd, imm, shift=0):
    hw = (shift // 16) & 3
    return 0xD2800000 | (hw << 21) | (imm << 5) | rd

def add_imm(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

def sub_imm(rd, rn, imm):
    return 0xD1000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

def subs_imm(rd, rn, imm):
    return 0xF1000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd

def str_imm(rt, rn, offset):
    return 0xF9000000 | (((offset >> 3) & 0xFFF) << 10) | (rn << 5) | rt

def ldr_imm(rt, rn, offset):
    return 0xF9400000 | (((offset >> 3) & 0xFFF) << 10) | (rn << 5) | rt

def eor_reg(rd, rn, rm):
    return 0xCA000000 | (rm << 16) | (rn << 5) | rd

def bl(offset):
    return 0x94000000 | ((offset >> 2) & 0x03FFFFFF)

def ret():
    return 0xD65F03C0

def nop():
    return 0xD503201F


class TraceWriter:
    def __init__(self, path):
        self.fp = open(path, 'wb')
        self.inst_count = 0
        self.emitted_pcs = set()
        self.gpr = [0] * NUM_GPR  # current full register state

    def write_header(self):
        hdr = bytearray(HEADER_SIZE)
        struct.pack_into('<IIIIQQQQ', hdr, 0,
            MAGIC, VERSION, ARCH_AARCH64, NUM_GPR,
            MODULE_BASE, MODULE_SLIDE,
            CODE_BASE, CODE_BASE + 0x100000)
        flags = HF_HAS_MEM | HF_HAS_NZCV | HF_REG_DIFF | HF_HAS_CODE
        struct.pack_into('<Q', hdr, 48, flags)
        name = b'test_binary'
        hdr[56:56+len(name)] = name
        self.fp.write(hdr)

    def emit_code(self, pc, opcode):
        if pc in self.emitted_pcs:
            return
        self.emitted_pcs.add(pc)
        # code_head: kind(1) + size(1) + pad(6) + pc(8) = 16 bytes
        head = struct.pack('<BBxxxxxx Q', REC_CODE, 4, pc)
        self.fp.write(head)
        self.fp.write(struct.pack('<I', opcode))

    def emit_anchor(self):
        # anchor_head: kind(1) + pad(7) + pc(8) = 16 bytes, then NUM_GPR * 8
        head = struct.pack('<Bxxxxxxx Q', REC_ANCHOR, self.gpr[33])
        self.fp.write(head)
        for i in range(NUM_GPR):
            self.fp.write(struct.pack('<Q', self.gpr[i]))

    def emit_inst(self, pc, opcode, reg_diffs=None, mem_accs=None, nzcv=0):
        """Emit an INST record.
        reg_diffs: list of (reg_index, value)
        mem_accs: list of (type, size, addr, value)  type: 0=read, 1=write
        """
        if reg_diffs is None:
            reg_diffs = []
        if mem_accs is None:
            mem_accs = []

        # Emit code record if first time seeing this PC
        self.emit_code(pc, opcode)

        # Maybe emit anchor
        if self.inst_count % 256 == 0:
            self.emit_anchor()

        n_reg = len(reg_diffs)
        n_mem = len(mem_accs)

        # inst_head_t: kind(1) + nzcv(1) + n_regdiff(1) + n_mem(1) + pad(4) + pc(8) = 16
        head = struct.pack('<BBBB xxxx Q', REC_INST, nzcv, n_reg, n_mem, pc)
        self.fp.write(head)

        # regdiff_t: reg_index(1) + pad(7) + value(8) = 16
        for (idx, val) in reg_diffs:
            self.fp.write(struct.pack('<B xxxxxxx Q', idx, val))
            self.gpr[idx] = val

        # memacc_t: type(1) + flags(1) + size(2) + pad(4) + addr(8) + value(8) + value_hi(8) = 32
        for (mtype, msize, maddr, mval) in mem_accs:
            self.fp.write(struct.pack('<BBH xxxx QQQ', mtype, 0, msize, maddr, mval, 0))

        self.gpr[33] = pc  # update PC in state
        self.inst_count += 1

    def close(self):
        self.fp.close()


def generate_trace(path):
    w = TraceWriter(path)
    w.write_header()

    # Initialize register state
    w.gpr[31] = 0x7FFFFFF000  # SP
    w.gpr[29] = 0x7FFFFFF000  # FP
    w.gpr[30] = 0             # LR
    w.gpr[33] = CODE_BASE     # PC

    pc = CODE_BASE
    inst_id = 0

    # ─── Part 1: Linear sequence (setup, ~20 instructions) ────────────
    # mov x0, #0x1000 (data buffer address)
    w.emit_inst(pc, movz(0, 0x1000), reg_diffs=[(0, 0x1000)])
    pc += 4; inst_id += 1

    # mov x1, #100 (loop counter)
    w.emit_inst(pc, movz(1, 100), reg_diffs=[(1, 100)])
    pc += 4; inst_id += 1

    # mov x2, #0 (accumulator)
    w.emit_inst(pc, movz(2, 0), reg_diffs=[(2, 0)])
    pc += 4; inst_id += 1

    # mov x3, #0x42 (xor key)
    w.emit_inst(pc, movz(3, 0x42), reg_diffs=[(3, 0x42)])
    pc += 4; inst_id += 1

    # ─── Part 2: Main loop (runs 100 iterations = 500 instructions) ───
    loop_start = pc
    for i in range(100):
        # ldr x4, [x0]
        mem_val = (i * 0x1234 + 0xDEAD) & 0xFFFFFFFFFFFFFFFF
        addr = 0x1000 + i * 8
        w.emit_inst(pc, ldr_imm(4, 0, 0),
                    reg_diffs=[(4, mem_val)],
                    mem_accs=[(0, 8, addr, mem_val)])

        # eor x4, x4, x3
        xored = mem_val ^ 0x42
        w.emit_inst(pc + 4, eor_reg(4, 4, 3), reg_diffs=[(4, xored)])

        # str x4, [x0]
        w.emit_inst(pc + 8, str_imm(4, 0, 0),
                    mem_accs=[(1, 8, addr, xored)])

        # add x0, x0, #8
        new_x0 = 0x1000 + (i + 1) * 8
        w.emit_inst(pc + 12, add_imm(0, 0, 8), reg_diffs=[(0, new_x0)])

        # subs x1, x1, #1
        new_x1 = 100 - i - 1
        nzcv_val = 0x4 if new_x1 == 0 else 0  # Z flag when counter hits 0
        w.emit_inst(pc + 16, subs_imm(1, 1, 1),
                    reg_diffs=[(1, new_x1)], nzcv=nzcv_val)

    # ─── Part 3: Function call pattern (~200 instructions) ────────────
    func_addr = CODE_BASE + 0x1000
    for call_i in range(20):
        # bl func
        call_pc = pc + 20  # after loop body
        w.gpr[30] = call_pc + 4  # LR = return address
        w.emit_inst(call_pc, bl(func_addr - call_pc),
                    reg_diffs=[(30, call_pc + 4)])

        # Inside function: 8 instructions per call
        fpc = func_addr
        for fi in range(8):
            if fi == 7:
                # ret
                w.emit_inst(fpc, ret(), reg_diffs=[(33, w.gpr[30])])
            elif fi == 0:
                # mov x5, x0
                w.emit_inst(fpc, 0xAA0003E5, reg_diffs=[(5, w.gpr[0])])
            elif fi == 3:
                # str x5, [sp, #offset]
                sp = w.gpr[31]
                w.emit_inst(fpc, str_imm(5, 31, fi * 8),
                            mem_accs=[(1, 8, sp + fi * 8, w.gpr[5])])
            else:
                # nop-like: add x5, x5, #1
                w.emit_inst(fpc, add_imm(5, 5, 1), reg_diffs=[(5, w.gpr[5] + 1)])
            fpc += 4

        # Return site
        w.emit_inst(call_pc + 4, nop())
        pc = call_pc + 8

    # ─── Part 4: More linear code to reach ~5000 instructions ─────────
    remaining = 5000 - w.inst_count
    lin_pc = pc
    for i in range(max(0, remaining)):
        # add x2, x2, #1
        w.emit_inst(lin_pc, add_imm(2, 2, 1), reg_diffs=[(2, w.gpr[2] + 1)])
        lin_pc += 4

    w.close()
    return w.inst_count


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(__file__), 'test_e2e.trace')
    count = generate_trace(out)
    print(f"Generated {count} instructions -> {out}")
    sz = os.path.getsize(out)
    print(f"File size: {sz} bytes ({sz/1024:.1f} KB)")
