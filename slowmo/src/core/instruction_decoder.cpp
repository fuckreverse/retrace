#include "core/instruction_decoder.h"
#include "common/types.h"
#include <capstone/capstone.h>
#include <cstring>
#include <cstdio>

namespace tenet {

// Convert Capstone ARM64 register ID to our register index (0-33).
// Returns 0xFF if not a GPR we track.
static uint8_t cs_reg_to_index(arm64_reg reg) {
    // X registers: ARM64_REG_X0 .. ARM64_REG_X28
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
        return static_cast<uint8_t>(reg - ARM64_REG_X0);
    // W registers map to same GPR
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28)
        return static_cast<uint8_t>(reg - ARM64_REG_W0);
    // Special registers
    if (reg == ARM64_REG_X29 || reg == ARM64_REG_FP) return IDX_FP;
    if (reg == ARM64_REG_X30 || reg == ARM64_REG_LR) return IDX_LR;
    if (reg == ARM64_REG_SP) return IDX_SP;
    if (reg == ARM64_REG_W29) return IDX_FP;
    if (reg == ARM64_REG_W30) return IDX_LR;
    if (reg == ARM64_REG_WSP) return IDX_SP;
    if (reg == ARM64_REG_NZCV) return IDX_NZCV;
    // XZR/WZR - zero register, not tracked
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return 0xFF;
    return 0xFF;
}

// Helper: add a register index to the fixed-size read array with dedup and bounds check.
static inline void add_reg_read(DecodedInst& d, uint8_t idx) {
    if (idx == 0xFF) return;
    // Avoid duplicates
    for (uint8_t i = 0; i < d.regs_read_count; i++) {
        if (d.regs_read[i] == idx) return;
    }
    if (d.regs_read_count < d.regs_read.size()) {
        d.regs_read[d.regs_read_count++] = idx;
    }
}

// Helper: add a register index to the fixed-size written array with dedup and bounds check.
static inline void add_reg_written(DecodedInst& d, uint8_t idx) {
    if (idx == 0xFF) return;
    // Avoid duplicates
    for (uint8_t i = 0; i < d.regs_written_count; i++) {
        if (d.regs_written[i] == idx) return;
    }
    if (d.regs_written_count < d.regs_written.size()) {
        d.regs_written[d.regs_written_count++] = idx;
    }
}

InstructionDecoder::InstructionDecoder() = default;

InstructionDecoder::~InstructionDecoder() {
    if (initialized_) {
        cs_close(&handle_);
    }
}

bool InstructionDecoder::init() {
    if (initialized_) return true;

    cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle_);
    if (err != CS_ERR_OK) return false;

    // Enable detail mode for register access info (useful later for XRef)
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);

    initialized_ = true;
    return true;
}

std::optional<DecodedInst> InstructionDecoder::decode(uint64_t pc, uint32_t opcode) {
    if (!initialized_) return std::nullopt;

    // Check cache
    if (auto cached = cache_.get(pc)) {
        return cached->get();
    }

    // Decode with Capstone
    const uint8_t* code = reinterpret_cast<const uint8_t*>(&opcode);
    size_t code_size = 4;
    uint64_t addr = pc;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle_, code, code_size, addr, 1, &insn);

    if (count == 0) {
        // Failed to decode - store a placeholder
        DecodedInst d{};
        d.pc = pc;
        d.opcode = opcode;
        std::strncpy(d.mnemonic, ".word", sizeof(d.mnemonic) - 1);
        d.mnemonic[sizeof(d.mnemonic) - 1] = '\0';
        std::snprintf(d.op_str, sizeof(d.op_str), "0x%x", opcode);
        d.size = 4;
        cache_.put(pc, d);
        return d;
    }

    DecodedInst d{};
    d.pc = pc;
    d.opcode = opcode;
    std::strncpy(d.mnemonic, insn[0].mnemonic, sizeof(d.mnemonic) - 1);
    d.mnemonic[sizeof(d.mnemonic) - 1] = '\0';
    std::strncpy(d.op_str, insn[0].op_str, sizeof(d.op_str) - 1);
    d.op_str[sizeof(d.op_str) - 1] = '\0';
    d.size = static_cast<uint8_t>(insn[0].size);

    // Extract register read/write info from Capstone detail
    if (insn[0].detail) {
        cs_detail* detail = insn[0].detail;
        // Implicit reads
        for (uint8_t i = 0; i < detail->regs_read_count; i++) {
            uint8_t idx = cs_reg_to_index(static_cast<arm64_reg>(detail->regs_read[i]));
            add_reg_read(d, idx);
        }
        // Implicit writes
        for (uint8_t i = 0; i < detail->regs_write_count; i++) {
            uint8_t idx = cs_reg_to_index(static_cast<arm64_reg>(detail->regs_write[i]));
            add_reg_written(d, idx);
        }
        // Explicit operand reads/writes
        if (detail->arm64.op_count > 0) {
            for (int i = 0; i < detail->arm64.op_count; i++) {
                cs_arm64_op& op = detail->arm64.operands[i];
                if (op.type == ARM64_OP_REG) {
                    uint8_t idx = cs_reg_to_index(static_cast<arm64_reg>(op.reg));
                    if (idx == 0xFF) continue;
                    if (op.access & CS_AC_READ) {
                        add_reg_read(d, idx);
                    }
                    if (op.access & CS_AC_WRITE) {
                        add_reg_written(d, idx);
                    }
                } else if (op.type == ARM64_OP_MEM) {
                    // Base and index registers are read
                    if (op.mem.base != ARM64_REG_INVALID) {
                        uint8_t idx = cs_reg_to_index(static_cast<arm64_reg>(op.mem.base));
                        add_reg_read(d, idx);
                    }
                    if (op.mem.index != ARM64_REG_INVALID) {
                        uint8_t idx = cs_reg_to_index(static_cast<arm64_reg>(op.mem.index));
                        add_reg_read(d, idx);
                    }
                }
            }
        }
    }

    cs_free(insn, count);

    cache_.put(pc, d);
    return d;
}

std::optional<DecodedInst> InstructionDecoder::decode(uint64_t pc, const CodeTable& code_table) {
    auto opcode = code_table.opcode_at(pc);
    if (!opcode) return std::nullopt;
    return decode(pc, *opcode);
}

std::string InstructionDecoder::format(uint64_t pc, uint32_t opcode) {
    auto d = decode(pc, opcode);
    if (!d) return "<unknown>";

    char buf[128];
    std::snprintf(buf, sizeof(buf), "0x%llx: %-8s %s",
             (unsigned long long)pc, d->mnemonic, d->op_str);
    return std::string(buf);
}

}  // namespace tenet
