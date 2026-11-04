#include "core/instruction_decoder.h"
#include "common/types.h"
#include <capstone/capstone.h>
#include <mutex>
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
    for (uint8_t i = 0; i < d.regs_read_count; i++) {
        if (d.regs_read[i] == idx) return;
    }
    if (d.regs_read_count < d.regs_read.size()) {
        d.regs_read[d.regs_read_count++] = idx;
    } else {
        d.register_access_overflow = true;
    }
}

// Helper: add a register index to the fixed-size written array with dedup and bounds check.
static inline void add_reg_written(DecodedInst& d, uint8_t idx) {
    if (idx == 0xFF) return;
    for (uint8_t i = 0; i < d.regs_written_count; i++) {
        if (d.regs_written[i] == idx) return;
    }
    if (d.regs_written_count < d.regs_written.size()) {
        d.regs_written[d.regs_written_count++] = idx;
    } else {
        d.register_access_overflow = true;
    }
}

// Capstone gives each scalar/vector alias its own ID. Keep this separate
// from the trace's GPR numbering, which is shared by existing consumers.
static uint8_t simd_index(arm64_reg reg) {
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) return reg - ARM64_REG_B0;
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) return reg - ARM64_REG_H0;
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) return reg - ARM64_REG_S0;
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) return reg - ARM64_REG_D0;
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) return reg - ARM64_REG_Q0;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) return reg - ARM64_REG_V0;
    return 0xff;
}

static void add_access(DecodedInst& d, arm64_reg reg, bool read, bool write) {
    const auto gpr = cs_reg_to_index(reg);
    const auto simd = simd_index(reg);
    if (gpr != 0xff) {
        if (read) add_reg_read(d, gpr);
        if (write) add_reg_written(d, gpr);
    } else if (simd != 0xff) {
        if (read) d.simd_reads |= uint32_t(1) << simd;
        if (write) d.simd_writes |= uint32_t(1) << simd;
    } else if (reg != ARM64_REG_INVALID && reg != ARM64_REG_XZR && reg != ARM64_REG_WZR) {
        d.untracked_register_access = true;
    }
}

// ─── PC-relative instruction detection ─────────────────────────────────────
// AArch64 PC-relative instructions have operand strings that depend on the
// execution PC (e.g. "b #0x100c" where 0x100c = pc + offset).  These cannot
// be cached by opcode alone because the same opcode at different PCs produces
// different op_str.  We detect them by mnemonic and bypass the cache.

static bool is_pc_relative_mnemonic(std::string_view mn) {
    if (mn == "b" || mn == "bl") return true;
    if (mn.size() > 2 && mn[0] == 'b' && mn[1] == '.') return true;  // b.cond
    if (mn == "cbz" || mn == "cbnz") return true;
    if (mn == "tbz" || mn == "tbnz") return true;
    if (mn == "adr" || mn == "adrp") return true;
    return false;
}

// ─── Thread-local Capstone handle ──────────────────────────────────────────
// Each thread gets its own Capstone handle, eliminating the global mutex that
// was the bottleneck under concurrent decode workloads.

csh& InstructionDecoder::tls_handle() {
    thread_local csh handle = 0;
    thread_local bool initialized = false;
    if (!initialized) {
        cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
        if (err == CS_ERR_OK) {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            initialized = true;
        }
    }
    return handle;
}

InstructionDecoder::InstructionDecoder() = default;

InstructionDecoder::~InstructionDecoder() = default;

bool InstructionDecoder::init() {
    if (initialized_) return true;
    csh& handle = tls_handle();
    if (handle == 0) return false;
    initialized_ = true;
    return true;
}

std::optional<DecodedInst> InstructionDecoder::decode(uint64_t pc, uint32_t opcode) {
    if (!initialized_) return std::nullopt;

    // ── Thread-local 1-entry cache ──────────────────────────────────────
    // Avoids lock contention for the common case of repeated decode of the
    // same opcode (loop bodies execute the same instruction thousands of
    // times).  PC-relative instructions are excluded because their op_str
    // depends on the execution PC.
    struct TLSEntry { uint32_t opcode = ~0u; DecodedInst inst; };
    static thread_local TLSEntry tls_last;

    if (tls_last.inst.size != 0 && tls_last.opcode == opcode && !is_pc_relative_mnemonic(tls_last.inst.mnemonic_sv())) {
        auto copy = tls_last.inst;
        copy.pc = pc;
        return copy;
    }

    // ── Opcode-keyed cache (thread-safe under run_all parallelism) ────────
    // AArch64 is fixed-length; the opcode word fully determines the mnemonic,
    // register access sets, and (for non-PC-relative instructions) the operand
    // string.  Cache by opcode for maximum reuse across PCs.
    //
    // PC-relative instructions (b, bl, b.cond, cbz, cbnz, tbz, tbnz, adr,
    // adrp) have op_str that depends on the execution PC, so they bypass the
    // cache and are always decoded with the actual PC.
    //
    // Note: we use a unique_lock (exclusive) for both get() and put() because
    // LRU get() mutates the linked list (promote).  The cache is small (4096
    // slots, ~2K distinct AArch64 encodings) so contention is negligible.
    {
        std::unique_lock<std::shared_mutex> lk(opcode_cache_mtx_);
        if (auto cached = opcode_cache_.get(opcode)) {
            DecodedInst d = cached->get();
            if (!is_pc_relative_mnemonic(d.mnemonic_sv())) {
                d.pc = pc;  // override PC for the caller
                return d;
            }
            // PC-relative: fall through to re-decode with actual PC
        }
    }

    csh& handle = tls_handle();
    if (handle == 0) return std::nullopt;

    // Decode with Capstone using the actual PC (needed for PC-relative
    // instructions to resolve branch targets correctly)
    const uint8_t* code = reinterpret_cast<const uint8_t*>(&opcode);
    size_t code_size = 4;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, code_size, pc, 1, &insn);

    DecodedInst d{};
    d.pc = pc;
    d.opcode = opcode;

    if (count == 0) {
        // Failed to decode - store a placeholder
        std::strncpy(d.mnemonic, ".word", sizeof(d.mnemonic) - 1);
        d.mnemonic[sizeof(d.mnemonic) - 1] = '\0';
        std::snprintf(d.op_str, sizeof(d.op_str), "0x%x", opcode);
        d.size = 4;
        {
            std::unique_lock<std::shared_mutex> lk(opcode_cache_mtx_);
            opcode_cache_.put(opcode, d);
        }
        return d;
    }

    std::strncpy(d.mnemonic, insn[0].mnemonic, sizeof(d.mnemonic) - 1);
    d.mnemonic[sizeof(d.mnemonic) - 1] = '\0';
    std::strncpy(d.op_str, insn[0].op_str, sizeof(d.op_str) - 1);
    d.op_str[sizeof(d.op_str) - 1] = '\0';
    d.size = static_cast<uint8_t>(insn[0].size);

    d.decoded = true;
    if (insn[0].detail) {
        // cs_regs_access includes implicit and explicit operands. In
        // particular, writeback bases and NZCV must not disappear merely
        // because the trace omits unchanged register values.
        // Capstone's AArch64 alias metadata may retain the underlying
        // arithmetic destination access on operand 0 of CMP/CMN/TST. Those
        // aliases read their explicit operands and only define NZCV.
        const bool compare_alias = insn[0].id == ARM64_INS_CMP ||
            insn[0].id == ARM64_INS_CMN || insn[0].id == ARM64_INS_TST;
        cs_regs reads{}, writes{};
        uint8_t nread = 0, nwrite = 0;
        if (cs_regs_access(handle, &insn[0], reads, &nread, writes, &nwrite) == CS_ERR_OK) {
            for (uint8_t i = 0; i < nread; ++i)
                add_access(d, static_cast<arm64_reg>(reads[i]), true, false);
            for (uint8_t i = 0; i < nwrite; ++i) {
                const auto reg = static_cast<arm64_reg>(writes[i]);
                if (!compare_alias || reg == ARM64_REG_NZCV) add_access(d, reg, false, true);
            }
        } else {
            d.untracked_register_access = true;
        }
        const auto& arm = insn[0].detail->arm64;
        if (arm.update_flags) add_reg_written(d, IDX_NZCV);
        if (arm.cc != ARM64_CC_INVALID && arm.cc != ARM64_CC_AL && arm.cc != ARM64_CC_NV)
            add_reg_read(d, IDX_NZCV);
        for (uint8_t i = 0; i < arm.op_count; ++i) {
            const auto& op = arm.operands[i];
            if (op.type == ARM64_OP_REG) {
                const auto reg = static_cast<arm64_reg>(op.reg);
                const bool written = !compare_alias && (op.access & CS_AC_WRITE) != 0;
                // Inserting one lane preserves the other lanes, so the old
                // vector remains a producer at our whole-register granularity.
                const bool partial = written && op.vector_index >= 0 && simd_index(reg) != 0xff;
                add_access(d, reg, compare_alias || (op.access & CS_AC_READ) != 0 || partial, written);
            } else if (op.type == ARM64_OP_MEM) {
                add_access(d, static_cast<arm64_reg>(op.mem.base), true, arm.writeback);
                add_access(d, static_cast<arm64_reg>(op.mem.index), true, false);
                if (arm.writeback) {
                    d.writeback_reg = cs_reg_to_index(static_cast<arm64_reg>(op.mem.base));
                    for (auto reg : {op.mem.base, op.mem.index}) {
                        const auto idx = cs_reg_to_index(static_cast<arm64_reg>(reg));
                        if (idx != 0xff) d.writeback_reads |= 1ULL << idx;
                    }
                }
            }
        }
    } else {
        d.untracked_register_access = true;
    }

    cs_free(insn, count);

    // Cache only non-PC-relative instructions (PC-relative op_str depends on PC)
    if (!is_pc_relative_mnemonic(d.mnemonic_sv())) {
        std::unique_lock<std::shared_mutex> lk(opcode_cache_mtx_);
        opcode_cache_.put(opcode, d);

        // Update thread-local 1-entry cache (lock-free fast path for next hit)
        tls_last.opcode = opcode;
        tls_last.inst = d;
    }

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
