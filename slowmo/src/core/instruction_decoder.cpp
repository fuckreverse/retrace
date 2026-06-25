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
    for (uint8_t i = 0; i < d.regs_written_count; i++) {
        if (d.regs_written[i] == idx) return;
    }
    if (d.regs_written_count < d.regs_written.size()) {
        d.regs_written[d.regs_written_count++] = idx;
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

    if (tls_last.opcode == opcode && !is_pc_relative_mnemonic(tls_last.inst.mnemonic_sv())) {
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
