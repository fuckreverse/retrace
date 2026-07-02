/*
 * trace_writer.h — Reusable synthetic AArch64 trace writer for Tenet tests.
 *
 * Extracted from gen_test_traces.cpp so that both the standalone trace
 * generator tool (tests/tools/gen_test_traces.cpp) and the Catch2 unit tests
 * share a single, authoritative implementation.
 *
 * Provides:
 *   - MachineState / SimMemory   : minimal AArch64 machine model
 *   - enc namespace              : AArch64 opcode encoding helpers
 *   - TraceWriter                : writes a valid v4 .trace file record-by-record
 *
 * Usage in tests:
 *   TraceWriter tw;
 *   tw.open(path);
 *   tw.write_header();
 *   MachineState ms; ms.sp() = 0x16F000000ULL;
 *   tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
 *   tw.emit_anchor(ms);
 *   tw.close();
 */
#ifndef TENET_TEST_TRACE_WRITER_H
#define TENET_TEST_TRACE_WRITER_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "TraceFormat.h"

namespace tenet::test {

// TraceFormat.h defines structs and enums inside `namespace qbditrace`. The
// #define macros (QBDITRACE_MAGIC, QBDITRACE_VERSION, …) are global, but the
// enum values (QBDITRACE_REC_*, QBDITRACE_HF_*, QBDITRACE_ARCH_*, …) live in
// the namespace. Pull them in so test code can use the short unqualified form.
using namespace qbditrace;

// ═══════════════════════════════════════════════════════════════════════════════
// Machine Simulation Framework
// ═══════════════════════════════════════════════════════════════════════════════

struct MachineState {
    uint64_t gpr[34] = {};
    uint64_t& x(int i) { return gpr[i]; }
    uint64_t& fp() { return gpr[29]; }
    uint64_t& lr() { return gpr[30]; }
    uint64_t& sp() { return gpr[31]; }
    uint64_t& nzcv() { return gpr[32]; }
    uint64_t& pc() { return gpr[33]; }
};

struct SimMemory {
    std::unordered_map<uint64_t, uint64_t> data;
    void store(uint64_t addr, uint64_t val) { data[addr] = val; }
    uint64_t load(uint64_t addr) {
        auto it = data.find(addr);
        return it != data.end() ? it->second : 0;
    }
};

// ═══════════════════════════════════════════════════════════════════════════════
// AArch64 Opcode Encoding Helpers
// ═══════════════════════════════════════════════════════════════════════════════

namespace enc {

    static uint32_t movz(int rd, uint16_t imm, int shift = 0) {
        uint32_t hw = (shift / 16) & 3;
        return 0xD2800000u | (hw << 21) | ((uint32_t)imm << 5) | rd;
    }
    static uint32_t movk(int rd, uint16_t imm, int shift = 0) {
        uint32_t hw = (shift / 16) & 3;
        return 0xF2800000u | (hw << 21) | ((uint32_t)imm << 5) | rd;
    }
    static uint32_t add_imm(int rd, int rn, uint16_t imm) {
        return 0x91000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
    }
    static uint32_t sub_imm(int rd, int rn, uint16_t imm) {
        return 0xD1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
    }
    static uint32_t subs_imm(int rd, int rn, uint16_t imm) {
        return 0xF1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
    }
    static uint32_t cmp_imm(int rn, uint16_t imm) { return subs_imm(31, rn, imm); }
    static uint32_t add_reg(int rd, int rn, int rm) {
        return 0x8B000000u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t sub_reg(int rd, int rn, int rm) {
        return 0xCB000000u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t eor_reg(int rd, int rn, int rm) {
        return 0xCA000000u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t and_reg(int rd, int rn, int rm) {
        return 0x8A000000u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t orr_reg(int rd, int rn, int rm) {
        return 0xAA000000u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t lsl_imm(int rd, int rn, int shift) {
        int immr = (64 - shift) & 63;
        int imms = (63 - shift) & 63;
        return 0xD3400000u | (immr << 16) | (imms << 10) | (rn << 5) | rd;
    }
    static uint32_t lsr_imm(int rd, int rn, int shift) {
        return 0xD340FC00u | (shift << 16) | (rn << 5) | rd;
    }
    static uint32_t mul_reg(int rd, int rn, int rm) {
        return 0x9B007C00u | (rm << 16) | (rn << 5) | rd;
    }
    static uint32_t ldr_imm(int rt, int rn, int16_t offset) {
        return 0xF9400000u | (((offset >> 3) & 0xFFF) << 10) | (rn << 5) | rt;
    }
    static uint32_t str_imm(int rt, int rn, int16_t offset) {
        return 0xF9000000u | (((offset >> 3) & 0xFFF) << 10) | (rn << 5) | rt;
    }
    static uint32_t ldr_reg(int rt, int rn, int rm) {
        return 0xF8687800u | (rm << 16) | (rn << 5) | rt;
    }
    static uint32_t str_reg(int rt, int rn, int rm) {
        return 0xF8287800u | (rm << 16) | (rn << 5) | rt;
    }
    static uint32_t bl(int32_t offset) {
        return 0x94000000u | ((offset >> 2) & 0x03FFFFFF);
    }
    static uint32_t b(int32_t offset) {
        return 0x14000000u | ((offset >> 2) & 0x03FFFFFF);
    }
    static uint32_t b_ne(int32_t offset) {
        return 0x54000001u | (((offset >> 2) & 0x7FFFF) << 5);
    }
    static uint32_t b_eq(int32_t offset) {
        return 0x54000000u | (((offset >> 2) & 0x7FFFF) << 5);
    }
    static uint32_t b_lt(int32_t offset) {
        return 0x5400000Bu | (((offset >> 2) & 0x7FFFF) << 5);
    }
    static uint32_t b_ge(int32_t offset) {
        return 0x5400000Au | (((offset >> 2) & 0x7FFFF) << 5);
    }
    static uint32_t ret() { return 0xD65F03C0u; }
    static uint32_t nop() { return 0xD503201Fu; }
    static uint32_t stp_pre(int rt, int rt2, int rn, int16_t imm7) {
        return 0xA9BF0000u | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt;
    }
    static uint32_t ldp_post(int rt, int rt2, int rn, int16_t imm7) {
        return 0xA8C10000u | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt;
    }
    static uint32_t mov_reg(int rd, int rm) {
        return 0xAA0003E0u | (rm << 16) | rd;
    }
    static uint32_t svc(uint16_t imm) {
        return 0xD4000001u | ((uint32_t)imm << 5);
    }
    // BR Xn — unconditional indirect branch (register)
    static uint32_t br(int rn) {
        return 0xD61F0000u | (rn << 5);
    }
    // BLR Xn — branch with link to register
    static uint32_t blr(int rn) {
        return 0xD63F0000u | (rn << 5);
    }
} // namespace enc

// ═══════════════════════════════════════════════════════════════════════════════
// Trace Writer — produces a valid v4 .trace file
// ═══════════════════════════════════════════════════════════════════════════════

struct TraceWriter {
    FILE* fp = nullptr;
    uint64_t module_base = 0x100000000ULL;
    uint64_t module_slide = 0x4000ULL;
    uint32_t num_gpr = 34;
    uint64_t inst_count = 0;
    uint32_t anchor_interval = 4096;
    std::unordered_set<uint64_t> emitted_code;
    const char* module_name = "test_binary";
    // v5 (HF_PC_DELTA) state: running PC for delta encoding
    uint64_t prev_pc_ = 0;

    struct RegDiff { uint8_t index; uint64_t value; };
    struct MemAcc { uint8_t type; uint16_t size; uint64_t addr; uint64_t value; };

    // v6 extended memory access (with old_value pre-write capture)
    struct MemAccV6 {
        uint8_t  type;          // QBDI::MEMORY_READ=1, WRITE=2
        uint16_t size;          // in bytes
        uint64_t addr;
        uint64_t value;         // new value (post-write)
        uint64_t value_hi;      // high bytes for >8-byte stores
        uint64_t old_value;     // pre-write value (WRITE only; 0 for READ)
        uint64_t old_value_hi;  // pre-write high bytes (>8-byte stores)
        bool     old_unknown;   // set QBDITRACE_MF_OLD_UNKNOWN in flags
    };

    bool open(const char* path) { fp = fopen(path, "wb"); return fp != nullptr; }
    void close() { if (fp) fclose(fp); fp = nullptr; }
    uint64_t rt(uint64_t static_pc) { return static_pc + module_slide; }

    void write_header(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
    }

    /// Write a v6 (HF_OLD_VALUE) header.  Version is bumped to
    /// QBDITRACE_VERSION_V6_OLD_VALUE and the HF_OLD_VALUE flag is set so that
    /// tenet's TraceReader recognises v6 mode and uses qbditrace_memacc_v6_t.
    void write_header_v6(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V6_OLD_VALUE;   // #define macro (not qualified)
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE |
                    QBDITRACE_HF_OLD_VALUE;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
    }

    /// Write a v5 (HF_PC_DELTA) header.  Version is bumped to
    /// QBDITRACE_VERSION_V5_PC_DELTA and HF_PC_DELTA is set so that
    /// tenet's TraceReader uses qbditrace_inst_head_v5_t (6-byte, pc_delta).
    void write_header_v5(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V5_PC_DELTA;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE |
                    QBDITRACE_HF_PC_DELTA;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        prev_pc_ = 0;
    }

    /// Write a header with HF_BRANCH_HINT set (branch class encoded in nzcv[7:4]).
    /// Used for tests that exercise the branch-hint fast path in FunctionCollector.
    void write_header_branch_hint(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE |
                    QBDITRACE_HF_BRANCH_HINT;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
    }

    /// Write a header with both HF_BRANCH_HINT and HF_PC_DELTA set.
    void write_header_branch_hint_v5(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V5_PC_DELTA;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE |
                    QBDITRACE_HF_PC_DELTA | QBDITRACE_HF_BRANCH_HINT;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        prev_pc_ = 0;
    }

    /// Write a v5+v6 combined header: HF_PC_DELTA + HF_OLD_VALUE.
    /// Version is set to QBDITRACE_VERSION_V6_OLD_VALUE (v6 supersedes v5 numerically).
    /// emit_v5v6() must be used with this header (6-byte inst head + 48-byte memacc).
    void write_header_v5v6(uint64_t code_size = 0x100000) {
        qbditrace::qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION_V6_OLD_VALUE;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + code_size;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE |
                    QBDITRACE_HF_PC_DELTA | QBDITRACE_HF_OLD_VALUE;
        strncpy(hdr.module_name, module_name, sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
        prev_pc_ = 0;
    }

    void emit_code(uint64_t runtime_pc, uint32_t opcode) {
        if (emitted_code.count(runtime_pc)) return;
        emitted_code.insert(runtime_pc);
        qbditrace::qbditrace_code_head_t h = {};
        h.kind = QBDITRACE_REC_CODE; h.size = 4; h.pc = runtime_pc;
        fwrite(&h, sizeof(h), 1, fp);
        fwrite(&opcode, 4, 1, fp);
    }

    void emit_anchor(const MachineState& state) {
        qbditrace::qbditrace_anchor_head_t h = {};
        h.kind = QBDITRACE_REC_ANCHOR; h.pc = state.gpr[33];
        fwrite(&h, sizeof(h), 1, fp);
        fwrite(state.gpr, sizeof(uint64_t), num_gpr, fp);
        // v5: anchor resets the running PC; track it so emit_v5() delta is correct
        prev_pc_ = state.gpr[33];
    }

    void emit_event(uint8_t ev, uint64_t addr, uint64_t site = 0) {
        qbditrace::qbditrace_event_head_t h = {};
        h.kind = QBDITRACE_REC_EVENT; h.event = ev; h.addr = addr; h.site = site;
        fwrite(&h, sizeof(h), 1, fp);
    }

    void emit_svc(uint64_t pc, uint64_t no, uint64_t a0 = 0, uint64_t a1 = 0) {
        qbditrace::qbditrace_svc_head_t h = {};
        h.kind = QBDITRACE_REC_SVC; h.pc = pc; h.syscall_no = no;
        h.args[0] = a0; h.args[1] = a1;
        fwrite(&h, sizeof(h), 1, fp);
    }

    /// Represents a single inline string capture to be written with emit_capicall().
    struct CapiStr {
        uint8_t     arg_idx  = 0;
        uint8_t     flags    = 0;   // QBDITRACE_SF_* bits
        std::string value;          // content (without trailing NUL)
    };

    /// Emit a REC_CAPICALL record with optional inline string captures.
    /// @param api_id  qbditrace_capi_id_t value (0 = unknown)
    /// @param pc      call-site PC inside the traced range
    /// @param target  runtime address of the called function
    /// @param args    up to 8 argument register values (x0..x7)
    /// @param strs    optional inline string captures (up to 4)
    void emit_capicall(uint8_t api_id, uint64_t pc, uint64_t target,
                       const std::vector<uint64_t>& args,
                       const std::vector<CapiStr>& strs = {}) {
        // Cap counts at format limits.
        uint8_t arg_count = static_cast<uint8_t>(std::min<size_t>(args.size(), 8));
        uint8_t str_count = static_cast<uint8_t>(
            std::min<size_t>(strs.size(), QBDITRACE_CAPICALL_MAX_STR_CAPS));

        qbditrace::qbditrace_capicall_head_t h = {};
        h.kind      = QBDITRACE_REC_CAPICALL;
        h.api_id    = api_id;
        h.arg_count = arg_count;
        h.str_count = str_count;
        h.pc        = pc;
        h.target    = target;
        for (uint8_t i = 0; i < arg_count; ++i) h.args[i] = args[i];
        fwrite(&h, sizeof(h), 1, fp);

        // Write variable-length string payloads.
        for (uint8_t si = 0; si < str_count; ++si) {
            const auto& s = strs[si];
            uint8_t slen = static_cast<uint8_t>(
                std::min<size_t>(s.value.size(), QBDITRACE_CAPICALL_MAX_STR_BYTES));

            qbditrace::qbditrace_capicall_str_t sh = {};
            sh.str_arg_idx = s.arg_idx;
            sh.str_len     = slen;
            sh.str_flags   = s.flags;
            sh._reserved   = 0;
            fwrite(&sh, sizeof(sh), 1, fp);

            // Write content bytes + NUL, padded to 4-byte alignment.
            uint16_t data_bytes = static_cast<uint16_t>(slen + 1);  // content + NUL
            uint16_t padded = (data_bytes + 3u) & ~3u;

            // Write content + NUL
            fwrite(s.value.data(), 1, slen, fp);
            char nul = '\0';
            fwrite(&nul, 1, 1, fp);
            // Padding bytes
            uint16_t pad = padded - data_bytes;
            for (uint16_t p = 0; p < pad; ++p) fwrite(&nul, 1, 1, fp);
        }
    }

    void emit_objc(uint64_t pc, uint64_t recv, uint64_t sel, const char* cls) {
        qbditrace::qbditrace_objc_head_t h = {};
        h.kind = QBDITRACE_REC_OBJC; h.variant = QBDITRACE_OBJC_MSGSEND;
        h.pc = pc; h.recv = recv; h.sel = sel;
        strncpy(h.cls, cls, sizeof(h.cls) - 1);
        fwrite(&h, sizeof(h), 1, fp);
    }

    void emit_thread(uint64_t tid) {
        qbditrace::qbditrace_thread_head_t h = {};
        h.kind = QBDITRACE_REC_THREAD; h.thread_id = tid;
        fwrite(&h, sizeof(h), 1, fp);
    }

    void emit(MachineState& ms, uint64_t spc, uint32_t opcode,
              std::vector<RegDiff> diffs, std::vector<MemAcc> mems, uint8_t nzcv = 0) {
        uint64_t rpc = rt(spc);
        for (auto& d : diffs) ms.gpr[d.index] = d.value;
        ms.nzcv() = nzcv;
        ms.pc() = rpc;

        // Auto-anchor
        if (inst_count % anchor_interval == 0) emit_anchor(ms);

        // Emit code
        emit_code(rpc, opcode);

        // Emit INST record (must use sizeof structs for correct alignment/padding)
        qbditrace::qbditrace_inst_head_t ih = {};
        ih.kind = QBDITRACE_REC_INST;
        ih.nzcv = nzcv;
        ih.n_regdiff = (uint8_t)diffs.size();
        ih.n_mem = (uint8_t)mems.size();
        ih.pc = rpc;
        fwrite(&ih, sizeof(ih), 1, fp);

        for (auto& d : diffs) {
            qbditrace::qbditrace_regdiff_t rd = {};
            rd.reg_index = d.index;
            rd.value = d.value;
            fwrite(&rd, sizeof(rd), 1, fp);
        }
        for (auto& m : mems) {
            qbditrace::qbditrace_memacc_t ma = {};
            ma.mem_type = m.type;
            ma.mem_flags = 0;
            ma.size = m.size;
            ma.addr = m.addr;
            ma.value = m.value;
            ma.value_hi = 0;
            fwrite(&ma, sizeof(ma), 1, fp);
        }
        inst_count++;
    }

    /// Emit a v6 INST record (48-byte memacc with old_value fields).
    /// Must be called after write_header_v6().  `mems_v6` provides both the
    /// new value and the pre-write old value for each memory access.
    void emit_v6(MachineState& ms, uint64_t spc, uint32_t opcode,
                 std::vector<RegDiff> diffs, std::vector<MemAccV6> mems_v6,
                 uint8_t nzcv = 0) {
        uint64_t rpc = rt(spc);
        for (auto& d : diffs) ms.gpr[d.index] = d.value;
        ms.nzcv() = nzcv;
        ms.pc() = rpc;

        // Auto-anchor
        if (inst_count % anchor_interval == 0) emit_anchor(ms);

        // Emit code
        emit_code(rpc, opcode);

        // Emit v4-format INST head (same header for v4/v5/v6 — only payload changes)
        qbditrace::qbditrace_inst_head_t ih = {};
        ih.kind = QBDITRACE_REC_INST;
        ih.nzcv = nzcv;
        ih.n_regdiff = (uint8_t)diffs.size();
        ih.n_mem = (uint8_t)mems_v6.size();
        ih.pc = rpc;
        fwrite(&ih, sizeof(ih), 1, fp);

        for (auto& d : diffs) {
            qbditrace::qbditrace_regdiff_t rd = {};
            rd.reg_index = d.index;
            rd.value = d.value;
            fwrite(&rd, sizeof(rd), 1, fp);
        }
        for (auto& m : mems_v6) {
            qbditrace::qbditrace_memacc_v6_t ma = {};
            ma.mem_type  = m.type;
            ma.mem_flags = m.old_unknown ? QBDITRACE_MF_OLD_UNKNOWN : 0;
            ma.size      = m.size;
            ma.addr      = m.addr;
            ma.value     = m.value;
            ma.value_hi  = m.value_hi;
            ma.old_value     = m.old_value;
            ma.old_value_hi  = m.old_value_hi;
            fwrite(&ma, sizeof(ma), 1, fp);
        }
        inst_count++;
    }

    /// Emit a v5 INST record (HF_PC_DELTA: 6-byte inst head with int16 pc_delta).
    /// Must be called after write_header_v5().  The delta from the previous
    /// instruction's absolute PC is computed automatically.
    /// If the delta would overflow int16, an ANCHOR is emitted first to reset
    /// the running PC, matching real qbditrace behavior.
    void emit_v5(MachineState& ms, uint64_t spc, uint32_t opcode,
                 std::vector<RegDiff> diffs, std::vector<MemAcc> mems,
                 uint8_t nzcv = 0) {
        uint64_t rpc = rt(spc);
        for (auto& d : diffs) ms.gpr[d.index] = d.value;
        ms.nzcv() = nzcv;
        ms.pc() = rpc;

        // Auto-anchor (also resets prev_pc_ via emit_anchor)
        if (inst_count % anchor_interval == 0) emit_anchor(ms);

        // Compute delta; if it overflows int16, emit an anchor first
        int64_t raw_delta = static_cast<int64_t>(rpc) - static_cast<int64_t>(prev_pc_);
        if (raw_delta < -32768 || raw_delta > 32767) {
            emit_anchor(ms);  // resets prev_pc_ = rpc
            raw_delta = 0;
        }
        int16_t delta = static_cast<int16_t>(raw_delta);
        prev_pc_ = rpc;

        // Emit code
        emit_code(rpc, opcode);

        // Emit v5 INST head (6 bytes: kind, nzcv, n_regdiff, n_mem, int16 pc_delta)
        qbditrace::qbditrace_inst_head_v5_t ih = {};
        ih.kind = QBDITRACE_REC_INST;
        ih.nzcv = nzcv;
        ih.n_regdiff = (uint8_t)diffs.size();
        ih.n_mem = (uint8_t)mems.size();
        ih.pc_delta = delta;
        fwrite(&ih, sizeof(ih), 1, fp);

        for (auto& d : diffs) {
            qbditrace::qbditrace_regdiff_t rd = {};
            rd.reg_index = d.index;
            rd.value = d.value;
            fwrite(&rd, sizeof(rd), 1, fp);
        }
        for (auto& m : mems) {
            qbditrace::qbditrace_memacc_t ma = {};
            ma.mem_type = m.type;
            ma.mem_flags = 0;
            ma.size = m.size;
            ma.addr = m.addr;
            ma.value = m.value;
            ma.value_hi = 0;
            fwrite(&ma, sizeof(ma), 1, fp);
        }
        inst_count++;
    }

    /// Emit a v5+v6 INST record: 6-byte pc_delta inst head + 48-byte memacc_v6_t.
    /// Must be called after write_header_v5v6().
    void emit_v5v6(MachineState& ms, uint64_t spc, uint32_t opcode,
                   std::vector<RegDiff> diffs, std::vector<MemAccV6> mems_v6,
                   uint8_t nzcv = 0) {
        uint64_t rpc = rt(spc);
        for (auto& d : diffs) ms.gpr[d.index] = d.value;
        ms.nzcv() = nzcv;
        ms.pc() = rpc;

        // Auto-anchor
        if (inst_count % anchor_interval == 0) emit_anchor(ms);

        // Compute delta; overflow → anchor first
        int64_t raw_delta = static_cast<int64_t>(rpc) - static_cast<int64_t>(prev_pc_);
        if (raw_delta < -32768 || raw_delta > 32767) {
            emit_anchor(ms);
            raw_delta = 0;
        }
        int16_t delta = static_cast<int16_t>(raw_delta);
        prev_pc_ = rpc;

        // Emit code
        emit_code(rpc, opcode);

        // Emit v5 INST head (6 bytes)
        qbditrace::qbditrace_inst_head_v5_t ih = {};
        ih.kind = QBDITRACE_REC_INST;
        ih.nzcv = nzcv;
        ih.n_regdiff = (uint8_t)diffs.size();
        ih.n_mem = (uint8_t)mems_v6.size();
        ih.pc_delta = delta;
        fwrite(&ih, sizeof(ih), 1, fp);

        for (auto& d : diffs) {
            qbditrace::qbditrace_regdiff_t rd = {};
            rd.reg_index = d.index;
            rd.value = d.value;
            fwrite(&rd, sizeof(rd), 1, fp);
        }
        for (auto& m : mems_v6) {
            qbditrace::qbditrace_memacc_v6_t ma = {};
            ma.mem_type  = m.type;
            ma.mem_flags = m.old_unknown ? QBDITRACE_MF_OLD_UNKNOWN : 0;
            ma.size      = m.size;
            ma.addr      = m.addr;
            ma.value     = m.value;
            ma.value_hi  = m.value_hi;
            ma.old_value     = m.old_value;
            ma.old_value_hi  = m.old_value_hi;
            fwrite(&ma, sizeof(ma), 1, fp);
        }
        inst_count++;
    }
};

} // namespace tenet::test

#endif // TENET_TEST_TRACE_WRITER_H
