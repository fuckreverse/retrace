/*
 * gen_trace.cpp  — Synthetic trace generator for tenet demo
 *
 * Produces a realistic AArch64 qbditrace binary with:
 *   - File header (magic/version/arch/slide info)
 *   - Code table (REC_CODE records for each unique PC)
 *   - Periodic anchors every 256 instructions
 *   - A multi-function execution trace with:
 *       main()  → calls sort_array() → calls swap()
 *       Includes loops, branches, memory loads/stores, register diffs
 *
 * The simulated program:
 *   int arr[8] = {42, 7, 13, 99, 3, 55, 21, 1};
 *   sort_array(arr, 8);   // bubble sort
 *
 * Build:
 *   clang++ -std=c++17 -O2 -I../../dashcam -o gen_trace gen_trace.cpp
 *
 * Run:
 *   ./gen_trace demo_trace.bin
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>
#include <unordered_set>
#include <unordered_map>

// Include the trace format header
#include "TraceFormat.h"

using namespace qbditrace;

// ─── Simulated machine state ─────────────────────────────────────────────────

struct MachineState {
    uint64_t gpr[34] = {};  // x0..x28, fp(29), lr(30), sp(31), nzcv(32), pc(33)
    
    uint64_t& x(int i) { return gpr[i]; }
    uint64_t& fp() { return gpr[29]; }
    uint64_t& lr() { return gpr[30]; }
    uint64_t& sp() { return gpr[31]; }
    uint64_t& nzcv() { return gpr[32]; }
    uint64_t& pc() { return gpr[33]; }
};

// ─── Simulated memory ────────────────────────────────────────────────────────

std::unordered_map<uint64_t, uint64_t> memory;

void mem_store64(uint64_t addr, uint64_t val) {
    memory[addr] = val;
}

uint64_t mem_load64(uint64_t addr) {
    auto it = memory.find(addr);
    return it != memory.end() ? it->second : 0;
}

// ─── Trace writer ────────────────────────────────────────────────────────────

struct TraceWriter {
    FILE* fp = nullptr;
    uint64_t module_base = 0x100000000ULL;   // simulated module base
    uint64_t module_slide = 0x4000ULL;       // small ASLR slide
    uint32_t num_gpr = 34;
    uint64_t inst_count = 0;
    std::unordered_set<uint64_t> emitted_code;
    
    // Opcode table: static_pc -> opcode
    std::unordered_map<uint64_t, uint32_t> opcode_map;
    
    bool open(const char* path) {
        fp = fopen(path, "wb");
        return fp != nullptr;
    }
    
    void close() {
        if (fp) fclose(fp);
        fp = nullptr;
    }
    
    void write_header() {
        qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = num_gpr;
        hdr.module_base = module_base;
        hdr.module_slide = module_slide;
        hdr.trace_start = module_base + module_slide;
        hdr.trace_end = module_base + module_slide + 0x10000;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;
        strncpy(hdr.module_name, "demo_binary", sizeof(hdr.module_name) - 1);
        fwrite(&hdr, sizeof(hdr), 1, fp);
    }
    
    // Emit a CODE record for a PC (only once per unique PC)
    void emit_code(uint64_t runtime_pc, uint32_t opcode) {
        if (emitted_code.count(runtime_pc)) return;
        emitted_code.insert(runtime_pc);
        opcode_map[runtime_pc] = opcode;
        
        qbditrace_code_head_t code_hdr = {};
        code_hdr.kind = QBDITRACE_REC_CODE;
        code_hdr.size = 4;  // AArch64 instructions are 4 bytes
        code_hdr.pc = runtime_pc;
        fwrite(&code_hdr, sizeof(code_hdr), 1, fp);
        fwrite(&opcode, 4, 1, fp);
    }
    
    // Emit an ANCHOR record (full register snapshot)
    void emit_anchor(const MachineState& state) {
        qbditrace_anchor_head_t anchor = {};
        anchor.kind = QBDITRACE_REC_ANCHOR;
        anchor.pc = state.gpr[33];
        fwrite(&anchor, sizeof(anchor), 1, fp);
        fwrite(state.gpr, sizeof(uint64_t), num_gpr, fp);
    }
    
    // Emit an INST record with register diffs and optional memory accesses
    struct RegDiff {
        uint8_t index;
        uint64_t value;
    };
    struct MemAcc {
        uint8_t type;   // 1=read, 2=write
        uint16_t size;
        uint64_t addr;
        uint64_t value;
    };
    
    void emit_inst(uint64_t runtime_pc, uint8_t nzcv_val,
                   const std::vector<RegDiff>& diffs,
                   const std::vector<MemAcc>& mems,
                   uint32_t opcode) {
        // Emit code record if first time seeing this PC
        emit_code(runtime_pc, opcode);
        
        qbditrace_inst_head_t inst_hdr = {};
        inst_hdr.kind = QBDITRACE_REC_INST;
        inst_hdr.nzcv = nzcv_val;
        inst_hdr.n_regdiff = static_cast<uint8_t>(diffs.size());
        inst_hdr.n_mem = static_cast<uint8_t>(mems.size());
        inst_hdr.pc = runtime_pc;
        fwrite(&inst_hdr, sizeof(inst_hdr), 1, fp);
        
        // Write reg diffs as the on-disk qbditrace_regdiff_t struct
        // (16 bytes: 1B reg_index + 7B padding + 8B value).  Writing the
        // struct wholesale (rather than field-by-field) is what guarantees
        // the decoder sees the exact same layout, including padding.
        for (auto& d : diffs) {
            qbditrace_regdiff_t rd = {};
            rd.reg_index = d.index;
            rd.value = d.value;
            fwrite(&rd, sizeof(rd), 1, fp);
        }

        // Write memory accesses as the on-disk qbditrace_memacc_t struct
        // (32 bytes: mem_type/mem_flags/size + 4B padding + addr + value +
        // value_hi).
        for (auto& m : mems) {
            qbditrace_memacc_t ma = {};
            ma.mem_type = m.type;
            ma.mem_flags = 0;
            ma.size = m.size;
            ma.addr = m.addr;
            ma.value = m.value;
            ma.value_hi = 0;  // <=8-byte accesses store the whole value in `value`
            fwrite(&ma, sizeof(ma), 1, fp);
        }
        
        inst_count++;
    }
};

// ─── Real AArch64 opcode encoding helpers ────────────────────────────────────

static uint32_t encode_mov_imm(int rd, uint16_t imm) {
    // MOVZ Xd, #imm
    return 0xD2800000u | (static_cast<uint32_t>(imm) << 5) | rd;
}

static uint32_t encode_add_imm(int rd, int rn, uint16_t imm) {
    // ADD Xd, Xn, #imm
    return 0x91000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
}

static uint32_t encode_sub_imm(int rd, int rn, uint16_t imm) {
    // SUB Xd, Xn, #imm
    return 0xD1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
}

static uint32_t encode_subs_imm(int rd, int rn, uint16_t imm) {
    // SUBS Xd, Xn, #imm
    return 0xF1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
}

static uint32_t encode_cmp_imm(int rn, uint16_t imm) {
    // CMP Xn, #imm = SUBS XZR, Xn, #imm
    return encode_subs_imm(31, rn, imm);
}

static uint32_t encode_ldr_reg(int rt, int rn, int rm) {
    // LDR Xt, [Xn, Xm, LSL #3]
    return 0xF8687800u | (rm << 16) | (rn << 5) | rt;
}

static uint32_t encode_str_reg(int rt, int rn, int rm) {
    // STR Xt, [Xn, Xm, LSL #3]
    return 0xF8287800u | (rm << 16) | (rn << 5) | rt;
}

static uint32_t encode_bl(int32_t offset_bytes) {
    // BL offset
    int32_t imm26 = offset_bytes >> 2;
    return 0x94000000u | (imm26 & 0x03FFFFFF);
}

static uint32_t encode_ret() {
    // RET
    return 0xD65F03C0u;
}

static uint32_t encode_b(int32_t offset_bytes) {
    // B offset
    int32_t imm26 = offset_bytes >> 2;
    return 0x14000000u | (imm26 & 0x03FFFFFF);
}

static uint32_t encode_b_lt(int32_t offset_bytes) {
    // B.LT offset
    int32_t imm19 = offset_bytes >> 2;
    return 0x5400000Bu | ((imm19 & 0x7FFFF) << 5);
}

static uint32_t encode_b_ge(int32_t offset_bytes) {
    // B.GE offset
    int32_t imm19 = offset_bytes >> 2;
    return 0x5400000Au | ((imm19 & 0x7FFFF) << 5);
}

static uint32_t encode_stp_pre(int rt, int rt2, int rn, int16_t imm7) {
    // STP Xt, Xt2, [Xn, #imm]!
    return 0xA9BF0000u | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt;
}

static uint32_t encode_ldp_post(int rt, int rt2, int rn, int16_t imm7) {
    // LDP Xt, Xt2, [Xn], #imm
    return 0xA8C10000u | ((imm7 & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt;
}

static uint32_t encode_mov_reg(int rd, int rm) {
    // MOV Xd, Xm = ORR Xd, XZR, Xm
    return 0xAA0003E0u | (rm << 16) | rd;
}

// ─── Simulation: generate the trace for a bubble sort program ────────────────

int main(int argc, char* argv[]) {
    const char* output = "demo_trace.bin";
    if (argc > 1) output = argv[1];
    
    TraceWriter tw;
    if (!tw.open(output)) {
        fprintf(stderr, "Cannot open %s for writing\n", output);
        return 1;
    }
    
    const uint64_t SLIDE = tw.module_slide;
    auto rt = [&](uint64_t static_pc) -> uint64_t { return static_pc + SLIDE; };
    
    // Memory: array at stack location
    const uint64_t STACK_TOP = 0x16F000000ULL;
    const uint64_t ARR_BASE = STACK_TOP - 0x100;
    
    int64_t arr[] = {42, 7, 13, 99, 3, 55, 21, 1};
    int n = 8;
    
    // Initialize memory
    for (int i = 0; i < n; i++) {
        mem_store64(ARR_BASE + i * 8, static_cast<uint64_t>(arr[i]));
    }
    
    // Machine state
    MachineState ms;
    ms.sp() = STACK_TOP;
    ms.fp() = STACK_TOP;
    ms.pc() = rt(0x1000);
    ms.lr() = 0;
    
    // Write header
    tw.write_header();
    
    // Helper: emit an instruction with state updates
    auto emit = [&](uint64_t static_pc, uint32_t opcode,
                    std::vector<TraceWriter::RegDiff> diffs,
                    std::vector<TraceWriter::MemAcc> mems,
                    uint8_t nzcv_val = 0) {
        uint64_t rpc = rt(static_pc);
        
        // Anchor every 256 instructions
        if (tw.inst_count % 256 == 0) {
            tw.emit_anchor(ms);
        }
        
        // Update machine state
        ms.pc() = rpc;
        for (auto& d : diffs) {
            ms.gpr[d.index] = d.value;
        }
        ms.nzcv() = nzcv_val;
        
        // Add PC update to diffs
        std::vector<TraceWriter::RegDiff> all_diffs = diffs;
        all_diffs.push_back({33, rpc});
        
        tw.emit_inst(rpc, nzcv_val, all_diffs, mems, opcode);
    };
    
    printf("Generating trace: bubble sort of 8 elements...\n");
    
    // ═══════════════════════════════════════════════════════════════════════
    // MAIN
    // ═══════════════════════════════════════════════════════════════════════
    
    // 0x1000: stp x29, x30, [sp, #-16]!
    ms.sp() -= 16;
    mem_store64(ms.sp(), ms.fp());
    mem_store64(ms.sp() + 8, ms.lr());
    emit(0x1000, encode_stp_pre(29, 30, 31, -2),
         {{31, ms.sp()}, {29, ms.fp()}},
         {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
    
    // 0x1004: mov x29, sp
    ms.fp() = ms.sp();
    emit(0x1004, encode_mov_reg(29, 31), {{29, ms.fp()}}, {});
    
    // 0x1008: mov x0, arr_base (lower bits)
    ms.x(0) = ARR_BASE;
    emit(0x1008, encode_mov_imm(0, ARR_BASE & 0xFFFF), {{0, ARR_BASE}}, {});
    
    // 0x100c: mov x1, #8
    ms.x(1) = 8;
    emit(0x100c, encode_mov_imm(1, 8), {{1, 8}}, {});
    
    // 0x1010: bl sort_array
    ms.lr() = rt(0x1014);
    emit(0x1010, encode_bl(0x1100 - 0x1010), {{30, ms.lr()}}, {});
    
    // ═══════════════════════════════════════════════════════════════════════
    // SORT_ARRAY
    // ═══════════════════════════════════════════════════════════════════════
    
    // 0x1100: stp x29, x30, [sp, #-16]!
    ms.sp() -= 16;
    mem_store64(ms.sp(), ms.fp());
    mem_store64(ms.sp() + 8, ms.lr());
    emit(0x1100, encode_stp_pre(29, 30, 31, -2),
         {{31, ms.sp()}},
         {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
    
    // 0x1104: mov x29, sp
    ms.fp() = ms.sp();
    emit(0x1104, encode_mov_reg(29, 31), {{29, ms.fp()}}, {});
    
    // 0x1108: mov x19, x0
    ms.x(19) = ARR_BASE;
    emit(0x1108, encode_mov_reg(19, 0), {{19, ARR_BASE}}, {});
    
    // 0x110c: mov x20, x1
    ms.x(20) = 8;
    emit(0x110c, encode_mov_reg(20, 1), {{20, 8}}, {});
    
    // 0x1110: mov x21, #0
    ms.x(21) = 0;
    emit(0x1110, encode_mov_imm(21, 0), {{21, 0}}, {});
    
    // ─── Outer loop ──────────────────────────────────────────────────────
    for (int i = 0; i < n - 1; i++) {
        // 0x1114: cmp x21, x20
        uint8_t nzcv_outer = (ms.x(21) < ms.x(20)) ? 0x8 : 0x6;
        emit(0x1114, encode_cmp_imm(21, 8), {}, {}, nzcv_outer);
        
        // 0x1118: b.ge end_outer → not taken
        emit(0x1118, encode_b_ge(0x1158 - 0x1118), {}, {}, nzcv_outer);
        
        // 0x111c: mov x22, #0
        ms.x(22) = 0;
        emit(0x111c, encode_mov_imm(22, 0), {{22, 0}}, {});
        
        // 0x1120: sub x23, x20, x21
        int limit = n - i - 1;
        ms.x(23) = ms.x(20) - ms.x(21);
        emit(0x1120, encode_sub_imm(23, 20, static_cast<uint16_t>(ms.x(21) & 0xFFF)),
             {{23, ms.x(23)}}, {});
        
        // 0x1124: sub x23, x23, #1
        ms.x(23) -= 1;
        emit(0x1124, encode_sub_imm(23, 23, 1), {{23, ms.x(23)}}, {});
        
        // ─── Inner loop ──────────────────────────────────────────────────
        for (int j = 0; j < limit; j++) {
            // 0x1128: cmp x22, x23
            uint8_t nzcv_inner = (ms.x(22) < ms.x(23)) ? 0x8 : 0x6;
            emit(0x1128, encode_cmp_imm(22, static_cast<uint16_t>(ms.x(23) & 0xFFF)),
                 {}, {}, nzcv_inner);
            
            // 0x112c: b.ge end_inner → not taken
            emit(0x112c, encode_b_ge(0x1150 - 0x112c), {}, {}, nzcv_inner);
            
            // 0x1130: ldr x24, [x19, x22, lsl #3]
            uint64_t addr_j = ARR_BASE + j * 8;
            uint64_t val_j = mem_load64(addr_j);
            ms.x(24) = val_j;
            emit(0x1130, encode_ldr_reg(24, 19, 22),
                 {{24, val_j}},
                 {{1, 8, addr_j, val_j}});
            
            // 0x1134: add x25, x22, #1
            ms.x(25) = ms.x(22) + 1;
            emit(0x1134, encode_add_imm(25, 22, 1), {{25, ms.x(25)}}, {});
            
            // 0x1138: ldr x26, [x19, x25, lsl #3]
            uint64_t addr_j1 = ARR_BASE + (j + 1) * 8;
            uint64_t val_j1 = mem_load64(addr_j1);
            ms.x(26) = val_j1;
            emit(0x1138, encode_ldr_reg(26, 19, 25),
                 {{26, val_j1}},
                 {{1, 8, addr_j1, val_j1}});
            
            // 0x113c: cmp x24, x26
            bool need_swap = (int64_t)val_j > (int64_t)val_j1;
            uint8_t nzcv_cmp = need_swap ? 0x2 : 0x8;
            emit(0x113c, encode_cmp_imm(24, static_cast<uint16_t>(val_j1 & 0xFFF)),
                 {}, {}, nzcv_cmp);
            
            if (need_swap) {
                // 0x1140: b.lt no_swap → not taken
                emit(0x1140, encode_b_lt(0x1148 - 0x1140), {}, {}, nzcv_cmp);
                
                // 0x1144: bl swap
                ms.lr() = rt(0x1148);
                emit(0x1144, encode_bl(0x1200 - 0x1144), {{30, ms.lr()}}, {});
                
                // ═══ SWAP function ═══
                // 0x1200: ldr x3, [x19, x22, lsl #3]
                uint64_t sv_j = mem_load64(addr_j);
                ms.x(3) = sv_j;
                emit(0x1200, encode_ldr_reg(3, 19, 22),
                     {{3, sv_j}},
                     {{1, 8, addr_j, sv_j}});
                
                // 0x1204: ldr x4, [x19, x25, lsl #3]
                uint64_t sv_j1 = mem_load64(addr_j1);
                ms.x(4) = sv_j1;
                emit(0x1204, encode_ldr_reg(4, 19, 25),
                     {{4, sv_j1}},
                     {{1, 8, addr_j1, sv_j1}});
                
                // 0x1208: str x4, [x19, x22, lsl #3]
                mem_store64(addr_j, sv_j1);
                emit(0x1208, encode_str_reg(4, 19, 22),
                     {},
                     {{2, 8, addr_j, sv_j1}});
                
                // 0x120c: str x3, [x19, x25, lsl #3]
                mem_store64(addr_j1, sv_j);
                emit(0x120c, encode_str_reg(3, 19, 25),
                     {},
                     {{2, 8, addr_j1, sv_j}});
                
                // 0x1210: ret
                emit(0x1210, encode_ret(), {}, {});
                
                // Update arr values
                int64_t tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            } else {
                // 0x1140: b.lt no_swap → taken
                emit(0x1140, encode_b_lt(0x1148 - 0x1140), {}, {}, nzcv_cmp);
            }
            
            // 0x1148: add x22, x22, #1
            ms.x(22) += 1;
            emit(0x1148, encode_add_imm(22, 22, 1), {{22, ms.x(22)}}, {});
            
            // 0x114c: b inner_loop
            emit(0x114c, encode_b(0x1128 - 0x114c), {}, {});
        }
        
        // End of inner loop: exit condition
        uint8_t nzcv_exit = 0x6;
        emit(0x1128, encode_cmp_imm(22, static_cast<uint16_t>(ms.x(23) & 0xFFF)),
             {}, {}, nzcv_exit);
        emit(0x112c, encode_b_ge(0x1150 - 0x112c), {}, {}, nzcv_exit);
        
        // 0x1150: add x21, x21, #1
        ms.x(21) += 1;
        emit(0x1150, encode_add_imm(21, 21, 1), {{21, ms.x(21)}}, {});
        
        // 0x1154: b outer_loop
        emit(0x1154, encode_b(0x1114 - 0x1154), {}, {});
    }
    
    // Final outer loop exit
    uint8_t nzcv_final = 0x6;
    emit(0x1114, encode_cmp_imm(21, 8), {}, {}, nzcv_final);
    emit(0x1118, encode_b_ge(0x1158 - 0x1118), {}, {}, nzcv_final);
    
    // 0x1158: ldp x29, x30, [sp], #16
    ms.fp() = mem_load64(ms.sp());
    ms.lr() = mem_load64(ms.sp() + 8);
    ms.sp() += 16;
    emit(0x1158, encode_ldp_post(29, 30, 31, 2),
         {{29, ms.fp()}, {30, ms.lr()}, {31, ms.sp()}},
         {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, ms.lr()}});
    
    // 0x115c: ret (from sort_array)
    emit(0x115c, encode_ret(), {}, {});
    
    // ═══════════════════════════════════════════════════════════════════════
    // BACK IN MAIN
    // ═══════════════════════════════════════════════════════════════════════
    
    // 0x1014: ldp x29, x30, [sp], #16
    ms.fp() = mem_load64(ms.sp());
    ms.lr() = mem_load64(ms.sp() + 8);
    ms.sp() += 16;
    emit(0x1014, encode_ldp_post(29, 30, 31, 2),
         {{29, ms.fp()}, {30, ms.lr()}, {31, ms.sp()}},
         {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, ms.lr()}});
    
    // 0x1018: ret (from main)
    emit(0x1018, encode_ret(), {}, {});
    
    // Final anchor
    tw.emit_anchor(ms);
    
    tw.close();
    
    printf("Trace written to: %s\n", output);
    printf("Total instructions: %llu\n", (unsigned long long)tw.inst_count);
    printf("Unique PCs: %zu\n", tw.emitted_code.size());
    printf("\nSorted array: ");
    for (int i = 0; i < n; i++) {
        printf("%lld ", (long long)arr[i]);
    }
    printf("\n");
    
    return 0;
}
