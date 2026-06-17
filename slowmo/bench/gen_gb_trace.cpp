/*
 * gen_gb_trace.cpp — Generate GB-scale synthetic traces for benchmarking
 *
 * Produces large qbditrace v4 files with realistic CFG structures.
 * Two modes:
 *   Mode 1 (default): Large trace, many instructions, moderate CFG
 *   Mode 2 (--complex-cfg): Large trace with thousands of unique PCs,
 *           hundreds of loops, deep nesting — stress-tests graph algorithms.
 *
 * Build:
 *   clang++ -std=c++17 -O2 -I../../tools/qbditrace -o gen_gb_trace gen_gb_trace.cpp
 *
 * Usage:
 *   ./gen_gb_trace <output.trace> [target_size_gb] [--complex-cfg]
 */

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <unordered_set>

#include "TraceFormat.h"

using namespace qbditrace;

// ─── Constants ───────────────────────────────────────────────────────────────

static constexpr uint64_t MODULE_BASE  = 0x100000000ULL;
static constexpr uint64_t MODULE_SLIDE = 0x4000ULL;
static constexpr uint32_t NUM_GPR      = 34;
static constexpr uint64_t ANCHOR_INTERVAL = 512;

// ─── Fast buffered writer ────────────────────────────────────────────────────

class FastWriter {
public:
    static constexpr size_t BUF_SIZE = 4 * 1024 * 1024;

    FILE* fp_ = nullptr;
    uint8_t* buf_;
    size_t pos_ = 0;
    uint64_t total_bytes_ = 0;

    FastWriter() { buf_ = new uint8_t[BUF_SIZE]; }
    ~FastWriter() { close(); delete[] buf_; }

    bool open(const char* path) {
        fp_ = fopen(path, "wb");
        if (fp_) setvbuf(fp_, nullptr, _IOFBF, BUF_SIZE);
        return fp_ != nullptr;
    }

    void flush() {
        if (pos_ > 0 && fp_) {
            fwrite(buf_, 1, pos_, fp_);
            total_bytes_ += pos_;
            pos_ = 0;
        }
    }

    void close() {
        flush();
        if (fp_) { fclose(fp_); fp_ = nullptr; }
    }

    void write_raw(const void* data, size_t len) {
        if (pos_ + len > BUF_SIZE) flush();
        if (len > BUF_SIZE) {
            fwrite(data, 1, len, fp_);
            total_bytes_ += len;
        } else {
            memcpy(buf_ + pos_, data, len);
            pos_ += len;
        }
    }

    template<typename T>
    void write_val(const T& v) { write_raw(&v, sizeof(T)); }

    uint64_t bytes_written() const { return total_bytes_ + pos_; }
};

// ─── Trace generator ─────────────────────────────────────────────────────────

class GBTraceGenerator {
public:
    FastWriter writer_;
    uint64_t inst_count_ = 0;
    uint64_t anchor_count_ = 0;
    std::unordered_set<uint64_t> emitted_code_;
    uint64_t regs_[NUM_GPR] = {};

    void write_header() {
        qbditrace_file_header_t hdr = {};
        hdr.magic = QBDITRACE_MAGIC;
        hdr.version = QBDITRACE_VERSION;
        hdr.arch = QBDITRACE_ARCH_AARCH64;
        hdr.num_gpr = NUM_GPR;
        hdr.module_base = MODULE_BASE;
        hdr.module_slide = MODULE_SLIDE;
        hdr.trace_start = MODULE_BASE + MODULE_SLIDE;
        hdr.trace_end = MODULE_BASE + MODULE_SLIDE + 0x1000000;
        hdr.flags = QBDITRACE_HF_HAS_MEM | QBDITRACE_HF_HAS_NZCV |
                    QBDITRACE_HF_REG_DIFF | QBDITRACE_HF_HAS_CODE;
        strncpy(hdr.module_name, "perf_gb_complex", sizeof(hdr.module_name) - 1);
        writer_.write_val(hdr);
    }

    void emit_code(uint64_t runtime_pc, uint32_t opcode) {
        if (emitted_code_.count(runtime_pc)) return;
        emitted_code_.insert(runtime_pc);
        qbditrace_code_head_t code_hdr = {};
        code_hdr.kind = QBDITRACE_REC_CODE;
        code_hdr.size = 4;
        code_hdr.pc = runtime_pc;
        writer_.write_val(code_hdr);
        writer_.write_val(opcode);
    }

    void emit_anchor() {
        qbditrace_anchor_head_t anchor = {};
        anchor.kind = QBDITRACE_REC_ANCHOR;
        anchor.pc = regs_[33];
        writer_.write_val(anchor);
        writer_.write_raw(regs_, sizeof(uint64_t) * NUM_GPR);
        anchor_count_++;
    }

    // Emit instruction: 2 reg diffs (one data reg + PC)
    void emit_inst(uint64_t static_pc, uint32_t opcode, uint8_t reg, uint64_t val) {
        uint64_t rpc = static_pc + MODULE_SLIDE;
        if (inst_count_ % ANCHOR_INTERVAL == 0) {
            regs_[33] = rpc;
            emit_anchor();
        }
        emit_code(rpc, opcode);

        qbditrace_inst_head_t inst_hdr = {};
        inst_hdr.kind = QBDITRACE_REC_INST;
        inst_hdr.nzcv = 0;
        inst_hdr.n_regdiff = 2;
        inst_hdr.n_mem = 0;
        inst_hdr.pc = rpc;
        writer_.write_val(inst_hdr);

        writer_.write_val(reg);
        writer_.write_val(val);
        regs_[reg] = val;

        uint8_t pc_idx = 33;
        writer_.write_val(pc_idx);
        writer_.write_val(rpc);
        regs_[33] = rpc;

        inst_count_++;
    }

    // Emit branch-like instruction: PC diff only
    void emit_branch(uint64_t static_pc, uint32_t opcode) {
        uint64_t rpc = static_pc + MODULE_SLIDE;
        if (inst_count_ % ANCHOR_INTERVAL == 0) {
            regs_[33] = rpc;
            emit_anchor();
        }
        emit_code(rpc, opcode);

        qbditrace_inst_head_t inst_hdr = {};
        inst_hdr.kind = QBDITRACE_REC_INST;
        inst_hdr.nzcv = 0x8;
        inst_hdr.n_regdiff = 1;
        inst_hdr.n_mem = 0;
        inst_hdr.pc = rpc;
        writer_.write_val(inst_hdr);

        uint8_t pc_idx = 33;
        writer_.write_val(pc_idx);
        writer_.write_val(rpc);
        regs_[33] = rpc;

        inst_count_++;
    }
};

// ─── Opcode helpers ──────────────────────────────────────────────────────────

static uint32_t enc_nop() { return 0xD503201F; }
static uint32_t enc_add_imm(int rd, int rn, int imm) {
    return 0x91000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
}
static uint32_t enc_sub_imm(int rd, int rn, int imm) {
    return 0xD1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | rd;
}
static uint32_t enc_cmp_imm(int rn, int imm) {
    return 0xF1000000u | ((imm & 0xFFF) << 10) | (rn << 5) | 31;
}
static uint32_t enc_b(int32_t off) {
    return 0x14000000u | ((off >> 2) & 0x03FFFFFF);
}
static uint32_t enc_b_ne(int32_t off) {
    return 0x54000001u | (((off >> 2) & 0x7FFFF) << 5);
}
static uint32_t enc_bl(int32_t off) {
    return 0x94000000u | ((off >> 2) & 0x03FFFFFF);
}
static uint32_t enc_ret() { return 0xD65F03C0u; }

// ─── Complex CFG trace generator ─────────────────────────────────────────────
//
// Strategy: Generate N_FUNCTIONS functions, each with M_LOOPS nested loops and
// B_BLOCKS basic blocks per function. The "main" loop calls these functions
// repeatedly. Each function has unique PCs spread across a wide address range.
//
// This creates:
//   - N_FUNCTIONS * B_BLOCKS unique PCs (~2000+)
//   - N_FUNCTIONS * M_LOOPS loops (~200+)
//   - Deep nesting (4-5 levels)
//   - Complex inter-procedural CFG

static void generate_complex_cfg(GBTraceGenerator& gen, uint64_t target_bytes) {
    // Layout: 100 functions, each occupying 0x400 bytes of address space
    // Each function has 10 basic blocks (4 instructions each) = 40 unique PCs
    // Plus 3 nested loops per function
    // Total: 100 * 40 = 4000 unique PCs, 100 * 3 = 300 loops

    constexpr int N_FUNCS = 100;
    constexpr int BLOCKS_PER_FUNC = 10;
    constexpr int INSTS_PER_BLOCK = 4;
    constexpr uint64_t FUNC_SPACING = 0x400;  // 1024 bytes between functions
    constexpr uint64_t BASE_ADDR = 0x10000;

    // Each function layout:
    //   Block 0: entry (prologue)      @ base + 0x000
    //   Block 1: loop1 header          @ base + 0x010
    //   Block 2: loop1 body            @ base + 0x020
    //   Block 3: loop2 header (nested) @ base + 0x030
    //   Block 4: loop2 body            @ base + 0x040
    //   Block 5: loop3 header (nested) @ base + 0x050
    //   Block 6: loop3 body (innermost)@ base + 0x060
    //   Block 7: loop3 exit            @ base + 0x070
    //   Block 8: loop1 latch           @ base + 0x080
    //   Block 9: epilogue + ret        @ base + 0x090

    // Iteration counts per level
    constexpr int OUTER_ITERS = 200;   // loop1
    constexpr int MID_ITERS = 20;      // loop2
    constexpr int INNER_ITERS = 10;    // loop3

    // Each full function call ≈ OUTER * (body + MID * (body + INNER * body))
    // ≈ 200 * (4 + 20 * (4 + 10 * 4)) = 200 * (4 + 20 * 44) = 200 * 884 = 176,800 insts
    // Per function: ~177K instructions, ~22 bytes each = ~3.9 MB
    // For 1 GB: need ~260 full function calls → cycle through N_FUNCS = 100 funcs
    // with ~3 rounds = 300 calls

    uint64_t insts_per_func_call = (uint64_t)OUTER_ITERS *
        (INSTS_PER_BLOCK + (uint64_t)MID_ITERS *
            (INSTS_PER_BLOCK + (uint64_t)INNER_ITERS * INSTS_PER_BLOCK));
    uint64_t bytes_per_func_call = insts_per_func_call * 22;
    uint64_t total_calls = target_bytes / bytes_per_func_call + 1;

    fprintf(stderr, "  Complex CFG mode:\n");
    fprintf(stderr, "    Functions: %d, blocks/func: %d\n", N_FUNCS, BLOCKS_PER_FUNC);
    fprintf(stderr, "    Expected unique PCs: %d\n", N_FUNCS * BLOCKS_PER_FUNC * INSTS_PER_BLOCK);
    fprintf(stderr, "    Expected loops: %d (3 per func, nesting depth 3)\n", N_FUNCS * 3);
    fprintf(stderr, "    Insts per function call: %llu\n", (unsigned long long)insts_per_func_call);
    fprintf(stderr, "    Total function calls needed: %llu\n", (unsigned long long)total_calls);

    uint64_t last_report = 0;
    uint64_t call_num = 0;

    for (uint64_t call_idx = 0; call_idx < total_calls; call_idx++) {
        int func_id = call_idx % N_FUNCS;
        uint64_t func_base = BASE_ADDR + func_id * FUNC_SPACING;

        // ─── Block 0: Entry/prologue ───
        for (int i = 0; i < INSTS_PER_BLOCK; i++) {
            gen.emit_inst(func_base + 0x000 + i * 4, enc_add_imm(0, 0, 1), 0, call_idx);
        }

        // ─── Loop 1 (outer) ───
        for (int i1 = 0; i1 < OUTER_ITERS; i1++) {
            // Block 1: loop1 header
            gen.emit_inst(func_base + 0x010 + 0, enc_add_imm(1, 1, 1), 1, i1);
            gen.emit_branch(func_base + 0x010 + 4, enc_cmp_imm(1, OUTER_ITERS));
            gen.emit_branch(func_base + 0x010 + 8, enc_b_ne(0x10));
            gen.emit_inst(func_base + 0x010 + 12, enc_nop(), 2, i1 * 2);

            // Block 2: loop1 body
            for (int i = 0; i < INSTS_PER_BLOCK; i++) {
                gen.emit_inst(func_base + 0x020 + i * 4, enc_add_imm(3, 1, i), 3, i1 + i);
            }

            // ─── Loop 2 (middle, nested in loop1) ───
            for (int i2 = 0; i2 < MID_ITERS; i2++) {
                // Block 3: loop2 header
                gen.emit_inst(func_base + 0x030 + 0, enc_add_imm(4, 4, 1), 4, i2);
                gen.emit_branch(func_base + 0x030 + 4, enc_cmp_imm(4, MID_ITERS));
                gen.emit_branch(func_base + 0x030 + 8, enc_b_ne(0x10));
                gen.emit_inst(func_base + 0x030 + 12, enc_nop(), 5, i2 * 3);

                // Block 4: loop2 body
                for (int i = 0; i < INSTS_PER_BLOCK; i++) {
                    gen.emit_inst(func_base + 0x040 + i * 4, enc_add_imm(6, 4, i), 6, i2 + i);
                }

                // ─── Loop 3 (innermost, nested in loop2) ───
                for (int i3 = 0; i3 < INNER_ITERS; i3++) {
                    // Block 5: loop3 header
                    gen.emit_inst(func_base + 0x050 + 0, enc_add_imm(7, 7, 1), 7, i3);
                    gen.emit_branch(func_base + 0x050 + 4, enc_cmp_imm(7, INNER_ITERS));
                    gen.emit_branch(func_base + 0x050 + 8, enc_b_ne(0x10));
                    gen.emit_inst(func_base + 0x050 + 12, enc_nop(), 8, i3 * 5);

                    // Block 6: loop3 body (innermost)
                    for (int i = 0; i < INSTS_PER_BLOCK; i++) {
                        gen.emit_inst(func_base + 0x060 + i * 4, enc_add_imm(9, 7, i), 9, i3 + i);
                    }

                    // Block 7: loop3 exit/latch (back to loop3 header)
                    gen.emit_branch(func_base + 0x070 + 0, enc_b(-(0x070 - 0x050)));
                }
                // loop3 exit → back to loop2 latch
                gen.emit_branch(func_base + 0x070 + 4, enc_b(0x080 - 0x070));

                // loop2 latch (in block 8 area, but unique for loop2)
                gen.emit_branch(func_base + 0x080 + 4, enc_b(-(0x080 + 4 - 0x030)));
            }
            // loop2 exit
            gen.emit_branch(func_base + 0x080 + 8, enc_b(0x090 - 0x080));

            // Block 8: loop1 latch (back to loop1 header)
            gen.emit_branch(func_base + 0x080 + 0, enc_b(-(0x080 - 0x010)));
        }
        // loop1 exit
        gen.emit_branch(func_base + 0x080 + 12, enc_b(0x090 - 0x080));

        // ─── Block 9: Epilogue + return ───
        for (int i = 0; i < INSTS_PER_BLOCK - 1; i++) {
            gen.emit_inst(func_base + 0x090 + i * 4, enc_nop(), 10, call_idx);
        }
        gen.emit_branch(func_base + 0x090 + (INSTS_PER_BLOCK - 1) * 4, enc_ret());

        call_num++;

        // Progress reporting
        uint64_t now = gen.writer_.bytes_written();
        if (now - last_report > 100 * 1024 * 1024) {
            fprintf(stderr, "\r  Progress: %.2f GB (%llu insts, %zu unique PCs, %llu calls)",
                    (double)now / (1024.0*1024.0*1024.0),
                    (unsigned long long)gen.inst_count_,
                    gen.emitted_code_.size(),
                    (unsigned long long)call_num);
            last_report = now;
        }

        if (gen.writer_.bytes_written() >= target_bytes) break;
    }
}

// ─── Simple high-volume trace (same as before but cleaner) ───────────────────

static void generate_simple_volume(GBTraceGenerator& gen, uint64_t target_bytes) {
    // Simple nested loop structure: main → outer → inner → compute
    constexpr uint64_t FUNC_MAIN = 0x1000;
    constexpr uint64_t FUNC_OUTER = 0x2000;
    constexpr uint64_t FUNC_INNER = 0x3000;
    constexpr uint64_t FUNC_COMPUTE = 0x4000;

    constexpr int N4 = 50;
    constexpr int N3 = 20;
    constexpr int N2 = 30;

    uint64_t insts_per_outer = N2 * (6 + N3 * (6 + N4 * 8));
    uint64_t N1 = target_bytes / (insts_per_outer * 22) + 1;

    fprintf(stderr, "  Simple volume mode:\n");
    fprintf(stderr, "    N1=%llu, N2=%d, N3=%d, N4=%d\n", (unsigned long long)N1, N2, N3, N4);

    uint64_t last_report = 0;

    for (uint64_t i1 = 0; i1 < N1; i1++) {
        gen.emit_inst(FUNC_MAIN + 0x00, enc_add_imm(0, 0, 1), 0, i1);
        gen.emit_branch(FUNC_MAIN + 0x04, enc_cmp_imm(0, N1 & 0xFFF));
        gen.emit_branch(FUNC_MAIN + 0x08, enc_b_ne(0x10));
        gen.emit_branch(FUNC_MAIN + 0x0C, enc_bl(FUNC_OUTER - FUNC_MAIN - 0x0C));

        for (int i2 = 0; i2 < N2; i2++) {
            gen.emit_inst(FUNC_OUTER + 0x00, enc_add_imm(1, 1, 1), 1, i2);
            gen.emit_branch(FUNC_OUTER + 0x04, enc_cmp_imm(1, N2));
            gen.emit_branch(FUNC_OUTER + 0x08, enc_b_ne(0x10));

            for (int i3 = 0; i3 < N3; i3++) {
                gen.emit_inst(FUNC_INNER + 0x00, enc_add_imm(2, 2, 1), 2, i3);
                gen.emit_branch(FUNC_INNER + 0x04, enc_cmp_imm(2, N3));
                gen.emit_branch(FUNC_INNER + 0x08, enc_b_ne(0x10));

                for (int i4 = 0; i4 < N4; i4++) {
                    gen.emit_inst(FUNC_COMPUTE + 0x00, enc_add_imm(3, 3, 1), 3, i4);
                    gen.emit_branch(FUNC_COMPUTE + 0x04, enc_cmp_imm(3, N4));
                    gen.emit_inst(FUNC_COMPUTE + 0x08, enc_add_imm(4, 3, 1), 4, i4 + 1);
                    gen.emit_inst(FUNC_COMPUTE + 0x0C, enc_add_imm(5, 4, 1), 5, i4 + 2);
                    gen.emit_inst(FUNC_COMPUTE + 0x10, enc_add_imm(6, 5, 1), 6, i4 + 3);
                    gen.emit_inst(FUNC_COMPUTE + 0x14, enc_add_imm(7, 6, 1), 7, i4 + 4);
                    gen.emit_branch(FUNC_COMPUTE + 0x18, enc_b(-(0x18)));
                }
                gen.emit_branch(FUNC_COMPUTE + 0x1C, enc_ret());
                gen.emit_branch(FUNC_INNER + 0x0C, enc_b(-(0x0C)));
            }
            gen.emit_branch(FUNC_INNER + 0x10, enc_ret());
            gen.emit_branch(FUNC_OUTER + 0x0C, enc_b(-(0x0C)));
        }
        gen.emit_branch(FUNC_OUTER + 0x10, enc_ret());
        gen.emit_branch(FUNC_MAIN + 0x10, enc_b(-(0x10)));

        uint64_t now = gen.writer_.bytes_written();
        if (now - last_report > 100 * 1024 * 1024) {
            fprintf(stderr, "\r  Progress: %.2f GB (%llu insts, %zu unique PCs)",
                    (double)now / (1024.0*1024.0*1024.0),
                    (unsigned long long)gen.inst_count_,
                    gen.emitted_code_.size());
            last_report = now;
        }

        if (gen.writer_.bytes_written() >= target_bytes) break;
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    const char* output = "/tmp/perf_gb.trace";
    double target_gb = 1.0;
    bool complex_cfg = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--complex-cfg") == 0) {
            complex_cfg = true;
        } else if (argv[i][0] != '-' && output == (const char*)"/tmp/perf_gb.trace") {
            output = argv[i];
        } else if (argv[i][0] != '-') {
            target_gb = atof(argv[i]);
        }
    }

    uint64_t target_bytes = static_cast<uint64_t>(target_gb * 1024.0 * 1024.0 * 1024.0);
    fprintf(stderr, "Generating ~%.2f GB trace to: %s%s\n",
            target_gb, output, complex_cfg ? " [COMPLEX CFG]" : "");

    GBTraceGenerator gen;
    if (!gen.writer_.open(output)) {
        fprintf(stderr, "Cannot open %s for writing\n", output);
        return 1;
    }
    gen.write_header();

    if (complex_cfg) {
        generate_complex_cfg(gen, target_bytes);
    } else {
        generate_simple_volume(gen, target_bytes);
    }

    gen.emit_anchor();
    gen.writer_.close();

    uint64_t file_size = gen.writer_.total_bytes_;
    fprintf(stderr, "\n\nDone!\n");
    fprintf(stderr, "  Output: %s\n", output);
    fprintf(stderr, "  File size: %.2f GB (%.0f MB)\n",
            (double)file_size / (1024.0*1024.0*1024.0),
            (double)file_size / (1024.0*1024.0));
    fprintf(stderr, "  Instructions: %llu (%.1fM)\n",
            (unsigned long long)gen.inst_count_,
            (double)gen.inst_count_ / 1e6);
    fprintf(stderr, "  Anchors: %llu\n", (unsigned long long)gen.anchor_count_);
    fprintf(stderr, "  Unique PCs: %zu\n", gen.emitted_code_.size());

    return 0;
}
