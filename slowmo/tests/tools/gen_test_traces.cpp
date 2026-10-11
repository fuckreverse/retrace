/*
 * gen_test_traces.cpp — Synthetic trace generator for Tenet unit tests & perf validation
 *
 * Produces deterministic, self-contained AArch64 trace files that exercise
 * every layer of the Tenet offline analyzer:
 *
 *   IO layer:   header parsing, record iteration, mmap paging, code table
 *   Core layer: anchor-based state reconstruction, register diff replay, LRU
 *   Analysis:   XRef, Taint, CFG, Pattern, CallGraph, String, Loop passes
 *
 * Two operating modes:
 *   1. Unit test traces (--suite unit)   : small, precise, one per test scenario
 *   2. Perf validation  (--suite perf)   : large-scale, parametric (1M..200M inst)
 *
 * Build:
 *   clang++ -std=c++17 -O2 -I../../dashcam -o gen_test_traces gen_test_traces.cpp
 *
 * Usage:
 *   ./gen_test_traces --suite unit  --outdir ./traces/unit
 *   ./gen_test_traces --suite perf  --outdir ./traces/perf --scale 10M
 *   ./gen_test_traces --suite perf  --outdir ./traces/perf --scale 100M
 *   ./gen_test_traces --list        (show available test cases)
 *   ./gen_test_traces --case <name> --outdir .
 */

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <algorithm>
#include <sys/stat.h>

#include "fixtures/trace_writer.h"

using namespace tenet::test;
using namespace qbditrace;


// ═══════════════════════════════════════════════════════════════════════════════
// Test Case Registry
// ═══════════════════════════════════════════════════════════════════════════════

struct TestCase {
    const char* name;
    const char* category;
    const char* description;
    std::function<void(const char*, uint64_t)> generate;
};

static std::vector<TestCase>& cases() {
    static std::vector<TestCase> c;
    return c;
}

#define REG_CASE(name_, cat_, desc_) \
    static void gen_##name_(const char*, uint64_t); \
    static struct _r_##name_ { _r_##name_() { \
        cases().push_back({#name_, cat_, desc_, gen_##name_}); \
    }} _ri_##name_; \
    static void gen_##name_(const char* path, uint64_t scale)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TEST TRACES
// ═══════════════════════════════════════════════════════════════════════════════

// --- UT1: minimal valid trace (1 anchor + 1 inst) ---
REG_CASE(ut_minimal, "unit", "1 instruction: validates header parse and minimal iteration") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 1; tw.module_name = "ut_minimal";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
    tw.emit_anchor(ms);
    tw.close();
}

// --- UT2: anchor boundary precision ---
REG_CASE(ut_anchor_boundary, "unit", "Exactly N*anchor_interval insts: validates anchor placement") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 8; tw.module_name = "ut_anchor";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    for (int i = 0; i < 24; i++) {
        tw.emit(ms, 0x1000 + i * 4, enc::add_imm(0, 0, 1),
                {{0, (uint64_t)(i + 1)}, {33, tw.rt(0x1004 + i * 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// --- UT3: all GPRs modified ---
REG_CASE(ut_regdiff_all, "unit", "Each instruction modifies a different GPR: validates reg-diff completeness") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 64; tw.module_name = "ut_regdiff";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    for (int i = 0; i < 29; i++) {
        uint64_t val = 0xA000ULL + i;
        tw.emit(ms, 0x1000 + i * 4, enc::movz(i, (uint16_t)val),
                {{(uint8_t)i, val}, {33, tw.rt(0x1004 + i * 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// --- UT4: memory access patterns (sequential, pointer chain, overlapping) ---
REG_CASE(ut_memory_patterns, "unit", "Store/load/pointer-chain/overlap: validates memory_model and XRef") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_memory";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t base = 0x200000000ULL;
    ms.x(10) = base;
    uint64_t pc = 0x1000;

    // Sequential store then load
    for (int i = 0; i < 8; i++) {
        uint64_t addr = base + i * 8, val = 0xCAFE0000ULL + i;
        tw.emit(ms, pc, enc::str_imm(0, 10, i * 8),
                {{0, val}, {33, tw.rt(pc + 4)}}, {{2, 8, addr, val}});
        pc += 4;
        tw.emit(ms, pc, enc::ldr_imm(1, 10, i * 8),
                {{1, val}, {33, tw.rt(pc + 4)}}, {{1, 8, addr, val}});
        pc += 4;
    }

    // Pointer chain: addr -> addr -> addr -> final_value
    uint64_t chain[] = {base + 0x100, base + 0x200, base + 0x300, 0x42424242ULL};
    ms.x(2) = base + 0x80;
    tw.emit(ms, pc, enc::str_imm(2, 10, 0x10),
            {{2, base + 0x80}, {33, tw.rt(pc + 4)}}, {{2, 8, base + 0x80, chain[0]}});
    pc += 4;
    for (int i = 0; i < 4; i++) {
        uint64_t addr = (i == 0) ? base + 0x80 : chain[i - 1];
        tw.emit(ms, pc, enc::ldr_imm(2, 2, 0),
                {{2, chain[i]}, {33, tw.rt(pc + 4)}}, {{1, 8, addr, chain[i]}});
        pc += 4;
    }

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT5: call graph (main -> foo -> bar, with proper frame push/pop) ---
REG_CASE(ut_call_graph, "unit", "3-level call chain with EVENT records: validates CallGraphPass") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_callgraph";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    // main prologue
    ms.sp() -= 16;
    tw.emit(ms, 0x1000, enc::stp_pre(29, 30, 31, -2),
            {{31, ms.sp()}, {33, tw.rt(0x1004)}},
            {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
    tw.emit(ms, 0x1004, enc::mov_reg(29, 31), {{29, ms.sp()}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::movz(0, 42), {{0, 42}, {33, tw.rt(0x100C)}}, {});
    // BL foo @ 0x2000
    tw.emit(ms, 0x100C, enc::bl(0x2000 - 0x100C), {{30, tw.rt(0x1010)}, {33, tw.rt(0x2000)}}, {});

    // foo prologue
    ms.sp() -= 16;
    tw.emit(ms, 0x2000, enc::stp_pre(29, 30, 31, -2),
            {{31, ms.sp()}, {33, tw.rt(0x2004)}},
            {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, tw.rt(0x1010)}});
    tw.emit(ms, 0x2004, enc::mov_reg(29, 31), {{29, ms.sp()}, {33, tw.rt(0x2008)}}, {});
    tw.emit(ms, 0x2008, enc::add_imm(0, 0, 10), {{0, 52}, {33, tw.rt(0x200C)}}, {});
    // BL bar @ 0x3000
    tw.emit(ms, 0x200C, enc::bl(0x3000 - 0x200C), {{30, tw.rt(0x2010)}, {33, tw.rt(0x3000)}}, {});

    // bar (leaf)
    tw.emit(ms, 0x3000, enc::add_imm(0, 0, 8), {{0, 60}, {33, tw.rt(0x3004)}}, {});
    tw.emit(ms, 0x3004, enc::ret(), {{33, tw.rt(0x2010)}}, {});

    // foo epilogue
    ms.sp() += 16;
    tw.emit(ms, 0x2010, enc::ldp_post(29, 30, 31, 2),
            {{29, ms.fp()}, {30, tw.rt(0x1010)}, {31, ms.sp()}, {33, tw.rt(0x2014)}},
            {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, tw.rt(0x1010)}});
    tw.emit(ms, 0x2014, enc::ret(), {{33, tw.rt(0x1010)}}, {});

    // main epilogue
    ms.sp() += 16;
    tw.emit(ms, 0x1010, enc::ldp_post(29, 30, 31, 2),
            {{29, ms.fp()}, {30, 0ULL}, {31, ms.sp()}, {33, tw.rt(0x1014)}},
            {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, 0ULL}});
    tw.emit(ms, 0x1014, enc::ret(), {{33, 0ULL}}, {});

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT6: taint propagation (key -> xor -> store -> load -> derive) ---
REG_CASE(ut_taint_chain, "unit", "Linear data dependency chain: validates TaintPass forward/backward") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_taint";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;
    uint64_t pc = 0x1000;

    // x0 = secret key (taint source)
    tw.emit(ms, pc, enc::movz(0, 0xBEEF), {{0, 0xBEEFULL}, {33, tw.rt(pc + 4)}}, {});
    pc += 4;

    // x1 = x0 ^ x2 (taint propagates x0 -> x1)
    ms.x(2) = 0x1234;
    tw.emit(ms, pc, enc::eor_reg(1, 0, 2), {{1, 0xBEEFULL ^ 0x1234}, {33, tw.rt(pc + 4)}}, {});
    pc += 4;

    // store x1 to memory (taint: reg -> mem)
    uint64_t addr = data_base;
    uint64_t tainted_val = 0xBEEFULL ^ 0x1234;
    tw.emit(ms, pc, enc::str_imm(1, 10, 0),
            {{33, tw.rt(pc + 4)}}, {{2, 8, addr, tainted_val}});
    pc += 4;

    // load from memory to x3 (taint: mem -> reg)
    tw.emit(ms, pc, enc::ldr_imm(3, 10, 0),
            {{3, tainted_val}, {33, tw.rt(pc + 4)}}, {{1, 8, addr, tainted_val}});
    pc += 4;

    // x4 = x3 + x5 (taint propagates through x3)
    ms.x(5) = 0xFF;
    tw.emit(ms, pc, enc::add_reg(4, 3, 5),
            {{4, tainted_val + 0xFF}, {33, tw.rt(pc + 4)}}, {});
    pc += 4;

    // x6 = x4 << 8 (further propagation)
    tw.emit(ms, pc, enc::lsl_imm(6, 4, 8),
            {{6, (tainted_val + 0xFF) << 8}, {33, tw.rt(pc + 4)}}, {});
    pc += 4;

    // Store derived value back
    uint64_t final_val = (tainted_val + 0xFF) << 8;
    tw.emit(ms, pc, enc::str_imm(6, 10, 8),
            {{33, tw.rt(pc + 4)}}, {{2, 8, data_base + 8, final_val}});
    pc += 4;

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT7: CFG with loop + branch ---
REG_CASE(ut_cfg_loop, "unit", "Loop with conditional break: validates CFGPass/LoopPass") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_cfg_loop";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    // x0 = counter, loop 10 times with conditional early break at i==7
    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::movz(1, 10), {{1, 10ULL}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::movz(2, 7), {{2, 7ULL}, {33, tw.rt(0x100C)}}, {});

    for (uint64_t i = 0; i < 10; i++) {
        // loop_top: cmp x0, x1
        uint8_t nz = (i < 10) ? 0x8 : 0x6;
        tw.emit(ms, 0x100C, enc::cmp_imm(0, 10), {{33, tw.rt(0x1010)}}, {}, nz);
        // b.ge exit
        tw.emit(ms, 0x1010, enc::b_ge(0x1028 - 0x1010), {{33, tw.rt(0x1014)}}, {}, nz);

        // cmp x0, x2 (check i == 7)
        uint8_t eq_nz = (i == 7) ? 0x4 : 0x0;  // Z flag set when equal
        tw.emit(ms, 0x1014, enc::cmp_imm(0, 7), {{33, tw.rt(0x1018)}}, {}, eq_nz);
        // b.eq break
        if (i == 7) {
            tw.emit(ms, 0x1018, enc::b_eq(0x1028 - 0x1018), {{33, tw.rt(0x1028)}}, {}, eq_nz);
            break;
        }
        tw.emit(ms, 0x1018, enc::b_eq(0x1028 - 0x1018), {{33, tw.rt(0x101C)}}, {}, eq_nz);

        // x0 = x0 + 1
        tw.emit(ms, 0x101C, enc::add_imm(0, 0, 1), {{0, i + 1}, {33, tw.rt(0x1020)}}, {});
        // x3 = x3 + x0 (accumulator)
        uint64_t acc = (i * (i + 1)) / 2 + (i + 1);
        tw.emit(ms, 0x1020, enc::add_reg(3, 3, 0), {{3, acc}, {33, tw.rt(0x1024)}}, {});
        // b loop_top
        tw.emit(ms, 0x1024, enc::b(0x100C - 0x1024), {{33, tw.rt(0x100C)}}, {});
    }

    // exit
    tw.emit(ms, 0x1028, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
    tw.close();
}

// --- UT8: event records (SVC, OBJC, THREAD, XFER) ---
REG_CASE(ut_all_record_types, "unit", "Every record type present: validates IO layer record dispatch") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_all_records";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    // Thread record
    tw.emit_thread(0x1001);

    // Normal instructions
    tw.emit(ms, 0x1000, enc::movz(0, 42), {{0, 42ULL}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::movz(1, 100), {{1, 100ULL}, {33, tw.rt(0x1008)}}, {});

    // XFER_CALL event (calling external function)
    tw.emit_event(QBDITRACE_EV_XFER_CALL, 0x180000000ULL, tw.rt(0x1008));

    // XFER_RETURN event
    tw.emit_event(QBDITRACE_EV_XFER_RETURN, tw.rt(0x100C), 0);

    // Continue after external call
    tw.emit(ms, 0x100C, enc::add_reg(2, 0, 1), {{2, 142ULL}, {33, tw.rt(0x1010)}}, {});

    // SVC record
    tw.emit_svc(tw.rt(0x1010), 20, 0, 0);  // getpid
    tw.emit(ms, 0x1010, enc::svc(0x80), {{0, 1234ULL}, {33, tw.rt(0x1014)}}, {});

    // ObjC record
    tw.emit_objc(tw.rt(0x1014), 0x200000000ULL, 0x300000000ULL, "NSObject");
    tw.emit(ms, 0x1014, enc::nop(), {{33, tw.rt(0x1018)}}, {});

    // Second thread
    tw.emit_thread(0x1002);
    tw.emit(ms, 0x2000, enc::movz(0, 99), {{0, 99ULL}, {33, tw.rt(0x2004)}}, {});

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT9: string constant materialization ---
REG_CASE(ut_string_constant, "unit", "MOVZ+MOVK sequence building ASCII string ptr: validates StringPass") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_string";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;

    // Build a 64-bit constant via MOVZ+MOVK (common pattern for string addr)
    uint64_t str_addr = 0x100004500ULL;  // "Hello\0"
    tw.emit(ms, 0x1000, enc::movz(0, (uint16_t)(str_addr & 0xFFFF)),
            {{0, str_addr & 0xFFFF}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::movk(0, (uint16_t)((str_addr >> 16) & 0xFFFF), 16),
            {{0, str_addr & 0xFFFFFFFF}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::movk(0, (uint16_t)((str_addr >> 32) & 0xFFFF), 32),
            {{0, str_addr & 0xFFFFFFFFFFFFULL}, {33, tw.rt(0x100C)}}, {});
    tw.emit(ms, 0x100C, enc::movk(0, (uint16_t)((str_addr >> 48) & 0xFFFF), 48),
            {{0, str_addr}, {33, tw.rt(0x1010)}}, {});

    // Store as pointer (simulates string reference)
    tw.emit(ms, 0x1010, enc::str_imm(0, 10, 0),
            {{33, tw.rt(0x1014)}}, {{2, 8, data_base, str_addr}});

    // Load bytes from the "string" (simulate reading "Hello")
    uint64_t hello = 0x006F6C6C6548ULL;  // "Hello\0" in little-endian
    tw.emit(ms, 0x1014, enc::ldr_imm(1, 0, 0),
            {{1, hello}, {33, tw.rt(0x1018)}}, {{1, 8, str_addr, hello}});

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT10: pattern detection (XOR decrypt loop, typical crypto pattern) ---
REG_CASE(ut_xor_decrypt, "unit", "XOR decrypt loop over buffer: validates PatternPass crypto detection") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_xor_decrypt";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t buf_base = 0x200000000ULL;
    ms.x(10) = buf_base;

    // x0 = key, x1 = len, x2 = index
    uint64_t key = 0xDEADBEEFCAFEBABEULL;
    tw.emit(ms, 0x1000, enc::movz(0, (uint16_t)(key & 0xFFFF)),
            {{0, key & 0xFFFF}, {33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::movk(0, (uint16_t)((key >> 16) & 0xFFFF), 16),
            {{0, key & 0xFFFFFFFF}, {33, tw.rt(0x1008)}}, {});
    tw.emit(ms, 0x1008, enc::movk(0, (uint16_t)((key >> 32) & 0xFFFF), 32),
            {{0, key & 0xFFFFFFFFFFFFULL}, {33, tw.rt(0x100C)}}, {});
    tw.emit(ms, 0x100C, enc::movk(0, (uint16_t)((key >> 48) & 0xFFFF), 48),
            {{0, key}, {33, tw.rt(0x1010)}}, {});

    tw.emit(ms, 0x1010, enc::movz(1, 16), {{1, 16ULL}, {33, tw.rt(0x1014)}}, {});
    tw.emit(ms, 0x1014, enc::movz(2, 0), {{2, 0ULL}, {33, tw.rt(0x1018)}}, {});

    // XOR decrypt loop: 16 iterations
    for (uint64_t i = 0; i < 16; i++) {
        uint64_t addr = buf_base + i * 8;
        uint64_t cipher = 0x1111111111111111ULL * (i + 1);
        uint64_t plain = cipher ^ key;

        // cmp x2, x1
        uint8_t nz = 0x8; // N set (less than)
        tw.emit(ms, 0x1018, enc::cmp_imm(2, 16), {{33, tw.rt(0x101C)}}, {}, nz);
        tw.emit(ms, 0x101C, enc::b_ge(0x1038 - 0x101C), {{33, tw.rt(0x1020)}}, {}, nz);

        // ldr x3, [x10, x2, lsl #3]
        tw.emit(ms, 0x1020, enc::ldr_reg(3, 10, 2),
                {{3, cipher}, {33, tw.rt(0x1024)}}, {{1, 8, addr, cipher}});
        // eor x3, x3, x0
        tw.emit(ms, 0x1024, enc::eor_reg(3, 3, 0),
                {{3, plain}, {33, tw.rt(0x1028)}}, {});
        // str x3, [x10, x2, lsl #3]
        tw.emit(ms, 0x1028, enc::str_reg(3, 10, 2),
                {{33, tw.rt(0x102C)}}, {{2, 8, addr, plain}});
        // add x2, x2, #1
        tw.emit(ms, 0x102C, enc::add_imm(2, 2, 1), {{2, i + 1}, {33, tw.rt(0x1030)}}, {});
        // b loop
        tw.emit(ms, 0x1030, enc::b(0x1018 - 0x1030), {{33, tw.rt(0x1018)}}, {});
    }
    // exit
    tw.emit(ms, 0x1018, enc::cmp_imm(2, 16), {{33, tw.rt(0x101C)}}, {}, 0x6);
    tw.emit(ms, 0x101C, enc::b_ge(0x1038 - 0x101C), {{33, tw.rt(0x1038)}}, {}, 0x6);
    tw.emit(ms, 0x1038, enc::ret(), {{33, 0ULL}}, {});

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT11: CFF-style dispatcher (state machine) ---
REG_CASE(ut_cff_dispatch, "unit", "Switch-based state machine (CFF flat): validates CFGPass de-flat heuristic") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 256; tw.module_name = "ut_cff";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    // Simulate: while(1) { switch(state) { case 0..5: ... state = next; } }
    // 6 states executed in order: 0, 3, 1, 4, 2, 5 (obfuscated ordering)
    int state_order[] = {0, 3, 1, 4, 2, 5};
    uint64_t state_results[] = {10, 20, 30, 40, 50, 60};

    // Initial: x0 = state = 0
    tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});

    for (int iter = 0; iter < 6; iter++) {
        int s = state_order[iter];
        int next_s = (iter < 5) ? state_order[iter + 1] : -1;

        // Dispatcher: compare state and branch
        // 0x1004: cmp x0, #state
        tw.emit(ms, 0x1004, enc::cmp_imm(0, (uint16_t)s), {{33, tw.rt(0x1008)}}, {}, 0x4);
        // 0x1008: b.eq handler
        uint64_t handler_pc = 0x2000 + s * 0x10;
        tw.emit(ms, 0x1008, enc::b_eq((int32_t)(handler_pc - 0x1008)),
                {{33, tw.rt(handler_pc)}}, {}, 0x4);

        // Handler: do work + set next state
        tw.emit(ms, handler_pc, enc::movz(1, (uint16_t)state_results[iter]),
                {{1, state_results[iter]}, {33, tw.rt(handler_pc + 4)}}, {});
        if (next_s >= 0) {
            tw.emit(ms, handler_pc + 4, enc::movz(0, (uint16_t)next_s),
                    {{0, (uint64_t)next_s}, {33, tw.rt(handler_pc + 8)}}, {});
            // b dispatcher
            tw.emit(ms, handler_pc + 8, enc::b((int32_t)(0x1004 - (handler_pc + 8))),
                    {{33, tw.rt(0x1004)}}, {});
        } else {
            // Exit
            tw.emit(ms, handler_pc + 4, enc::ret(), {{33, 0ULL}}, {});
        }
    }

    tw.emit_anchor(ms);
    tw.close();
}

// --- UT12: backward seek stress (access patterns that force far backward jumps) ---
REG_CASE(ut_backward_seek, "unit", "1000 insts then seek to inst 0: validates IO paging + LRU eviction") {
    (void)scale;
    TraceWriter tw; tw.anchor_interval = 64; tw.module_name = "ut_backward_seek";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    // Emit 1000 instructions with monotonically increasing x0
    for (uint64_t i = 0; i < 1000; i++) {
        tw.emit(ms, 0x1000 + (i % 250) * 4, enc::add_imm(0, 0, 1),
                {{0, i + 1}, {33, tw.rt(0x1000 + ((i + 1) % 250) * 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERFORMANCE VALIDATION TRACES — Large-scale, parametric
// ═══════════════════════════════════════════════════════════════════════════════

// --- P1: linear_scan — Pure sequential instructions, minimal per-record overhead
//     Benchmarks: IO read throughput, record parsing speed
REG_CASE(perf_linear_scan, "perf", "Sequential NOPs: measures raw IO/parse throughput (bytes/sec)") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_linear";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;

    for (uint64_t i = 0; i < scale; i++) {
        uint64_t pc = 0x1000 + (i % 65536) * 4;
        tw.emit(ms, pc, enc::add_imm(0, 0, 1), {{0, i + 1}, {33, tw.rt(pc + 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// --- P2: random_access_pattern — Many unique PCs, forces code table lookups
//     Benchmarks: code_table lookup speed, instruction_decoder cache hit rate
REG_CASE(perf_code_table, "perf", "10K unique PCs cycled N times: measures code_table + decoder cache") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_codetable";
    if (!tw.open(path)) return;
    tw.write_header(0x100000);
    MachineState ms; ms.sp() = 0x16F000000ULL;

    const uint64_t NUM_UNIQUE_PCS = 10000;
    for (uint64_t i = 0; i < scale; i++) {
        uint64_t pc = 0x1000 + (i % NUM_UNIQUE_PCS) * 4;
        uint32_t opcode = enc::add_imm((int)(i % 28), (int)((i + 1) % 28), (uint16_t)(i & 0xFFF));
        tw.emit(ms, pc, opcode, {{(uint8_t)(i % 28), i}, {33, tw.rt(pc + 4)}}, {});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// --- P3: heavy_memory — Every instruction has memory access
//     Benchmarks: memory_model update speed, XRef build time
REG_CASE(perf_heavy_memory, "perf", "Every inst does load+store: measures memory_model + XRef scaling") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_memory";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;

    for (uint64_t i = 0; i < scale; i++) {
        uint64_t pc = 0x1000 + (i % 1024) * 4;
        uint64_t addr = data_base + (i % 8192) * 8;
        uint64_t val = i * 0x1337;
        tw.emit(ms, pc, enc::str_imm(0, 10, (int16_t)((i % 1024) * 8)),
                {{0, val}, {33, tw.rt(pc + 4)}},
                {{2, 8, addr, val}});
    }
    tw.emit_anchor(ms);
    tw.close();
}

// --- P4: deep_call_stack — Simulates 100-deep recursion repeated many times
//     Benchmarks: CallGraphPass, FunctionPass at scale
REG_CASE(perf_deep_calls, "perf", "100-deep recursive calls repeated: measures CallGraph/Function pass scaling") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_calls";
    if (!tw.open(path)) return;
    tw.write_header(0x200000);
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    const int DEPTH = 100;
    uint64_t total_emitted = 0;

    while (total_emitted < scale) {
        // Descend: call chain depth levels
        for (int d = 0; d < DEPTH && total_emitted < scale; d++) {
            uint64_t fn_base = 0x1000 + d * 0x20;
            // Push frame
            ms.sp() -= 16;
            tw.emit(ms, fn_base, enc::stp_pre(29, 30, 31, -2),
                    {{31, ms.sp()}, {33, tw.rt(fn_base + 4)}},
                    {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
            total_emitted++;
            if (total_emitted >= scale) break;

            tw.emit(ms, fn_base + 4, enc::mov_reg(29, 31),
                    {{29, ms.sp()}, {33, tw.rt(fn_base + 8)}}, {});
            total_emitted++;
            if (total_emitted >= scale) break;

            // Work
            tw.emit(ms, fn_base + 8, enc::add_imm(0, 0, 1),
                    {{0, ms.x(0) + 1}, {33, tw.rt(fn_base + 12)}}, {});
            total_emitted++;
            if (total_emitted >= scale) break;

            // BL next level
            uint64_t next_fn = 0x1000 + (d + 1) * 0x20;
            tw.emit(ms, fn_base + 12, enc::bl((int32_t)(next_fn - (fn_base + 12))),
                    {{30, tw.rt(fn_base + 16)}, {33, tw.rt(next_fn)}}, {});
            total_emitted++;
        }

        // Ascend: return from each level
        for (int d = DEPTH - 1; d >= 0 && total_emitted < scale; d--) {
            uint64_t fn_base = 0x1000 + d * 0x20;
            // Pop frame
            ms.sp() += 16;
            tw.emit(ms, fn_base + 16, enc::ldp_post(29, 30, 31, 2),
                    {{29, ms.fp()}, {30, ms.lr()}, {31, ms.sp()}, {33, tw.rt(fn_base + 20)}},
                    {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, ms.lr()}});
            total_emitted++;
            if (total_emitted >= scale) break;

            tw.emit(ms, fn_base + 20, enc::ret(), {{33, tw.rt(fn_base - 0x20 + 16)}}, {});
            total_emitted++;
        }
    }

    tw.emit_anchor(ms);
    tw.close();
}

// --- P5: taint_explosion — Dense data dependencies causing taint set growth
//     Benchmarks: TaintPass with Roaring bitmap performance
REG_CASE(perf_taint_explosion, "perf", "Dense inter-register deps: measures TaintPass/Roaring bitmap scaling") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_taint";
    if (!tw.open(path)) return;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL;
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;

    // Phase 1: Initialize registers with unique sources
    for (int i = 0; i < 10; i++) {
        tw.emit(ms, 0x1000 + i * 4, enc::movz(i, (uint16_t)(i * 111)),
                {{(uint8_t)i, (uint64_t)(i * 111)}, {33, tw.rt(0x1004 + i * 4)}}, {});
    }

    // Phase 2: Mix registers in a pattern that causes exponential taint spread
    uint64_t pc = 0x1100;
    for (uint64_t i = 0; i < scale - 10; i++) {
        int dst = (int)(i % 10);
        int src1 = (int)((i + 1) % 10);
        int src2 = (int)((i + 3) % 10);
        uint64_t val = ms.x(src1) ^ ms.x(src2);
        ms.gpr[dst] = val;

        // Alternate between reg-reg ops and memory-mediated deps
        if (i % 4 == 0) {
            // EOR through memory
            uint64_t addr = data_base + (i % 4096) * 8;
            tw.emit(ms, pc, enc::str_imm(src1, 10, (int16_t)((i % 512) * 8)),
                    {{33, tw.rt(pc + 4)}}, {{2, 8, addr, ms.x(src1)}});
            pc = (pc + 4 - 0x1100) % 0x2000 + 0x1100;

            tw.emit(ms, pc, enc::ldr_imm(dst, 10, (int16_t)((i % 512) * 8)),
                    {{(uint8_t)dst, ms.x(src1)}, {33, tw.rt(pc + 4)}},
                    {{1, 8, addr, ms.x(src1)}});
            pc = (pc + 4 - 0x1100) % 0x2000 + 0x1100;
            i++; // counts as 2 instructions
        } else {
            tw.emit(ms, pc, enc::eor_reg(dst, src1, src2),
                    {{(uint8_t)dst, val}, {33, tw.rt(pc + 4)}}, {});
            pc = (pc + 4 - 0x1100) % 0x2000 + 0x1100;
        }
    }

    tw.emit_anchor(ms);
    tw.close();
}

// --- P6: cfg_explosion — Many basic blocks with complex branching
//     Benchmarks: CFGPass construction time at scale
REG_CASE(perf_cfg_explosion, "perf", "1000 unique BBs with cross-edges: measures CFG construction time") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_cfg";
    if (!tw.open(path)) return;
    tw.write_header(0x200000);
    MachineState ms; ms.sp() = 0x16F000000ULL;

    const int NUM_BLOCKS = 1000;
    uint64_t total = 0;

    while (total < scale) {
        // Visit blocks in pseudo-random order (LCG)
        uint64_t block_id = (total * 6364136223846793005ULL + 1) % NUM_BLOCKS;
        uint64_t bb_base = 0x1000 + block_id * 0x20;

        // Each block: 4 instructions + conditional branch
        for (int j = 0; j < 4 && total < scale; j++) {
            uint64_t pc = bb_base + j * 4;
            tw.emit(ms, pc, enc::add_imm(0, 0, 1),
                    {{0, total + 1}, {33, tw.rt(pc + 4)}}, {});
            total++;
        }
        if (total >= scale) break;

        // Conditional branch to another block
        uint64_t next_block = ((block_id + 7) * 2654435761ULL) % NUM_BLOCKS;
        uint64_t target_pc = 0x1000 + next_block * 0x20;
        tw.emit(ms, bb_base + 16, enc::b((int32_t)(target_pc - (bb_base + 16))),
                {{33, tw.rt(target_pc)}}, {});
        total++;
    }

    tw.emit_anchor(ms);
    tw.close();
}

// --- P7: mixed_workload — Realistic mix of all record types at scale
//     Benchmarks: overall system throughput (the "real-world" benchmark)
REG_CASE(perf_mixed_workload, "perf", "Realistic mix: arithmetic+memory+calls+events = real-world throughput") {
    if (scale == 0) scale = 1000000;
    TraceWriter tw; tw.anchor_interval = 4096; tw.module_name = "perf_mixed";
    if (!tw.open(path)) return;
    tw.write_header(0x200000);
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();
    uint64_t data_base = 0x200000000ULL;
    ms.x(10) = data_base;

    uint64_t total = 0;
    uint64_t call_depth = 0;

    while (total < scale) {
        uint64_t phase = total % 100;

        if (phase < 40) {
            // 40%: arithmetic (register-register)
            uint64_t pc = 0x1000 + (total % 8192) * 4;
            int rd = (int)(total % 10);
            int rs = (int)((total + 3) % 10);
            uint64_t val = ms.x(rs) + total;
            tw.emit(ms, pc, enc::add_reg(rd, rd, rs),
                    {{(uint8_t)rd, val}, {33, tw.rt(pc + 4)}}, {});
            total++;
        } else if (phase < 70) {
            // 30%: memory load/store
            uint64_t pc = 0x10000 + (total % 4096) * 4;
            uint64_t addr = data_base + (total % 16384) * 8;
            uint64_t val = total * 0x31337;
            if (phase % 2 == 0) {
                tw.emit(ms, pc, enc::str_imm(0, 10, (int16_t)((total % 512) * 8)),
                        {{0, val}, {33, tw.rt(pc + 4)}}, {{2, 8, addr, val}});
            } else {
                tw.emit(ms, pc, enc::ldr_imm(1, 10, (int16_t)((total % 512) * 8)),
                        {{1, val}, {33, tw.rt(pc + 4)}}, {{1, 8, addr, val}});
            }
            total++;
        } else if (phase < 85) {
            // 15%: function call/return
            uint64_t fn = 0x20000 + (total % 64) * 0x100;
            if (call_depth < 20) {
                ms.sp() -= 16;
                tw.emit(ms, fn, enc::stp_pre(29, 30, 31, -2),
                        {{31, ms.sp()}, {33, tw.rt(fn + 4)}},
                        {{2, 8, ms.sp(), ms.fp()}, {2, 8, ms.sp() + 8, ms.lr()}});
                total++;
                call_depth++;
            } else {
                ms.sp() += 16;
                tw.emit(ms, fn + 0x80, enc::ldp_post(29, 30, 31, 2),
                        {{29, ms.fp()}, {30, ms.lr()}, {31, ms.sp()}, {33, tw.rt(fn + 0x84)}},
                        {{1, 8, ms.sp() - 16, ms.fp()}, {1, 8, ms.sp() - 8, ms.lr()}});
                total++;
                tw.emit(ms, fn + 0x84, enc::ret(), {{33, tw.rt(fn)}}, {});
                total++;
                call_depth--;
            }
        } else if (phase < 95) {
            // 10%: branching (conditional)
            uint64_t pc = 0x30000 + (total % 2048) * 4;
            uint8_t nz = (total % 3 == 0) ? 0x4 : 0x0;
            tw.emit(ms, pc, enc::cmp_imm(0, (uint16_t)(total & 0xFFF)),
                    {{33, tw.rt(pc + 4)}}, {}, nz);
            total++;
            if (total < scale) {
                tw.emit(ms, pc + 4, enc::b_eq(8), {{33, tw.rt(pc + 8)}}, {}, nz);
                total++;
            }
        } else {
            // 5%: events (XFER, SVC)
            if (phase == 95) {
                tw.emit_event(QBDITRACE_EV_XFER_CALL, 0x180000000ULL + total, tw.rt(0x40000));
                tw.emit_event(QBDITRACE_EV_XFER_RETURN, tw.rt(0x40004), 0);
            }
            uint64_t pc = 0x40000 + (total % 1024) * 4;
            tw.emit(ms, pc, enc::nop(), {{33, tw.rt(pc + 4)}}, {});
            total++;
        }
    }

    tw.emit_anchor(ms);
    tw.close();
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main: CLI driver
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t parse_scale(const char* s) {
    char* end = nullptr;
    double val = strtod(s, &end);
    if (end && (*end == 'M' || *end == 'm')) return (uint64_t)(val * 1000000);
    if (end && (*end == 'K' || *end == 'k')) return (uint64_t)(val * 1000);
    if (end && (*end == 'G' || *end == 'g')) return (uint64_t)(val * 1000000000);
    return (uint64_t)val;
}

static void ensure_dir(const char* dir) {
    mkdir(dir, 0755);
}

static void print_usage() {
    printf("gen_test_traces — Synthetic trace generator for Tenet\n\n");
    printf("Usage:\n");
    printf("  --suite <unit|perf|all>  Generate a suite of traces\n");
    printf("  --case <name>            Generate a single named trace\n");
    printf("  --outdir <path>          Output directory (default: ./traces)\n");
    printf("  --scale <N[K|M|G]>      Instruction count for perf traces (default: 1M)\n");
    printf("  --list                   List all available test cases\n");
    printf("  --help                   Show this help\n");
}

int main(int argc, char* argv[]) {
    const char* suite = nullptr;
    const char* single_case = nullptr;
    const char* outdir = "./traces";
    uint64_t scale = 0;  // 0 means use default per case

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--suite") == 0 && i + 1 < argc) {
            suite = argv[++i];
        } else if (strcmp(argv[i], "--case") == 0 && i + 1 < argc) {
            single_case = argv[++i];
        } else if (strcmp(argv[i], "--outdir") == 0 && i + 1 < argc) {
            outdir = argv[++i];
        } else if (strcmp(argv[i], "--scale") == 0 && i + 1 < argc) {
            scale = parse_scale(argv[++i]);
        } else if (strcmp(argv[i], "--list") == 0) {
            printf("Available test cases:\n\n");
            printf("  %-25s %-6s %s\n", "NAME", "TYPE", "DESCRIPTION");
            printf("  %-25s %-6s %s\n", "----", "----", "-----------");
            for (auto& tc : cases()) {
                printf("  %-25s %-6s %s\n", tc.name, tc.category, tc.description);
            }
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
    }

    if (!suite && !single_case) {
        print_usage();
        return 1;
    }

    ensure_dir(outdir);

    auto run_case = [&](const TestCase& tc) {
        std::string fname = std::string(outdir) + "/" + tc.name + ".trace";
        auto t0 = std::chrono::high_resolution_clock::now();
        tc.generate(fname.c_str(), scale);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        // Get file size
        FILE* f = fopen(fname.c_str(), "rb");
        long sz = 0;
        if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }

        printf("[%s] %-25s → %s  (%.1f ms, %.2f MB)\n",
               tc.category, tc.name, fname.c_str(), ms, sz / 1048576.0);
    };

    if (single_case) {
        bool found = false;
        for (auto& tc : cases()) {
            if (strcmp(tc.name, single_case) == 0) {
                run_case(tc);
                found = true;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "Unknown case: %s (use --list to see available)\n", single_case);
            return 1;
        }
    } else {
        bool run_unit = (strcmp(suite, "unit") == 0 || strcmp(suite, "all") == 0);
        bool run_perf = (strcmp(suite, "perf") == 0 || strcmp(suite, "all") == 0);

        if (run_unit) {
            std::string udir = std::string(outdir) + "/unit";
            ensure_dir(udir.c_str());
            for (auto& tc : cases()) {
                if (strcmp(tc.category, "unit") == 0) {
                    std::string fname = udir + "/" + tc.name + ".trace";
                    auto t0 = std::chrono::high_resolution_clock::now();
                    tc.generate(fname.c_str(), scale);
                    auto t1 = std::chrono::high_resolution_clock::now();
                    double ms_val = std::chrono::duration<double, std::milli>(t1 - t0).count();
                    FILE* f = fopen(fname.c_str(), "rb");
                    long sz = 0;
                    if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }
                    printf("[unit] %-25s → %s  (%.1f ms, %ld bytes)\n",
                           tc.name, fname.c_str(), ms_val, sz);
                }
            }
        }

        if (run_perf) {
            std::string pdir = std::string(outdir) + "/perf";
            ensure_dir(pdir.c_str());
            for (auto& tc : cases()) {
                if (strcmp(tc.category, "perf") == 0) {
                    std::string fname = pdir + "/" + tc.name + ".trace";
                    auto t0 = std::chrono::high_resolution_clock::now();
                    tc.generate(fname.c_str(), scale);
                    auto t1 = std::chrono::high_resolution_clock::now();
                    double ms_val = std::chrono::duration<double, std::milli>(t1 - t0).count();
                    FILE* f = fopen(fname.c_str(), "rb");
                    long sz = 0;
                    if (f) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }
                    printf("[perf] %-25s → %s  (%.1f ms, %.2f MB)\n",
                           tc.name, fname.c_str(), ms_val, sz / 1048576.0);
                }
            }
        }
    }

    printf("\nDone.\n");
    return 0;
}
