/*
 * test_qbditrace_macos.cpp — qbditrace + tenet joint integration test
 *
 * Runs the tracer in-process (no Frida) on a set of local target functions,
 * writes a .trace file, then opens it with tenet's TraceReader to verify:
 *
 *   1. File header is valid (magic, version >= 4, arch = AArch64).
 *   2. At least one INST record was produced.
 *   3. At least one ANCHOR record was produced.
 *   4. PC values in INST records fall within the traced range.
 *   5. The REC_CODE table is present (deduplicated code bytes).
 *   6. A full tenet analysis pipeline (XrefPass → CFGPass → LoopPass) runs
 *      against the live trace without error.
 *   7. The instrumented function's return value matches the native result
 *      (semantic correctness under instrumentation).
 *
 * Prerequisites (macOS arm64 only):
 *   - QBDI must be built in ../../build-macos (see run_macos.sh for details).
 *   - This test is compiled as part of the qbditrace CMake build when
 *     QBDITRACE_BUILD_TESTS_INTEGRATION is ON.
 *
 * Run:  ctest -R qbditrace_macos --output-on-failure
 */

// ─── Platform guard ───────────────────────────────────────────────────────────
#if !defined(__APPLE__) || !defined(__aarch64__)
#error "test_qbditrace_macos.cpp is only built on macOS arm64"
#endif

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>

// qbditrace public API
#include "QBDITrace.h"
#include "TraceFormat.h"

// tenet IO/analysis headers (included when QBDITRACE_TENET_INTEGRATION=1)
#ifdef QBDITRACE_TENET_INTEGRATION

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/function_pass.h"

using namespace tenet;

#endif  // QBDITRACE_TENET_INTEGRATION

// ─── Lightweight target functions ─────────────────────────────────────────────

// fib() and helper_sum() must not be inlined to produce cross-function call events.

__attribute__((noinline)) static uint64_t fib10_helper(uint64_t n) {
    if (n < 2) return n;
    return fib10_helper(n - 1) + fib10_helper(n - 2);
}

__attribute__((noinline)) static uint64_t array_sum(const uint64_t* p, int n) {
    uint64_t acc = 0;
    for (int i = 0; i < n; i++) acc += p[i];
    return acc;
}

uint64_t integration_target(uint64_t seed) {
    // 1. Arithmetic with branching
    uint64_t x = (seed & 1) ? seed + 7 : seed * 2;

    // 2. Memory write + read via helper
    uint64_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = seed + (uint64_t)i;
    uint64_t s = array_sum(buf, 8);

    // 3. Recursion (cross-function call + loop)
    uint64_t f = fib10_helper(10);

    return x ^ s ^ (f << 1);
}

void integration_target_end(void) {}  // sentinel

// ─── Helper: run tracer and return trace path ─────────────────────────────────

static std::string run_tracer(const char* output_path, uint64_t seed,
                               uint64_t* native_result_out) {
    uint64_t start = (uint64_t)(uintptr_t)&integration_target;
    uint64_t end   = (uint64_t)(uintptr_t)&integration_target_end;
    if (end <= start || (end - start) > 0x8000) {
        end = start + 0x2000;  // conservative fallback
    }

    // Compute native reference
    *native_result_out = integration_target(seed);

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.struct_size    = sizeof(cfg);
    cfg.trace_start    = start;
    cfg.trace_end      = end;
    cfg.module_base    = start;
    cfg.module_slide   = 0;
    cfg.module_name    = "integration_target";
    cfg.output_path    = output_path;
    cfg.record         = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval = 64;

    int rc = qbditrace_configure(&cfg);
    if (rc != 0) return "";

    uint64_t ret = 0;
    uint64_t args[1] = {seed};
    rc = qbditrace_run_call(&ret, start, 1, args);
    qbditrace_stop();

    if (rc != 0 || ret != *native_result_out) return "";
    return output_path;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

TEST_CASE("qbditrace: in-process trace is semantically correct",
          "[integration][qbditrace]") {
    const char* out = "/tmp/qbditrace_test_integration.bin";
    const uint64_t kSeed = 0x1234;

    uint64_t native = 0;
    auto path = run_tracer(out, kSeed, &native);

    REQUIRE_FALSE(path.empty());
    REQUIRE(std::filesystem::exists(path));

    SECTION("semantic correctness: return value matches native") {
        // The tracer was already verified in run_tracer (rc != 0 returns "")
        // so reaching here means the instrumented value matched native.
        SUCCEED("instrumented return value matched native result");
    }
}

TEST_CASE("qbditrace: trace file header is valid",
          "[integration][qbditrace]") {
    const char* out = "/tmp/qbditrace_test_header.bin";
    uint64_t native = 0;
    auto path = run_tracer(out, 0xABCD, &native);
    REQUIRE_FALSE(path.empty());

    // Read header directly (no tenet dependency needed)
    FILE* f = fopen(out, "rb");
    REQUIRE(f != nullptr);

    qbditrace::qbditrace_file_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    size_t n = fread(&hdr, 1, sizeof(hdr), f);
    fclose(f);

    REQUIRE(n == sizeof(hdr));

    SECTION("magic is QBDT") {
        REQUIRE(hdr.magic == QBDITRACE_MAGIC);
    }
    SECTION("version >= 4") {
        REQUIRE(hdr.version >= 4u);
    }
    SECTION("arch == AArch64") {
        REQUIRE(hdr.arch == QBDITRACE_ARCH_AARCH64);
    }
    SECTION("num_gpr == 34") {
        REQUIRE(hdr.num_gpr == QBDITRACE_AARCH64_NUM_GPR);
    }
    SECTION("flags contain REG_DIFF | HAS_CODE") {
        REQUIRE((hdr.flags & QBDITRACE_HF_REG_DIFF) != 0);
        REQUIRE((hdr.flags & QBDITRACE_HF_HAS_CODE) != 0);
    }
}

TEST_CASE("qbditrace: trace file contains expected record types",
          "[integration][qbditrace]") {
    const char* out = "/tmp/qbditrace_test_records.bin";
    uint64_t native = 0;
    auto path = run_tracer(out, 0x5678, &native);
    REQUIRE_FALSE(path.empty());

    // Parse records manually (no tenet dependency needed for this basic check)
    FILE* f = fopen(out, "rb");
    REQUIRE(f != nullptr);

    qbditrace::qbditrace_file_header_t hdr;
    fread(&hdr, sizeof(hdr), 1, f);

    int inst_count   = 0;
    int anchor_count = 0;
    int code_count   = 0;

    // Scan records (stop after 50000 to bound test time)
    for (int iter = 0; iter < 50000; iter++) {
        uint8_t kind = 0;
        if (fread(&kind, 1, 1, f) != 1) break;
        fseek(f, -1, SEEK_CUR);

        if (kind == QBDITRACE_REC_INST) {
            if (hdr.version >= 5 && (hdr.flags & QBDITRACE_HF_PC_DELTA)) {
                qbditrace::qbditrace_inst_head_v5_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                size_t skip = ih.n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t);
                size_t macc_size = (hdr.flags & QBDITRACE_HF_OLD_VALUE)
                    ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                    : sizeof(qbditrace::qbditrace_memacc_t);
                skip += ih.n_mem * macc_size;
                fseek(f, (long)skip, SEEK_CUR);
            } else {
                qbditrace::qbditrace_inst_head_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                size_t skip = ih.n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t);
                size_t macc_size = (hdr.flags & QBDITRACE_HF_OLD_VALUE)
                    ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                    : sizeof(qbditrace::qbditrace_memacc_t);
                skip += ih.n_mem * macc_size;
                fseek(f, (long)skip, SEEK_CUR);
            }
            inst_count++;
        } else if (kind == QBDITRACE_REC_ANCHOR) {
            qbditrace::qbditrace_anchor_head_t ah;
            if (fread(&ah, sizeof(ah), 1, f) != 1) break;
            fseek(f, hdr.num_gpr * 8, SEEK_CUR);
            anchor_count++;
        } else if (kind == QBDITRACE_REC_CODE) {
            qbditrace::qbditrace_code_head_t ch;
            if (fread(&ch, sizeof(ch), 1, f) != 1) break;
            fseek(f, ch.size, SEEK_CUR);
            code_count++;
        } else {
            // Unknown or other record: stop scanning
            break;
        }
    }
    fclose(f);

    SECTION("at least 50 INST records for a non-trivial function") {
        REQUIRE(inst_count >= 50);
    }
    SECTION("at least 1 ANCHOR record") {
        REQUIRE(anchor_count >= 1);
    }
    SECTION("at least 5 CODE records (deduplicated instruction bytes)") {
        REQUIRE(code_count >= 5);
    }
}

// ─── Tenet joint analysis (only when tenet headers are available) ─────────────

#ifdef QBDITRACE_TENET_INTEGRATION

TEST_CASE("qbditrace + tenet: TraceReader opens live trace successfully",
          "[integration][qbditrace][tenet]") {
    const char* out = "/tmp/qbditrace_test_tenet.bin";
    uint64_t native = 0;
    auto path = run_tracer(out, 0x9876, &native);
    REQUIRE_FALSE(path.empty());

    auto reader_result = TraceReader::open(std::filesystem::path(out));
    REQUIRE(reader_result.has_value());

    auto& reader = *reader_result;
    SECTION("version >= 4") {
        REQUIRE(reader.version() >= 4);
    }
    SECTION("total instruction count > 0") {
        uint64_t cnt = 0;
        for (auto it = reader.begin(); it != reader.end(); ++it) {
            if ((*it).kind == RecordKind::Inst) cnt++;
        }
        REQUIRE(cnt > 0);
    }
}

TEST_CASE("qbditrace + tenet: full analysis pipeline succeeds on live trace",
          "[integration][qbditrace][tenet]") {
    const char* out = "/tmp/qbditrace_test_pipeline.bin";
    uint64_t native = 0;
    auto path = run_tracer(out, 0xFEDC, &native);
    REQUIRE_FALSE(path.empty());

    // Open TraceReader
    auto reader_result = TraceReader::open(std::filesystem::path(out));
    REQUIRE(reader_result.has_value());
    auto reader = std::make_unique<TraceReader>(std::move(*reader_result));

    // Build index
    auto index_result = TraceIndex::open_or_build(*reader, nullptr);
    REQUIRE(index_result.has_value());
    auto index = std::make_unique<TraceIndex>(std::move(*index_result));

    // Build code table
    CodeTable code_table;
    for (auto it = reader->begin(); it != reader->end(); ++it) {
        auto rec = *it;
        if (rec.kind == RecordKind::Code) {
            auto code = rec.as_code();
            if (code.size == 4) {
                uint32_t opcode = 0;
                std::memcpy(&opcode, code.bytes, 4);
                code_table.insert(code.pc, opcode);
            }
        }
    }

    // Initialize analysis components
    InstructionDecoder decoder;
    decoder.init();

    auto regfile = std::make_unique<RegisterFile>(*reader, *index);
    auto memory  = std::make_unique<MemoryModel>(
        *reader, *index,
        index->raw_db(), index->mem_write_cf(), index->mem_read_cf());

    // Create PassManager
    auto pm = std::make_unique<PassManager>();
    pm->set_reader(reader.get());
    pm->set_index(index.get());
    pm->set_code_table(&code_table);
    pm->set_regfile(regfile.get());
    pm->set_memory(memory.get());
    pm->set_decoder(&decoder);

    // Register passes
    pm->register_pass(std::make_unique<XrefPass>());
    pm->register_pass(std::make_unique<CFGPass>());
    pm->register_pass(std::make_unique<LoopPass>());
    pm->register_pass(std::make_unique<FunctionPass>());

    SECTION("XrefPass on live trace") {
        auto& xr = pm->require("xref");
        REQUIRE(xr.ok());
        auto& xref = xr.get<XrefResult>();
        REQUIRE(xref.total_indexed > 0);
    }

    SECTION("CFGPass on live trace") {
        auto& cr = pm->require("cfg");
        REQUIRE(cr.ok());
        auto& cfg = cr.get<CFGResult>();
        REQUIRE(cfg.block_count() > 0);
    }

    SECTION("LoopPass on live trace — fib10_helper loop should be detected") {
        auto& lr = pm->require("loop");
        REQUIRE(lr.ok());
        // fib10_helper is recursive; the CFG will have back-edges
        // (at least one loop from the recursive structure)
        auto& loop = lr.get<LoopResult>();
        REQUIRE(loop.total_back_edges > 0);
    }

    SECTION("FunctionPass on live trace — calls to array_sum detected") {
        auto& fr = pm->require("function");
        REQUIRE(fr.ok());
        auto& func = fr.get<FunctionResult>();
        REQUIRE(func.call_events.size() > 0);
    }
}

TEST_CASE("qbditrace + tenet: PC values in live trace are within instrumented range",
          "[integration][qbditrace][tenet]") {
    const char* out = "/tmp/qbditrace_test_pcrange.bin";
    uint64_t native = 0;
    auto path = run_tracer(out, 0x1111, &native);
    REQUIRE_FALSE(path.empty());

    // Read header to get trace_start / trace_end
    qbditrace::qbditrace_file_header_t hdr;
    {
        FILE* f = fopen(out, "rb");
        REQUIRE(f != nullptr);
        fread(&hdr, sizeof(hdr), 1, f);
        fclose(f);
    }

    auto reader_result = TraceReader::open(std::filesystem::path(out));
    REQUIRE(reader_result.has_value());
    auto reader = std::make_unique<TraceReader>(std::move(*reader_result));

    int checked = 0;
    int in_range = 0;

    for (auto it = reader->begin(); it != reader->end() && checked < 10000; ++it) {
        auto rec = *it;
        if (rec.kind != RecordKind::Inst) continue;
        auto inst = rec.as_inst();
        checked++;
        if (inst.pc >= hdr.trace_start && inst.pc < hdr.trace_end) in_range++;
    }

    SECTION("at least 90% of checked instructions are within the traced range") {
        REQUIRE(checked > 0);
        double ratio = (double)in_range / (double)checked;
        // Allow 10% for any helper functions or stubs within a few pages
        REQUIRE(ratio >= 0.9);
    }
}

#endif  // QBDITRACE_TENET_INTEGRATION
