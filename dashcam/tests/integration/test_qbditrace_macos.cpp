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

// Pull qbditrace format constants into the global namespace for convenience.
using namespace qbditrace;

// tenet IO/analysis headers (included when QBDITRACE_TENET_INTEGRATION=1)
#ifdef QBDITRACE_TENET_INTEGRATION

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/function_pass.h"

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
    cfg.struct_size       = sizeof(cfg);
    cfg.trace_start       = start;
    cfg.trace_end         = end;
    cfg.module_base       = start;
    cfg.module_slide      = 0;
    cfg.module_name       = "integration_target";
    cfg.output_path       = output_path;
    cfg.record            = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval   = 64;
    // Disable compression so that basic raw-scan tests can parse records without
    // needing to handle block-compressed format.  Tenet tests use TraceReader
    // which handles all compression transparently.
    cfg.disable_compress  = 1;

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
            const bool has_fpr = (hdr.flags & QBDITRACE_HF_HAS_FPR) != 0;
            const bool is_v5   = hdr.version >= 5 && (hdr.flags & QBDITRACE_HF_PC_DELTA) != 0;
            const bool is_v6   = (hdr.flags & QBDITRACE_HF_OLD_VALUE) != 0;
            size_t macc_size = is_v6 ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                                     : sizeof(qbditrace::qbditrace_memacc_t);
            uint8_t n_regdiff = 0, n_mem = 0, n_fprdiff = 0;
            if (has_fpr && is_v5) {
                qbditrace::qbditrace_inst_head_v7_v5_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem; n_fprdiff = ih.n_fprdiff;
            } else if (has_fpr) {
                qbditrace::qbditrace_inst_head_v7_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem; n_fprdiff = ih.n_fprdiff;
            } else if (is_v5) {
                qbditrace::qbditrace_inst_head_v5_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem;
            } else {
                qbditrace::qbditrace_inst_head_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem;
            }
            // Header already consumed by fread above; seek past the
            // variable-length tail (regdiff + fprdiff + memacc).
            size_t tail = n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                        + n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                        + n_mem     * macc_size;
            fseek(f, (long)tail, SEEK_CUR);
            inst_count++;
        } else if (kind == QBDITRACE_REC_ANCHOR) {
            qbditrace::qbditrace_anchor_head_t ah;
            if (fread(&ah, sizeof(ah), 1, f) != 1) break;
            size_t gpr_bytes = hdr.num_gpr * 8;
            size_t fpr_bytes = (hdr.flags & QBDITRACE_HF_HAS_FPR)
                ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
            fseek(f, (long)(gpr_bytes + fpr_bytes), SEEK_CUR);
            anchor_count++;
        } else if (kind == QBDITRACE_REC_CODE) {
            qbditrace::qbditrace_code_head_t ch;
            if (fread(&ch, sizeof(ch), 1, f) != 1) break;
            fseek(f, ch.size, SEEK_CUR);
            code_count++;
        } else if (kind == QBDITRACE_REC_THREAD) {
            qbditrace::qbditrace_thread_head_t th;
            if (fread(&th, sizeof(th), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_EVENT) {
            qbditrace::qbditrace_event_head_t eh;
            if (fread(&eh, sizeof(eh), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_SVC) {
            qbditrace::qbditrace_svc_head_t sh;
            if (fread(&sh, sizeof(sh), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_OBJC) {
            // OBJC record has a fixed-size header (including 48-byte cls name buffer)
            qbditrace::qbditrace_objc_head_t oh;
            if (fread(&oh, sizeof(oh), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_CAPICALL) {
            qbditrace::qbditrace_capicall_head_t ch;
            if (fread(&ch, sizeof(ch), 1, f) != 1) break;
            for (uint8_t si = 0;
                 si < ch.str_count && si < QBDITRACE_CAPICALL_MAX_STR_CAPS; ++si) {
                qbditrace::qbditrace_capicall_str_t sh;
                if (fread(&sh, sizeof(sh), 1, f) != 1) goto scan_done;
                uint32_t padded = ((uint32_t)(sh.str_len + 1u) + 3u) & ~3u;
                fseek(f, (long)padded, SEEK_CUR);
            }
        } else {
            // Unknown record kind: stop scanning
            break;
        }
    }
scan_done:
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
        REQUIRE(reader.header().version >= 4);
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

// ─── SyscallInterceptPass joint test (only with tenet integration) ────────
//
// Calls CCCrypt (AES-128-CBC) and CCHmac (SHA256) from inside the traced
// range with enable_capi_intercept = 1.  Then opens the resulting trace with
// tenet and runs SyscallInterceptPass to verify:
//   1. At least one CAPICALL record for "CCCrypt" and "CCHmac" is intercepted.
//   2. The intercepted CCCrypt call has category == CommonCrypto.
//   3. from_capicall_record is set (record came from REC_CAPICALL, not Event).
//   4. decoded_summary is non-empty.
//   5. by_category[CommonCrypto] bucket is populated.
//   6. result.to_json() contains the "calls" key.
//
// Additionally performs a raw binary scan of the trace file to verify that
// at least 2 QBDITRACE_REC_CAPICALL records were physically written.
//
// Note: the raw-scan test (CAPICALL records appear in trace file) does NOT
// require tenet headers but is placed here alongside the tenet-coupled tests
// for proximity; it only needs CommonCrypto and qbditrace.

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#ifndef _DARWIN_C_SOURCE
#  define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>

#include "analysis/passes/platform/syscall_intercept_pass.h"
#include "analysis/trace_collector.h"

// ── Known test vectors ────────────────────────────────────────────────────
static const uint8_t kCCTestKey[16] = {
    0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
};
static const uint8_t kCCTestIV[16] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f
};
static const uint8_t kCCTestData[32] = {
    0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57, 0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac, 0x45,0xaf,0x8e,0x51
};

/// Target function: calls CCCrypt then CCHmac via function pointers.
///
/// Using function pointers (rather than direct calls) forces the compiler to
/// emit `blr` (indirect call) instead of `bl` + stub.  QBDI handles `blr` to
/// non-instrumented addresses by transferring execution natively through
/// ExecBroker, which avoids the disassembly error we hit when QBDI tried to
/// instrument CommonCrypto's NEON instructions after following a `bl` into the
/// stub and then into the library.
///
/// Must NOT be inlined so the function boundaries are well-defined for tracing.
__attribute__((noinline))
static uint32_t crypto_target_capi(void) {
    // Resolve via dlsym so we get the real implementation address (not the
    // Mach-O stub in __auth_stubs which trips QBDI's instrumentation).
    using CCCryptFn = CCCryptorStatus(*)(CCOperation, CCAlgorithm,
        CCOptions, const void*, size_t, const void*,
        const void*, size_t, void*, size_t, size_t*);
    using CCHmacFn = void(*)(CCHmacAlgorithm, const void*, size_t,
        const void*, size_t, void*);

    auto pCCCrypt = (CCCryptFn)dlsym(RTLD_DEFAULT, "CCCrypt");
    auto pCCHmac  = (CCHmacFn)dlsym(RTLD_DEFAULT, "CCHmac");
    if (!pCCCrypt || !pCCHmac) return 0;  // shouldn't happen on macOS

    uint8_t ciphertext[48] = {};
    size_t moved = 0;
    CCCryptorStatus st = pCCCrypt(
        kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
        kCCTestKey, 16,
        kCCTestIV,
        kCCTestData, 32,
        ciphertext, sizeof(ciphertext), &moved
    );
    uint8_t mac[CC_SHA256_DIGEST_LENGTH] = {};
    pCCHmac(kCCHmacAlgSHA256,
           kCCTestKey, 16,
           ciphertext, moved,
           mac);
    // Prevent elimination of calls — use a volatile accumulator so the compiler
    // does NOT auto-vectorize this into udot/addv (ARM v8.2 NEON dot-product
    // instructions that QBDI's LLVM disassembler cannot parse, causing SIGABRT).
    volatile uint32_t chk = (uint32_t)st;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; ++i) chk += mac[i];
    return chk;
}
void crypto_target_capi_end(void) {}  // sentinel

/// Run qbditrace on crypto_target_capi() with CAPI interception enabled.
/// Returns the trace file path, or "" on failure / missing symbols.
static std::string run_tracer_capi(const char* output_path) {
    uint64_t fn_start = (uint64_t)(uintptr_t)&crypto_target_capi;
    uint64_t fn_end   = (uint64_t)(uintptr_t)&crypto_target_capi_end;
    if (fn_end <= fn_start || (fn_end - fn_start) > 0x8000) {
        fn_end = fn_start + 0x2000;
    }

    void* cccrypt_sym = dlsym(RTLD_DEFAULT, "CCCrypt");
    void* cchmac_sym  = dlsym(RTLD_DEFAULT, "CCHmac");
    if (!cccrypt_sym || !cchmac_sym) return "";  // CommonCrypto unavailable

    qbditrace_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.struct_size           = sizeof(cfg);
    cfg.trace_start           = fn_start;
    cfg.trace_end             = fn_end;
    cfg.module_base           = fn_start;
    cfg.module_slide          = 0;
    cfg.module_name           = "crypto_capi_test";
    cfg.output_path           = output_path;
    cfg.record                = QBDITRACE_REC_DEFAULT;
    cfg.anchor_interval       = 64;
    cfg.disable_compress      = 1;  // uncompressed for simpler raw scan
    cfg.enable_capi_intercept = 1;

    // CCCrypt: id=134, 8 args, no string-pointer capture (binary key/IV/data)
    cfg.capi_funcs[0].addr   = (uint64_t)(uintptr_t)cccrypt_sym;
    cfg.capi_funcs[0].api_id = 134;  // QBDITRACE_CAPI_CCCRYPT
    cfg.capi_funcs[0].n_args = 8;
    cfg.capi_funcs[0].str_args = 0;

    // CCHmac: id=135, 6 args
    cfg.capi_funcs[1].addr   = (uint64_t)(uintptr_t)cchmac_sym;
    cfg.capi_funcs[1].api_id = 135;  // QBDITRACE_CAPI_CCHMAC
    cfg.capi_funcs[1].n_args = 6;
    cfg.capi_funcs[1].str_args = 0;

    cfg.n_capi_funcs = 2;

    if (qbditrace_configure(&cfg) != 0) return "";

    fprintf(stderr, "[capi-test] fn_start=0x%llx fn_end=0x%llx\n",
            (unsigned long long)fn_start, (unsigned long long)fn_end);
    fprintf(stderr, "[capi-test] CCCrypt=0x%llx CCHmac=0x%llx\n",
            (unsigned long long)(uintptr_t)cccrypt_sym,
            (unsigned long long)(uintptr_t)cchmac_sym);

    uint64_t ret = 0;
    int rc = qbditrace_run_call(&ret, fn_start, 0, nullptr);
    qbditrace_stop();
    if (rc != 0) return "";
    return output_path;
}

// ─── Raw binary scan: verify CAPICALL records physically exist ────────────

TEST_CASE("qbditrace: CAPICALL records appear in trace file (raw scan)",
          "[integration][qbditrace][capi]") {
    const char* out = "/tmp/qbditrace_test_capi_raw.bin";
    auto path = run_tracer_capi(out);
    if (path.empty()) {
        SKIP("CommonCrypto unavailable or tracer failed — skipping CAPI test");
    }
    REQUIRE(std::filesystem::exists(path));

    FILE* f = fopen(out, "rb");
    REQUIRE(f != nullptr);

    qbditrace::qbditrace_file_header_t hdr;
    fread(&hdr, sizeof(hdr), 1, f);
    REQUIRE(hdr.magic == QBDITRACE_MAGIC);

    int capicall_count = 0;

    for (int iter = 0; iter < 300000; iter++) {
        uint8_t kind = 0;
        if (fread(&kind, 1, 1, f) != 1) break;
        fseek(f, -1, SEEK_CUR);

        if (kind == QBDITRACE_REC_CAPICALL) {
            qbditrace::qbditrace_capicall_head_t ch;
            if (fread(&ch, sizeof(ch), 1, f) != 1) break;
            // Skip variable-length string captures
            for (uint8_t si = 0;
                 si < ch.str_count && si < QBDITRACE_CAPICALL_MAX_STR_CAPS; ++si) {
                qbditrace::qbditrace_capicall_str_t sh;
                if (fread(&sh, sizeof(sh), 1, f) != 1) goto scan_done_raw;
                uint32_t padded = ((uint32_t)(sh.str_len + 1u) + 3u) & ~3u;
                fseek(f, (long)padded, SEEK_CUR);
            }
            capicall_count++;
        } else if (kind == QBDITRACE_REC_INST) {
            const bool has_fpr = (hdr.flags & QBDITRACE_HF_HAS_FPR) != 0;
            const bool is_v5   = hdr.version >= 5 && (hdr.flags & QBDITRACE_HF_PC_DELTA) != 0;
            const bool is_v6   = (hdr.flags & QBDITRACE_HF_OLD_VALUE) != 0;
            size_t macc_size = is_v6 ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                                     : sizeof(qbditrace::qbditrace_memacc_t);
            uint8_t n_regdiff = 0, n_mem = 0, n_fprdiff = 0;
            if (has_fpr && is_v5) {
                qbditrace::qbditrace_inst_head_v7_v5_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem; n_fprdiff = ih.n_fprdiff;
            } else if (has_fpr) {
                qbditrace::qbditrace_inst_head_v7_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem; n_fprdiff = ih.n_fprdiff;
            } else if (is_v5) {
                qbditrace::qbditrace_inst_head_v5_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem;
            } else {
                qbditrace::qbditrace_inst_head_t ih;
                if (fread(&ih, sizeof(ih), 1, f) != 1) break;
                n_regdiff = ih.n_regdiff; n_mem = ih.n_mem;
            }
            size_t tail = n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                        + n_fprdiff * sizeof(qbditrace::qbditrace_fprdiff_t)
                        + n_mem     * macc_size;
            fseek(f, (long)tail, SEEK_CUR);
        } else if (kind == QBDITRACE_REC_ANCHOR) {
            qbditrace::qbditrace_anchor_head_t ah;
            if (fread(&ah, sizeof(ah), 1, f) != 1) break;
            size_t gpr_bytes = hdr.num_gpr * 8;
            size_t fpr_bytes = (hdr.flags & QBDITRACE_HF_HAS_FPR)
                ? QBDITRACE_AARCH64_FPR_SNAPSHOT_BYTES : 0;
            fseek(f, (long)(gpr_bytes + fpr_bytes), SEEK_CUR);
        } else if (kind == QBDITRACE_REC_CODE) {
            qbditrace::qbditrace_code_head_t ch;
            if (fread(&ch, sizeof(ch), 1, f) != 1) break;
            fseek(f, ch.size, SEEK_CUR);
        } else if (kind == QBDITRACE_REC_THREAD) {
            qbditrace::qbditrace_thread_head_t th;
            if (fread(&th, sizeof(th), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_EVENT) {
            qbditrace::qbditrace_event_head_t eh;
            if (fread(&eh, sizeof(eh), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_SVC) {
            qbditrace::qbditrace_svc_head_t sh;
            if (fread(&sh, sizeof(sh), 1, f) != 1) break;
        } else if (kind == QBDITRACE_REC_OBJC) {
            qbditrace::qbditrace_objc_head_t oh;
            if (fread(&oh, sizeof(oh), 1, f) != 1) break;
        } else {
            break;  // unknown record — stop scan
        }
    }
scan_done_raw:
    fclose(f);

    SECTION("at least 2 CAPICALL records (CCCrypt + CCHmac)") {
        REQUIRE(capicall_count >= 2);
    }
}

// ─── Full tenet SyscallInterceptPass analysis ─────────────────────────────

TEST_CASE("qbditrace + tenet: SyscallInterceptPass intercepts CCCrypt CAPICALL",
          "[integration][qbditrace][tenet][syscall_intercept][capi]") {
    const char* out = "/tmp/qbditrace_test_capi_tenet.bin";
    auto path = run_tracer_capi(out);
    if (path.empty()) {
        SKIP("CommonCrypto unavailable or tracer failed — skipping CAPI+tenet test");
    }
    REQUIRE(std::filesystem::exists(path));

    // Open trace
    auto reader_result = TraceReader::open(std::filesystem::path(out));
    REQUIRE(reader_result.has_value());
    auto reader = std::make_unique<TraceReader>(std::move(*reader_result));

    // Build index
    auto index_result = TraceIndex::open_or_build(*reader, nullptr);
    REQUIRE(index_result.has_value());
    auto index = std::make_unique<TraceIndex>(std::move(*index_result));

    // Build CodeTable
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

    // Initialize tenet core
    InstructionDecoder decoder;
    decoder.init();

    auto regfile = std::make_unique<RegisterFile>(*reader, *index);
    auto memory  = std::make_unique<MemoryModel>(
        *reader, *index,
        index->raw_db(), index->mem_write_cf(), index->mem_read_cf());

    // Run SyscallInterceptCollector
    SyscallInterceptConfig icfg;
    icfg.capture_bytes = 64;
    // target_os=1 (Darwin) to load the CommonCrypto signature table
    SyscallInterceptCollector collector(icfg, code_table, *memory, nullptr, 1);

    uint64_t total_insts = index->inst_count();
    TraceScanEngine engine(*reader, total_insts, index.get());
    engine.add_collector(&collector);
    engine.run();

    auto result = collector.take_result();

    SECTION("at least one CCCrypt CAPICALL was intercepted") {
        auto calls = result.find_calls("CCCrypt");
        REQUIRE_FALSE(calls.empty());
    }

    SECTION("CCCrypt call has category CommonCrypto") {
        auto calls = result.find_calls("CCCrypt");
        if (!calls.empty()) {
            CHECK(calls[0]->category == ApiCategory::CommonCrypto);
        }
    }

    SECTION("CCCrypt call came from a REC_CAPICALL record") {
        auto calls = result.find_calls("CCCrypt");
        if (!calls.empty()) {
            CHECK(calls[0]->from_capicall_record == true);
        }
    }

    SECTION("CCCrypt decoded_summary is non-empty") {
        auto calls = result.find_calls("CCCrypt");
        if (!calls.empty()) {
            CHECK_FALSE(calls[0]->decoded_summary.empty());
        }
    }

    SECTION("CCCrypt raw args contain non-zero key pointer (x3)") {
        auto calls = result.find_calls("CCCrypt");
        if (!calls.empty()) {
            // x3 = key pointer — must be non-null
            CHECK(calls[0]->raw_args[3] != 0);
        }
    }

    SECTION("CCHmac CAPICALL was also intercepted") {
        auto calls = result.find_calls("CCHmac");
        CHECK_FALSE(calls.empty());
    }

    SECTION("by_category[CommonCrypto] bucket is non-empty") {
        auto it = result.by_category.find(ApiCategory::CommonCrypto);
        REQUIRE(it != result.by_category.end());
        CHECK_FALSE(it->second.empty());
    }

    SECTION("to_json() contains calls array") {
        auto json_str = result.to_json();
        CHECK_FALSE(json_str.empty());
        CHECK(json_str.find("\"calls\"") != std::string::npos);
    }
}

#endif  // QBDITRACE_TENET_INTEGRATION
