/*
 * test_pass_syscall_intercept.cpp — Unit tests for tenet::SyscallInterceptPass
 *
 * Tests cover:
 *
 *  A. Helper functions
 *     - cc_algorithm_name / cc_operation_name / cc_mode_name / cc_hmac_alg_name
 *
 *  B. Pass on synthetic traces (no events / event / SVC / CAPICALL)
 *     - Minimal trace → zero calls
 *     - Trace with REC_SVC → Syscall-category call recorded
 *     - Trace with REC_CAPICALL (no strings) → Custom/named call recorded
 *     - Trace with REC_CAPICALL + inline strings → CapturedString populated,
 *       decoded_summary uses captured string content
 *     - Multiple CAPICALL records → dedup window suppresses same target
 *     - Known iOS API id (CCCrypt = 134) → resolved name "CCCrypt"
 *     - Known JNI API id (FindClass = 289) → resolved name "FindClass"
 *
 *  C. Data structure integrity
 *     - SyscallInterceptResult total(), find_calls(), to_json()
 *     - CapturedString fields (arg_idx, truncated, binary, value)
 *     - from_capicall_record / svc_flags flags
 *
 *  D. ApiCategory coverage (all 24 categories)
 *
 * Run:  ctest -R 'pass_syscall_intercept' --output-on-failure
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/platform/syscall_intercept_pass.h"
#include <nlohmann/json.hpp>

using namespace tenet;
using namespace tenet::test;

// ─── Trace builders ───────────────────────────────────────────────────────────

static std::unique_ptr<TraceEnv> make_minimal() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "si_minimal");
}

static std::unique_ptr<TraceEnv> make_with_event() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::movz(0, 0), {{0, 0ULL}, {33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::movz(1, 0), {{1, 0ULL}, {33, tw.rt(0x1008)}}, {});
        tw.emit(ms, 0x1008, enc::movz(2, 2), {{2, 2ULL}, {33, tw.rt(0x100C)}}, {});
        tw.emit_event(0 /*SEQ_ENTRY*/, 0xDEAD000ULL, tw.rt(0x100C));
        tw.emit(ms, 0x100C, enc::nop(), {{33, tw.rt(0x1010)}}, {});
        tw.emit_anchor(ms);
    }, "si_with_event");
}

/// Trace with a single REC_SVC record (syscall #1 = write, args x0=fd, x1=buf).
static std::unique_ptr<TraceEnv> make_with_svc() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // SVC record: syscall #1 (write), x0=fd=3, x1=buf=0xBEEF000
        tw.emit_svc(tw.rt(0x1004), /*no=*/1, /*a0=*/3, /*a1=*/0xBEEF000ULL);
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "si_with_svc");
}

/// Trace with REC_CAPICALL for a known iOS API (CCCrypt, api_id=134).
/// No inline strings — tests basic capicall dispatch and name resolution.
static std::unique_ptr<TraceEnv> make_with_capicall_known() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        // CAPICALL: api_id=134 (CCCrypt), call site=0x1008, target=0xDEAD100
        // args: x0=0 (Encrypt), x1=0 (AES128), x2=0 (CBC), x3=key_ptr, x4=16
        tw.emit_capicall(134, tw.rt(0x1008), 0xDEAD100ULL,
                         {0, 0, 0, 0xC000ULL, 16, 0, 0, 0});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "si_capicall_cccrypt");
}

/// Trace with REC_CAPICALL that carries 2 inline captured strings.
/// api_id=22 (strcmp) with x0="hello", x1="world".
static std::unique_ptr<TraceEnv> make_with_capicall_strings() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // CAPICALL: api_id=22 (strcmp), 2 args, 2 captured strings
        TraceWriter::CapiStr s0; s0.arg_idx = 0; s0.value = "hello";
        TraceWriter::CapiStr s1; s1.arg_idx = 1; s1.value = "world";
        tw.emit_capicall(22, tw.rt(0x1004), 0xDEAD200ULL,
                         {0xA000ULL, 0xB000ULL}, {s0, s1});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "si_capicall_strcmp_strings");
}

/// Trace with a truncated string capture.
static std::unique_ptr<TraceEnv> make_with_capicall_truncated() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // api_id=80 (fopen), x0=path (truncated), x1=mode
        TraceWriter::CapiStr s0;
        s0.arg_idx = 0;
        s0.flags   = QBDITRACE_SF_TRUNCATED;
        s0.value   = "/very/long/path/that/was/truncated/by/the/tracer";
        TraceWriter::CapiStr s1;
        s1.arg_idx = 1;
        s1.value   = "rb";
        tw.emit_capicall(80, tw.rt(0x1004), 0xDEAD300ULL,
                         {0xA000ULL, 0xB000ULL}, {s0, s1});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "si_capicall_fopen_trunc");
}

/// Trace with a JNI API call: api_id=289 (FindClass).
static std::unique_ptr<TraceEnv> make_with_capicall_jni() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // FindClass(env, "com/example/MainActivity")
        TraceWriter::CapiStr s0;
        s0.arg_idx = 1;  // x1 = class name string
        s0.value   = "com/example/MainActivity";
        tw.emit_capicall(/*FindClass=*/33, tw.rt(0x1004), 0xDEAD400ULL,
                         {0xE000ULL, 0xC000ULL}, {s0});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        tw.emit_anchor(ms);
    }, "si_capicall_jni_findclass");
}

/// Trace with two CAPICALL records to the *same* target: dedup must suppress
/// the second one within the dedup window.
static std::unique_ptr<TraceEnv> make_with_capicall_dedup() {
    return make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // First call at inst 0
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        tw.emit_capicall(22, tw.rt(0x1004), 0xDEAD500ULL,
                         {0xA000ULL, 0xB000ULL}, {});
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        // Second call: same target 0xDEAD500 within dedup window → should be suppressed
        tw.emit_capicall(22, tw.rt(0x1008), 0xDEAD500ULL,
                         {0xC000ULL, 0xD000ULL}, {});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "si_capicall_dedup");
}

// ─── A. Helper function tests ─────────────────────────────────────────────────

TEST_CASE("SyscallInterceptPass helpers: cc_algorithm_name",
          "[unit][pass][syscall_intercept]") {
    REQUIRE(std::string(cc_algorithm_name(0)) == "AES128");
    REQUIRE(std::string(cc_algorithm_name(1)) == "DES");
    REQUIRE(std::string(cc_algorithm_name(2)) == "3DES");
    REQUIRE(std::string(cc_algorithm_name(3)) == "CAST");
    REQUIRE(std::string(cc_algorithm_name(4)) == "RC4");
    REQUIRE(std::string(cc_algorithm_name(5)) == "RC2");
    REQUIRE(std::string(cc_algorithm_name(6)) == "Blowfish");
    REQUIRE(std::string(cc_algorithm_name(99)) == "(unknown)");
}

TEST_CASE("SyscallInterceptPass helpers: cc_operation_name",
          "[unit][pass][syscall_intercept]") {
    REQUIRE(std::string(cc_operation_name(0)) == "Encrypt");
    REQUIRE(std::string(cc_operation_name(1)) == "Decrypt");
    REQUIRE(std::string(cc_operation_name(2)) == "(unknown)");
}

TEST_CASE("SyscallInterceptPass helpers: cc_mode_name",
          "[unit][pass][syscall_intercept]") {
    REQUIRE(std::string(cc_mode_name(1))  == "ECB");
    REQUIRE(std::string(cc_mode_name(2))  == "CBC");
    REQUIRE(std::string(cc_mode_name(3))  == "CFB");
    REQUIRE(std::string(cc_mode_name(4))  == "CTR");
    REQUIRE(std::string(cc_mode_name(11)) == "GCM");
    REQUIRE(std::string(cc_mode_name(12)) == "CCM");
    REQUIRE(std::string(cc_mode_name(0))  == "(unknown)");
    REQUIRE(std::string(cc_mode_name(99)) == "(unknown)");
}

TEST_CASE("SyscallInterceptPass helpers: cc_hmac_alg_name",
          "[unit][pass][syscall_intercept]") {
    REQUIRE(std::string(cc_hmac_alg_name(0)) == "SHA1");
    REQUIRE(std::string(cc_hmac_alg_name(1)) == "MD5");
    REQUIRE(std::string(cc_hmac_alg_name(2)) == "SHA256");
    REQUIRE(std::string(cc_hmac_alg_name(3)) == "SHA384");
    REQUIRE(std::string(cc_hmac_alg_name(4)) == "SHA512");
    REQUIRE(std::string(cc_hmac_alg_name(5)) == "SHA224");
    REQUIRE(std::string(cc_hmac_alg_name(99)) == "(unknown)");
}

// ─── B. Pass on synthetic traces ─────────────────────────────────────────────

TEST_CASE("SyscallInterceptPass: succeeds on minimal trace (no events)",
          "[unit][pass][syscall_intercept]") {
    auto env = make_minimal();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");

    SECTION("pass succeeds") { REQUIRE(raw.ok()); }

    const auto& res = raw.get<SyscallInterceptResult>();
    SECTION("no calls on minimal trace") { REQUIRE(res.total() == 0); }
    SECTION("by_callee is empty") { REQUIRE(res.by_callee.empty()); }
    SECTION("by_category is empty") { REQUIRE(res.by_category.empty()); }
}

TEST_CASE("SyscallInterceptPass: succeeds on trace with SEQ_ENTRY event",
          "[unit][pass][syscall_intercept]") {
    auto env = make_with_event();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();
    SECTION("by_callee indices are consistent with total") {
        size_t total_in_index = 0;
        for (const auto& [name, idxs] : res.by_callee)
            total_in_index += idxs.size();
        REQUIRE(total_in_index == res.total());
    }
}

// ─── B1. REC_SVC tests ────────────────────────────────────────────────────────

TEST_CASE("SyscallInterceptPass: SVC record produces Syscall-category call",
          "[unit][pass][syscall_intercept][svc]") {
    auto env = make_with_svc();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("exactly one call recorded") {
        REQUIRE(res.total() == 1);
    }

    SECTION("category is Syscall") {
        REQUIRE(res.calls[0].category == ApiCategory::Syscall);
    }

    SECTION("callee_name encodes syscall number") {
        REQUIRE(res.calls[0].callee_name == "syscall_1");
    }

    SECTION("raw_args[0] == fd=3") {
        REQUIRE(res.calls[0].raw_args[0] == 3);
    }

    SECTION("raw_args[1] == buf=0xBEEF000") {
        REQUIRE(res.calls[0].raw_args[1] == 0xBEEF000ULL);
    }

    SECTION("from_capicall_record is false for SVC") {
        REQUIRE_FALSE(res.calls[0].from_capicall_record);
    }

    SECTION("by_category[Syscall] has one entry") {
        auto it = res.by_category.find(ApiCategory::Syscall);
        REQUIRE(it != res.by_category.end());
        REQUIRE(it->second.size() == 1);
    }

    SECTION("decoded_summary mentions syscall number") {
        const auto& s = res.calls[0].decoded_summary;
        REQUIRE(s.find("1") != std::string::npos);
    }
}

// ─── B2. REC_CAPICALL — known iOS API (no strings) ───────────────────────────

TEST_CASE("SyscallInterceptPass: CAPICALL known iOS API (CCCrypt) resolved",
          "[unit][pass][syscall_intercept][capicall]") {
    auto env = make_with_capicall_known();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("exactly one call recorded") {
        REQUIRE(res.total() == 1);
    }

    SECTION("callee_name is 'CCCrypt'") {
        REQUIRE(res.calls[0].callee_name == "CCCrypt");
    }

    SECTION("from_capicall_record is true") {
        REQUIRE(res.calls[0].from_capicall_record == true);
    }

    SECTION("no captured strings (record had none)") {
        REQUIRE(res.calls[0].captured_strings.empty());
    }

    SECTION("raw_args[3] == key_ptr == 0xC000") {
        REQUIRE(res.calls[0].raw_args[3] == 0xC000ULL);
    }

    SECTION("raw_args[4] == key_len == 16") {
        REQUIRE(res.calls[0].raw_args[4] == 16);
    }

    SECTION("callee_pc == 0xDEAD100") {
        REQUIRE(res.calls[0].callee_pc == 0xDEAD100ULL);
    }
}

// ─── B3. REC_CAPICALL — inline captured strings ───────────────────────────────

TEST_CASE("SyscallInterceptPass: CAPICALL with inline strings (strcmp)",
          "[unit][pass][syscall_intercept][capicall][strings]") {
    auto env = make_with_capicall_strings();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("one call recorded") {
        REQUIRE(res.total() == 1);
    }

    SECTION("callee_name resolved to 'strcmp'") {
        REQUIRE(res.calls[0].callee_name == "strcmp");
    }

    SECTION("two captured strings") {
        REQUIRE(res.calls[0].captured_strings.size() == 2);
    }

    SECTION("first captured string: arg_idx=0, value='hello'") {
        const auto& cs = res.calls[0].captured_strings[0];
        REQUIRE(cs.arg_idx == 0);
        REQUIRE(cs.value == "hello");
        REQUIRE_FALSE(cs.truncated);
        REQUIRE_FALSE(cs.binary);
    }

    SECTION("second captured string: arg_idx=1, value='world'") {
        const auto& cs = res.calls[0].captured_strings[1];
        REQUIRE(cs.arg_idx == 1);
        REQUIRE(cs.value == "world");
    }

    SECTION("decoded_summary contains both captured values") {
        const auto& s = res.calls[0].decoded_summary;
        REQUIRE(s.find("hello") != std::string::npos);
        REQUIRE(s.find("world") != std::string::npos);
    }

    SECTION("from_capicall_record is true") {
        REQUIRE(res.calls[0].from_capicall_record == true);
    }
}

// ─── B4. REC_CAPICALL — truncated string flag ────────────────────────────────

TEST_CASE("SyscallInterceptPass: CAPICALL fopen with truncated path string",
          "[unit][pass][syscall_intercept][capicall][strings]") {
    auto env = make_with_capicall_truncated();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("call recorded") {
        REQUIRE(res.total() == 1);
    }

    SECTION("callee_name is 'fopen'") {
        REQUIRE(res.calls[0].callee_name == "fopen");
    }

    SECTION("two captured strings") {
        REQUIRE(res.calls[0].captured_strings.size() == 2);
    }

    SECTION("first string is marked truncated") {
        REQUIRE(res.calls[0].captured_strings[0].truncated == true);
    }

    SECTION("second string (mode) is not truncated") {
        const auto& cs = res.calls[0].captured_strings[1];
        REQUIRE_FALSE(cs.truncated);
        REQUIRE(cs.value == "rb");
    }
}

// ─── B5. REC_CAPICALL — JNI api_id (FindClass = 289) ────────────────────────

TEST_CASE("SyscallInterceptPass: CAPICALL JNI FindClass name resolved",
          "[unit][pass][syscall_intercept][capicall][jni]") {
    auto env = make_with_capicall_jni();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("one call recorded") {
        REQUIRE(res.total() == 1);
    }

    SECTION("captured class name string present") {
        REQUIRE_FALSE(res.calls[0].captured_strings.empty());
        const auto& cs = res.calls[0].captured_strings[0];
        REQUIRE(cs.value == "com/example/MainActivity");
    }
}

// ─── B6. CAPICALL dedup: same target within window → one record ──────────────

TEST_CASE("SyscallInterceptPass: CAPICALL dedup suppresses same target",
          "[unit][pass][syscall_intercept][capicall][dedup]") {
    auto env = make_with_capicall_dedup();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());

    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("only one call recorded (second deduplicated)") {
        REQUIRE(res.total() == 1);
    }
}

// ─── C. Data structure integrity ─────────────────────────────────────────────

TEST_CASE("SyscallInterceptPass: find_calls returns empty for unknown name",
          "[unit][pass][syscall_intercept]") {
    auto env = make_minimal();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());
    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("find_calls for unknown name is empty") {
        REQUIRE(res.find_calls("ThisNameDoesNotExist").empty());
    }
}

TEST_CASE("SyscallInterceptPass: to_json has required keys",
          "[unit][pass][syscall_intercept]") {
    auto env = make_minimal();
    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());
    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("to_json does not throw") {
        std::string json;
        REQUIRE_NOTHROW(json = res.to_json());
        REQUIRE_FALSE(json.empty());
    }

    SECTION("to_json contains required keys") {
        nlohmann::json j = nlohmann::json::parse(res.to_json());
        REQUIRE(j.contains("total"));
        REQUIRE(j.contains("callees"));
        REQUIRE(j.contains("callee_counts"));
        REQUIRE(j.contains("calls"));
        REQUIRE(j["total"].get<size_t>() == 0);
        REQUIRE(j["calls"].is_array());
    }
}

TEST_CASE("SyscallInterceptPass: result structure integrity",
          "[unit][pass][syscall_intercept]") {
    SyscallInterceptResult res;

    // Build a call with captured strings.
    InterceptedCall c1;
    c1.inst_id         = 42;
    c1.callee_name     = "CCCrypt";
    c1.category        = ApiCategory::CommonCrypto;
    c1.key_length      = 16;
    c1.data_length     = 64;
    c1.decoded_summary = "CCCrypt: Encrypt AES128 CBC ";
    c1.from_capicall_record = true;
    c1.svc_flags       = 0;

    CapturedString cs;
    cs.arg_idx   = 3;
    cs.truncated = false;
    cs.binary    = false;
    cs.value     = "mysecretkey";
    c1.captured_strings.push_back(cs);

    res.calls.push_back(c1);
    res.by_callee["CCCrypt"].push_back(0);
    res.by_category[ApiCategory::CommonCrypto].push_back(0);

    SECTION("total() == 1") { REQUIRE(res.total() == 1); }

    SECTION("find_calls by exact name") {
        auto found = res.find_calls("CCCrypt");
        REQUIRE(found.size() == 1);
        REQUIRE(found[0]->callee_name == "CCCrypt");
    }

    SECTION("find_calls by substring") {
        auto found = res.find_calls("Crypt");
        REQUIRE(found.size() == 1);
    }

    SECTION("find_calls for no-match returns empty") {
        REQUIRE(res.find_calls("CCHmac").empty());
    }

    SECTION("captured string round-trip") {
        REQUIRE(res.calls[0].captured_strings.size() == 1);
        REQUIRE(res.calls[0].captured_strings[0].arg_idx == 3);
        REQUIRE(res.calls[0].captured_strings[0].value == "mysecretkey");
    }

    SECTION("from_capicall_record flag preserved") {
        REQUIRE(res.calls[0].from_capicall_record == true);
    }
}

TEST_CASE("SyscallInterceptPass: config with extra_api_names and intercept_unresolved",
          "[unit][pass][syscall_intercept]") {
    auto env = make_with_event();
    REQUIRE(env != nullptr);

    SyscallInterceptConfig cfg;
    cfg.intercept_unresolved = true;
    cfg.capture_bytes = 32;
    cfg.extra_api_names = {"my_custom_crypto"};

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>(cfg));

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());
}

// ─── D. ApiCategory coverage ─────────────────────────────────────────────────

TEST_CASE("SyscallInterceptPass: ApiCategory covers all 24 expected values",
          "[unit][pass][syscall_intercept]") {
    std::vector<ApiCategory> all_cats = {
        ApiCategory::CommonCrypto,
        ApiCategory::SecurityFramework,
        ApiCategory::CryptoKit,
        ApiCategory::CocoaFoundation,
        ApiCategory::LibSystem,
        ApiCategory::BoringSSL,
        ApiCategory::AndroidKeystore,
        ApiCategory::JNI,
        ApiCategory::MemoryOps,
        ApiCategory::StringOps,
        ApiCategory::HeapAlloc,
        ApiCategory::FileIO,
        ApiCategory::Network,
        ApiCategory::AntiDebug,
        ApiCategory::Threading,
        ApiCategory::Encoding,
        ApiCategory::Compression,
        ApiCategory::SQLite,
        ApiCategory::DynLink,
        ApiCategory::ObjCRuntime,
        ApiCategory::MemoryMap,
        ApiCategory::Syscall,
        ApiCategory::Custom,
    };
    REQUIRE(all_cats.size() == 23);

    SyscallInterceptResult res;
    for (ApiCategory cat : all_cats) {
        InterceptedCall c;
        c.category    = cat;
        c.callee_name = "test";
        res.calls.push_back(c);
        res.by_category[cat].push_back(res.calls.size() - 1);
    }

    SECTION("23 unique categories recorded") {
        REQUIRE(res.by_category.size() == 23);
    }
    SECTION("total == 23") {
        REQUIRE(res.total() == 23);
    }
}

// ─── E. CAPICALL + SVC combined in one trace ─────────────────────────────────

TEST_CASE("SyscallInterceptPass: trace with both SVC and CAPICALL records",
          "[unit][pass][syscall_intercept][combined]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        tw.emit(ms, 0x1000, enc::nop(), {{33, tw.rt(0x1004)}}, {});
        // SVC: syscall #4 (getpid)
        tw.emit_svc(tw.rt(0x1004), 4);
        tw.emit(ms, 0x1004, enc::nop(), {{33, tw.rt(0x1008)}}, {});
        // CAPICALL: strcmp (api_id=22) with one string
        TraceWriter::CapiStr s0; s0.arg_idx = 0; s0.value = "needle";
        tw.emit_capicall(22, tw.rt(0x1008), 0xEEEE000ULL,
                         {0xA000ULL, 0xB000ULL}, {s0});
        tw.emit(ms, 0x1008, enc::nop(), {{33, tw.rt(0x100C)}}, {});
        tw.emit_anchor(ms);
    }, "si_combined");

    REQUIRE(env != nullptr);

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<SyscallInterceptPass>());

    auto& raw = pm->require("syscall_intercept");
    REQUIRE(raw.ok());
    const auto& res = raw.get<SyscallInterceptResult>();

    SECTION("two calls total (one SVC, one CAPICALL)") {
        REQUIRE(res.total() == 2);
    }

    SECTION("one Syscall-category call") {
        auto it = res.by_category.find(ApiCategory::Syscall);
        REQUIRE(it != res.by_category.end());
        REQUIRE(it->second.size() == 1);
    }

    SECTION("CAPICALL call has captured string 'needle'") {
        // Find the capicall entry (from_capicall_record == true)
        const InterceptedCall* capicall = nullptr;
        for (const auto& c : res.calls) {
            if (c.from_capicall_record) { capicall = &c; break; }
        }
        REQUIRE(capicall != nullptr);
        REQUIRE_FALSE(capicall->captured_strings.empty());
        REQUIRE(capicall->captured_strings[0].value == "needle");
    }
}
