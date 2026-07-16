#pragma once

#include "analysis/pass_manager.h"
#include "analysis/trace_collector.h"
#include "infra/scan_orchestrator.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <array>
#include <memory>
#include <ankerl/unordered_dense.h>

namespace tenet {

class CodeTable;  // forward declaration
class MemoryModel;
struct ObjcResult;

// ─── Known cross-library API categories ──────────────────────────────────

enum class ApiCategory : uint8_t {
    // ── iOS / macOS (Darwin) ──────────────────────────────────────────────
    CommonCrypto,
    SecurityFramework,
    CryptoKit,
    CocoaFoundation,
    LibSystem,
    // ── Android / Linux ──────────────────────────────────────────────────
    BoringSSL,         // BoringSSL / OpenSSL (EVP_*, HMAC_*, AES_*)
    AndroidKeystore,   // Android Keystore JNI
    // ── JNI (cross-platform) ─────────────────────────────────────────────
    JNI,               // JNI env functions (GetStringUTFChars, FindClass, ...)
    // ── Memory / String (cross-platform) ─────────────────────────────────
    MemoryOps,         // memcpy, memmove, memset, memcmp, ...
    StringOps,         // strlen, strcmp, strcpy, sprintf, ...
    HeapAlloc,         // malloc, calloc, realloc, free, ...
    // ── I/O / FS (cross-platform) ─────────────────────────────────────────
    FileIO,            // fopen, fread, open, read, write, ...
    Network,           // socket, connect, send, recv, getaddrinfo, ...
    // ── Anti-debug / integrity ───────────────────────────────────────────
    AntiDebug,         // ptrace, sysctl, prctl, getenv, access, isatty, ...
    // ── Threading / sync ─────────────────────────────────────────────────
    Threading,         // pthread_create/join/mutex, dispatch, ...
    // ── Encoding ─────────────────────────────────────────────────────────
    Encoding,          // base64_encode/decode, iconv, ...
    // ── Compression ──────────────────────────────────────────────────────
    Compression,
    // ── SQLite ───────────────────────────────────────────────────────────
    SQLite,            // sqlite3_open, sqlite3_prepare, sqlite3_exec, ...
    // ── Dynamic linking ───────────────────────────────────────────────────
    DynLink,           // dlopen, dlsym, dlclose
    // ── ObjC runtime / CF ─────────────────────────────────────────────────
    ObjCRuntime,       // NSString UTF8String, CFStringCreate, CFDataCreate, ...
    // ── Memory mapping ────────────────────────────────────────────────────
    MemoryMap,         // mmap, munmap, mprotect
    // ── Syscalls (SVC records) ────────────────────────────────────────────
    Syscall,           // raw syscall number
    // ── Fallback ─────────────────────────────────────────────────────────
    Custom,
};

} // namespace tenet

// Hash specialization for ApiCategory (required by ankerl::unordered_dense)
template <>
struct ankerl::unordered_dense::hash<tenet::ApiCategory> {
    using is_avalanching = void;
    auto operator()(tenet::ApiCategory cat) const noexcept -> uint64_t {
        return static_cast<uint64_t>(cat);
    }
};

namespace tenet {

// ─── CCAlgorithm / CCOperation enums ──────────────────────────────────────

inline const char* cc_algorithm_name(uint32_t alg) {
    switch (alg) {
        case 0: return "AES128"; case 1: return "DES"; case 2: return "3DES";
        case 3: return "CAST";   case 4: return "RC4"; case 5: return "RC2";
        case 6: return "Blowfish"; default: return "(unknown)";
    }
}

inline const char* cc_operation_name(uint32_t op) {
    switch (op) { case 0: return "Encrypt"; case 1: return "Decrypt"; default: return "(unknown)"; }
}

inline const char* cc_mode_name(uint32_t mode) {
    switch (mode) {
        case 1: return "ECB"; case 2: return "CBC"; case 3: return "CFB";
        case 4: return "CTR"; case 5: return "F8";  case 6: return "LRW";
        case 7: return "OFB"; case 8: return "XTS"; case 9: return "RC4";
        case 10: return "CFB8"; case 11: return "GCM"; case 12: return "CCM";
        default: return "(unknown)";
    }
}

inline const char* cc_hmac_alg_name(uint32_t alg) {
    switch (alg) {
        case 0: return "SHA1"; case 1: return "MD5"; case 2: return "SHA256";
        case 3: return "SHA384"; case 4: return "SHA512"; case 5: return "SHA224";
        default: return "(unknown)";
    }
}

// ─── A captured inline string from CapiCallStrView ────────────────────────

struct CapturedString {
    uint8_t arg_idx   = 0;     // which x-register argument this came from
    bool    truncated = false;
    bool    binary    = false;
    std::string value;         // UTF-8 content
};

// ─── A single API argument captured from the trace ───────────────────────

struct ApiArg {
    uint64_t raw_value = 0;
    std::optional<std::string> as_string;
    std::optional<std::vector<uint8_t>> as_bytes;
    std::optional<uint64_t> as_int;
    bool is_length_arg = false;
    uint64_t buffer_length = 0;
    std::string to_string() const;
};

// ─── A single intercepted API call ────────────────────────────────────────

struct InterceptedCall {
    uint64_t inst_id;
    uint64_t call_site_pc;
    uint64_t callee_pc;
    std::string callee_name;
    ApiCategory category;
    std::array<uint64_t, 8> raw_args{};
    uint8_t arg_count = 0;
    std::string decoded_summary;
    std::optional<std::vector<uint8_t>> key_bytes;
    std::optional<std::vector<uint8_t>> iv_bytes;
    std::optional<std::vector<uint8_t>> data_bytes;
    uint64_t key_length  = 0;
    uint64_t data_length = 0;
    uint64_t return_value = 0;
    bool has_return = false;
    std::optional<std::string> objc_context;

    /// Inline string captures directly from the CapiCall record (tracer-side).
    /// Available only for REC_CAPICALL records; empty for Event-derived calls.
    std::vector<CapturedString> captured_strings;

    /// True when this call was created from a REC_CAPICALL record.
    bool from_capicall_record = false;

    /// SVC flags (QBDITRACE_SVC_FL_* bits) — non-zero only for Syscall category.
    uint8_t svc_flags = 0;
};

// ─── Known API signatures ─────────────────────────────────────────────────

struct ApiSignature {
    std::string name;
    ApiCategory category;
    uint8_t arg_count;
    uint8_t key_ptr_arg   = UINT8_MAX;
    uint8_t key_len_arg   = UINT8_MAX;
    uint8_t iv_ptr_arg    = UINT8_MAX;
    uint8_t iv_len_arg    = UINT8_MAX;
    uint8_t data_ptr_arg  = UINT8_MAX;
    uint8_t data_len_arg  = UINT8_MAX;
    uint8_t operation_arg = UINT8_MAX;
    uint8_t algorithm_arg = UINT8_MAX;
    uint8_t mode_arg      = UINT8_MAX;
};

// ─── SyscallInterceptResult ───────────────────────────────────────────────

struct SyscallInterceptResult {
    std::vector<InterceptedCall> calls;
    ankerl::unordered_dense::map<std::string, std::vector<size_t>> by_callee;
    ankerl::unordered_dense::map<ApiCategory, std::vector<size_t>> by_category;
    size_t total() const { return calls.size(); }
    std::vector<const InterceptedCall*> find_calls(const std::string& name_pattern) const;
    std::string to_json() const;
};

// ─── SyscallInterceptConfig ───────────────────────────────────────────────

struct SyscallInterceptConfig {
    uint32_t capture_bytes = 64;
    bool intercept_unresolved = false;
    std::vector<std::string> extra_api_names;
};

// ─── SyscallInterceptCollector ────────────────────────────────────────────

/// TraceCollector that handles three record sources for API interception:
///
///   1. REC_CAPICALL   — highest priority, tracer-side resolved with inline strings.
///   2. REC_SVC        — raw syscall numbers, classified by flags and syscall_no.
///   3. Event XFER_CALL — heuristic cross-library call detection (fallback).
///
/// The `target_os` parameter selects the API signature table:
///   1=iOS/Darwin (CommonCrypto/Security), 2=Android (BoringSSL), 0=both.
class SyscallInterceptCollector final : public TraceCollector {
public:
    SyscallInterceptCollector(const SyscallInterceptConfig& config,
                               const CodeTable& code_table,
                               MemoryModel& memory,
                               const ObjcResult* objc,
                               uint32_t target_os = 0);

    std::string_view name() const override { return "SyscallInterceptCollector"; }

    bool begin(uint64_t start_inst_id, uint64_t end_inst_id) override;
    void on_inst(uint64_t inst_id, const InstView& inst) override;
    void on_capicall(uint64_t inst_id, const CapiCallView& capi) override;
    void on_svc(uint64_t inst_id, const SvcView& svc) override;
    void on_objc(uint64_t inst_id, const ObjcView& objc) override;
    void on_event(const EventView& ev) override;
    void end() override;

    SyscallInterceptResult take_result() { return std::move(result_); }

private:
    std::vector<uint8_t> read_memory_at(uint64_t addr, uint32_t max_bytes, uint64_t at_inst_id);
    void decode_known_api(InterceptedCall& call, const ApiSignature& sig);
    void finalize_call(InterceptedCall call);

    static const std::vector<ApiSignature>& known_apis();
    static const std::vector<ApiSignature>& known_android_apis();

    struct CapiEntry {
        const char* name = nullptr;
        const ApiSignature* sig = nullptr;
    };
    static const CapiEntry& capi_entry(uint8_t api_id);

    // ── Configuration ──
    const SyscallInterceptConfig& config_;
    const CodeTable& code_table_;
    MemoryModel& memory_;
    const ObjcResult* objc_result_;
    uint32_t target_os_;

    // ── Known API lookup ──
    ankerl::unordered_dense::map<std::string, const ApiSignature*> api_by_name_;

    /// Set of callee PCs handled by on_capicall() to suppress duplicate Event matches.
    ankerl::unordered_dense::map<uint64_t, uint64_t> capicall_seen_;

    // ── Rolling register state ──
    static constexpr uint32_t MAX_ARG_REGS = 8;
    uint64_t cur_regs_[MAX_ARG_REGS] = {};
    bool regs_valid_ = false;
    uint64_t cur_inst_id_ = 0;

    // ── ObjC context ──
    uint64_t last_objc_inst_id_ = 0;
    std::string last_objc_context_;

    // ── Result ──
    SyscallInterceptResult result_;
};

// ─── SyscallInterceptPass ─────────────────────────────────────────────────

class SyscallInterceptPass final : public AnalysisPass {
public:
    explicit SyscallInterceptPass(SyscallInterceptConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "syscall_intercept"; }
    std::string_view description() const override {
        return "Extract parameters from platform crypto/system API calls";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};
    }

    bool has_scan() const override { return true; }
    std::optional<PassResult> try_load_cached(PassContext& ctx) override;
    void declare_scan(ScanOrchestrator& orch, PassContext& ctx) override;
    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    SyscallInterceptConfig config_;
    std::unique_ptr<SyscallInterceptCollector> collector_;
};

}  // namespace tenet
