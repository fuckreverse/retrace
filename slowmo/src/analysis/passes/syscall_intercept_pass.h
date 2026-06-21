#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <array>

namespace tenet {

// ─── Known cross-library API categories ──────────────────────────────────

enum class ApiCategory {
    CommonCrypto,       // CCCrypt, CCHmac, CCKeyDerivation, etc.
    SecurityFramework,  // SecKey*, SecItem*, SecCertificate*, etc.
    CryptoKit,          // Swift CryptoKit bridged to ObjC
    Compression,        // libcompression / zlib
    CocoaFoundation,    // NSData crypto helpers, NSString encoding
    LibSystem,          // libc memcpy/memset on large buffers (key material)
    Custom,             // User-defined intercept point
};

// ─── CCAlgorithm / CCOperation enums (mirrors CommonCrypto headers) ──────

/// Maps CCAlgorithm integer values to human-readable names.
/// See <CommonCrypto/CommonCryptor.h>
inline const char* cc_algorithm_name(uint32_t alg) {
    switch (alg) {
        case 0: return "AES128";
        case 1: return "DES";
        case 2: return "3DES";
        case 3: return "CAST";
        case 4: return "RC4";
        case 5: return "RC2";
        case 6: return "Blowfish";
        default: return "(unknown)";
    }
}

/// Maps CCOperation integer values to human-readable names.
inline const char* cc_operation_name(uint32_t op) {
    switch (op) {
        case 0: return "Encrypt";
        case 1: return "Decrypt";
        default: return "(unknown)";
    }
}

/// Maps CCMode integer values to human-readable names.
/// See <CommonCrypto/CommonCryptor.h>
inline const char* cc_mode_name(uint32_t mode) {
    switch (mode) {
        case 1: return "ECB";
        case 2: return "CBC";
        case 3: return "CFB";
        case 4: return "CTR";
        case 5: return "F8";
        case 6: return "LRW";
        case 7: return "OFB";
        case 8: return "XTS";
        case 9: return "RC4";
        case 10: return "CFB8";
        case 11: return "GCM";
        case 12: return "CCM";
        default: return "(unknown)";
    }
}

/// Maps CCHmacAlgorithm to human-readable names.
inline const char* cc_hmac_alg_name(uint32_t alg) {
    switch (alg) {
        case 0: return "SHA1";
        case 1: return "MD5";
        case 2: return "SHA256";
        case 3: return "SHA384";
        case 4: return "SHA512";
        case 5: return "SHA224";
        default: return "(unknown)";
    }
}

// ─── A single API argument captured from the trace ───────────────────────

struct ApiArg {
    uint64_t raw_value = 0;             // raw register value (x0-x7)

    // Decoded interpretations (at most one will be valid)
    std::optional<std::string> as_string;   // if pointer to C string
    std::optional<std::vector<uint8_t>> as_bytes;  // if pointer to data buffer
    std::optional<uint64_t> as_int;         // always set (= raw_value)

    // Buffer metadata (if this arg is a (ptr, len) pair)
    bool is_length_arg = false;         // this arg provides the length of prev arg
    uint64_t buffer_length = 0;         // inferred from paired length arg

    std::string to_string() const;
};

// ─── A single intercepted API call ────────────────────────────────────────

struct InterceptedCall {
    uint64_t inst_id;               // inst_id of the XFER_CALL / BL instruction
    uint64_t call_site_pc;          // PC of the call site (in the target module)
    uint64_t callee_pc;             // PC of the callee (in the system library)
    std::string callee_name;        // Resolved name e.g. "CCCrypt"
    ApiCategory category;

    /// Input arguments (registers x0-x7 at the call site, AArch64 ABI).
    /// Arg semantics depend on `callee_name`.
    std::array<uint64_t, 8> raw_args{};  // x0-x7 at the moment of the call
    uint8_t arg_count = 0;               // How many args are meaningful

    /// Decoded key material or algorithm parameters (populated for known APIs).
    std::string decoded_summary;    // Human-readable one-liner e.g.:
                                    //  "CCCrypt: Encrypt AES-128/CBC key[16]=0x... iv[16]=0x..."
                                    //  "SecKeyCreateSignature: EC key=0x..."

    /// Raw key/IV/data bytes extracted from memory at call time.
    std::optional<std::vector<uint8_t>> key_bytes;    // extracted key material
    std::optional<std::vector<uint8_t>> iv_bytes;     // extracted IV / nonce
    std::optional<std::vector<uint8_t>> data_bytes;   // plaintext/ciphertext (first 64 bytes)

    uint64_t key_length  = 0;
    uint64_t data_length = 0;

    /// Return value (x0 after the call — populated by looking at next INST records).
    uint64_t return_value = 0;
    bool has_return = false;

    /// ObjC context: the most recent ObjC message before this call.
    std::optional<std::string> objc_context;  // "[ClassName selector]"
};

// ─── Known API signatures ─────────────────────────────────────────────────

/// Describes a known iOS system API that we want to intercept.
struct ApiSignature {
    std::string name;                  // Function name (for matching against symbol table)
    ApiCategory category;
    uint8_t arg_count;                 // Number of meaningful args (x0..x(n-1))

    // CommonCrypto-specific field indices (UINT8_MAX = not applicable)
    uint8_t key_ptr_arg   = UINT8_MAX; // x[n] is the key pointer
    uint8_t key_len_arg   = UINT8_MAX; // x[n] is the key length
    uint8_t iv_ptr_arg    = UINT8_MAX; // x[n] is the IV pointer
    uint8_t iv_len_arg    = UINT8_MAX; // x[n] is the IV length
    uint8_t data_ptr_arg  = UINT8_MAX; // x[n] is the input data pointer
    uint8_t data_len_arg  = UINT8_MAX; // x[n] is the input data length
    uint8_t operation_arg = UINT8_MAX; // x[n] encodes the operation (enc/dec)
    uint8_t algorithm_arg = UINT8_MAX; // x[n] encodes the algorithm enum
    uint8_t mode_arg      = UINT8_MAX; // x[n] encodes the mode enum
};

// ─── SyscallInterceptResult ───────────────────────────────────────────────

struct SyscallInterceptResult {
    /// All intercepted calls in trace order.
    std::vector<InterceptedCall> calls;

    /// Index: callee_name → indices into calls
    std::unordered_map<std::string, std::vector<size_t>> by_callee;

    /// Index: category → indices into calls
    std::unordered_map<ApiCategory, std::vector<size_t>> by_category;

    /// Total intercepted calls.
    size_t total() const { return calls.size(); }

    /// Get all calls matching a callee name pattern (substring match).
    std::vector<const InterceptedCall*> find_calls(const std::string& name_pattern) const;

    /// Serialize to JSON string.
    std::string to_json() const;
};

// ─── SyscallInterceptConfig ───────────────────────────────────────────────

struct SyscallInterceptConfig {
    /// How many bytes to capture from key / IV / data pointer arguments.
    uint32_t capture_bytes = 64;

    /// Whether to also intercept calls identified only by XFER_CALL events
    /// (when callee PC is known but no symbol name is available).
    bool intercept_unresolved = false;

    /// User-specified additional API names to intercept.
    /// Matched as prefix against resolved symbol names.
    std::vector<std::string> extra_api_names;
};

// ─── SyscallInterceptPass ─────────────────────────────────────────────────

/// Intercepts calls to iOS system library APIs (CommonCrypto, Security.framework,
/// etc.) and extracts their input parameters from the trace.
///
/// Solves the iOS-specific problem where the actual crypto algorithm body is
/// in a system dylib that was NOT traced — we still want to know:
///   - Which algorithm was invoked (AES? HMAC-SHA256?)
///   - What key and IV were used
///   - What was the input data / output data
///   - Where in the target code was this call made
///
/// ## How it works
///
/// The pass scans XFER_CALL / EVENT records in the trace.  When an EVENT of type
/// XFER_CALL fires with a callee PC outside the traced module, the pass:
///   1. Reads x0-x7 register values from the most recent INST record (via
///      a lightweight register state tracker — no RegisterFile required).
///   2. Matches the callee PC against a known API address table built from
///      the trace file header's module_slide and known dylib offsets, OR
///      matches the callee name via CodeTable symbol lookup.
///   3. Decodes the arguments according to the known API signature
///      (key pointer, key length, IV, data, algorithm enums, etc.).
///   4. Reads the actual key/IV/data bytes from MemoryModel at the call time.
///
/// ## Data sources
///
/// - REC_INST reg_diffs: register state at the call site
/// - REC_EVENT (XFER_CALL): callee PC / entry-point detection
/// - REC_OBJC: nearby ObjC messages for context annotation
/// - CodeTable symbol table: callee name resolution
/// - MemoryModel: pointer argument dereference
///
/// Result type: SyscallInterceptResult
class SyscallInterceptPass final : public AnalysisPass {
public:
    explicit SyscallInterceptPass(SyscallInterceptConfig config = {})
        : config_(std::move(config)) {}

    std::string_view name() const override { return "syscall_intercept"; }
    std::string_view description() const override {
        return "Extract parameters from iOS system API calls (CommonCrypto, Security.framework)";
    }

    std::vector<std::string_view> dependencies() const override {
        // objc is a soft dependency for context annotation
        return {};
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    SyscallInterceptConfig config_;

    /// Read up to `max_bytes` from MemoryModel at `addr` at time `at_inst_id`.
    std::vector<uint8_t> read_memory_at(PassContext& ctx, uint64_t addr,
                                         uint32_t max_bytes, uint64_t at_inst_id);

    /// Decode a known API call given its signature and register state.
    void decode_known_api(InterceptedCall& call, const ApiSignature& sig,
                          PassContext& ctx);

    /// Build the known API signature table (static).
    static const std::vector<ApiSignature>& known_apis();
};

}  // namespace tenet
