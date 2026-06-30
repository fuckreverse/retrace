#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstring>

namespace tenet {

using json = nlohmann::json;

// ─── SyscallInterceptResult serialization helpers ─────────────────────────
//
// Blob format (all little-endian):
//   u32  magic   = 0x53494341 ("SICA")
//   u32  version = 1
//   u64  num_calls
//   for each InterceptedCall:
//     u64  inst_id
//     u64  call_site_pc
//     u64  callee_pc
//     u32  callee_name_len; u8[] callee_name
//     u8   category  (cast of ApiCategory)
//     u8   arg_count
//     u64[8]  raw_args
//     u32  summary_len; u8[] decoded_summary
//     u8   has_key_bytes; if 1: u32 key_len, u8[] key_bytes
//     u8   has_iv_bytes;  if 1: u32 iv_len, u8[] iv_bytes
//     u8   has_data_bytes;if 1: u32 data_len, u8[] data_bytes
//     u64  key_length
//     u64  data_length
//     u64  return_value
//     u8   has_return
//     u8   has_objc_ctx; if 1: u32 objc_len, u8[] objc_ctx

namespace {

static constexpr uint32_t SICA_BLOB_MAGIC   = 0x53494341u;  // "SICA"
static constexpr uint32_t SICA_BLOB_VERSION = 1u;

// Helper: compute serialized size of an InterceptedCall
static size_t call_serial_size(const InterceptedCall& c) {
    size_t sz = 8 + 8 + 8;  // inst_id, call_site_pc, callee_pc
    sz += 4 + c.callee_name.size();  // callee_name
    sz += 1 + 1 + 8 * 8;  // category, arg_count, raw_args
    sz += 4 + c.decoded_summary.size();  // summary
    sz += 1;  // has_key_bytes
    if (c.key_bytes.has_value()) sz += 4 + c.key_bytes->size();
    sz += 1;  // has_iv_bytes
    if (c.iv_bytes.has_value()) sz += 4 + c.iv_bytes->size();
    sz += 1;  // has_data_bytes
    if (c.data_bytes.has_value()) sz += 4 + c.data_bytes->size();
    sz += 8 + 8 + 8 + 1;  // key_length, data_length, return_value, has_return
    sz += 1;  // has_objc_ctx
    if (c.objc_context.has_value()) sz += 4 + c.objc_context->size();
    return sz;
}

std::string syscall_intercept_serialize(const SyscallInterceptResult& res) {
    size_t total = 4 + 4 + 8;  // magic, version, num_calls
    for (const auto& c : res.calls) total += call_serial_size(c);

    std::string buf(total, '\0');
    char* p = buf.data();

    auto write_u8  = [&](uint8_t  v) { std::memcpy(p, &v, 1); p += 1; };
    auto write_u32 = [&](uint32_t v) { std::memcpy(p, &v, 4); p += 4; };
    auto write_u64 = [&](uint64_t v) { std::memcpy(p, &v, 8); p += 8; };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        std::memcpy(p, s.data(), s.size()); p += s.size();
    };
    auto write_opt_bytes = [&](const std::optional<std::vector<uint8_t>>& ob) {
        if (ob.has_value()) {
            write_u8(1u);
            write_u32(static_cast<uint32_t>(ob->size()));
            std::memcpy(p, ob->data(), ob->size()); p += ob->size();
        } else {
            write_u8(0u);
        }
    };
    auto write_opt_str = [&](const std::optional<std::string>& os) {
        if (os.has_value()) {
            write_u8(1u);
            write_str(*os);
        } else {
            write_u8(0u);
        }
    };

    write_u32(SICA_BLOB_MAGIC);
    write_u32(SICA_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.calls.size()));

    for (const auto& c : res.calls) {
        write_u64(c.inst_id);
        write_u64(c.call_site_pc);
        write_u64(c.callee_pc);
        write_str(c.callee_name);
        write_u8(static_cast<uint8_t>(c.category));
        write_u8(c.arg_count);
        for (uint64_t a : c.raw_args) write_u64(a);
        write_str(c.decoded_summary);
        write_opt_bytes(c.key_bytes);
        write_opt_bytes(c.iv_bytes);
        write_opt_bytes(c.data_bytes);
        write_u64(c.key_length);
        write_u64(c.data_length);
        write_u64(c.return_value);
        write_u8(c.has_return ? 1u : 0u);
        write_opt_str(c.objc_context);
    }

    return buf;
}

bool syscall_intercept_deserialize(const std::string& blob, SyscallInterceptResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&](std::string& s) -> bool {
        if (p + 4 > end) return false;
        uint32_t len = read_u32();
        if (p + len > end) return false;
        s.assign(p, len); p += len;
        return true;
    };
    auto read_opt_bytes = [&](std::optional<std::vector<uint8_t>>& ob) -> bool {
        if (p + 1 > end) return false;
        uint8_t has = read_u8();
        if (has) {
            if (p + 4 > end) return false;
            uint32_t len = read_u32();
            if (p + len > end) return false;
            ob.emplace(p, p + len); p += len;
        }
        return true;
    };
    auto read_opt_str = [&](std::optional<std::string>& os) -> bool {
        if (p + 1 > end) return false;
        uint8_t has = read_u8();
        if (has) {
            std::string s;
            if (!read_str(s)) return false;
            os = std::move(s);
        }
        return true;
    };

    if (read_u32() != SICA_BLOB_MAGIC)   return false;
    if (read_u32() != SICA_BLOB_VERSION) return false;

    uint64_t n = read_u64();
    out.calls.reserve(static_cast<size_t>(n));

    for (uint64_t i = 0; i < n; i++) {
        if (p + 8 + 8 + 8 > end) return false;
        InterceptedCall c;
        c.inst_id      = read_u64();
        c.call_site_pc = read_u64();
        c.callee_pc    = read_u64();
        if (!read_str(c.callee_name)) return false;
        if (p + 1 + 1 + 8 * 8 > end) return false;
        c.category  = static_cast<ApiCategory>(read_u8());
        c.arg_count = read_u8();
        for (uint64_t& a : c.raw_args) a = read_u64();
        if (!read_str(c.decoded_summary)) return false;
        if (!read_opt_bytes(c.key_bytes)) return false;
        if (!read_opt_bytes(c.iv_bytes)) return false;
        if (!read_opt_bytes(c.data_bytes)) return false;
        if (p + 8 + 8 + 8 + 1 > end) return false;
        c.key_length   = read_u64();
        c.data_length  = read_u64();
        c.return_value = read_u64();
        c.has_return   = read_u8() != 0;
        if (!read_opt_str(c.objc_context)) return false;

        size_t idx = out.calls.size();
        out.by_callee[c.callee_name].push_back(idx);
        out.by_category[c.category].push_back(idx);
        out.calls.push_back(std::move(c));
    }

    return true;
}

}  // anonymous namespace (syscall_intercept serialization)

// ─── Known iOS API signature table ────────────────────────────────────────
//
// Argument indices are AArch64 ABI (x0=0, x1=1, ... x7=7).
//
// CCCrypt signature (from CommonCrypto/CommonCryptor.h):
//   CCCryptorStatus CCCrypt(
//       CCOperation op,         // x0 — 0=encrypt, 1=decrypt
//       CCAlgorithm alg,        // x1 — 0=AES, 1=DES, 2=3DES, ...
//       CCOptions options,      // x2 — mode flags (CBC=0, ECB=1, PKCS7=2)
//       const void *key,        // x3 — key pointer
//       size_t keyLength,       // x4 — key length
//       const void *iv,         // x5 — IV pointer (NULL for ECB/stream)
//       const void *dataIn,     // x6 — plaintext/ciphertext input pointer
//       size_t dataInLength,    // x7 — input length
//       ...                     // x8+ stack args (output buffer, output len, moved)
//   );
//
// CCHmac signature:
//   void CCHmac(
//       CCHmacAlgorithm algorithm, // x0
//       const void *key,           // x1
//       size_t keyLength,          // x2
//       const void *data,          // x3
//       size_t dataLength,         // x4
//       void *macOut               // x5
//   );
//
// CCKeyDerivationPBKDF:
//   int CCKeyDerivationPBKDF(
//       CCPBKDFAlgorithm algorithm,  // x0
//       const char *password,        // x1
//       size_t passwordLen,          // x2
//       const uint8_t *salt,         // x3
//       size_t saltLen,              // x4
//       CCPseudoRandomAlgorithm prf, // x5
//       uint rounds,                 // x6
//       uint8_t *derivedKey,         // x7
//       ...
//   );
//
// SecKeyCreateSignature (Security.framework):
//   CFDataRef SecKeyCreateSignature(
//       SecKeyRef key,          // x0 — SecKey object
//       SecKeyAlgorithm alg,    // x1 — CFStringRef naming the algorithm
//       CFDataRef dataToSign,   // x2 — data to sign
//       CFErrorRef *error       // x3
//   );
//
// SecItemCopyMatching:
//   OSStatus SecItemCopyMatching(
//       CFDictionaryRef query, // x0
//       CFTypeRef *result      // x1
//   );

const std::vector<ApiSignature>& SyscallInterceptCollector::known_apis() {
    static const std::vector<ApiSignature> apis = {
        // ── CommonCrypto ──────────────────────────────────────────────────
        {
            .name          = "CCCrypt",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 3,    // x3 = key pointer
            .key_len_arg   = 4,    // x4 = key length
            .iv_ptr_arg    = 5,    // x5 = IV pointer
            .iv_len_arg    = UINT8_MAX, // no separate iv_len in x0-x7 (it's implied by algorithm)
            .data_ptr_arg  = 6,    // x6 = input data pointer
            .data_len_arg  = 7,    // x7 = input data length
            .operation_arg = 0,    // x0 = CCOperation (0=enc, 1=dec)
            .algorithm_arg = 1,    // x1 = CCAlgorithm
            .mode_arg      = 2,    // x2 = CCOptions (mode flags)
        },
        {
            .name          = "CCCryptorCreate",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 7,
            .key_ptr_arg   = 3,
            .key_len_arg   = 4,
            .iv_ptr_arg    = 5,
            .operation_arg = 0,
            .algorithm_arg = 1,
            .mode_arg      = 2,
        },
        {
            .name          = "CCCryptorCreateWithMode",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 4,
            .key_len_arg   = 5,
            .iv_ptr_arg    = 6,
            .operation_arg = 0,
            .algorithm_arg = 1,
            .mode_arg      = 2,
        },
        {
            .name          = "CCHmac",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 6,
            .key_ptr_arg   = 1,
            .key_len_arg   = 2,
            .data_ptr_arg  = 3,
            .data_len_arg  = 4,
            .algorithm_arg = 0,
        },
        {
            .name          = "CCHmacInit",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 4,
            .key_ptr_arg   = 2,
            .key_len_arg   = 3,
            .algorithm_arg = 1,
        },
        {
            .name          = "CCDigest",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 4,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
            .algorithm_arg = 0,
        },
        {
            .name          = "CCKeyDerivationPBKDF",
            .category      = ApiCategory::CommonCrypto,
            .arg_count     = 8,
            .key_ptr_arg   = 1,  // password ptr
            .key_len_arg   = 2,  // password len
            .data_ptr_arg  = 3,  // salt ptr
            .data_len_arg  = 4,  // salt len
            .algorithm_arg = 0,
        },
        // ── Security.framework ────────────────────────────────────────────
        {
            .name          = "SecKeyCreateSignature",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 4,
            .key_ptr_arg   = 0,   // x0 = SecKeyRef
            .data_ptr_arg  = 2,   // x2 = CFDataRef to sign
        },
        {
            .name          = "SecKeyRawSign",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            .key_ptr_arg   = 0,   // x0 = SecKeyRef
            .data_ptr_arg  = 2,   // x2 = data to sign
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyRawVerify",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 6,
            .key_ptr_arg   = 0,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyEncrypt",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            .key_ptr_arg   = 0,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecKeyDecrypt",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 5,
            .key_ptr_arg   = 0,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "SecItemCopyMatching",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 2,
        },
        {
            .name          = "SecItemAdd",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 2,
        },
        {
            .name          = "SecKeyCreateWithData",
            .category      = ApiCategory::SecurityFramework,
            .arg_count     = 3,
            .key_ptr_arg   = 0,  // x0 = CFDataRef (key bytes)
        },
        // ── Compression / zlib ────────────────────────────────────────────
        {
            .name          = "compress2",
            .category      = ApiCategory::Compression,
            .arg_count     = 5,
            .data_ptr_arg  = 2,  // source
            .data_len_arg  = 3,
        },
        {
            .name          = "uncompress",
            .category      = ApiCategory::Compression,
            .arg_count     = 4,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
    };
    return apis;
}

// ─── Android / Linux (BoringSSL / OpenSSL) API signature table ────────────
//
// BoringSSL is the default TLS/crypto library on Android (used by
// conscrypt, OkHttp, Chromium, ...).  Function signatures follow
// the OpenSSL EVP interface — same argument positions on AArch64.

static const std::vector<ApiSignature>& known_android_apis() {
    static const std::vector<ApiSignature> apis = {
        // ── BoringSSL / OpenSSL EVP symmetric cipher ──────────────────────
        {
            .name          = "EVP_EncryptInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .key_ptr_arg   = 3,    // x3 = key pointer
            .iv_ptr_arg    = 4,    // x4 = IV pointer
        },
        {
            .name          = "EVP_DecryptInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .key_ptr_arg   = 3,
            .iv_ptr_arg    = 4,
        },
        {
            .name          = "EVP_CipherInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 6,
            .key_ptr_arg   = 3,
            .iv_ptr_arg    = 4,
            .operation_arg = 5,    // x5 = enc (1) or dec (0)
        },
        {
            .name          = "EVP_EncryptUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .data_ptr_arg  = 3,    // x3 = input data
            .data_len_arg  = 4,    // x4 = input length
        },
        {
            .name          = "EVP_DecryptUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
            .data_ptr_arg  = 3,
            .data_len_arg  = 4,
        },
        {
            .name          = "EVP_EncryptFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DecryptFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        // ── BoringSSL / OpenSSL HMAC ──────────────────────────────────────
        {
            .name          = "HMAC",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 7,
            .key_ptr_arg   = 1,    // x1 = key
            .key_len_arg   = 2,    // x2 = key_len
            .data_ptr_arg  = 3,    // x3 = data
            .data_len_arg  = 4,    // x4 = data_len
        },
        {
            .name          = "HMAC_Init_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 4,
            .key_ptr_arg   = 1,
            .key_len_arg   = 2,
        },
        {
            .name          = "HMAC_Update",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        // ── BoringSSL / OpenSSL Digest ────────────────────────────────────
        {
            .name          = "EVP_DigestInit_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DigestUpdate",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        {
            .name          = "EVP_DigestFinal_ex",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        // ── BoringSSL / OpenSSL RSA / EC signing ──────────────────────────
        {
            .name          = "EVP_DigestSignInit",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
        },
        {
            .name          = "EVP_DigestSignFinal",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
        },
        {
            .name          = "EVP_DigestVerifyInit",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 5,
        },
        {
            .name          = "EVP_DigestVerifyFinal",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .data_ptr_arg  = 1,
            .data_len_arg  = 2,
        },
        // ── BoringSSL / OpenSSL AES low-level ─────────────────────────────
        {
            .name          = "AES_set_encrypt_key",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .key_ptr_arg   = 0,    // x0 = userKey
            .key_len_arg   = 1,    // x1 = bits (128/192/256)
        },
        {
            .name          = "AES_set_decrypt_key",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 3,
            .key_ptr_arg   = 0,
            .key_len_arg   = 1,
        },
        {
            .name          = "AES_cbc_encrypt",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 6,
            .data_ptr_arg  = 0,    // x0 = in
            .data_len_arg  = 2,    // x2 = length
            .iv_ptr_arg    = 4,    // x4 = ivec
            .operation_arg = 5,    // x5 = enc
        },
        // ── BoringSSL / OpenSSL KDF ───────────────────────────────────────
        {
            .name          = "PKCS5_PBKDF2_HMAC",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 8,
            .key_ptr_arg   = 0,    // x0 = password
            .key_len_arg   = 1,    // x1 = pass_len
            .data_ptr_arg  = 3,    // x3 = salt
            .data_len_arg  = 4,    // x4 = salt_len
        },
        {
            .name          = "PKCS5_PBKDF2_HMAC_SHA1",
            .category      = ApiCategory::BoringSSL,
            .arg_count     = 7,
            .key_ptr_arg   = 0,
            .key_len_arg   = 1,
            .data_ptr_arg  = 2,    // x2 = salt
            .data_len_arg  = 3,    // x3 = salt_len
        },
        // ── Compression (shared with iOS) ─────────────────────────────────
        {
            .name          = "compress2",
            .category      = ApiCategory::Compression,
            .arg_count     = 5,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
        {
            .name          = "uncompress",
            .category      = ApiCategory::Compression,
            .arg_count     = 4,
            .data_ptr_arg  = 2,
            .data_len_arg  = 3,
        },
    };
    return apis;
}

// ─── SyscallInterceptCollector ────────────────────────────────────────────

SyscallInterceptCollector::SyscallInterceptCollector(
    const SyscallInterceptConfig& config,
    const CodeTable& code_table,
    MemoryModel& memory,
    const ObjcResult* objc,
    uint32_t target_os)
    : config_(config)
    , code_table_(code_table)
    , memory_(memory)
    , objc_result_(objc)
{
    // Select the API signature table based on target platform.
    // Darwin → CommonCrypto/Security.framework table.
    // Android/Linux → BoringSSL/OpenSSL table.
    // Unknown → load both tables (best-effort match).
    auto load_table = [&](const std::vector<ApiSignature>& table) {
        for (const auto& sig : table) {
            api_by_name_[sig.name] = &sig;
        }
    };

    bool is_darwin_target = (target_os == 1);   // TargetOS::iOS
    bool is_linux_target  = (target_os == 2 || target_os == 3);  // Android or Linux

    if (is_darwin_target) {
        load_table(known_apis());
    } else if (is_linux_target) {
        load_table(known_android_apis());
    } else {
        // Unknown platform — load both tables for best coverage.
        load_table(known_apis());
        load_table(known_android_apis());
    }

    // Add user-specified extra names (matched as prefix, no decode).
    for (const auto& extra : config_.extra_api_names) {
        if (api_by_name_.find(extra) == api_by_name_.end()) {
            api_by_name_[extra] = nullptr;  // nullptr = no signature
        }
    }
}

bool SyscallInterceptCollector::begin(uint64_t /*start_inst_id*/,
                                       uint64_t /*end_inst_id*/) {
    // Reset state for a fresh scan.
    std::memset(cur_regs_, 0, sizeof(cur_regs_));
    regs_valid_ = false;
    cur_inst_id_ = 0;
    last_objc_inst_id_ = 0;
    last_objc_context_.clear();
    result_ = {};
    return true;
}

void SyscallInterceptCollector::on_inst(uint64_t /*inst_id*/, const InstView& inst) {
    // Apply reg_diffs to maintain x0-x7 state.
    for (uint8_t r = 0; r < inst.reg_diff_count; ++r) {
        auto diff = inst.reg_diff(r);
        if (diff.index < MAX_ARG_REGS) {
            cur_regs_[diff.index] = diff.value;
            regs_valid_ = true;
        }
    }
    cur_inst_id_++;
}

void SyscallInterceptCollector::on_objc(uint64_t /*inst_id*/, const ObjcView& objc) {
    // Track ObjC context for annotation.
    last_objc_inst_id_ = cur_inst_id_;

    std::string cls_name(objc.cls ? objc.cls : "");
    // Try to resolve selector from symbol table.
    std::string sel_name;
    if (objc.sel != 0) {
        auto s = code_table_.image_read_cstring(objc.sel, 128);
        if (s) sel_name = *s;
    }
    if (sel_name.empty()) {
        // Fallback: use previously resolved selector from ObjcResult.
        if (objc_result_) {
            for (auto rit = objc_result_->messages.rbegin();
                 rit != objc_result_->messages.rend(); ++rit) {
                if (rit->inst_id <= cur_inst_id_) {
                    sel_name = rit->selector_name;
                    if (cls_name.empty()) cls_name = rit->class_name;
                    break;
                }
            }
        }
    }
    if (!cls_name.empty() || !sel_name.empty()) {
        last_objc_context_ = '[' + cls_name + ' ' + sel_name + ']';
    }
}

void SyscallInterceptCollector::on_event(const EventView& ev) {
    // XFER_CALL events: callee PC is outside the traced module.
    // event type: XFER_CALL = EventKind value (check TraceFormat.h)
    // qbditrace defines: QBDITRACE_EV_SEQ_ENTRY=0, XFER_CALL=2, XFER_RETURN=3
    // We accept both types 2 (XFER_CALL) and 0 to catch cross-module calls.
    if (ev.event != 2 && ev.event != 0) return;

    uint64_t callee_pc = ev.addr;
    if (callee_pc == 0) return;

    // ── Resolve callee name ────────────────────────────────────────
    std::string callee_name;

    if (!code_table_.opcode_at(callee_pc).has_value()) {
        // The callee is NOT in the traced module — it's a cross-library call.
        auto sym = code_table_.image_read_cstring(callee_pc, 64);
        if (sym) callee_name = *sym;
    }

    // ── Match against known APIs ──────────────────────────────────
    const ApiSignature* sig = nullptr;
    if (!callee_name.empty()) {
        auto ait = api_by_name_.find(callee_name);
        if (ait != api_by_name_.end()) {
            sig = ait->second;
        } else {
            // Prefix match for user-specified extra names.
            for (const auto& [name, s] : api_by_name_) {
                if (callee_name.rfind(name, 0) == 0) {
                    sig = s;
                    callee_name = name;
                    break;
                }
            }
        }
    }

    // If we have a signature match OR user requested all unresolved.
    if (sig == nullptr && !config_.intercept_unresolved) return;
    if (sig == nullptr && callee_name.empty()) return;

    if (!regs_valid_) return;

    // ── Build the intercepted call record ─────────────────────────
    InterceptedCall call;
    call.inst_id       = cur_inst_id_;
    call.call_site_pc  = ev.site;
    call.callee_pc     = callee_pc;
    call.callee_name   = callee_name.empty() ?
                             fmt::format("sub_{:x}", callee_pc) : callee_name;
    call.category      = sig ? sig->category : ApiCategory::Custom;
    std::memcpy(call.raw_args.data(), cur_regs_, sizeof(uint64_t) * MAX_ARG_REGS);
    call.arg_count     = sig ? sig->arg_count : MAX_ARG_REGS;

    // Attach ObjC context if recent.
    if (!last_objc_context_.empty() &&
        cur_inst_id_ - last_objc_inst_id_ < 100000) {
        call.objc_context = last_objc_context_;
    }

    // Decode arguments for known APIs.
    if (sig) {
        decode_known_api(call, *sig);
    } else {
        call.decoded_summary = call.callee_name +
            fmt::format(": x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
                        cur_regs_[0], cur_regs_[1], cur_regs_[2], cur_regs_[3]);
    }

    // ── Index and store ───────────────────────────────────────────
    size_t hit_idx = result_.calls.size();
    result_.by_callee[call.callee_name].push_back(hit_idx);
    result_.by_category[call.category].push_back(hit_idx);
    result_.calls.push_back(std::move(call));
}

void SyscallInterceptCollector::end() {
    // Nothing to finalize — results are already accumulated.
}

// ─── Memory reading helper ────────────────────────────────────────────────

std::vector<uint8_t> SyscallInterceptCollector::read_memory_at(
    uint64_t addr, uint32_t max_bytes, uint64_t at_inst_id)
{
    if (addr == 0 || max_bytes == 0) return {};

    std::vector<uint8_t> result;
    result.reserve(max_bytes);

    uint64_t cur = addr;
    uint32_t remaining = max_bytes;

    while (remaining > 0) {
        uint8_t chunk = static_cast<uint8_t>(std::min<uint32_t>(remaining, 16));
        auto mem_res = memory_.read(cur, chunk, at_inst_id);

        bool any_known = false;
        for (uint8_t i = 0; i < chunk; ++i) {
            if (mem_res.known[i]) any_known = true;
        }
        if (!any_known) break;  // Stop at first unknown region

        for (uint8_t i = 0; i < chunk; ++i) {
            if (!mem_res.known[i]) {
                // Partial: include zeros for unknown bytes, but stop if at start
                if (result.empty()) goto done;
                result.push_back(0);
            } else {
                result.push_back(mem_res.data[i]);
            }
        }
        cur       += chunk;
        remaining -= chunk;
    }
done:
    return result;
}

// ─── Decode a known API call ──────────────────────────────────────────────

void SyscallInterceptCollector::decode_known_api(InterceptedCall& call,
                                                  const ApiSignature& sig)
{
    const auto* regs = call.raw_args.data();
    const uint32_t capture = config_.capture_bytes;

    // Helper lambda for reading a pointer arg and returning bytes.
    auto read_ptr_arg = [&](uint8_t ptr_idx, uint8_t len_idx,
                             uint64_t default_len) -> std::vector<uint8_t> {
        if (ptr_idx >= 8) return {};
        uint64_t ptr = regs[ptr_idx];
        if (ptr == 0) return {};
        uint64_t len = default_len;
        if (len_idx < 8 && regs[len_idx] > 0 && regs[len_idx] < (1ULL << 20)) {
            len = regs[len_idx];
        }
        uint32_t cap = static_cast<uint32_t>(std::min<uint64_t>(len, capture));
        return read_memory_at(ptr, cap, call.inst_id);
    };

    // Extract key material.
    if (sig.key_ptr_arg < 8) {
        auto kb = read_ptr_arg(sig.key_ptr_arg, sig.key_len_arg, 32);
        if (!kb.empty()) {
            call.key_length = (sig.key_len_arg < 8) ? regs[sig.key_len_arg] : kb.size();
            call.key_bytes = std::move(kb);
        }
    }

    // Extract IV.
    if (sig.iv_ptr_arg < 8) {
        auto iv = read_ptr_arg(sig.iv_ptr_arg, sig.iv_len_arg, 16);
        if (!iv.empty()) call.iv_bytes = std::move(iv);
    }

    // Extract input data (first `capture` bytes).
    if (sig.data_ptr_arg < 8) {
        auto db = read_ptr_arg(sig.data_ptr_arg, sig.data_len_arg, 64);
        if (!db.empty()) {
            call.data_length = (sig.data_len_arg < 8) ? regs[sig.data_len_arg] : db.size();
            call.data_bytes = std::move(db);
        }
    }

    // Build human-readable decoded_summary.
    std::string summary = sig.name;
    summary += ": ";

    if (sig.operation_arg < 8) {
        uint32_t op = static_cast<uint32_t>(regs[sig.operation_arg]);
        summary += cc_operation_name(op);
        summary += " ";
    }
    if (sig.algorithm_arg < 8) {
        uint32_t alg = static_cast<uint32_t>(regs[sig.algorithm_arg]);
        // Distinguish CCAlgorithm vs CCHmacAlgorithm vs CCPBKDFAlgorithm
        // by function name prefix.
        if (sig.name.rfind("CCHmac", 0) == 0) {
            summary += cc_hmac_alg_name(alg);
        } else {
            summary += cc_algorithm_name(alg);
        }
        summary += " ";
    }
    if (sig.mode_arg < 8) {
        uint32_t mode = static_cast<uint32_t>(regs[sig.mode_arg]);
        summary += cc_mode_name(mode);
        summary += " ";
    }
    if (call.key_bytes.has_value()) {
        summary += fmt::format("key[{}]=", call.key_length);
        for (size_t i = 0; i < std::min<size_t>(call.key_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.key_bytes)[i]);
        }
        if (call.key_bytes->size() > 8) summary += "...";
        summary += " ";
    }
    if (call.iv_bytes.has_value()) {
        summary += fmt::format("iv[{}]=", call.iv_bytes->size());
        for (size_t i = 0; i < std::min<size_t>(call.iv_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.iv_bytes)[i]);
        }
        if (call.iv_bytes->size() > 8) summary += "...";
        summary += " ";
    }
    if (call.data_bytes.has_value()) {
        summary += fmt::format("data[{}]=", call.data_length);
        for (size_t i = 0; i < std::min<size_t>(call.data_bytes->size(), 8); ++i) {
            summary += fmt::format("{:02x}", (*call.data_bytes)[i]);
        }
        if (call.data_bytes->size() > 8) summary += "...";
    }

    call.decoded_summary = std::move(summary);
}

// ─── SyscallInterceptPass::run ────────────────────────────────────────────

PassResult SyscallInterceptPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    const auto& code_table = ctx.code_table();

    // ── Fast path: load from persisted cache ──────────────────────────────
    // Only cache when default config (no extra_api_names, no intercept_unresolved)
    // to keep the cache key unambiguous.
    const bool is_default_cfg =
        config_.extra_api_names.empty() && !config_.intercept_unresolved &&
        config_.capture_bytes == 64;
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob;
        if (ctx.index().load_pass_blob("syscall_intercept", blob)) {
            SyscallInterceptResult cached;
            if (syscall_intercept_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "syscall_intercept: {} calls ({} unique callees) (from cache)",
                    cached.calls.size(), cached.by_callee.size()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    // Optional: get ObjC messages for context annotation.
    const ObjcResult* objc = ctx.try_require<ObjcResult>("objc");

    ctx.progress(0.01f, "syscall_intercept: scanning trace...");

    SyscallInterceptCollector collector(config_, code_table, ctx.memory(), objc,
                                       static_cast<uint32_t>(reader.header().target_os));

    auto* engine = ctx.scan_engine();
    if (engine) {
        engine->add_collector(&collector);
        engine->run();
    } else {
        auto& index = ctx.index();
        uint64_t total_insts = index.inst_count();
        TraceScanEngine local_engine(reader, total_insts, &index);
        local_engine.set_progress([&](uint64_t processed, uint64_t total) {
            if (total > 0) {
                ctx.progress(std::min(0.99f,
                    static_cast<float>(processed) / static_cast<float>(total)));
            }
        });
        local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
        local_engine.add_collector(&collector);
        local_engine.run();
    }

    auto result = collector.take_result();

    // ── Persist result for future sessions ───────────────────────────────
    if (is_default_cfg && ctx.range().is_full_trace()) {
        std::string blob = syscall_intercept_serialize(result);
        if (!blob.empty()) {
            ctx.index().save_pass_blob("syscall_intercept", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format(
        "syscall_intercept: {} API calls intercepted ({} unique callees)",
        result.calls.size(), result.by_callee.size()));

    return PassResult::success(std::move(result));
}

// ─── SyscallInterceptResult helpers ──────────────────────────────────────

std::vector<const InterceptedCall*>
SyscallInterceptResult::find_calls(const std::string& name_pattern) const {
    std::vector<const InterceptedCall*> found;
    for (const auto& c : calls) {
        if (c.callee_name.find(name_pattern) != std::string::npos) {
            found.push_back(&c);
        }
    }
    return found;
}

static const char* api_category_str(ApiCategory cat) {
    switch (cat) {
        case ApiCategory::CommonCrypto:      return "CommonCrypto";
        case ApiCategory::SecurityFramework: return "Security.framework";
        case ApiCategory::CryptoKit:         return "CryptoKit";
        case ApiCategory::CocoaFoundation:   return "Foundation";
        case ApiCategory::LibSystem:         return "libSystem";
        case ApiCategory::BoringSSL:         return "BoringSSL";
        case ApiCategory::AndroidKeystore:   return "AndroidKeystore";
        case ApiCategory::Compression:       return "Compression";
        case ApiCategory::Custom:            return "Custom";
    }
    return "Unknown";
}

std::string SyscallInterceptResult::to_json() const {
    json output;
    output["total"]   = calls.size();
    output["callees"] = by_callee.size();

    // Summary table: callee → call count
    json callee_summary = json::object();
    for (const auto& [name, idxs] : by_callee) {
        callee_summary[name] = idxs.size();
    }
    output["callee_counts"] = std::move(callee_summary);

    json calls_arr = json::array();
    for (const auto& c : calls) {
        json cj;
        cj["inst_id"]     = c.inst_id;
        cj["call_site"]   = fmt::format("0x{:X}", c.call_site_pc);
        cj["callee"]      = c.callee_name;
        cj["callee_pc"]   = fmt::format("0x{:X}", c.callee_pc);
        cj["category"]    = api_category_str(c.category);
        cj["summary"]     = c.decoded_summary;

        if (c.objc_context.has_value()) {
            cj["objc_context"] = *c.objc_context;
        }

        // Raw args
        json args_arr = json::array();
        for (uint8_t i = 0; i < std::min<uint8_t>(c.arg_count, 8); ++i) {
            args_arr.push_back(fmt::format("0x{:X}", c.raw_args[i]));
        }
        cj["args_x0_x7"] = std::move(args_arr);

        // Key material
        if (c.key_bytes.has_value()) {
            cj["key_length"] = c.key_length;
            std::string hex;
            for (uint8_t b : *c.key_bytes) hex += fmt::format("{:02x}", b);
            cj["key_hex"] = hex;
        }
        if (c.iv_bytes.has_value()) {
            std::string hex;
            for (uint8_t b : *c.iv_bytes) hex += fmt::format("{:02x}", b);
            cj["iv_hex"] = hex;
        }
        if (c.data_bytes.has_value()) {
            cj["data_length"] = c.data_length;
            std::string hex;
            for (uint8_t b : *c.data_bytes) hex += fmt::format("{:02x}", b);
            cj["data_hex_first64"] = hex;
        }

        calls_arr.push_back(std::move(cj));
    }
    output["calls"] = std::move(calls_arr);

    return output.dump(2);
}

// ─── ApiArg::to_string ───────────────────────────────────────────────────

std::string ApiArg::to_string() const {
    if (as_string.has_value()) return *as_string;
    if (as_bytes.has_value()) {
        std::string hex;
        for (uint8_t b : *as_bytes) hex += fmt::format("{:02x}", b);
        return hex;
    }
    return fmt::format("0x{:x}", raw_value);
}

}  // namespace tenet
