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

const std::vector<ApiSignature>& SyscallInterceptCollector::known_android_apis() {
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

// ─── CapiCall ID → name / signature lookup ────────────────────────────────
//
// Maps qbditrace_capi_id_t (uint8_t, but stored as uint8_t in the record) to
// a human-readable name and optionally the matching ApiSignature from the
// known-API tables.  We use a flat switch for O(1) lookup; the compiler will
// typically turn this into a jump table.

const SyscallInterceptCollector::CapiEntry&
SyscallInterceptCollector::capi_entry(uint8_t api_id) {
    using namespace qbditrace;

    // Each entry is { name, nullptr } — we set sig pointers lazily from the
    // known_apis() / known_android_apis() tables in the constructor, but for
    // the simple name lookup we just need the name string here.
    static const CapiEntry kEntries[] = {
        // 0
        { nullptr,                           nullptr },  // UNKNOWN
        // 1–8  Memory
        { "memcpy",                          nullptr },
        { "memmove",                         nullptr },
        { "memset",                          nullptr },
        { "memcmp",                          nullptr },
        { "memchr",                          nullptr },
        { "bcopy",                           nullptr },
        { "bzero",                           nullptr },
        { "memmem",                          nullptr },
        // 9–19 reserved
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr },
        // 20–48 Strings
        { "strlen",          nullptr },  // 20
        { "strnlen",         nullptr },  // 21
        { "strcmp",          nullptr },  // 22
        { "strncmp",         nullptr },  // 23
        { "strcasecmp",      nullptr },  // 24
        { "strncasecmp",     nullptr },  // 25
        { "strcpy",          nullptr },  // 26
        { "strncpy",         nullptr },  // 27
        { "strlcpy",         nullptr },  // 28
        { "strcat",          nullptr },  // 29
        { "strncat",         nullptr },  // 30
        { "strlcat",         nullptr },  // 31
        { "strdup",          nullptr },  // 32
        { "strndup",         nullptr },  // 33
        { "strchr",          nullptr },  // 34
        { "strrchr",         nullptr },  // 35
        { "strstr",          nullptr },  // 36
        { "strtok",          nullptr },  // 37
        { "strtok_r",        nullptr },  // 38
        { "sprintf",         nullptr },  // 39
        { "snprintf",        nullptr },  // 40
        { "sscanf",          nullptr },  // 41
        { "atoi",            nullptr },  // 42
        { "atol",            nullptr },  // 43
        { "atoll",           nullptr },  // 44
        { "strtol",          nullptr },  // 45
        { "strtoll",         nullptr },  // 46
        { "strtoul",         nullptr },  // 47
        { "strtoull",        nullptr },  // 48
        // 49–59 reserved (11 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr },
        // 60–65 Heap alloc
        { "malloc",          nullptr },  // 60
        { "calloc",          nullptr },  // 61
        { "realloc",         nullptr },  // 62
        { "free",            nullptr },  // 63
        { "posix_memalign",  nullptr },  // 64
        { "valloc",          nullptr },  // 65
        // 66–79 reserved (14 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        // 80–91 I/O
        { "fopen",           nullptr },  // 80
        { "fclose",          nullptr },  // 81
        { "fread",           nullptr },  // 82
        { "fwrite",          nullptr },  // 83
        { "fgets",           nullptr },  // 84
        { "fputs",           nullptr },  // 85
        { "read",            nullptr },  // 86
        { "write",           nullptr },  // 87
        { "pread",           nullptr },  // 88
        { "pwrite",          nullptr },  // 89
        { "open",            nullptr },  // 90
        { "close",           nullptr },  // 91
        // 92–99 reserved (8 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr },
        // 100–102 Crypto libc
        { "arc4random",         nullptr },  // 100
        { "arc4random_buf",     nullptr },  // 101
        { "getrandom",          nullptr },  // 102
        // 103–129 reserved (27 entries)
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr }, { nullptr }, { nullptr }, { nullptr },
        { nullptr }, { nullptr },
        // 130–142 iOS platform APIs
        { "CFStringCreateWithCString",      nullptr },  // 130
        { "CFStringCreateWithBytes",        nullptr },  // 131
        { "CFDataCreate",                   nullptr },  // 132
        { "CFDataGetBytePtr",               nullptr },  // 133
        { "CCCrypt",                        nullptr },  // 134
        { "CCHmac",                         nullptr },  // 135
        { "CC_SHA256",                      nullptr },  // 136
        { "CCKeyDerivationPBKDF",           nullptr },  // 137
        { "SecItemCopyMatching",            nullptr },  // 138
        { "SecKeyCreateWithData",           nullptr },  // 139
        { "SecTransformExecute",            nullptr },  // 140
        { "CFURLCreateWithBytes",           nullptr },  // 141
        { "NSURLSession_dataTask",          nullptr },  // 142
    };

    // kEntries covers indices 0..142 (143 entries).
    static constexpr uint8_t kTableSize = 143;

    if (api_id < kTableSize) {
        return kEntries[api_id];
    }

    // For IDs not in the compact table, use a secondary switch for the extended
    // ranges (200+, 280+, 360+, 380+, 400+, 420+, 450+, 470+, 600+, 700+).
    // We return static locals to avoid allocations.

    static const CapiEntry kFallback = { nullptr, nullptr };

    // Extended table via switch.
    switch (static_cast<uint16_t>(api_id)) {
        // 200–207 Android
        case 200: { static CapiEntry e{"strlcpy",               nullptr}; return e; }
        case 201: { static CapiEntry e{"__android_log_print",   nullptr}; return e; }
        case 202: { static CapiEntry e{"__android_log_write",   nullptr}; return e; }
        case 203: { static CapiEntry e{"SharedPreferences_getString", nullptr}; return e; }
        case 204: { static CapiEntry e{"SharedPreferences_putString", nullptr}; return e; }
        case 205: { static CapiEntry e{"IBinder_transact",      nullptr}; return e; }
        case 206: { static CapiEntry e{"dlopen",                nullptr}; return e; }
        case 207: { static CapiEntry e{"dlsym",                 nullptr}; return e; }
        // 280–300 JNI base
        case 280: { static CapiEntry e{"GetStringUTFChars",     nullptr}; return e; }
        case 281: { static CapiEntry e{"ReleaseStringUTFChars", nullptr}; return e; }
        case 282: { static CapiEntry e{"NewStringUTF",          nullptr}; return e; }
        case 283: { static CapiEntry e{"GetStringUTFLength",    nullptr}; return e; }
        case 284: { static CapiEntry e{"GetByteArrayElements",  nullptr}; return e; }
        case 285: { static CapiEntry e{"ReleaseByteArrayElements", nullptr}; return e; }
        case 286: { static CapiEntry e{"GetByteArrayRegion",    nullptr}; return e; }
        case 287: { static CapiEntry e{"SetByteArrayRegion",    nullptr}; return e; }
        case 288: { static CapiEntry e{"NewByteArray",          nullptr}; return e; }
        case 289: { static CapiEntry e{"FindClass",             nullptr}; return e; }
        case 290: { static CapiEntry e{"GetMethodID",           nullptr}; return e; }
        case 291: { static CapiEntry e{"GetStaticMethodID",     nullptr}; return e; }
        case 292: { static CapiEntry e{"CallObjectMethod",      nullptr}; return e; }
        case 293: { static CapiEntry e{"CallStaticObjectMethod",nullptr}; return e; }
        case 294: { static CapiEntry e{"CallVoidMethod",        nullptr}; return e; }
        case 295: { static CapiEntry e{"CallBooleanMethod",     nullptr}; return e; }
        case 296: { static CapiEntry e{"CallIntMethod",         nullptr}; return e; }
        case 297: { static CapiEntry e{"CallLongMethod",        nullptr}; return e; }
        case 298: { static CapiEntry e{"ExceptionCheck",        nullptr}; return e; }
        case 299: { static CapiEntry e{"ExceptionClear",        nullptr}; return e; }
        case 300: { static CapiEntry e{"DefineClass",           nullptr}; return e; }
        // 360–363 pthread
        case 360: { static CapiEntry e{"pthread_create",        nullptr}; return e; }
        case 361: { static CapiEntry e{"pthread_join",          nullptr}; return e; }
        case 362: { static CapiEntry e{"pthread_mutex_lock",    nullptr}; return e; }
        case 363: { static CapiEntry e{"pthread_mutex_unlock",  nullptr}; return e; }
        // 380–385 Network
        case 380: { static CapiEntry e{"socket",                nullptr}; return e; }
        case 381: { static CapiEntry e{"connect",               nullptr}; return e; }
        case 382: { static CapiEntry e{"send",                  nullptr}; return e; }
        case 383: { static CapiEntry e{"recv",                  nullptr}; return e; }
        case 384: { static CapiEntry e{"sendto",                nullptr}; return e; }
        case 385: { static CapiEntry e{"recvfrom",              nullptr}; return e; }
        // 400–401 Encoding
        case 400: { static CapiEntry e{"base64_encode",         nullptr}; return e; }
        case 401: { static CapiEntry e{"base64_decode",         nullptr}; return e; }
        // 420–429 AntiDebug
        case 420: { static CapiEntry e{"ptrace",                nullptr}; return e; }
        case 421: { static CapiEntry e{"sysctl",                nullptr}; return e; }
        case 422: { static CapiEntry e{"prctl",                 nullptr}; return e; }
        case 423: { static CapiEntry e{"getenv",                nullptr}; return e; }
        case 424: { static CapiEntry e{"access",                nullptr}; return e; }
        case 425: { static CapiEntry e{"stat",                  nullptr}; return e; }
        case 426: { static CapiEntry e{"kill",                  nullptr}; return e; }
        case 427: { static CapiEntry e{"getpid",                nullptr}; return e; }
        case 428: { static CapiEntry e{"sysctlbyname",          nullptr}; return e; }
        case 429: { static CapiEntry e{"isatty",                nullptr}; return e; }
        // 450–460 FS / mmap
        case 450: { static CapiEntry e{"rename",                nullptr}; return e; }
        case 451: { static CapiEntry e{"unlink",                nullptr}; return e; }
        case 452: { static CapiEntry e{"mkdir",                 nullptr}; return e; }
        case 453: { static CapiEntry e{"rmdir",                 nullptr}; return e; }
        case 454: { static CapiEntry e{"openat",                nullptr}; return e; }
        case 455: { static CapiEntry e{"pread64",               nullptr}; return e; }
        case 456: { static CapiEntry e{"pwrite64",              nullptr}; return e; }
        case 457: { static CapiEntry e{"lseek",                 nullptr}; return e; }
        case 458: { static CapiEntry e{"mmap",                  nullptr}; return e; }
        case 459: { static CapiEntry e{"munmap",                nullptr}; return e; }
        case 460: { static CapiEntry e{"mprotect",              nullptr}; return e; }
        // 470–526 iOS extended
        case 470: { static CapiEntry e{"CC_SHA224",             nullptr}; return e; }
        case 471: { static CapiEntry e{"CC_SHA384",             nullptr}; return e; }
        case 472: { static CapiEntry e{"CC_SHA512",             nullptr}; return e; }
        case 473: { static CapiEntry e{"CC_SHA256_Init",        nullptr}; return e; }
        case 474: { static CapiEntry e{"CC_SHA256_Update",      nullptr}; return e; }
        case 475: { static CapiEntry e{"CC_SHA256_Final",       nullptr}; return e; }
        case 476: { static CapiEntry e{"CCHmacInit",            nullptr}; return e; }
        case 477: { static CapiEntry e{"CCHmacUpdate",          nullptr}; return e; }
        case 478: { static CapiEntry e{"CCHmacFinal",           nullptr}; return e; }
        case 479: { static CapiEntry e{"CCCryptorCreate",       nullptr}; return e; }
        case 480: { static CapiEntry e{"CCCryptorUpdate",       nullptr}; return e; }
        case 481: { static CapiEntry e{"CCCryptorFinal",        nullptr}; return e; }
        case 482: { static CapiEntry e{"CCCryptorRelease",      nullptr}; return e; }
        case 483: { static CapiEntry e{"CCRandomGenerateBytes", nullptr}; return e; }
        case 484: { static CapiEntry e{"CFStringGetCString",    nullptr}; return e; }
        case 485: { static CapiEntry e{"CFStringGetCStringPtr", nullptr}; return e; }
        case 486: { static CapiEntry e{"CFStringCompare",       nullptr}; return e; }
        case 487: { static CapiEntry e{"CFStringHasPrefix",     nullptr}; return e; }
        case 488: { static CapiEntry e{"CFStringHasSuffix",     nullptr}; return e; }
        case 489: { static CapiEntry e{"CFDataGetBytePtr",      nullptr}; return e; }
        case 490: { static CapiEntry e{"CFDataGetLength",       nullptr}; return e; }
        case 491: { static CapiEntry e{"CFDictionaryGetValue",  nullptr}; return e; }
        case 492: { static CapiEntry e{"CFDictionaryCreate",    nullptr}; return e; }
        case 493: { static CapiEntry e{"CFArrayCreate",         nullptr}; return e; }
        case 494: { static CapiEntry e{"CFArrayGetValueAtIndex",nullptr}; return e; }
        case 495: { static CapiEntry e{"CFNumberCreate",        nullptr}; return e; }
        case 496: { static CapiEntry e{"CFNumberGetValue",      nullptr}; return e; }
        case 497: { static CapiEntry e{"CFPropertyListCreateWithData", nullptr}; return e; }
        case 498: { static CapiEntry e{"CFPropertyListCreateXMLData",  nullptr}; return e; }
        case 499: { static CapiEntry e{"CFRelease",             nullptr}; return e; }
        case 500: { static CapiEntry e{"CFRetain",              nullptr}; return e; }
        case 501: { static CapiEntry e{"SecRandomCopyBytes",    nullptr}; return e; }
        case 502: { static CapiEntry e{"SecKeyCopyExternalRepresentation", nullptr}; return e; }
        case 503: { static CapiEntry e{"SecKeyCreateFromData",  nullptr}; return e; }
        case 504: { static CapiEntry e{"SecKeyEncrypt",         nullptr}; return e; }
        case 505: { static CapiEntry e{"SecKeyDecrypt",         nullptr}; return e; }
        case 506: { static CapiEntry e{"SecCertificateCreateWithData", nullptr}; return e; }
        case 507: { static CapiEntry e{"SecIdentityCopyCertificate", nullptr}; return e; }
        case 508: { static CapiEntry e{"SecTrustEvaluate",      nullptr}; return e; }
        case 509: { static CapiEntry e{"SecItemAdd",            nullptr}; return e; }
        case 510: { static CapiEntry e{"SecItemUpdate",         nullptr}; return e; }
        case 511: { static CapiEntry e{"SecItemDelete",         nullptr}; return e; }
        case 512: { static CapiEntry e{"CFURLGetString",        nullptr}; return e; }
        case 513: { static CapiEntry e{"CFHTTPMessageCreateRequest",  nullptr}; return e; }
        case 514: { static CapiEntry e{"CFHTTPMessageSetHeaderFieldValue", nullptr}; return e; }
        case 515: { static CapiEntry e{"CFHTTPMessageSetBody",  nullptr}; return e; }
        case 516: { static CapiEntry e{"dispatch_async",        nullptr}; return e; }
        case 517: { static CapiEntry e{"dispatch_sync",         nullptr}; return e; }
        case 518: { static CapiEntry e{"dispatch_after",        nullptr}; return e; }
        case 519: { static CapiEntry e{"dispatch_once",         nullptr}; return e; }
        case 520: { static CapiEntry e{"NSString_UTF8String",   nullptr}; return e; }
        case 521: { static CapiEntry e{"NSString_dataUsingEncoding", nullptr}; return e; }
        case 522: { static CapiEntry e{"NSData_bytes",          nullptr}; return e; }
        case 523: { static CapiEntry e{"b64_encode",            nullptr}; return e; }
        case 524: { static CapiEntry e{"b64_decode",            nullptr}; return e; }
        case 525: { static CapiEntry e{"iconv_open",            nullptr}; return e; }
        case 526: { static CapiEntry e{"iconv",                 nullptr}; return e; }
        // 600–644 Android extended
        case 600: { static CapiEntry e{"EVP_EncryptInit_ex",    nullptr}; return e; }
        case 601: { static CapiEntry e{"EVP_EncryptUpdate",     nullptr}; return e; }
        case 602: { static CapiEntry e{"EVP_EncryptFinal_ex",   nullptr}; return e; }
        case 603: { static CapiEntry e{"EVP_DecryptInit_ex",    nullptr}; return e; }
        case 604: { static CapiEntry e{"EVP_DecryptUpdate",     nullptr}; return e; }
        case 605: { static CapiEntry e{"EVP_DecryptFinal_ex",   nullptr}; return e; }
        case 606: { static CapiEntry e{"EVP_DigestInit_ex",     nullptr}; return e; }
        case 607: { static CapiEntry e{"EVP_DigestUpdate",      nullptr}; return e; }
        case 608: { static CapiEntry e{"EVP_DigestFinal_ex",    nullptr}; return e; }
        case 609: { static CapiEntry e{"HMAC_CTX_new",          nullptr}; return e; }
        case 610: { static CapiEntry e{"HMAC_Init_ex",          nullptr}; return e; }
        case 611: { static CapiEntry e{"HMAC_Update",           nullptr}; return e; }
        case 612: { static CapiEntry e{"HMAC_Final",            nullptr}; return e; }
        case 613: { static CapiEntry e{"SHA256_Init",           nullptr}; return e; }
        case 614: { static CapiEntry e{"SHA256_Update",         nullptr}; return e; }
        case 615: { static CapiEntry e{"SHA256_Final",          nullptr}; return e; }
        case 616: { static CapiEntry e{"AES_set_encrypt_key",   nullptr}; return e; }
        case 617: { static CapiEntry e{"AES_set_decrypt_key",   nullptr}; return e; }
        case 618: { static CapiEntry e{"AES_cbc_encrypt",       nullptr}; return e; }
        case 619: { static CapiEntry e{"RSA_sign",              nullptr}; return e; }
        case 620: { static CapiEntry e{"RSA_verify",            nullptr}; return e; }
        case 621: { static CapiEntry e{"RAND_bytes",            nullptr}; return e; }
        case 622: { static CapiEntry e{"RAND_priv_bytes",       nullptr}; return e; }
        case 623: { static CapiEntry e{"EVP_md5",               nullptr}; return e; }
        case 624: { static CapiEntry e{"EVP_sha1",              nullptr}; return e; }
        case 625: { static CapiEntry e{"EVP_sha256",            nullptr}; return e; }
        case 626: { static CapiEntry e{"BIO_new_mem_buf",       nullptr}; return e; }
        case 627: { static CapiEntry e{"PEM_read_bio_RSAPublicKey", nullptr}; return e; }
        case 628: { static CapiEntry e{"Base64_encode",         nullptr}; return e; }
        case 629: { static CapiEntry e{"Base64_decode",         nullptr}; return e; }
        case 630: { static CapiEntry e{"sqlite3_open",          nullptr}; return e; }
        case 631: { static CapiEntry e{"sqlite3_prepare_v2",    nullptr}; return e; }
        case 632: { static CapiEntry e{"sqlite3_step",          nullptr}; return e; }
        case 633: { static CapiEntry e{"sqlite3_column_text",   nullptr}; return e; }
        case 634: { static CapiEntry e{"sqlite3_close",         nullptr}; return e; }
        case 635: { static CapiEntry e{"sqlite3_exec",          nullptr}; return e; }
        case 636: { static CapiEntry e{"Keymaster_importKey",   nullptr}; return e; }
        case 637: { static CapiEntry e{"Keymaster_exportKey",   nullptr}; return e; }
        case 638: { static CapiEntry e{"Keymaster_finish",      nullptr}; return e; }
        case 639: { static CapiEntry e{"art_InvokeVirtual",     nullptr}; return e; }
        case 640: { static CapiEntry e{"art_Thread_Current",    nullptr}; return e; }
        case 641: { static CapiEntry e{"getaddrinfo",           nullptr}; return e; }
        case 642: { static CapiEntry e{"getnameinfo",           nullptr}; return e; }
        case 643: { static CapiEntry e{"inet_aton",             nullptr}; return e; }
        case 644: { static CapiEntry e{"inet_ntop",             nullptr}; return e; }
        // 700–726 JNI extended
        case 700: { static CapiEntry e{"GetIntField",           nullptr}; return e; }
        case 701: { static CapiEntry e{"GetLongField",          nullptr}; return e; }
        case 702: { static CapiEntry e{"GetObjectField",        nullptr}; return e; }
        case 703: { static CapiEntry e{"SetObjectField",        nullptr}; return e; }
        case 704: { static CapiEntry e{"GetFieldID",            nullptr}; return e; }
        case 705: { static CapiEntry e{"GetStaticFieldID",      nullptr}; return e; }
        case 706: { static CapiEntry e{"GetStringUTFRegion",    nullptr}; return e; }
        case 707: { static CapiEntry e{"GetArrayLength",        nullptr}; return e; }
        case 708: { static CapiEntry e{"NewObjectArray",        nullptr}; return e; }
        case 709: { static CapiEntry e{"GetObjectArrayElement", nullptr}; return e; }
        case 710: { static CapiEntry e{"SetObjectArrayElement", nullptr}; return e; }
        case 711: { static CapiEntry e{"NewIntArray",           nullptr}; return e; }
        case 712: { static CapiEntry e{"GetIntArrayElements",   nullptr}; return e; }
        case 713: { static CapiEntry e{"ReleaseIntArrayElements",nullptr}; return e; }
        case 714: { static CapiEntry e{"CallStaticIntMethod",   nullptr}; return e; }
        case 715: { static CapiEntry e{"CallStaticBooleanMethod",nullptr}; return e; }
        case 716: { static CapiEntry e{"NewObject",             nullptr}; return e; }
        case 717: { static CapiEntry e{"IsInstanceOf",          nullptr}; return e; }
        case 718: { static CapiEntry e{"NewGlobalRef",          nullptr}; return e; }
        case 719: { static CapiEntry e{"DeleteGlobalRef",       nullptr}; return e; }
        case 720: { static CapiEntry e{"DeleteLocalRef",        nullptr}; return e; }
        case 721: { static CapiEntry e{"PushLocalFrame",        nullptr}; return e; }
        case 722: { static CapiEntry e{"PopLocalFrame",         nullptr}; return e; }
        case 723: { static CapiEntry e{"GetVersion",            nullptr}; return e; }
        case 724: { static CapiEntry e{"MonitorEnter",          nullptr}; return e; }
        case 725: { static CapiEntry e{"MonitorExit",           nullptr}; return e; }
        case 726: { static CapiEntry e{"GetJavaVM",             nullptr}; return e; }
        default: break;
    }
    return kFallback;
}

void SyscallInterceptCollector::on_svc(uint64_t inst_id, const SvcView& svc) {
    // Build an InterceptedCall for a raw syscall record.
    InterceptedCall call;
    call.inst_id      = inst_id;
    call.call_site_pc = svc.pc;
    call.callee_pc    = 0;  // no callee address for syscalls
    call.callee_name  = fmt::format("syscall_{}", svc.syscall_no);
    call.category     = ApiCategory::Syscall;
    call.svc_flags    = 0;

    // Copy up to 6 syscall arguments.
    call.arg_count = 6;
    for (uint8_t i = 0; i < 6 && i < static_cast<uint8_t>(call.raw_args.size()); ++i) {
        call.raw_args[i] = svc.args[i];
    }

    call.decoded_summary = fmt::format("syscall #{}: x0=0x{:x} x1=0x{:x} x2=0x{:x}",
        svc.syscall_no, svc.args[0], svc.args[1], svc.args[2]);

    size_t idx = result_.calls.size();
    result_.by_callee[call.callee_name].push_back(idx);
    result_.by_category[call.category].push_back(idx);
    result_.calls.push_back(std::move(call));
}

void SyscallInterceptCollector::on_capicall(uint64_t inst_id, const CapiCallView& capi) {
    // Look up the API name from the static entry table.
    const CapiEntry& entry = capi_entry(capi.api_id);
    const char* api_name = entry.name ? entry.name : nullptr;

    // Suppress duplicate: if this callee was already handled, skip it.
    // (The event-based on_event may also fire for the same call site.)
    auto seen_it = capicall_seen_.find(capi.target);
    if (seen_it != capicall_seen_.end()) {
        // Already seen at a different inst_id — update dedup window.
        if (seen_it->second + 4096 > inst_id) {
            return;  // Duplicate within window.
        }
    }
    capicall_seen_[capi.target] = inst_id;

    InterceptedCall call;
    call.inst_id           = inst_id;
    call.call_site_pc      = capi.pc;
    call.callee_pc         = capi.target;
    call.from_capicall_record = true;

    // Determine name: from table first, else synthetic.
    if (api_name) {
        call.callee_name = api_name;
    } else {
        call.callee_name = fmt::format("sub_{:x}", capi.target);
    }

    // Determine category from signature table.
    call.category = ApiCategory::Custom;
    if (entry.sig) {
        call.category = entry.sig->category;
    } else if (api_name) {
        // Try to match against our known API tables.
        auto ait = api_by_name_.find(call.callee_name);
        if (ait != api_by_name_.end() && ait->second) {
            call.category = ait->second->category;
        }
    }

    // Copy raw args from CapiCallView.
    call.arg_count = std::min<uint8_t>(capi.arg_count, static_cast<uint8_t>(call.raw_args.size()));
    for (uint8_t i = 0; i < call.arg_count; ++i) {
        call.raw_args[i] = capi.args[i];
    }

    // Copy captured inline strings from the record.
    for (uint8_t si = 0; si < capi.str_count; ++si) {
        auto sv = capi.str_at(si);
        CapturedString cs;
        cs.arg_idx   = sv.arg_idx;
        cs.truncated = sv.is_truncated();
        cs.binary    = sv.is_binary();
        if (sv.data && sv.str_len > 0) {
            cs.value.assign(sv.data, sv.str_len);
        }
        call.captured_strings.push_back(std::move(cs));
    }

    // Attach ObjC context if recent.
    if (!last_objc_context_.empty() &&
        cur_inst_id_ - last_objc_inst_id_ < 100000) {
        call.objc_context = last_objc_context_;
    }

    // Build decoded summary — prefer captured strings.
    if (!call.captured_strings.empty()) {
        std::string summary = call.callee_name + ": ";
        for (const auto& cs : call.captured_strings) {
            summary += fmt::format("x{}=\"{}\"{}  ",
                cs.arg_idx,
                cs.value.substr(0, std::min<size_t>(cs.value.size(), 64)),
                cs.truncated ? "…" : "");
        }
        call.decoded_summary = std::move(summary);
    } else if (entry.sig) {
        decode_known_api(call, *entry.sig);
    } else {
        auto ait = api_by_name_.find(call.callee_name);
        if (ait != api_by_name_.end() && ait->second) {
            decode_known_api(call, *ait->second);
        } else {
            call.decoded_summary = call.callee_name +
                fmt::format(": x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
                    call.raw_args[0], call.raw_args[1],
                    call.raw_args[2], call.raw_args[3]);
        }
    }

    size_t idx = result_.calls.size();
    result_.by_callee[call.callee_name].push_back(idx);
    result_.by_category[call.category].push_back(idx);
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
        case ApiCategory::JNI:               return "JNI";
        case ApiCategory::MemoryOps:         return "MemoryOps";
        case ApiCategory::StringOps:         return "StringOps";
        case ApiCategory::HeapAlloc:         return "HeapAlloc";
        case ApiCategory::FileIO:            return "FileIO";
        case ApiCategory::Network:           return "Network";
        case ApiCategory::AntiDebug:         return "AntiDebug";
        case ApiCategory::Threading:         return "Threading";
        case ApiCategory::Encoding:          return "Encoding";
        case ApiCategory::Compression:       return "Compression";
        case ApiCategory::SQLite:            return "SQLite";
        case ApiCategory::DynLink:           return "DynLink";
        case ApiCategory::ObjCRuntime:       return "ObjCRuntime";
        case ApiCategory::MemoryMap:         return "MemoryMap";
        case ApiCategory::Syscall:           return "Syscall";
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
