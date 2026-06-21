#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/objc_pass.h"
#include "io/trace_reader.h"
#include "io/code_table.h"
#include "core/memory_model.h"

#include <fmt/core.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cstring>

namespace tenet {

using json = nlohmann::json;

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

const std::vector<ApiSignature>& SyscallInterceptPass::known_apis() {
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

// ─── Memory reading helper ────────────────────────────────────────────────

std::vector<uint8_t> SyscallInterceptPass::read_memory_at(
    PassContext& ctx, uint64_t addr, uint32_t max_bytes, uint64_t at_inst_id)
{
    if (addr == 0 || max_bytes == 0) return {};

    std::vector<uint8_t> result;
    result.reserve(max_bytes);

    auto& memory = ctx.memory();
    uint64_t cur = addr;
    uint32_t remaining = max_bytes;

    while (remaining > 0) {
        uint8_t chunk = static_cast<uint8_t>(std::min<uint32_t>(remaining, 16));
        auto mem_res = memory.read(cur, chunk, at_inst_id);

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

void SyscallInterceptPass::decode_known_api(InterceptedCall& call,
                                             const ApiSignature& sig,
                                             PassContext& ctx)
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
        return read_memory_at(ctx, ptr, cap, call.inst_id);
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
    const auto& hdr = reader.header();
    const auto& code_table = ctx.code_table();

    // Optional: get ObjC messages for context annotation.
    const ObjcResult* objc = ctx.try_require<ObjcResult>("objc");

    SyscallInterceptResult result;

    // ── Build known API name → signature lookup ───────────────────────────
    const auto& apis = known_apis();
    std::unordered_map<std::string, const ApiSignature*> api_by_name;
    for (const auto& sig : apis) {
        api_by_name[sig.name] = &sig;
    }
    // Add user-specified extra names (matched as prefix, no decode).
    for (const auto& extra : config_.extra_api_names) {
        if (api_by_name.find(extra) == api_by_name.end()) {
            api_by_name[extra] = nullptr;  // nullptr = no signature
        }
    }

    // ── Track register state with a lightweight tracker ──────────────────
    // We maintain a rolling register state (x0-x7) by replaying reg_diffs.
    // This is cheaper than using RegisterFile (no RocksDB, no anchor replay).
    // We only need x0-x7 for ABI argument extraction.
    constexpr uint32_t MAX_ARG_REGS = 8;
    uint64_t cur_regs[MAX_ARG_REGS] = {};
    bool regs_valid = false;

    // Track last ObjC message for context annotation.
    uint64_t last_objc_inst_id = 0;
    std::string last_objc_context;

    uint64_t cur_inst_id = 0;
    uint64_t total_calls = 0;

    ctx.progress(0.01f, "syscall_intercept: scanning trace...");

    reader.advise_sequential();
    for (auto it = reader.begin(); it != reader.end(); ++it) {
        auto rec = *it;

        if (ctx.cancelled()) {
            reader.advise_random();
            return PassResult::failed("syscall_intercept: cancelled");
        }

        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            // Apply reg_diffs to maintain x0-x7 state.
            for (uint8_t r = 0; r < inst.reg_diff_count; ++r) {
                auto diff = inst.reg_diff(r);
                if (diff.index < MAX_ARG_REGS) {
                    cur_regs[diff.index] = diff.value;
                    regs_valid = true;
                }
            }
            cur_inst_id++;

        } else if (rec.kind == RecordKind::Objc) {
            // Track ObjC context for annotation.
            auto objc_rec = rec.as_objc();
            last_objc_inst_id = cur_inst_id;

            std::string cls_name(objc_rec.cls ? objc_rec.cls : "");
            // Try to resolve selector from symbol table.
            std::string sel_name;
            if (objc_rec.sel != 0) {
                auto s = code_table.image_read_cstring(objc_rec.sel, 128);
                if (s) sel_name = *s;
            }
            if (sel_name.empty()) {
                // Fallback: use previously resolved selector from ObjcResult.
                if (objc) {
                    for (auto rit = objc->messages.rbegin(); rit != objc->messages.rend(); ++rit) {
                        if (rit->inst_id <= cur_inst_id) {
                            sel_name = rit->selector_name;
                            if (cls_name.empty()) cls_name = rit->class_name;
                            break;
                        }
                    }
                }
            }
            if (!cls_name.empty() || !sel_name.empty()) {
                last_objc_context = '[' + cls_name + ' ' + sel_name + ']';
            }

        } else if (rec.kind == RecordKind::Event) {
            // XFER_CALL events: callee PC is outside the traced module.
            auto ev = rec.as_event();

            // event type: XFER_CALL = EventKind value (check TraceFormat.h)
            // qbditrace defines: QBDITRACE_EV_SEQ_ENTRY=0, XFER_CALL=2, XFER_RETURN=3
            // We accept both types 2 (XFER_CALL) to catch cross-module calls.
            if (ev.event != 2 && ev.event != 0) continue;

            uint64_t callee_pc = ev.addr;
            if (callee_pc == 0) continue;

            // ── Resolve callee name ────────────────────────────────────────
            // First, check if callee is inside the traced module range.
            // If it's outside, attempt symbol name resolution.
            // The CodeTable doesn't have external symbol names directly.
            // We resolve by checking for known function name patterns in the
            // callee address region (via image_read_cstring on export stub).
            // For now: we match by comparing known API addresses if available.
            // Without a symbol table for external dylibs, we use heuristic:
            // look for a CODE record or function name from the code_table
            // at the callee PC.
            std::string callee_name;

            // Try code_table image read at callee PC as a symbol (works when
            // the ImageFallback is loaded and contains the Mach-O symbol table).
            // Since we don't have an external dylib, this may not resolve.
            // Fall back to checking whether callee_pc looks like it's in a
            // known dylib range by examining if code_table has it.
            if (!code_table.opcode_at(callee_pc).has_value()) {
                // The callee is NOT in the traced module — it's a cross-library call.
                // For well-known iOS APIs, the callee symbol might appear in the
                // traced module's import stub section. Try reading a string near
                // the call target.
                auto sym = code_table.image_read_cstring(callee_pc, 64);
                if (sym) callee_name = *sym;
            }

            // ── Match against known APIs ──────────────────────────────────
            const ApiSignature* sig = nullptr;
            if (!callee_name.empty()) {
                auto ait = api_by_name.find(callee_name);
                if (ait != api_by_name.end()) {
                    sig = ait->second;
                } else {
                    // Prefix match for user-specified extra names.
                    for (const auto& [name, s] : api_by_name) {
                        if (callee_name.rfind(name, 0) == 0) {
                            sig = s;
                            callee_name = name;
                            break;
                        }
                    }
                }
            }

            // If we have a signature match OR user requested all unresolved.
            if (sig == nullptr && !config_.intercept_unresolved) continue;
            if (sig == nullptr && callee_name.empty()) continue;

            if (!regs_valid) continue;

            // ── Build the intercepted call record ─────────────────────────
            InterceptedCall call;
            call.inst_id       = cur_inst_id;
            call.call_site_pc  = ev.site;
            call.callee_pc     = callee_pc;
            call.callee_name   = callee_name.empty() ?
                                     fmt::format("sub_{:x}", callee_pc) : callee_name;
            call.category      = sig ? sig->category : ApiCategory::Custom;
            std::memcpy(call.raw_args.data(), cur_regs, sizeof(uint64_t) * MAX_ARG_REGS);
            call.arg_count     = sig ? sig->arg_count : MAX_ARG_REGS;

            // Attach ObjC context if recent.
            if (!last_objc_context.empty() &&
                cur_inst_id - last_objc_inst_id < 100000) {
                call.objc_context = last_objc_context;
            }

            // Decode arguments for known APIs.
            if (sig) {
                decode_known_api(call, *sig, ctx);
            } else {
                call.decoded_summary = call.callee_name +
                    fmt::format(": x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
                                cur_regs[0], cur_regs[1], cur_regs[2], cur_regs[3]);
            }

            // ── Index and store ───────────────────────────────────────────
            size_t hit_idx = result.calls.size();
            result.by_callee[call.callee_name].push_back(hit_idx);
            result.by_category[call.category].push_back(hit_idx);
            result.calls.push_back(std::move(call));
            total_calls++;
        }

        // Progress every 100K records
        if (cur_inst_id % 100000 == 0 && cur_inst_id > 0) {
            ctx.progress(std::min(0.99f,
                static_cast<float>(cur_inst_id) / static_cast<float>(
                    std::max<uint64_t>(1, reader.file_size() / 64))));
        }
    }
    reader.advise_random();

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
        case ApiCategory::Compression:       return "Compression";
        case ApiCategory::CocoaFoundation:   return "Foundation";
        case ApiCategory::LibSystem:         return "libSystem";
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

}  // namespace tenet
