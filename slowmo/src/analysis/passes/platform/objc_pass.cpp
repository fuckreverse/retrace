#include "analysis/passes/platform/objc_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"
#include "infra/string_resolver.h"
#include "common/byte_codec.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>
#include <sys/mman.h>

namespace tenet {

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Read a C string from memory at the given address and inst_id.
/// Uses read_region() for bulk reads (one RocksDB seek per 32-byte chunk)
/// instead of per-byte byte_at() calls.
/// Returns the string content or a hex fallback if unreadable.
static std::string read_cstring_from_memory(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id, size_t max_len = 128)
{
    if (addr == 0) return "(null)";

    static constexpr size_t CHUNK = 64;
    std::string result;
    result.reserve(32);

    for (size_t offset = 0; offset < max_len; offset += CHUNK) {
        size_t to_read = std::min(CHUNK, max_len - offset);
        auto region = mem.read_region(addr + offset, to_read, at_inst_id);

        for (size_t i = 0; i < to_read; ++i) {
            if (!region.known[i]) goto done;
            uint8_t c = region.data[i];
            if (c == 0) goto done;        // NUL terminator
            if (c < 0x20 || c > 0x7E) goto done;  // non-printable — stop
            result.push_back(static_cast<char>(c));
        }
    }
done:
    if (result.empty()) {
        return fmt::format("0x{:x}", addr);
    }
    return result;
}

/// Extract a class name from the 48-byte cls buffer in ObjcView.
static std::string extract_class_name(const char* cls_buf) {
    // cls is a 48-byte buffer containing a NUL-terminated C string
    std::string name;
    for (size_t i = 0; i < 48 && cls_buf[i] != '\0'; ++i) {
        name.push_back(cls_buf[i]);
    }
    return name;
}

/// Count the number of colons in a selector name to determine arg count.
static uint8_t count_selector_args(const std::string& sel_name) {
    uint8_t count = 0;
    for (char c : sel_name) {
        if (c == ':') count++;
    }
    return count;
}

/// Heuristic: determine if an address value is likely a valid userspace pointer.
/// Skips small integers, tagged pointers with non-zero top bits, kernel addresses,
/// and obviously misaligned values for string pointers.
static inline bool is_likely_pointer(uint64_t addr) {
    // NULL or small integer
    if (addr < 0x1000) return false;
    // Kernel addresses (top bit set on AArch64)
    if (addr >= 0xFFFF000000000000ULL) return false;
    // Tagged pointer pattern (ObjC tagged pointers have top nibble set)
    // These are immediate values, not real heap pointers to strings
    if ((addr >> 60) != 0 && (addr >> 60) != 1) return false;
    return true;
}

/// C-string dereference result. Only an unreadable byte is eligible for a
/// latest-observed fallback; non-printable content and the length cap preserve
/// the existing best-effort behavior without changing the time point.
struct DerefStringResult {
    std::optional<std::string> value;
    bool nul_terminated = false;
    bool unreadable = false;
};

/// Try to dereference a pointer value as a printable C string from memory.
/// Uses read_region() for bulk reads instead of per-byte byte_at() calls.
static DerefStringResult try_deref_string(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id)
{
    if (!is_likely_pointer(addr)) return {};

    static constexpr size_t MAX_LEN = 256;
    static constexpr size_t CHUNK = 64;
    std::string result;
    result.reserve(32);

    for (size_t offset = 0; offset < MAX_LEN; offset += CHUNK) {
        size_t to_read = std::min(CHUNK, MAX_LEN - offset);
        auto region = mem.read_region(addr + offset, to_read, at_inst_id);

        for (size_t i = 0; i < to_read; ++i) {
            if (!region.known[i]) {
                return {result.size() >= 2 ? std::optional<std::string>(std::move(result))
                                           : std::nullopt, false, true};
            }
            uint8_t c = region.data[i];
            if (c == 0) {
                return {result.size() >= 2 ? std::optional<std::string>(std::move(result))
                                           : std::nullopt, true, false};
            }
            if (c < 0x20 || c > 0x7E) {
                return {result.size() >= 2 ? std::optional<std::string>(std::move(result))
                                           : std::nullopt, false, false};
            }
            result.push_back(static_cast<char>(c));
        }
    }
    return {result.size() >= 2 ? std::optional<std::string>(std::move(result))
                               : std::nullopt, false, false};
}

/// Try to decode a 64-bit register value as a little-endian ASCII string.
static std::optional<std::string> try_decode_reg_ascii(uint64_t value) {
    uint8_t bytes[8];
    std::memcpy(bytes, &value, 8);
    std::string str;
    for (int b = 0; b < 8; b++) {
        if (bytes[b] >= 0x20 && bytes[b] <= 0x7e) {
            str.push_back(static_cast<char>(bytes[b]));
        } else if (bytes[b] == 0) {
            break;  // NUL terminator
        } else {
            break;  // Non-printable
        }
    }
    if (str.size() < 4) return std::nullopt;
    return str;
}

static const char* selector_source_name(ObjcSelectorSource source) {
    switch (source) {
    case ObjcSelectorSource::Inline: return "inline";
    case ObjcSelectorSource::Image:  return "image";
    case ObjcSelectorSource::Memory: return "memory";
    case ObjcSelectorSource::Hex:    return "hex";
    }
    return "hex";
}

static const char* selector_resolution_name(ObjcSelectorResolution resolution) {
    switch (resolution) {
    case ObjcSelectorResolution::Resolved:   return "resolved";
    case ObjcSelectorResolution::Truncated:  return "truncated";
    case ObjcSelectorResolution::ReadFailed: return "read_failed";
    case ObjcSelectorResolution::Unresolved: return "unresolved";
    }
    return "unresolved";
}

static const char* class_resolution_name(ObjcClassResolution resolution) {
    return resolution == ObjcClassResolution::Resolved ? "resolved" : "unknown";
}

static const char* return_kind_name(ObjcReturnKind kind) {
    switch (kind) {
    case ObjcReturnKind::None:     return "none";
    case ObjcReturnKind::X0:       return "x0";
    case ObjcReturnKind::StretRaw: return "stret_raw";
    }
    return "none";
}

static const char* return_string_time_name(ObjcReturnStringTime time) {
    switch (time) {
    case ObjcReturnStringTime::AtReturn:       return "at_return";
    case ObjcReturnStringTime::LatestObserved: return "latest";
    }
    return "at_return";
}

// ─── ObjcResult::to_json ─────────────────────────────────────────────────

nlohmann::json ObjcResult::to_json() const {
    using json = nlohmann::json;

    json j;
    j["total_messages"] = total_messages();
    j["unique_classes"] = unique_classes();

    // Messages array
    json msgs = json::array();
    for (const auto& msg : messages) {
        json m;
        m["inst_id"] = msg.inst_id;
        m["pc"] = fmt::format("0x{:x}", msg.pc);
        m["receiver"] = fmt::format("0x{:x}", msg.receiver);
        m["selector"] = fmt::format("0x{:x}", msg.selector);
        m["class_name"] = msg.class_name;
        m["class_resolution"] = class_resolution_name(msg.class_resolution);
        m["selector_name"] = msg.selector_name;
        m["selector_source"] = selector_source_name(msg.selector_source);
        m["selector_resolution"] = selector_resolution_name(msg.selector_resolution);
        m["variant"] = msg.variant;
        m["is_stret"] = msg.is_stret;
        m["return_kind"] = return_kind_name(msg.return_kind);

        // Arguments
        if (msg.arg_count > 0) {
            json args_arr = json::array();
            uint8_t n = std::min(msg.arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));
            for (uint8_t k = 0; k < n; ++k) {
                json a;
                a["reg"] = fmt::format("x{}", k + 2);
                a["value"] = fmt::format("0x{:x}", msg.args[k].value);
                if (msg.args[k].deref_str.has_value()) {
                    a["string"] = *msg.args[k].deref_str;
                }
                args_arr.push_back(std::move(a));
            }
            m["arguments"] = std::move(args_arr);
        }

        // Return value
        if (msg.has_return) {
            json ret;
            ret["value"] = fmt::format("0x{:x}", msg.return_value);
            ret["inst_id"] = msg.return_inst_id;
            if (msg.return_deref_str.has_value()) {
                ret["string"] = *msg.return_deref_str;
                ret["string_time"] = return_string_time_name(msg.return_string_time);
            }
            m["return"] = std::move(ret);
        }

        msgs.push_back(std::move(m));
    }
    j["messages"] = std::move(msgs);

    // Classes summary (sorted by message_count descending)
    std::vector<const ObjcClassInfo*> sorted_classes;
    sorted_classes.reserve(classes.size());
    for (const auto& [name, info] : classes) {
        sorted_classes.push_back(&info);
    }
    std::sort(sorted_classes.begin(), sorted_classes.end(),
              [](const ObjcClassInfo* a, const ObjcClassInfo* b) {
                  return a->message_count > b->message_count;
              });

    json cls_arr = json::array();
    for (const auto* ci : sorted_classes) {
        json c;
        c["name"] = ci->name;
        c["message_count"] = ci->message_count;
        c["selectors_seen"] = ci->selectors_seen;
        cls_arr.push_back(std::move(c));
    }
    j["classes"] = std::move(cls_arr);

    return j;
}

// ─── ObjcResult serialization (for blob cache) ───────────────────────────
//
// NOTE: an earlier sequential TraceCollector-based implementation
// ("ObjcCollector") used to live here.  ObjcPass::run() has since been
// rewritten to use a raw-pointer fast scan (see below) that bypasses
// TraceScanEngine/InstView entirely for ~1000x fewer virtual calls on large
// traces.  The old collector class was never instantiated anywhere in the
// codebase after that rewrite and has been removed as dead code; the
// raw-pointer scan below is the sole implementation of the ObjC parsing
// logic (class/selector resolution, arg/return extraction, caching).

namespace {

static constexpr uint32_t OBJC_BLOB_MAGIC   = 0x4F424A43u;  // "OBJC"
static constexpr uint32_t OBJC_BLOB_VERSION  = 3u;

std::string objc_serialize(const ObjcResult& res) {
    ByteWriter w;

    w.u32(OBJC_BLOB_MAGIC);
    w.u32(OBJC_BLOB_VERSION);
    w.u64(static_cast<uint64_t>(res.messages.size()));

    for (const auto& msg : res.messages) {
        w.u64(msg.inst_id);
        w.u64(msg.pc);
        w.u64(msg.receiver);
        w.u64(msg.selector);
        w.str(msg.class_name);
        w.str(msg.selector_name);
        w.u8(static_cast<uint8_t>(msg.class_resolution));
        w.u8(static_cast<uint8_t>(msg.selector_source));
        w.u8(static_cast<uint8_t>(msg.selector_resolution));
        w.u8(msg.variant);
        w.u8(msg.arg_count);
        w.u8(msg.is_stret ? 1 : 0);

        uint8_t n = std::min(msg.arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));
        for (uint8_t k = 0; k < n; ++k) {
            w.u64(msg.args[k].value);
            w.opt_str(msg.args[k].deref_str);
        }

        w.u8(msg.has_return ? 1 : 0);
        w.u8(static_cast<uint8_t>(msg.return_kind));
        if (msg.has_return) {
            w.u64(msg.return_value);
            w.u64(msg.return_inst_id);
            w.opt_str(msg.return_deref_str);
            w.u8(static_cast<uint8_t>(msg.return_string_time));
        }
    }

    return std::move(w).take();
}

bool objc_deserialize(const std::string& blob, ObjcResult& out) {
    ByteReader r(blob.data(), blob.size());

    if (r.u32() != OBJC_BLOB_MAGIC)   return false;
    if (r.u32() != OBJC_BLOB_VERSION) return false;

    uint64_t n_msgs = r.u64();
    out.messages.reserve(static_cast<size_t>(n_msgs));

    for (uint64_t i = 0; i < n_msgs; i++) {
        ObjcMessage msg;
        msg.inst_id       = r.u64();
        msg.pc            = r.u64();
        msg.receiver      = r.u64();
        msg.selector      = r.u64();
        r.str(msg.class_name);
        r.str(msg.selector_name);
        msg.class_resolution = static_cast<ObjcClassResolution>(r.u8());
        msg.selector_source = static_cast<ObjcSelectorSource>(r.u8());
        msg.selector_resolution = static_cast<ObjcSelectorResolution>(r.u8());
        msg.variant       = r.u8();
        msg.arg_count     = r.u8();
        msg.is_stret      = r.u8() != 0;

        uint8_t n = std::min(msg.arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));
        for (uint8_t k = 0; k < n; ++k) {
            msg.args[k].value = r.u64();
            r.opt_str(msg.args[k].deref_str);
        }

        uint8_t has_ret = r.u8();
        msg.has_return = (has_ret != 0);
        msg.return_kind = static_cast<ObjcReturnKind>(r.u8());
        if (msg.has_return) {
            msg.return_value = r.u64();
            msg.return_inst_id = r.u64();
            r.opt_str(msg.return_deref_str);
            msg.return_string_time = static_cast<ObjcReturnStringTime>(r.u8());
        }

        // Rebuild class info
        size_t msg_idx = out.messages.size();
        auto& cls_info = out.classes[msg.class_name];
        if (cls_info.name.empty()) cls_info.name = msg.class_name;
        cls_info.message_count++;
        cls_info.message_indices.push_back(msg_idx);
        cls_info.selectors_seen.insert(msg.selector_name);

        out.by_pc[msg.pc].push_back(msg_idx);
        out.messages.push_back(std::move(msg));
    }

    return r.ok();
}

/// Compute record size from raw pointer — now delegates to the shared
/// ::tenet::raw_record_size from trace_reader.h (handles all 8 record types
/// and all 4 INST header formats: v4, v5, v7, v7+v5).
inline size_t objc_raw_record_size(const uint8_t* ptr, uint32_t num_gpr,
                                   bool is_v5, bool is_v6, bool is_v7, bool is_v8) {
    return raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
}

}  // anonymous namespace

// ─── ObjcPass::run — raw pointer fast scan ───────────────────────────────

PassResult ObjcPass::run(PassContext& ctx) {
    auto& reader  = ctx.reader();

    // ObjC messages only exist on Darwin targets.  Skip on Android/Linux.
    if (!is_darwin(reader.header().target_os) &&
        reader.header().target_os != TargetOS::Unknown) {
        return PassResult::success(ObjcResult{});
    }

    auto& index   = ctx.index();
    auto& memory  = ctx.memory();
    auto& regfile = ctx.regfile();
    auto& code_table = ctx.code_table();
    auto& string_resolver = ctx.string_resolver();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    // ─── Fast path: load from persisted cache ─────────────────────────────
    const bool has_filter = !class_filter_.empty() || !selector_filter_.empty();
    if (!has_filter && range.is_full_trace()) {
        std::string blob;
        if (index.load_pass_blob("objc", blob)) {
            ObjcResult cached;
            if (objc_deserialize(blob, cached)) {
                ctx.progress(1.0f, fmt::format(
                    "ObjC: {} messages, {} unique classes (from cache)",
                    cached.total_messages(), cached.unique_classes()));
                return PassResult::success(std::move(cached));
            }
        }
    }

    ctx.progress(0.0f, "ObjC: scanning trace (fast scan)...");

    // ─── Raw pointer fast scan ────────────────────────────────────────────
    // Instead of using TraceScanEngine (which constructs InstView for every
    // INST record and calls on_inst() 19M+ times), we directly iterate the
    // raw trace bytes, only stopping to process OBJC records (kind=5).
    // For ~20M insts but only ~1500 OBJC records, this avoids >99.99% of
    // virtual function call overhead.

    const uint32_t num_gpr = reader.header().num_gpr;
    const bool is_v5 = (reader.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    const bool is_v6 = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    const bool is_v7 = (reader.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
    const bool is_v8 = (reader.header().flags & qbditrace::QBDITRACE_HF_CALL_META) != 0;
    const size_t inst_hdr_sz = inst_header_size(is_v5, is_v7);
    const size_t fprdiff_sz = is_v7
        ? sizeof(qbditrace::qbditrace_fprdiff_t)          // 24 bytes
        : 0;
    const size_t fprdiff_off = fprdiff_byte_offset(is_v5, is_v7);

    // Create a thread reader for lock-free access
    auto thread_reader = reader.create_thread_reader(16);
    reader.advise_sequential();

    const uint64_t file_size = reader.file_size();
    const uint64_t header_size = reader.header_size();
    uint64_t offset = header_size;
    uint64_t inst_id = 0;

    struct SelectorInfo {
        std::string name;
        ObjcSelectorSource source = ObjcSelectorSource::Hex;
        ObjcSelectorResolution resolution = ObjcSelectorResolution::Unresolved;
    };
    // Legacy selector resolution is cached by selector pointer. v8 inline
    // metadata is authoritative per record and deliberately bypasses it.
    ankerl::unordered_dense::map<uint64_t, SelectorInfo> legacy_sel_cache;
    // String deref cache is now delegated to StringResolver (cross-pass
    // positive + negative caching), eliminating the per-pass deref_cache.

    ObjcResult result;
    struct PendingObjc {
        uint64_t site;
        uint16_t variant;
        std::optional<size_t> message_index;
    };
    std::vector<PendingObjc> pending_objc;

    auto cached_deref = [&](uint64_t addr, uint64_t at_inst_id) -> std::optional<std::string> {
        if (!is_likely_pointer(addr)) return std::nullopt;
        // StringResolver has both positive (addr_index_) and negative
        // (negative_cache_) caches, so repeated probes of the same
        // non-string address are O(1) set lookups instead of 256-byte
        // read_region + parse_cstring calls.
        auto rs = string_resolver.resolve(addr, at_inst_id);
        if (rs) return rs->value;
        return std::nullopt;
    };

    uint64_t total = end - start;
    uint64_t last_progress = 0;

    while (offset < file_size && inst_id < end) {
        const uint8_t* ptr = thread_reader.data_at(offset);
        uint8_t kind = ptr[0];

        if (kind == 0) { // INST — fast skip
            uint8_t n_regdiff = ptr[2];
            uint8_t n_mem = ptr[3];
            uint8_t n_fprdiff = is_v7 ? ptr[fprdiff_off] : 0;
            const size_t memacc_size = is_v6
                ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                : sizeof(qbditrace::qbditrace_memacc_t);
            offset += inst_hdr_sz
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff * fprdiff_sz
                + n_mem     * memacc_size;
            inst_id++;

            // Progress reporting every 256K instructions
            if ((inst_id & 0x3FFFF) == 0 && inst_id >= start) {
                uint64_t prog = inst_id - start;
                if (prog > last_progress + 0x3FFFF) {
                    ctx.progress(static_cast<float>(prog) / static_cast<float>(total));
                    last_progress = prog;
                    if (ctx.cancelled()) break;
                }
            }
        } else if (kind == 5) { // OBJC — the record we actually care about
            if (inst_id >= start && inst_id < end) {
                const auto* oh = reinterpret_cast<const qbditrace::qbditrace_objc_head_t*>(ptr);
                const auto* oh8 = is_v8
                    ? reinterpret_cast<const qbditrace::qbditrace_objc_head_v8_t*>(ptr)
                    : nullptr;

                // Extract class name early for filtering
                std::string cls_name = extract_class_name(oh->cls);
                const bool class_matches = class_filter_.empty() || cls_name == class_filter_;
                bool message_recorded = false;

                if (class_matches) {
                    ObjcMessage msg;
                    msg.inst_id   = inst_id;
                    msg.pc        = oh->pc;
                    msg.receiver  = oh->recv;
                    msg.selector  = oh->sel;
                    msg.variant   = oh->variant;
                    msg.is_stret  = oh->variant == qbditrace::QBDITRACE_OBJC_MSGSEND_STRET;
                    msg.class_name = std::move(cls_name);
                    msg.class_resolution = msg.class_name.empty()
                        ? ObjcClassResolution::Unknown
                        : ObjcClassResolution::Resolved;

                    // Resolve selector name. v8's online payload is
                    // authoritative; only legacy records use offline image /
                    // memory fallback.
                    //
                    // `inst_id` here is the raw scan counter: the number of INST
                    // records already processed when this OBJC record was
                    // encountered, i.e. the index of the *next* instruction to
                    // execute (the objc_msgSend call site itself, or the first
                    // instruction of its effect in synthetic traces). Per
                    // RegisterFile::state_before()'s contract ("state BEFORE
                    // instruction N executes" = diffs of 0..N-1 already
                    // applied), `state_before(inst_id)` is exactly "all
                    // register/memory writes that happened before this
                    // objc_msgSend fired" — which is what we want for both the
                    // selector string and the argument registers (x2-x7) that
                    // the caller set up right before the call. Using
                    // `inst_id - 1` here (as a prior version of this code did)
                    // under-counts by one instruction and silently drops the
                    // most recently-written argument/selector-string byte.
                    if (oh8) {
                        if (oh8->sel_len > 0) {
                            msg.selector_name.assign(
                                reinterpret_cast<const char*>(ptr + sizeof(*oh8)),
                                oh8->sel_len);
                            msg.selector_source = ObjcSelectorSource::Inline;
                            msg.selector_resolution =
                                (oh8->flags & QBDITRACE_OBJC_FL_SEL_TRUNCATED)
                                    ? ObjcSelectorResolution::Truncated
                                    : ObjcSelectorResolution::Resolved;
                        } else {
                            msg.selector_name = fmt::format("0x{:x}", oh->sel);
                            msg.selector_source = ObjcSelectorSource::Hex;
                            msg.selector_resolution =
                                (oh8->flags & QBDITRACE_OBJC_FL_SEL_READ_FAIL)
                                    ? ObjcSelectorResolution::ReadFailed
                                    : ObjcSelectorResolution::Unresolved;
                        }
                    } else {
                        auto [sel_it, inserted] = legacy_sel_cache.emplace(oh->sel, SelectorInfo{});
                        if (inserted) {
                            auto img_str = code_table.image_read_cstring(oh->sel);
                            if (img_str.has_value()) {
                                sel_it->second.name = std::move(*img_str);
                                sel_it->second.source = ObjcSelectorSource::Image;
                                sel_it->second.resolution = ObjcSelectorResolution::Resolved;
                            } else {
                                sel_it->second.name = read_cstring_from_memory(memory, oh->sel, inst_id);
                                if (sel_it->second.name.rfind("0x", 0) == 0) {
                                    sel_it->second.source = ObjcSelectorSource::Hex;
                                    sel_it->second.resolution = ObjcSelectorResolution::Unresolved;
                                } else {
                                    sel_it->second.source = ObjcSelectorSource::Memory;
                                    sel_it->second.resolution = ObjcSelectorResolution::Resolved;
                                }
                            }
                        }
                        msg.selector_name = sel_it->second.name;
                        msg.selector_source = sel_it->second.source;
                        msg.selector_resolution = sel_it->second.resolution;
                    }

                    // Apply selector filter if set (substring match)
                    if (!selector_filter_.empty() &&
                        msg.selector_name.find(selector_filter_) == std::string::npos) {
                        goto skip_objc;
                    }

                    // Extract arguments (x2-x7)
                    {
                    uint8_t sel_arg_count = count_selector_args(msg.selector_name);
                    if (sel_arg_count == 0 && msg.selector_name.find("0x") == 0) {
                        sel_arg_count = OBJC_MAX_ARGS;
                    }
                    msg.arg_count = std::min(sel_arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));

                    RegState pre_regs = regfile.state_before(inst_id);

                    for (uint8_t k = 0; k < msg.arg_count; ++k) {
                        uint64_t val = pre_regs.gpr[k + 2];
                        msg.args[k].value = val;
                        msg.args[k].deref_str = cached_deref(val, inst_id);
                        if (!msg.args[k].deref_str.has_value()) {
                            msg.args[k].deref_str = try_decode_reg_ascii(val);
                        }
                    }

                    // Return values are attached only from v8 REC_RETVAL below.
                    // In particular, pre-call x0 is the receiver, not a return.

                    // Update class info
                    size_t msg_idx = result.messages.size();
                    auto& cls_info = result.classes[msg.class_name];
                    if (cls_info.name.empty()) cls_info.name = msg.class_name;
                    cls_info.message_count++;
                    cls_info.message_indices.push_back(msg_idx);
                    cls_info.selectors_seen.insert(msg.selector_name);

                    // Index by PC
                    result.by_pc[msg.pc].push_back(msg_idx);

                    // Store message and retain its LIFO return association.
                    result.messages.push_back(std::move(msg));
                    message_recorded = true;
                    if (is_v8) {
                        pending_objc.push_back({oh->pc, oh->variant, msg_idx});
                    }
                    }  // end argument extraction scope
                skip_objc:
                    if (is_v8 && !message_recorded) {
                        // A selector filter may exclude this call. Keep a
                        // placeholder so its nested return cannot be attached
                        // to an older visible message.
                        pending_objc.push_back({oh->pc, oh->variant, std::nullopt});
                    }
                }
            }
            offset += objc_raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
        } else if (kind == qbditrace::QBDITRACE_REC_RETVAL && is_v8) {
            const auto* rv = reinterpret_cast<const qbditrace::qbditrace_retval_t*>(ptr);
            if (rv->source_kind == qbditrace::QBDITRACE_REC_OBJC) {
                auto match = pending_objc.rend();
                for (auto it = pending_objc.rbegin(); it != pending_objc.rend(); ++it) {
                    if (it->site == rv->site && it->variant == rv->aux_id) {
                        match = it;
                        break;
                    }
                }
                if (match != pending_objc.rend()) {
                    const auto message_index = match->message_index;
                    pending_objc.erase(std::next(match).base());
                    if (message_index.has_value() && *message_index < result.messages.size()) {
                        auto& msg = result.messages[*message_index];
                        msg.has_return = true;
                        msg.return_value = rv->x0;
                        msg.return_inst_id = inst_id;
                        msg.return_kind = msg.is_stret
                            ? ObjcReturnKind::StretRaw
                            : ObjcReturnKind::X0;
                        const auto return_string = try_deref_string(memory, rv->x0, inst_id);
                        msg.return_deref_str = return_string.value;
                        if (return_string.unreadable) {
                            const auto latest_string = try_deref_string(
                                memory, rv->x0, index.inst_count());
                            if (latest_string.value.has_value() && latest_string.nul_terminated) {
                                msg.return_deref_str = std::move(latest_string.value);
                                msg.return_string_time = ObjcReturnStringTime::LatestObserved;
                            }
                        }
                        if (!msg.return_deref_str.has_value()) {
                            msg.return_deref_str = try_decode_reg_ascii(rv->x0);
                        }
                    }
                }
            }
            offset += objc_raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
        } else {
            // Other record types: skip quickly
            offset += objc_raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
        }
    }

    reader.advise_random();

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    // ─── Persist result for future sessions ───────────────────────────────
    if (!has_filter && range.is_full_trace()) {
        std::string blob = objc_serialize(result);
        if (!blob.empty()) {
            index.save_pass_blob("objc", blob.data(), blob.size());
        }
    }

    ctx.progress(1.0f, fmt::format("ObjC: {} messages, {} unique classes",
                                    result.total_messages(),
                                    result.unique_classes()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
