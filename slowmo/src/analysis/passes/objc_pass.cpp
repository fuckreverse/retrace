#include "analysis/passes/objc_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"

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

/// Try to dereference a pointer value as a C string from memory.
/// Uses read_region() for bulk reads instead of per-byte byte_at() calls.
/// Returns nullopt if the address looks like a small integer or can't be read.
static std::optional<std::string> try_deref_string(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id)
{
    if (!is_likely_pointer(addr)) return std::nullopt;

    static constexpr size_t MAX_LEN = 256;
    static constexpr size_t CHUNK = 64;
    std::string result;
    result.reserve(32);

    for (size_t offset = 0; offset < MAX_LEN; offset += CHUNK) {
        size_t to_read = std::min(CHUNK, MAX_LEN - offset);
        auto region = mem.read_region(addr + offset, to_read, at_inst_id);

        for (size_t i = 0; i < to_read; ++i) {
            if (!region.known[i]) goto done;
            uint8_t c = region.data[i];
            if (c == 0) goto done;  // NUL terminator
            if (c < 0x20 || c > 0x7E) {
                // Non-printable — this probably isn't a string
                if (offset + i == 0) return std::nullopt;
                goto done;
            }
            result.push_back(static_cast<char>(c));
        }
    }
done:
    // Require at least 2 chars to consider it a meaningful string
    if (result.size() < 2) return std::nullopt;
    return result;
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
        m["selector_name"] = msg.selector_name;
        m["variant"] = msg.variant;

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
            if (msg.return_deref_str.has_value()) {
                ret["string"] = *msg.return_deref_str;
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
static constexpr uint32_t OBJC_BLOB_VERSION  = 1u;

std::string objc_serialize(const ObjcResult& res) {
    // Estimate size: header + messages + classes
    size_t est = 4 + 4 + 8;  // magic + version + num_messages
    est += res.messages.size() * 256;  // rough estimate per message
    est += res.classes.size() * 128;

    std::string buf;
    buf.reserve(est);

    auto write_u8  = [&](uint8_t v)  { buf.append(reinterpret_cast<const char*>(&v), 1); };
    auto write_u32 = [&](uint32_t v) { buf.append(reinterpret_cast<const char*>(&v), 4); };
    auto write_u64 = [&](uint64_t v) { buf.append(reinterpret_cast<const char*>(&v), 8); };
    auto write_str = [&](const std::string& s) {
        write_u32(static_cast<uint32_t>(s.size()));
        buf.append(s);
    };
    auto write_opt_str = [&](const std::optional<std::string>& s) {
        if (s.has_value()) {
            write_u8(1);
            write_str(*s);
        } else {
            write_u8(0);
        }
    };

    write_u32(OBJC_BLOB_MAGIC);
    write_u32(OBJC_BLOB_VERSION);
    write_u64(static_cast<uint64_t>(res.messages.size()));

    for (const auto& msg : res.messages) {
        write_u64(msg.inst_id);
        write_u64(msg.pc);
        write_u64(msg.receiver);
        write_u64(msg.selector);
        write_str(msg.class_name);
        write_str(msg.selector_name);
        write_u8(msg.variant);
        write_u8(msg.arg_count);

        uint8_t n = std::min(msg.arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));
        for (uint8_t k = 0; k < n; ++k) {
            write_u64(msg.args[k].value);
            write_opt_str(msg.args[k].deref_str);
        }

        write_u8(msg.has_return ? 1 : 0);
        if (msg.has_return) {
            write_u64(msg.return_value);
            write_opt_str(msg.return_deref_str);
        }
    }

    return buf;
}

bool objc_deserialize(const std::string& blob, ObjcResult& out) {
    if (blob.size() < 4 + 4 + 8) return false;
    const char* p = blob.data();
    const char* end = p + blob.size();

    auto read_u8  = [&]() -> uint8_t  { uint8_t  v; std::memcpy(&v, p, 1); p += 1; return v; };
    auto read_u32 = [&]() -> uint32_t { uint32_t v; std::memcpy(&v, p, 4); p += 4; return v; };
    auto read_u64 = [&]() -> uint64_t { uint64_t v; std::memcpy(&v, p, 8); p += 8; return v; };
    auto read_str = [&]() -> std::string {
        uint32_t len = read_u32();
        if (p + len > end) return {};
        std::string s(p, len);
        p += len;
        return s;
    };
    auto read_opt_str = [&]() -> std::optional<std::string> {
        uint8_t has = read_u8();
        if (has) return read_str();
        return std::nullopt;
    };

    if (read_u32() != OBJC_BLOB_MAGIC)   return false;
    if (read_u32() != OBJC_BLOB_VERSION) return false;

    uint64_t n_msgs = read_u64();
    out.messages.reserve(static_cast<size_t>(n_msgs));

    for (uint64_t i = 0; i < n_msgs; i++) {
        if (p + 8 * 4 > end) return false;
        ObjcMessage msg;
        msg.inst_id       = read_u64();
        msg.pc            = read_u64();
        msg.receiver      = read_u64();
        msg.selector      = read_u64();
        msg.class_name    = read_str();
        msg.selector_name = read_str();
        msg.variant       = read_u8();
        msg.arg_count     = read_u8();

        uint8_t n = std::min(msg.arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));
        for (uint8_t k = 0; k < n; ++k) {
            if (p + 8 > end) return false;
            msg.args[k].value = read_u64();
            msg.args[k].deref_str = read_opt_str();
        }

        uint8_t has_ret = read_u8();
        msg.has_return = (has_ret != 0);
        if (msg.has_return) {
            if (p + 8 > end) return false;
            msg.return_value = read_u64();
            msg.return_deref_str = read_opt_str();
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

    return true;
}

/// Compute record size from raw pointer (same logic as trace_collector.cpp).
inline size_t objc_raw_record_size(const uint8_t* ptr, uint32_t num_gpr, bool is_v6) {
    switch (ptr[0]) {
    case 0: { // INST
        uint8_t n_regdiff = ptr[2];
        uint8_t n_mem = ptr[3];
        const size_t memacc_size = is_v6
            ? sizeof(qbditrace::qbditrace_memacc_v6_t)
            : sizeof(qbditrace::qbditrace_memacc_t);
        return sizeof(qbditrace::qbditrace_inst_head_t)
            + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
            + n_mem     * memacc_size;
    }
    case 1: // ANCHOR
        return sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8;
    case 2: // THREAD
        return sizeof(qbditrace::qbditrace_thread_head_t);
    case 3: // EVENT
        return sizeof(qbditrace::qbditrace_event_head_t);
    case 4: // SVC
        return sizeof(qbditrace::qbditrace_svc_head_t);
    case 5: // OBJC
        return sizeof(qbditrace::qbditrace_objc_head_t);
    case 6: // CODE
        return sizeof(qbditrace::qbditrace_code_head_t) + ptr[1];
    default:
        return 1;
    }
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
    const bool is_v6 = (reader.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;

    // Create a thread reader for lock-free access
    auto thread_reader = reader.create_thread_reader(16);
    reader.advise_sequential();

    const uint64_t file_size = reader.file_size();
    const uint64_t header_size = reader.header_size();
    uint64_t offset = header_size;
    uint64_t inst_id = 0;

    // Selector name cache
    ankerl::unordered_dense::map<uint64_t, std::string> sel_name_cache;
    // String deref cache
    ankerl::unordered_dense::map<uint64_t, std::optional<std::string>> deref_cache;

    ObjcResult result;

    auto cached_deref = [&](uint64_t addr, uint64_t at_inst_id) -> std::optional<std::string> {
        if (!is_likely_pointer(addr)) return std::nullopt;
        auto [it, inserted] = deref_cache.emplace(addr, std::nullopt);
        if (inserted) {
            it->second = try_deref_string(memory, addr, at_inst_id);
        }
        return it->second;
    };

    uint64_t total = end - start;
    uint64_t last_progress = 0;

    while (offset < file_size && inst_id < end) {
        const uint8_t* ptr = thread_reader.data_at(offset);
        uint8_t kind = ptr[0];

        if (kind == 0) { // INST — fast skip
            uint8_t n_regdiff = ptr[2];
            uint8_t n_mem = ptr[3];
            const size_t memacc_size = is_v6
                ? sizeof(qbditrace::qbditrace_memacc_v6_t)
                : sizeof(qbditrace::qbditrace_memacc_t);
            offset += sizeof(qbditrace::qbditrace_inst_head_t)
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
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

                // Extract class name early for filtering
                std::string cls_name = extract_class_name(oh->cls);

                if (class_filter_.empty() || cls_name == class_filter_) {
                    ObjcMessage msg;
                    msg.inst_id   = inst_id;
                    msg.pc        = oh->pc;
                    msg.receiver  = oh->recv;
                    msg.selector  = oh->sel;
                    msg.variant   = oh->variant;
                    msg.class_name = std::move(cls_name);

                    // Resolve selector name — cached by address.
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
                    auto [sel_it, sel_inserted] = sel_name_cache.emplace(oh->sel, std::string{});
                    if (sel_inserted) {
                        auto img_str = code_table.image_read_cstring(oh->sel);
                        if (img_str.has_value()) {
                            sel_it->second = std::move(*img_str);
                        } else {
                            sel_it->second = read_cstring_from_memory(memory, oh->sel, inst_id);
                        }
                    }
                    msg.selector_name = sel_it->second;

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

                    const RegState* pre_regs = nullptr;
                    if (msg.arg_count > 0) {
                        pre_regs = &regfile.state_before(inst_id);
                    }
                    if (pre_regs) {
                        for (uint8_t k = 0; k < msg.arg_count; ++k) {
                            uint64_t val = pre_regs->gpr[k + 2];
                            msg.args[k].value = val;
                            msg.args[k].deref_str = cached_deref(val, inst_id);
                            if (!msg.args[k].deref_str.has_value()) {
                                msg.args[k].deref_str = try_decode_reg_ascii(val);
                            }
                        }
                    }

                    // Extract return value (x0 after the method returns)
                    {
                        const auto& inst_regs = regfile.state_before(inst_id);
                        msg.return_value = inst_regs.gpr[0];
                        msg.return_deref_str = cached_deref(inst_regs.gpr[0], inst_id);
                        auto reg_str = try_decode_reg_ascii(inst_regs.gpr[0]);
                        if (reg_str.has_value() && !msg.return_deref_str.has_value()) {
                            msg.return_deref_str = std::move(reg_str);
                        }
                        msg.has_return = true;
                    }

                    // Update class info
                    size_t msg_idx = result.messages.size();
                    auto& cls_info = result.classes[msg.class_name];
                    if (cls_info.name.empty()) cls_info.name = msg.class_name;
                    cls_info.message_count++;
                    cls_info.message_indices.push_back(msg_idx);
                    cls_info.selectors_seen.insert(msg.selector_name);

                    // Index by PC
                    result.by_pc[msg.pc].push_back(msg_idx);

                    // Store message
                    result.messages.push_back(std::move(msg));
                    }  // end argument extraction scope
                skip_objc:;
                }
            }
            offset += sizeof(qbditrace::qbditrace_objc_head_t);
        } else {
            // Other record types: skip quickly
            offset += objc_raw_record_size(ptr, num_gpr, is_v6);
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
