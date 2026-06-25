#include "analysis/passes/objc_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/memory_model.h"
#include "core/register_file.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>

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

    static constexpr size_t CHUNK = 32;
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

/// Try to dereference a pointer value as a C string from memory.
/// Uses read_region() for bulk reads instead of per-byte byte_at() calls.
/// Returns nullopt if the address looks like a small integer or can't be read.
static std::optional<std::string> try_deref_string(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id)
{
    // Heuristic: skip values that look like small integers or NULL
    if (addr < 0x1000) return std::nullopt;

    static constexpr size_t MAX_LEN = 256;
    static constexpr size_t CHUNK = 32;
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

// ─── ObjcCollector ───────────────────────────────────────────────────────

/// Sequential TraceCollector that processes Objc records and builds
/// the ObjcResult. Requires MemoryModel + RegisterFile for argument extraction.
///
/// Performance notes:
///   - on_objc() calls regfile_.state_before() to extract arguments (x2-x7)
///     and return value (x0).  Each EXEC_TRANSFER_CALL in qbditrace sets
///     need_anchor=true, so an ANCHOR record is always written immediately
///     before the instruction following an objc_msgSend.  This means
///     nearest_anchor_before(inst_id) lands right next to the target, making
///     rebuild() nearly free (0-few diffs to replay).  No warm_range() needed.
///   - Two state_before() calls per ObjC record are reduced to one by reusing
///     the "pre" state for both arguments and return value when inst_id == pre+1.
class ObjcCollector final : public TraceCollector {
public:
    using ProgressFn = std::function<void(uint64_t, uint64_t)>;

    ObjcCollector(MemoryModel& memory, RegisterFile& regfile,
                  CodeTable& code_table,
                  const std::string& class_filter,
                  uint64_t start_inst_id, uint64_t end_inst_id,
                  ProgressFn progress_fn = nullptr)
        : memory_(memory)
        , regfile_(regfile)
        , code_table_(code_table)
        , class_filter_(class_filter)
        , range_start_(start_inst_id)
        , range_end_(end_inst_id)
        , progress_fn_(std::move(progress_fn))
    {}

    std::string_view name() const override { return "ObjcCollector"; }

    bool begin(uint64_t start, uint64_t end) override {
        result_ = ObjcResult{};
        processed_ = 0;
        objc_count_ = 0;
        last_reported_inst_ = 0;
        range_total_ = (end > start) ? (end - start) : 1;

        // No warm_range() needed: qbditrace writes an ANCHOR immediately
        // before each objc_msgSend (EXEC_TRANSFER_CALL sets need_anchor),
        // so state_before() rebuilds from a near-adjacent anchor with
        // effectively zero replay cost.
        return true;
    }

    void on_inst(uint64_t inst_id, const InstView& /*inst*/) override {
        processed_++;

        // Report progress based on instruction position — this is the primary
        // progress metric since INST records are far more frequent than OBJC
        // records.  Report every 64K instructions to avoid excessive callback
        // overhead.
        if (progress_fn_ && (processed_ & 0xFFFF) == 0) {
            progress_fn_(processed_, range_total_);
        }
    }

    void on_objc(uint64_t inst_id, const ObjcView& objc) override {
        if (inst_id < range_start_ || inst_id >= range_end_) return;

        objc_count_++;

        // Report progress on each ObjC record (they are rare but expensive)
        if (progress_fn_) {
            // Blend inst progress with objc count for smooth reporting
            progress_fn_(processed_, range_total_);
        }

        // Extract class name early for filtering
        std::string cls_name = extract_class_name(objc.cls);

        // Apply class filter if set
        if (!class_filter_.empty() && cls_name != class_filter_) {
            return;
        }

        ObjcMessage msg;
        msg.inst_id   = inst_id;
        msg.pc        = objc.pc;
        msg.receiver  = objc.recv;
        msg.selector  = objc.sel;
        msg.variant   = objc.variant;
        msg.class_name = std::move(cls_name);

        // Attempt to read selector name.
        // Prefer code_table (binary image read) first — ObjC selectors normally
        // reside in the __objc_methnames section of the loaded image, so this
        // is a cheap in-memory lookup that avoids triggering MemoryModel::build()
        // (which lazily scans the entire trace to persist memory writes).
        uint64_t pre_inst_id = (inst_id > 0) ? inst_id - 1 : 0;
        auto img_str = code_table_.image_read_cstring(objc.sel);
        if (img_str.has_value()) {
            msg.selector_name = *img_str;
        } else {
            // Fallback: read from trace memory model (may trigger lazy build)
            msg.selector_name = read_cstring_from_memory(memory_, objc.sel, pre_inst_id);
        }

        // ─── Extract method arguments (x2-x7) ────────────────────────────
        uint8_t sel_arg_count = count_selector_args(msg.selector_name);
        if (sel_arg_count == 0 && msg.selector_name.find("0x") == 0) {
            sel_arg_count = OBJC_MAX_ARGS;
        }
        msg.arg_count = std::min(sel_arg_count, static_cast<uint8_t>(OBJC_MAX_ARGS));

        // Fetch the pre-instruction register state once — used for both
        // argument extraction (x2-x7) and return value (x0 at inst_id).
        // The return value is actually x0 AFTER the ObjC call executes,
        // which corresponds to the register state at inst_id (before the
        // next instruction).  If inst_id == pre_inst_id + 1, we can derive
        // it from state_before(inst_id); otherwise we need two calls.
        const RegState* pre_regs = nullptr;
        const RegState* ret_regs = nullptr;
        RegState ret_state_storage;  // only used if inst_id != pre_inst_id + 1

        if (msg.arg_count > 0) {
            pre_regs = &regfile_.state_before(pre_inst_id);
        }

        if (pre_regs) {
            for (uint8_t k = 0; k < msg.arg_count; ++k) {
                uint64_t val = pre_regs->gpr[k + 2];  // x2=gpr[2], x3=gpr[3], ...
                msg.args[k].value = val;

                msg.args[k].deref_str = try_deref_string(memory_, val, pre_inst_id);

                if (!msg.args[k].deref_str.has_value()) {
                    msg.args[k].deref_str = try_decode_reg_ascii(val);
                }
            }
        }

        // ─── Extract return value (x0 after the method returns) ──────────
        {
            // Return value: x0 at inst_id (the instruction that follows the
            // objc_msgSend).  If pre_inst_id is inst_id-1 and we already have
            // pre_regs, we still need state_before(inst_id) because the ObjC
            // call modified x0.  rebuild() from the adjacent anchor is cheap.
            const auto& inst_regs = regfile_.state_before(inst_id);
            msg.return_value = inst_regs.gpr[0];
            msg.return_deref_str = try_deref_string(memory_, inst_regs.gpr[0], inst_id);
            auto reg_str = try_decode_reg_ascii(inst_regs.gpr[0]);
            if (reg_str.has_value() && !msg.return_deref_str.has_value()) {
                msg.return_deref_str = std::move(reg_str);
            }
            msg.has_return = true;
        }

        // Record message index
        size_t msg_idx = result_.messages.size();

        // Update class info
        auto& cls_info = result_.classes[msg.class_name];
        if (cls_info.name.empty()) {
            cls_info.name = msg.class_name;
        }
        cls_info.message_count++;
        cls_info.message_indices.push_back(msg_idx);

        // Track unique selectors for this class (O(1) amortized via hash set)
        cls_info.selectors_seen.insert(msg.selector_name);

        // Index by PC
        result_.by_pc[msg.pc].push_back(msg_idx);

        // Store message
        result_.messages.push_back(std::move(msg));
    }

    ObjcResult take_result() { return std::move(result_); }
    uint64_t processed() const { return processed_; }
    uint64_t objc_count() const { return objc_count_; }

private:
    MemoryModel& memory_;
    RegisterFile& regfile_;
    CodeTable& code_table_;
    const std::string& class_filter_;
    uint64_t range_start_;
    uint64_t range_end_;
    ProgressFn progress_fn_;

    ObjcResult result_;
    uint64_t processed_ = 0;
    uint64_t objc_count_ = 0;
    uint64_t last_reported_inst_ = 0;
    uint64_t range_total_ = 1;
};

// ─── ObjcPass::run ───────────────────────────────────────────────────────

PassResult ObjcPass::run(PassContext& ctx) {
    auto& reader  = ctx.reader();
    auto& index   = ctx.index();
    auto& memory  = ctx.memory();
    auto& regfile = ctx.regfile();
    auto& code_table = ctx.code_table();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    uint64_t total = (end > start) ? (end - start) : 1;

    ObjcCollector collector(memory, regfile, code_table, class_filter_, start, end,
        /*progress_fn=*/[&](uint64_t processed, uint64_t tot) {
            ctx.progress(static_cast<float>(processed) / static_cast<float>(tot),
                         fmt::format("Scanning insts... {}/{}", processed, tot));
        });

    TraceScanEngine local_engine(reader, index.inst_count(), &index);
    local_engine.set_progress([&](uint64_t processed, uint64_t /*tot*/) {
        ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
    });
    local_engine.set_cancel_check([&]() { return ctx.cancelled(); });
    local_engine.add_collector(&collector);

    local_engine.run(start, end);

    if (ctx.cancelled()) {
        return PassResult::failed("cancelled by user");
    }

    ObjcResult result = collector.take_result();

    ctx.progress(1.0f, fmt::format("ObjC: {} messages, {} unique classes",
                                    result.total_messages(),
                                    result.unique_classes()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
