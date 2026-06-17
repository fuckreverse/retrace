#include "analysis/passes/objc_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/memory_model.h"

#include <fmt/core.h>
#include <algorithm>
#include <cstring>

namespace tenet {

// ─── Helpers ──────────────────────────────────────────────────────────────

/// Read a C string from memory at the given address and inst_id.
/// Returns the string content or a hex fallback if unreadable.
static std::string read_cstring_from_memory(
    MemoryModel& mem, uint64_t addr, uint64_t at_inst_id, size_t max_len = 128)
{
    if (addr == 0) return "(null)";

    std::string result;
    result.reserve(32);

    for (size_t i = 0; i < max_len; ++i) {
        auto byte = mem.byte_at(addr + i, at_inst_id);
        if (!byte.has_value()) break;

        uint8_t c = *byte;
        if (c == 0) break;  // NUL terminator
        if (c < 0x20 || c > 0x7E) break;  // non-printable — stop

        result.push_back(static_cast<char>(c));
    }

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

// ─── ObjcPass::run ───────────────────────────────────────────────────────

PassResult ObjcPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index  = ctx.index();
    auto& memory = ctx.memory();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end   = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    ObjcResult result;

    uint64_t inst_id   = 0;
    uint64_t processed = 0;
    uint64_t total     = (end > start) ? (end - start) : 1;

    // Direct iteration over all records — TraceCollector lacks on_objc callback
    for (auto it = reader.begin(); it != reader.end(); ++it) {
        if (ctx.cancelled()) {
            return PassResult::failed("cancelled by user");
        }

        auto rec = *it;

        if (rec.kind == RecordKind::Inst) {
            if (inst_id >= end) break;
            inst_id++;
            processed++;

            if (processed % 100000 == 0) {
                ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
            }
            continue;
        }

        if (rec.kind == RecordKind::Objc) {
            // Only process if we're within the analysis range
            if (inst_id < start || inst_id >= end) continue;

            auto objc = rec.as_objc();

            ObjcMessage msg;
            msg.inst_id   = inst_id;
            msg.pc        = objc.pc;
            msg.receiver  = objc.recv;
            msg.selector  = objc.sel;
            msg.variant   = objc.variant;

            // Extract class name from the 48-byte buffer
            msg.class_name = extract_class_name(objc.cls);

            // Attempt to read selector name from memory
            msg.selector_name = read_cstring_from_memory(memory, objc.sel, inst_id);

            // Record message index
            size_t msg_idx = result.messages.size();

            // Update class info
            auto& cls_info = result.classes[msg.class_name];
            if (cls_info.name.empty()) {
                cls_info.name = msg.class_name;
            }
            cls_info.message_count++;
            cls_info.message_indices.push_back(msg_idx);

            // Track unique selectors for this class
            if (std::find(cls_info.selectors_seen.begin(),
                          cls_info.selectors_seen.end(),
                          msg.selector_name) == cls_info.selectors_seen.end()) {
                cls_info.selectors_seen.push_back(msg.selector_name);
            }

            // Index by PC
            result.by_pc[msg.pc].push_back(msg_idx);

            // Store message
            result.messages.push_back(std::move(msg));
        }
    }

    ctx.progress(1.0f, fmt::format("ObjC: {} messages, {} unique classes",
                                    result.total_messages(),
                                    result.unique_classes()));
    return PassResult::success(std::move(result));
}

}  // namespace tenet
