#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <ankerl/unordered_dense.h>
#include <array>
#include <optional>

namespace tenet {

// ─── ObjC message record ──────────────────────────────────────────────────

/// Maximum number of method arguments captured (x2-x7 on AArch64).
static constexpr size_t OBJC_MAX_ARGS = 6;

/// A single method argument with optional string dereference.
struct ObjcArg {
    uint64_t value = 0;                     // raw register value
    std::optional<std::string> deref_str;   // dereferenced C-string if pointer
};

/// A single Objective-C message send captured from the trace.
struct ObjcMessage {
    uint64_t inst_id;           // inst_id of the surrounding instruction
    uint64_t pc;                // PC of the objc_msgSend call
    uint64_t receiver;          // receiver object address
    uint64_t selector;          // selector pointer
    std::string class_name;     // resolved class name (from trace data)
    std::string selector_name;  // selector name (from memory or hex fallback)
    uint8_t variant;            // 0=msgSend, 1=stret, 2=super, etc.

    /// Method arguments (x2-x7). Only populated when register state is available.
    std::array<ObjcArg, OBJC_MAX_ARGS> args{};
    uint8_t arg_count = 0;      // number of args based on selector colon count

    /// Return value (x0 after the method returns).
    /// Populated by looking at the register state at the next OBJC call or end of trace.
    uint64_t return_value = 0;
    std::optional<std::string> return_deref_str;  // dereferenced if pointer
    bool has_return = false;
};

// ─── ObjC class info ──────────────────────────────────────────────────────

/// Aggregated information about a single Objective-C class seen at runtime.
struct ObjcClassInfo {
    std::string name;
    uint64_t message_count = 0;                 // total messages sent to instances
    ankerl::unordered_dense::set<std::string> selectors_seen;  // unique selectors called on this class
    std::vector<size_t> message_indices;        // indices into messages vector
};

// ─── ObjC analysis result ─────────────────────────────────────────────────

/// Result of the ObjC analysis pass.
struct ObjcResult {
    /// All ObjC messages in trace order.
    std::vector<ObjcMessage> messages;

    /// Class name → aggregated class info.
    ankerl::unordered_dense::map<std::string, ObjcClassInfo> classes;

    /// PC → indices into messages vector (for looking up calls at a given site).
    ankerl::unordered_dense::map<uint64_t, std::vector<size_t>> by_pc;

    // ─── Query helpers ───────────────────────────────────────────────────

    /// Get all messages sent to instances of a given class.
    std::vector<const ObjcMessage*> messages_for_class(const std::string& cls) const {
        std::vector<const ObjcMessage*> result;
        auto it = classes.find(cls);
        if (it != classes.end()) {
            result.reserve(it->second.message_indices.size());
            for (size_t idx : it->second.message_indices) {
                result.push_back(&messages[idx]);
            }
        }
        return result;
    }

    /// Get the N classes with the most messages, sorted descending.
    std::vector<const ObjcClassInfo*> hottest_classes(size_t n) const {
        std::vector<const ObjcClassInfo*> sorted;
        sorted.reserve(classes.size());
        for (const auto& [name, info] : classes) {
            sorted.push_back(&info);
        }
        std::sort(sorted.begin(), sorted.end(),
                  [](const ObjcClassInfo* a, const ObjcClassInfo* b) {
                      return a->message_count > b->message_count;
                  });
        if (sorted.size() > n) sorted.resize(n);
        return sorted;
    }

    /// Total number of ObjC messages in the trace.
    size_t total_messages() const { return messages.size(); }

    /// Number of unique classes seen.
    size_t unique_classes() const { return classes.size(); }

    /// Serialize the result to JSON.
    nlohmann::json to_json() const;
};

// ─── ObjC pass ────────────────────────────────────────────────────────────

/// Analyzes Objective-C message sends recorded in the trace.
///
/// Builds a map of ObjC method calls, call counts, class hierarchies seen
/// at runtime, and selector frequency.  Critical for iOS reverse engineering.
///
/// When register state is available, also extracts method arguments (x2-x7)
/// and attempts to dereference pointer arguments as C strings.
///
/// Result type: ObjcResult
class ObjcPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "objc"; }
    std::string_view description() const override {
        return "Analyze Objective-C message sends in the trace";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — iterates raw trace records
    }

    /// Optional: filter results to only include messages for this class.
    void set_class_filter(const std::string& cls) { class_filter_ = cls; }

    /// Optional: filter results to only include messages matching this selector substring.
    void set_selector_filter(const std::string& sel) { selector_filter_ = sel; }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 4.0f; }

private:
    std::string class_filter_;     // empty = no filter
    std::string selector_filter_;  // empty = no filter
};

}  // namespace tenet
