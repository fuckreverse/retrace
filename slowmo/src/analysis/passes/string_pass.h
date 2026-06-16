#pragma once

#include "analysis/pass_manager.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

namespace tenet {

// ─── String pass result ──────────────────────────────────────────────────

/// A reference to a string discovered in traced memory.
struct StringRef {
    uint64_t addr;              // String start address
    uint64_t discovered_at;     // inst_id when this string was first found
    std::string content;        // UTF-8 content (up to MAX_STRING_LEN chars)

    enum Encoding {
        ASCII,
        UTF8,
        UTF16LE,
        Wide,       // wchar_t
    };
    Encoding encoding = ASCII;

    /// Reference information: which instruction accessed this string.
    struct Reference {
        uint64_t inst_id;       // Which instruction referenced it
        uint64_t pc;            // PC of that instruction
    };
    std::vector<Reference> references;  // All instructions that referenced this string
};

/// Result of the string discovery pass.
struct StringResult {
    std::vector<StringRef> strings;                             // All discovered strings
    std::unordered_map<uint64_t, size_t> addr_to_index;        // addr → strings[] index
    std::unordered_map<uint64_t, std::vector<size_t>> inst_to_strings; // inst_id → referenced string indices

    static constexpr size_t MAX_STRING_LEN = 256;
    static constexpr size_t MIN_STRING_LEN = 4;    // Minimum 4 chars to qualify as a string

    // Sentinel value in addr_to_index meaning "probed but not a string".
    static constexpr size_t NOT_STRING = SIZE_MAX;

    /// Lookup a string by its start address.
    const StringRef* at_addr(uint64_t addr) const {
        auto it = addr_to_index.find(addr);
        if (it == addr_to_index.end() || it->second == NOT_STRING) return nullptr;
        return &strings[it->second];
    }

    /// Find all strings referenced by a given instruction.
    std::vector<const StringRef*> at_inst(uint64_t inst_id) const {
        std::vector<const StringRef*> result;
        auto it = inst_to_strings.find(inst_id);
        if (it != inst_to_strings.end()) {
            result.reserve(it->second.size());
            for (size_t idx : it->second) {
                result.push_back(&strings[idx]);
            }
        }
        return result;
    }

    /// Case-insensitive substring search across all discovered strings.
    std::vector<const StringRef*> search(const std::string& pattern) const;

    /// Total number of discovered strings.
    size_t total() const { return strings.size(); }
};

// ─── String pass ─────────────────────────────────────────────────────────

/// Discovers printable strings in traced memory by scanning memory read events.
///
/// Strategy: for every memory read in the trace, probe the read address for a
/// contiguous sequence of printable characters (ASCII or UTF-16LE).  This is
/// more reliable than register-based heuristics because the trace already tells
/// us which addresses were actually accessed.
///
/// Result type: StringResult
class StringPass final : public AnalysisPass {
public:
    std::string_view name() const override { return "strings"; }
    std::string_view description() const override {
        return "Discover printable strings in traced memory";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — runs independently
    }

    PassResult run(PassContext& ctx) override;
    float estimated_cost() const override { return 5.0f; }
};

}  // namespace tenet
