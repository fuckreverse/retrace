#pragma once

#include "common/types.h"
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tenet {

class MemoryModel;
class PageStats;

/// A string resolved from memory at a specific point in time.
struct ResolvedString {
    uint64_t addr;              ///< string start address
    std::string value;          ///< parsed string value
    uint64_t inst_id;           ///< time of memory read
    enum Kind { CStr, Utf16, Raw } kind;
    size_t   length;            ///< raw byte length
};

/// Unified string parsing from memory with cross-pass caching.
///
/// Lifecycle: Lazy — built on first access via ensure_built().
///
/// Uses PageStats::string_candidate_pages() to filter which pages to scan.
class StringResolver {
public:
    StringResolver(MemoryModel& memory, PageStats& page_stats);

    void ensure_built(uint64_t at_inst_id = UINT64_MAX);

    std::optional<ResolvedString> resolve(uint64_t addr, uint64_t at_inst_id);
    std::vector<ResolvedString> resolve_region(uint64_t base_addr, size_t size,
                                                uint64_t at_inst_id);
    const std::vector<ResolvedString>& all_strings() const { return strings_; }

    bool is_built() const { return built_; }

private:
    void build(uint64_t at_inst_id);
    std::optional<ResolvedString> parse_cstring(uint64_t addr, uint64_t at_inst_id);

    MemoryModel& memory_;
    PageStats& page_stats_;

    std::vector<ResolvedString> strings_;
    std::unordered_map<uint64_t, size_t> addr_index_;  // addr → index in strings_
    /// Addresses probed via resolve() that did NOT yield a valid string.
    /// Prevents repeated read_region + parse_cstring calls for the same
    /// non-string pointer (common in objc_msgSend / syscall arg scanning
    /// where many registers hold integers, not string pointers).
    std::unordered_set<uint64_t> negative_cache_;
    bool built_ = false;
};

}  // namespace tenet
