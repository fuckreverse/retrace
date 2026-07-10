#pragma once

#include "common/types.h"
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace tenet {

class MemoryModel;

/// Single memory page statistics summary.
struct PageSummary {
    uint64_t page_addr;         ///< page-aligned address (page_number << 12)
    uint64_t first_access;      ///< first inst_id that accessed this page
    uint64_t last_access;       ///< last inst_id that accessed this page
    uint32_t write_count;       ///< write events to this page
    uint32_t read_count;        ///< read events to this page
    bool     has_strings;       ///< heuristic: contains readable strings
    double   entropy;           ///< page entropy (0.0-8.0, -1.0 = not computed)
};

/// Cached page-level memory statistics.
///
/// Lifecycle: Lazy — built on first access via ensure_built().
///
/// Built on top of MemoryModel::active_pages(), incrementally computing
/// entropy and string heuristics. Page bytes are read once and cached.
class PageStats {
public:
    explicit PageStats(MemoryModel& memory);

    /// Ensure statistics are built (lazy trigger point)
    void ensure_built();

    const PageSummary* page(uint64_t page_addr) const;
    const std::vector<PageSummary>& all_pages() const { return pages_; }

    /// Pages with entropy > threshold
    std::vector<const PageSummary*> high_entropy_pages(double threshold = 7.0) const;

    /// Pages that may contain strings (heuristic)
    std::vector<const PageSummary*> string_candidate_pages() const;

    bool is_built() const { return built_; }

private:
    void build();

    MemoryModel& memory_;
    std::vector<PageSummary> pages_;
    std::unordered_map<uint64_t, size_t> page_index_;  // page_addr → index in pages_
    bool built_ = false;
};

}  // namespace tenet
