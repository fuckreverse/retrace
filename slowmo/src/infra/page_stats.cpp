#include "infra/page_stats.h"
#include "core/memory_model.h"

namespace tenet {

PageStats::PageStats(MemoryModel& memory) : memory_(memory) {}

void PageStats::ensure_built() {
    if (built_) return;
    build();
}

void PageStats::build() {
    // Stub — real implementation in Task 4
    built_ = true;
}

const PageSummary* PageStats::page(uint64_t page_addr) const {
    auto it = page_index_.find(page_addr);
    if (it == page_index_.end()) return nullptr;
    return &pages_[it->second];
}

std::vector<const PageSummary*> PageStats::high_entropy_pages(double threshold) const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.entropy > threshold) result.push_back(&p);
    }
    return result;
}

std::vector<const PageSummary*> PageStats::string_candidate_pages() const {
    std::vector<const PageSummary*> result;
    for (const auto& p : pages_) {
        if (p.has_strings) result.push_back(&p);
    }
    return result;
}

}  // namespace tenet
