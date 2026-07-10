#include "infra/page_stats.h"
#include "core/memory_model.h"
#include "common/entropy.h"
#include <algorithm>
#include <cstring>

namespace tenet {

PageStats::PageStats(MemoryModel& memory) : memory_(memory) {}

void PageStats::ensure_built() {
    if (built_) return;
    build();
}

void PageStats::build() {
    // Get raw page activity from MemoryModel
    auto activities = memory_.active_pages();

    pages_.clear();
    pages_.reserve(activities.size());
    page_index_.clear();
    page_index_.reserve(activities.size());

    // Read each page's bytes and compute statistics
    // Use UINT64_MAX as the snapshot time (end of trace state)
    const uint64_t at_inst_id = UINT64_MAX;

    for (const auto& act : activities) {
        PageSummary summary;
        summary.page_addr = act.page_addr;
        summary.first_access = act.first_inst_id;
        summary.last_access = act.last_inst_id;
        summary.write_count = act.write_count;
        summary.read_count = act.read_count;
        summary.has_strings = false;
        summary.entropy = -1.0;

        // Read the full page (4096 bytes)
        auto region = memory_.read_region(act.page_addr, 4096, at_inst_id);

        if (region.known_count > 0) {
            // Collect known bytes for entropy
            std::vector<uint8_t> known_bytes;
            known_bytes.reserve(region.known_count);
            for (size_t i = 0; i < region.data.size(); i++) {
                if (region.known[i]) {
                    known_bytes.push_back(region.data[i]);
                }
            }

            // Compute entropy
            if (!known_bytes.empty()) {
                summary.entropy = shannon_entropy(known_bytes.data(), known_bytes.size());
            }

            // String heuristic: check for runs of printable ASCII (>= 4 chars)
            size_t printable_run = 0;
            for (size_t i = 0; i < region.data.size(); i++) {
                if (region.known[i]) {
                    uint8_t c = region.data[i];
                    if (c >= 0x20 && c < 0x7f) {
                        printable_run++;
                        if (printable_run >= 4) {
                            summary.has_strings = true;
                            break;
                        }
                    } else {
                        printable_run = 0;
                    }
                } else {
                    printable_run = 0;
                }
            }
        }

        page_index_[summary.page_addr] = pages_.size();
        pages_.push_back(std::move(summary));
    }

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
