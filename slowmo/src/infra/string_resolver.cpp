#include "infra/string_resolver.h"
#include "core/memory_model.h"
#include "infra/page_stats.h"
#include <algorithm>
#include <cstring>

namespace tenet {

StringResolver::StringResolver(MemoryModel& memory, PageStats& page_stats)
    : memory_(memory), page_stats_(page_stats) {}

void StringResolver::ensure_built(uint64_t at_inst_id) {
    if (built_) return;
    build(at_inst_id);
}

void StringResolver::build(uint64_t at_inst_id) {
    page_stats_.ensure_built();

    strings_.clear();
    addr_index_.clear();

    // Scan only string candidate pages
    auto candidate_pages = page_stats_.string_candidate_pages();

    for (const PageSummary* ps : candidate_pages) {
        // Read the full page
        auto region = memory_.read_region(ps->page_addr, 4096, at_inst_id);

        // Extract C-strings from the page
        size_t i = 0;
        while (i < region.data.size()) {
            // Skip unknown bytes
            if (!region.known[i]) {
                i++;
                continue;
            }

            // Check for printable ASCII run
            if (region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                size_t start = i;
                std::string s;
                while (i < region.data.size() && region.known[i] &&
                       region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                    s += static_cast<char>(region.data[i]);
                    i++;
                }

                // Must be at least 4 chars
                if (s.length() >= 4) {
                    ResolvedString rs;
                    rs.addr = ps->page_addr + start;
                    rs.value = std::move(s);
                    rs.inst_id = at_inst_id;
                    rs.kind = ResolvedString::CStr;
                    rs.length = rs.value.length();

                    addr_index_[rs.addr] = strings_.size();
                    strings_.push_back(std::move(rs));
                }
            } else {
                i++;
            }
        }
    }

    built_ = true;
}

std::optional<ResolvedString> StringResolver::resolve(uint64_t addr, uint64_t at_inst_id) {
    // Check positive cache first
    auto it = addr_index_.find(addr);
    if (it != addr_index_.end()) {
        return strings_[it->second];
    }

    // Check negative cache — this address was probed before and is NOT a string.
    // This is the key optimisation for objc/syscall passes that probe every
    // register value as a potential string pointer: most registers hold
    // integers or pointers to non-string data, and without a negative cache
    // each probe triggers a 256-byte read_region + parse.
    if (negative_cache_.count(addr)) {
        return std::nullopt;
    }

    // Not in either cache — parse on demand
    auto result = parse_cstring(addr, at_inst_id);
    if (!result) {
        negative_cache_.insert(addr);
    }
    return result;
}

std::optional<ResolvedString> StringResolver::parse_cstring(uint64_t addr, uint64_t at_inst_id) {
    // Read up to 256 bytes looking for a C-string
    auto region = memory_.read_region(addr, 256, at_inst_id);

    std::string s;
    for (size_t i = 0; i < region.data.size(); i++) {
        if (!region.known[i]) break;
        uint8_t c = region.data[i];
        if (c == 0) break;
        if (c >= 0x20 && c < 0x7f) {
            s += static_cast<char>(c);
        } else {
            break;  // non-printable
        }
    }

    if (s.length() < 1) return std::nullopt;

    ResolvedString rs;
    rs.addr = addr;
    rs.value = std::move(s);
    rs.inst_id = at_inst_id;
    rs.kind = ResolvedString::CStr;
    rs.length = rs.value.length();

    // Cache it
    addr_index_[addr] = strings_.size();
    strings_.push_back(rs);

    return strings_.back();
}

std::vector<ResolvedString> StringResolver::resolve_region(uint64_t base_addr, size_t size,
                                                             uint64_t at_inst_id) {
    std::vector<ResolvedString> result;
    auto region = memory_.read_region(base_addr, size, at_inst_id);

    size_t i = 0;
    while (i < region.data.size()) {
        if (!region.known[i]) {
            i++;
            continue;
        }

        if (region.data[i] >= 0x20 && region.data[i] < 0x7f) {
            size_t start = i;
            std::string s;
            while (i < region.data.size() && region.known[i] &&
                   region.data[i] >= 0x20 && region.data[i] < 0x7f) {
                s += static_cast<char>(region.data[i]);
                i++;
            }

            if (s.length() >= 4) {
                ResolvedString rs;
                rs.addr = base_addr + start;
                rs.value = std::move(s);
                rs.inst_id = at_inst_id;
                rs.kind = ResolvedString::CStr;
                rs.length = rs.value.length();
                result.push_back(std::move(rs));
            }
        } else {
            i++;
        }
    }

    return result;
}

}  // namespace tenet
