#include "infra/string_resolver.h"
#include "core/memory_model.h"
#include "infra/page_stats.h"

namespace tenet {

StringResolver::StringResolver(MemoryModel& memory, PageStats& page_stats)
    : memory_(memory), page_stats_(page_stats) {}

void StringResolver::ensure_built(uint64_t at_inst_id) {
    if (built_) return;
    build(at_inst_id);
}

void StringResolver::build(uint64_t at_inst_id) {
    (void)at_inst_id;
    // Stub — real implementation in Task 5
    built_ = true;
}

std::optional<ResolvedString> StringResolver::resolve(uint64_t addr, uint64_t at_inst_id) {
    (void)addr;
    (void)at_inst_id;
    // Stub — real implementation in Task 5
    return std::nullopt;
}

std::vector<ResolvedString> StringResolver::resolve_region(uint64_t base_addr, size_t size,
                                                             uint64_t at_inst_id) {
    (void)base_addr;
    (void)size;
    (void)at_inst_id;
    return {};
}

}  // namespace tenet
