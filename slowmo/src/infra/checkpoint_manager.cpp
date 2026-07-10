#include "infra/checkpoint_manager.h"
#include "core/register_file.h"
#include <algorithm>
#include <stdexcept>

namespace tenet {

CheckpointManager::CheckpointManager(RegisterFile& regfile) : regfile_(regfile) {}

void CheckpointManager::ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress) {
    if (checkpoints_built_) return;
    if (regfile_.has_checkpoints()) {
        checkpoints_built_ = true;
        return;
    }
    regfile_.build_checkpoints(0, std::move(progress));
    checkpoints_built_ = true;
}

void CheckpointManager::declare_warm_range(uint64_t start_id, uint64_t end_id) {
    declared_ranges_.push_back({start_id, end_id});
}

void CheckpointManager::execute_warms() {
    if (declared_ranges_.empty()) return;

    // Sort by start address
    std::sort(declared_ranges_.begin(), declared_ranges_.end());

    // Merge overlapping/adjacent ranges
    std::vector<Range> merged;
    merged.reserve(declared_ranges_.size());
    for (const auto& r : declared_ranges_) {
        if (!merged.empty() && r.start <= merged.back().end) {
            merged.back().end = std::max(merged.back().end, r.end);
        } else {
            merged.push_back(r);
        }
    }

    // Execute warm_range for each merged range
    for (const auto& r : merged) {
        regfile_.warm_range(r.start, r.end, 0, nullptr);
    }

    declared_ranges_.clear();
}

RegisterFileCursor CheckpointManager::create_cursor() const {
    // RegisterFileCursor takes (const TraceReader&, const TraceIndex&).
    // RegisterFile holds references to both, but doesn't expose them.
    // We need to pass them — but RegisterFileCursor's constructor needs them.
    // Since RegisterFile stores reader_ and index_ as const references,
    // and we only have the RegisterFile, we must access them through a
    // friend mechanism or add accessors. The cleanest approach: RegisterFile
    // already provides the reader/index via its own constructor, so we
    // reconstruct the cursor using the same references.
    //
    // However, RegisterFile doesn't expose reader()/index() accessors.
    // We'll add them in a separate step if needed. For now, this is a
    // known limitation — passes that need cursors can construct them directly.
    //
    // TODO: Add RegisterFile::reader() and RegisterFile::index() const accessors
    //       in a follow-up, then implement this properly.
    throw std::runtime_error("CheckpointManager::create_cursor requires RegisterFile accessors (TODO)");
}

bool CheckpointManager::has_checkpoints() const {
    return checkpoints_built_;
}

}  // namespace tenet
