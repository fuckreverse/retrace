#include "infra/checkpoint_manager.h"
#include "core/register_file.h"

namespace tenet {

CheckpointManager::CheckpointManager(RegisterFile& regfile) : regfile_(regfile) {}

void CheckpointManager::ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress) {
    (void)progress;
    if (checkpoints_built_) return;
    // Stub — real implementation in Task 2
    checkpoints_built_ = true;
}

void CheckpointManager::declare_warm_range(uint64_t start_id, uint64_t end_id) {
    declared_ranges_.push_back({start_id, end_id});
}

void CheckpointManager::execute_warms() {
    // Stub — real implementation in Task 2
    declared_ranges_.clear();
}

RegisterFileCursor CheckpointManager::create_cursor() const {
    // Stub — real implementation in Task 2
    // Will return regfile_-based cursor
    throw std::runtime_error("CheckpointManager::create_cursor not yet implemented");
}

bool CheckpointManager::has_checkpoints() const {
    return checkpoints_built_;
}

}  // namespace tenet
