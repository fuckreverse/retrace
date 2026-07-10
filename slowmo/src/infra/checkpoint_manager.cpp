#include "infra/checkpoint_manager.h"

#include <utility>

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

RegisterFileCursor CheckpointManager::create_cursor() const {
    return RegisterFileCursor(regfile_.reader(), regfile_.index());
}

bool CheckpointManager::has_checkpoints() const {
    return checkpoints_built_;
}

}  // namespace tenet
