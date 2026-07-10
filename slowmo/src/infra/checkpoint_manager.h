#pragma once

#include "common/types.h"
#include "core/register_file.h"
#include <cstdint>
#include <functional>

namespace tenet {

/// Unified register checkpoint strategy manager.
///
/// Ensures RegisterFile::build_checkpoints() is called at most once.
class CheckpointManager {
public:
    explicit CheckpointManager(RegisterFile& regfile);

    /// Build checkpoint array (idempotent — only once)
    void ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Create a RegisterFileCursor (unified factory)
    RegisterFileCursor create_cursor() const;

    bool has_checkpoints() const;

private:
    RegisterFile& regfile_;
    bool checkpoints_built_ = false;
};

}  // namespace tenet
