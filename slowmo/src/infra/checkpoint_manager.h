#pragma once

#include "common/types.h"
#include "core/register_file.h"
#include <cstdint>
#include <functional>
#include <vector>

namespace tenet {

/// Unified register checkpoint strategy manager.
///
/// Lifecycle: Eager — checkpoints built at init_infra(); warm ranges declared
/// by passes and executed in batch via execute_warms().
///
/// Ensures RegisterFile::build_checkpoints() is called at most once, and
/// warm_range() calls are merged (overlapping ranges deduplicated).
class CheckpointManager {
public:
    explicit CheckpointManager(RegisterFile& regfile);

    /// Build checkpoint array (idempotent — only once)
    void ensure_checkpoints(std::function<void(uint64_t, uint64_t)> progress = nullptr);

    /// Declare a range needing warm (pass calls during declare_scan or run)
    void declare_warm_range(uint64_t start_id, uint64_t end_id);

    /// Execute all declared warms (merge overlapping, batch warm)
    void execute_warms();

    /// Create a RegisterFileCursor (unified factory)
    RegisterFileCursor create_cursor() const;

    bool has_checkpoints() const;

private:
    RegisterFile& regfile_;

    struct Range {
        uint64_t start, end;
        bool operator<(const Range& o) const { return start < o.start; }
    };
    std::vector<Range> declared_ranges_;
    bool checkpoints_built_ = false;
};

}  // namespace tenet
