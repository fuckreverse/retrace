#pragma once

#include "common/types.h"
#include <ankerl/unordered_dense.h>
#include <algorithm>
#include <vector>
#include <utility>

namespace tenet {

/// Stores the raw instruction bytes for each distinct executed PC.
/// Populated from REC_CODE records in the trace file.
///
/// Performance: uses ankerl::unordered_dense::map (open-addressing, contiguous
/// memory) instead of std::unordered_map (per-node heap allocation). For a
/// typical trace with 5-50K unique PCs, this provides 2-3× faster lookups
/// due to better cache locality and elimination of pointer chasing.
class CodeTable {
public:
    CodeTable() = default;

    /// Pre-allocate for expected number of unique PCs.
    void reserve(size_t n) { opcodes_.reserve(n); }

    /// Ingest a CODE record (pc → opcode bytes).
    void insert(uint64_t pc, uint32_t opcode) {
        opcodes_.emplace(pc, opcode);
    }

    /// Look up the 4-byte opcode at a given PC.
    /// Returns nullopt if that PC was never recorded.
    std::optional<uint32_t> opcode_at(uint64_t pc) const {
        auto it = opcodes_.find(pc);
        if (it == opcodes_.end()) return std::nullopt;
        return it->second;
    }

    /// Number of distinct PCs stored.
    size_t size() const { return opcodes_.size(); }

    /// Iterator access for bulk operations.
    auto begin() const { return opcodes_.begin(); }
    auto end()   const { return opcodes_.end(); }

    /// Get all entries as a sorted vector (by PC).
    std::vector<std::pair<uint64_t, uint32_t>> all_entries() const {
        std::vector<std::pair<uint64_t, uint32_t>> result(opcodes_.begin(), opcodes_.end());
        std::sort(result.begin(), result.end());
        return result;
    }

private:
    ankerl::unordered_dense::map<uint64_t, uint32_t> opcodes_;
};

}  // namespace tenet
