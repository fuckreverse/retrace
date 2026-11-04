#pragma once

#include "io/index_builder.h"
#include "io/trace_reader.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace tenet {

// Owns copied INST bytes: references never depend on a compressed cache block
// remaining pinned. One indexed seek serves a window of backward queries.
class ReverseTraceWindow {
public:
    ReverseTraceWindow(const TraceReader& reader, const TraceIndex& index,
                       size_t window_insts = 4096, size_t max_bytes = 8u << 20)
        : reader_(reader), index_(index), tr_(reader.create_thread_reader(2)),
          window_insts_(std::max<size_t>(1, window_insts)), max_bytes_(std::max<size_t>(65536, max_bytes)) {}

    RecordView at(uint64_t inst_id) {
        if (inst_id < first_ || inst_id >= first_ + records_.size()) load(inst_id);
        auto entry = records_.at(static_cast<size_t>(inst_id - first_));
        entry.view.raw_ptr = bytes_.data() + entry.offset;
        entry.view.available_size = entry.size;
        return entry.view;
    }
    uint64_t window_loads() const { return loads_; }
    size_t buffered_bytes() const { return bytes_.size(); }
private:
    struct Entry { RecordView view; size_t offset, size; };
    void load(uint64_t target) {
        // Refill backwards, shrinking the window if unusually large records
        // exceed the byte budget. The target is always included.
        uint64_t start = target >= window_insts_ - 1 ? target - window_insts_ + 1 : 0;
        for (;;) {
            records_.clear(); bytes_.clear();
            auto off = index_.offset_of_with_pc(start, reader_);
            auto it = TraceReader::Iterator(&reader_, off.offset, off.seed_pc, &tr_);
            uint64_t id = start;
            bool overflow = false;
            for (; it != reader_.end() && id <= target; ++it) {
                const auto rec = *it;
                if (rec.kind != RecordKind::Inst) continue;
                const auto n = rec.as_inst().byte_size();
                if (bytes_.size() + n > max_bytes_ && start < target) { overflow = true; break; }
                const auto pos = bytes_.size();
                bytes_.resize(pos + n);
                std::memcpy(bytes_.data() + pos, rec.raw_ptr, n);
                records_.push_back({rec, pos, n});
                ++id;
            }
            if (overflow) { start = start + (target - start + 1) / 2; continue; }
            if (id <= target) throw std::runtime_error("reverse window: instruction outside trace");
            first_ = start; ++loads_; return;
        }
    }
    const TraceReader& reader_;
    const TraceIndex& index_;
    TraceReader::ThreadReader tr_;
    size_t window_insts_, max_bytes_;
    uint64_t first_ = UINT64_MAX, loads_ = 0;
    std::vector<Entry> records_;
    std::vector<uint8_t> bytes_;
};
}
