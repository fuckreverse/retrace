#include "analysis/trace_collector.h"

#include <algorithm>

namespace tenet {

uint64_t TraceScanEngine::run(uint64_t start_inst_id, uint64_t end_inst_id) {
    uint64_t end = std::min(end_inst_id, inst_count_);
    if (end == 0) end = inst_count_;

    // Initialize collectors
    std::vector<TraceCollector*> active;
    active.reserve(collectors_.size());
    for (auto* c : collectors_) {
        if (c->begin(start_inst_id, end)) {
            active.push_back(c);
        }
    }

    if (active.empty()) return 0;

    // Advise sequential access for the mmap
    reader_.advise_sequential();

    uint64_t inst_id = 0;
    uint64_t processed = 0;
    uint64_t total = end - start_inst_id;
    bool cancelled = false;

    for (auto it = reader_.begin(); it != reader_.end() && inst_id < end; ++it) {
        auto rec = *it;

        switch (rec.kind) {
        case RecordKind::Inst: {
            if (inst_id >= start_inst_id) {
                auto inst = rec.as_inst();
                for (auto* c : active) {
                    c->on_inst(inst_id, inst);
                }
                processed++;

                if (progress_fn_ && (processed & 0xFFFF) == 0) {
                    progress_fn_(processed, total);
                }
                if (cancel_fn_ && (processed & 0x3FFF) == 0 && cancel_fn_()) {
                    cancelled = true;
                }
            }
            inst_id++;
            break;
        }
        case RecordKind::Code: {
            auto code = rec.as_code();
            for (auto* c : active) {
                c->on_code(code);
            }
            break;
        }
        case RecordKind::Svc: {
            if (inst_id >= start_inst_id) {
                auto svc = rec.as_svc();
                for (auto* c : active) {
                    c->on_svc(inst_id, svc);
                }
            }
            break;
        }
        case RecordKind::Event: {
            auto ev = rec.as_event();
            for (auto* c : active) {
                c->on_event(ev);
            }
            break;
        }
        default:
            break;
        }

        if (cancelled) break;
    }

    // Finalize collectors
    for (auto* c : active) {
        c->end();
    }

    reader_.advise_random();
    return processed;
}

}  // namespace tenet
