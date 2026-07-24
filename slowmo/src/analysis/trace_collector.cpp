#include "analysis/trace_collector.h"
#include "io/index_builder.h"

#include <algorithm>
#include <thread>
#include <atomic>
#include <cstring>

#include <sys/mman.h>

namespace tenet {

// ─── Raw pointer helpers ──────────────────────────────────────────────────
//
// raw_record_size() and fprdiff_byte_offset() are now shared from trace_reader.h.

namespace {

/// Determine hardware concurrency, capped to reasonable values.
inline unsigned worker_count() {
    unsigned n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    return std::min(n, 16u);
}

/// Per-shard boundary descriptor.
struct ScanShard {
    uint64_t file_start;
    uint64_t file_end;
    uint64_t start_inst_id;
    uint64_t end_inst_id;
};

/// Scan a shard and broadcast INST records to a set of collector clones.
/// Only on_inst() is called; non-INST records are skipped.
/// Uses a per-thread ThreadReader to avoid mutex contention on the shared cache.
void scan_shard_collectors(const ScanShard& shard, uint32_t num_gpr,
                           bool is_v5, bool is_v6, bool is_v7, bool is_v8,
                           const std::vector<TraceCollector*>& clones,
                           std::atomic<uint64_t>& progress_counter,
                           const TraceReader::ThreadReader& thread_reader,
                           const std::atomic<bool>* cancel_token,
                           const std::vector<std::pair<uint64_t, uint64_t>>& exclude_ranges) {
    uint64_t offset = shard.file_start;
    const uint64_t end_offset = shard.file_end;
    uint64_t inst_id = shard.start_inst_id;
    const size_t memacc_size = is_v6
        ? sizeof(qbditrace::qbditrace_memacc_v6_t)
        : sizeof(qbditrace::qbditrace_memacc_t);
    const size_t inst_hdr_sz = inst_header_size(is_v5, is_v7);
    const size_t fprdiff_sz = is_v7
        ? sizeof(qbditrace::qbditrace_fprdiff_t)          // 24 bytes
        : 0;
    const size_t fprdiff_offset = fprdiff_byte_offset(is_v5, is_v7);
    const bool has_excludes = !exclude_ranges.empty();

    while (offset < end_offset) {
        const uint8_t* ptr = thread_reader.data_at(offset);
        uint8_t kind = ptr[0];

        if (kind == 0) { // INST — hot path
            uint64_t pc;
            uint8_t nzcv_val;
            uint8_t n_regdiff;
            uint8_t n_mem;
            const uint8_t* raw_diffs;

            if (is_v7) {
                const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_v7_t*>(ptr);
                pc = hdr->pc;
                nzcv_val = hdr->nzcv;
                n_regdiff = hdr->n_regdiff;
                n_mem = hdr->n_mem;
                raw_diffs = ptr + inst_hdr_sz;
            } else {
                const auto* hdr = reinterpret_cast<const qbditrace::qbditrace_inst_head_t*>(ptr);
                pc = hdr->pc;
                nzcv_val = hdr->nzcv;
                n_regdiff = hdr->n_regdiff;
                n_mem = hdr->n_mem;
                raw_diffs = ptr + inst_hdr_sz;
            }

            bool excluded = false;
            if (has_excludes) {
                for (const auto& [start, end] : exclude_ranges) {
                    if (pc >= start && pc < end) { excluded = true; break; }
                }
            }

            uint8_t n_fprdiff = is_v7 ? ptr[fprdiff_offset] : 0;

            if (!excluded) {
                InstView inst;
                inst.pc = pc;
                inst.nzcv = nzcv_val;
                inst.reg_diff_count = n_regdiff;
                inst.mem_access_count = n_mem;
                inst.raw_diffs = raw_diffs;
                inst.raw_mems = raw_diffs + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                              + (is_v7 ? n_fprdiff * fprdiff_sz : 0);
                inst.is_v5 = false;
                inst.is_v6 = is_v6;
                inst.is_v7 = is_v7;
                inst.fpr_diff_count = n_fprdiff;
                inst.raw_fprdiffs = is_v7
                    ? (raw_diffs + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t))
                    : nullptr;

                for (auto* c : clones) {
                    c->on_inst(inst_id, inst);
                }
            }
            offset += inst_hdr_sz
                + n_regdiff * sizeof(qbditrace::qbditrace_regdiff_t)
                + n_fprdiff * fprdiff_sz
                + n_mem     * memacc_size;
            inst_id++;

            // Update shared progress counter every 64K instructions
            if ((inst_id & 0xFFFF) == 0) {
                progress_counter.fetch_add(0x10000, std::memory_order_relaxed);
                // Check for cancellation at the same cadence.
                if (cancel_token &&
                    cancel_token->load(std::memory_order_relaxed)) {
                    return;
                }
            }
        } else {
            // Non-INST record: skip using shared raw_record_size
            offset += raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
        }
    }

    // Flush remaining progress
    uint64_t remaining = inst_id & 0xFFFF;
    if (remaining > 0) {
        progress_counter.fetch_add(remaining, std::memory_order_relaxed);
    }
}

} // anonymous namespace

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

    // Create a thread-local reader for lock-free data access.
    // This gives us our own BlockCacheReader instance, eliminating contention
    // when multiple passes scan the trace concurrently.
    auto thread_reader = reader_.create_thread_reader(16);

    uint64_t inst_id = 0;
    uint64_t processed = 0;
    uint64_t total = end - start_inst_id;
    bool cancelled = false;

    const uint32_t num_gpr = reader_.header().num_gpr;

    for (auto it = reader_.begin(thread_reader); it != reader_.end(thread_reader) && inst_id < end; ++it) {
        auto rec = *it;

        switch (rec.kind) {
        case RecordKind::Inst: {
            if (inst_id >= start_inst_id) {
                auto inst = rec.as_inst();
                if (exclude_pc_ranges_.empty() || !is_pc_excluded(inst.pc)) {
                    for (auto* c : active) {
                        c->on_inst(inst_id, inst);
                    }
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
        case RecordKind::Anchor: {
            auto anchor = rec.as_anchor(num_gpr);
            for (auto* c : active) {
                c->on_anchor(inst_id, anchor);
            }
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
        case RecordKind::CapiCall: {
            if (inst_id >= start_inst_id) {
                auto capi = rec.as_capicall();
                for (auto* c : active) {
                    c->on_capicall(inst_id, capi);
                }
            }
            break;
        }
        case RecordKind::Objc: {
            if (inst_id >= start_inst_id) {
                auto objc = rec.as_objc();
                for (auto* c : active) {
                    c->on_objc(inst_id, objc);
                }
            }
            break;
        }
        case RecordKind::Retval: {
            if (inst_id >= start_inst_id) {
                auto retval = rec.as_retval();
                for (auto* c : active) c->on_retval(inst_id, retval);
            }
            break;
        }
        case RecordKind::Thread: {
            auto thread = rec.as_thread();
            for (auto* c : active) {
                c->on_thread(inst_id, thread);
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

uint64_t TraceScanEngine::run_parallel(uint64_t start_inst_id, uint64_t end_inst_id,
                                       unsigned num_threads) {
    uint64_t end = std::min(end_inst_id, inst_count_);
    if (end == 0) end = inst_count_;

    // ─── Classify collectors into parallel vs sequential ──────────────────
    std::vector<TraceCollector*> par_collectors;
    std::vector<TraceCollector*> seq_collectors;

    for (auto* c : collectors_) {
        if (c->supports_parallel() && c->clone() != nullptr) {
            par_collectors.push_back(c);
        } else {
            seq_collectors.push_back(c);
        }
    }

    bool is_v5 = (reader_.header().flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
    bool is_v6 = (reader_.header().flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
    bool is_v7 = (reader_.header().flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
    bool is_v8 = (reader_.header().flags & qbditrace::QBDITRACE_HF_CALL_META) != 0;

    // Fallback to sequential if: no parallel collectors, no index, small trace, or v5/v7 format
    if (par_collectors.empty() || index_ == nullptr ||
        inst_count_ < 50000 || is_v5 || is_v7) {
        return run(start_inst_id, end_inst_id);
    }

    // ─── Build shard boundaries using sparse offset index ─────────────────

    unsigned n_workers = num_threads;
    if (n_workers == 0) n_workers = worker_count();

    const uint32_t num_gpr = reader_.header().num_gpr;
    const uint64_t file_size = reader_.file_size();

    uint64_t insts_per_shard = (end - start_inst_id + n_workers - 1) / n_workers;

    std::vector<ScanShard> shards;
    shards.reserve(n_workers);

    for (unsigned i = 0; i < n_workers; i++) {
        uint64_t shard_start = start_inst_id + i * insts_per_shard;
        uint64_t shard_end = std::min(shard_start + insts_per_shard, end);
        if (shard_start >= end) break;

        uint64_t start_offset = index_->offset_of(shard_start, reader_);
        uint64_t end_offset;
        if (shard_end >= end) {
            end_offset = file_size;
        } else {
            end_offset = index_->offset_of(shard_end, reader_);
        }

        if (start_offset >= file_size) start_offset = file_size;
        if (end_offset > file_size) end_offset = file_size;
        if (start_offset >= end_offset) continue;

        ScanShard s;
        s.file_start = start_offset;
        s.file_end = end_offset;
        s.start_inst_id = shard_start;
        s.end_inst_id = shard_end;
        shards.push_back(s);
    }

    if (shards.empty()) {
        return run(start_inst_id, end_inst_id);
    }

    // ─── Phase 1: Initialize parallel collectors ──────────────────────────

    for (auto* c : par_collectors) {
        c->begin(start_inst_id, end);
    }

    // Create per-shard clones: clones[shard_idx][collector_idx]
    std::vector<std::vector<std::unique_ptr<TraceCollector>>> shard_clones(shards.size());
    // Raw pointers for inner loop (avoids unique_ptr overhead in hot path)
    std::vector<std::vector<TraceCollector*>> shard_clone_ptrs(shards.size());

    for (size_t s = 0; s < shards.size(); s++) {
        shard_clones[s].reserve(par_collectors.size());
        shard_clone_ptrs[s].reserve(par_collectors.size());
        for (auto* c : par_collectors) {
            auto cl = c->clone();
            shard_clone_ptrs[s].push_back(cl.get());
            shard_clones[s].push_back(std::move(cl));
        }
    }

    // ─── Phase 2: Parallel scan ───────────────────────────────────────────

    reader_.advise_sequential();

    std::atomic<uint64_t> progress_counter{0};
    uint64_t total = end - start_inst_id;

    std::vector<std::thread> threads;
    threads.reserve(shards.size() - 1);

    // Create per-shard ThreadReaders to eliminate mutex contention.
    std::vector<TraceReader::ThreadReader> thread_readers;
    thread_readers.reserve(shards.size());
    for (size_t i = 0; i < shards.size(); i++) {
        thread_readers.push_back(reader_.create_thread_reader(8));
    }

    // Launch worker threads for shards[1..N-1]
    const std::atomic<bool>* cancel_tok = cancel_token_;
    const auto& excludes = exclude_pc_ranges_;
    for (size_t i = 1; i < shards.size(); i++) {
        threads.emplace_back([&shards, &shard_clone_ptrs, &progress_counter, &thread_readers, &excludes, num_gpr, is_v5, is_v6, is_v7, is_v8, cancel_tok, i]() {
            scan_shard_collectors(shards[i], num_gpr, is_v5, is_v6, is_v7, is_v8, shard_clone_ptrs[i], progress_counter, thread_readers[i], cancel_tok, excludes);
        });
    }

    // Shard 0 on current thread
    scan_shard_collectors(shards[0], num_gpr, is_v5, is_v6, is_v7, is_v8, shard_clone_ptrs[0], progress_counter, thread_readers[0], cancel_tok, excludes);

    // Report progress while waiting
    if (progress_fn_) {
        progress_fn_(progress_counter.load(std::memory_order_relaxed), total);
    }

    // Wait for all workers
    for (auto& t : threads) t.join();

    // ─── Phase 3: Merge shard results ─────────────────────────────────────

    for (size_t ci = 0; ci < par_collectors.size(); ci++) {
        for (size_t s = 0; s < shards.size(); s++) {
            par_collectors[ci]->merge(*shard_clones[s][ci]);
        }
    }

    // Finalize parallel collectors
    for (auto* c : par_collectors) {
        c->end();
    }

    uint64_t processed = progress_counter.load(std::memory_order_relaxed);

    // ─── Phase 4: Sequential pass for non-parallel collectors ─────────────

    if (!seq_collectors.empty()) {
        // Temporarily replace collectors_ with just the sequential ones
        auto saved = std::move(collectors_);
        collectors_ = std::move(seq_collectors);
        processed = std::max(processed, run(start_inst_id, end_inst_id));
        collectors_ = std::move(saved);
    } else {
        reader_.advise_random();
    }

    return processed;
}

}  // namespace tenet
