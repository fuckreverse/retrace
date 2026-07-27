#include "streaming_index.h"

#include "io/index_builder.h"
#include "io/trace_reader.h"

#include <sys/stat.h>
#include <filesystem>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>
#include <optional>
#include <fcntl.h>
#include <unistd.h>

namespace tenet {

namespace {

std::optional<size_t> complete_record_size(const uint8_t* ptr, size_t remaining,
                                           uint32_t num_gpr, bool is_v5,
                                           bool is_v6, bool is_v7, bool is_v8) {
    const auto fits = [remaining](size_t size) { return size <= remaining; };
    if (remaining == 0) return std::nullopt;

    switch (ptr[0]) {
    case qbditrace::QBDITRACE_REC_INST: {
        const size_t header_size = inst_header_size(is_v5, is_v7);
        if (!fits(header_size)) return std::nullopt;
        break;
    }
    case qbditrace::QBDITRACE_REC_ANCHOR:
        return fits(sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + (is_v7 ? 32 * 16 : 0))
            ? std::optional<size_t>(sizeof(qbditrace::qbditrace_anchor_head_t) + num_gpr * 8 + (is_v7 ? 32 * 16 : 0)) : std::nullopt;
    case qbditrace::QBDITRACE_REC_THREAD:
        return fits(sizeof(qbditrace::qbditrace_thread_head_t)) ? std::optional<size_t>(sizeof(qbditrace::qbditrace_thread_head_t)) : std::nullopt;
    case qbditrace::QBDITRACE_REC_EVENT:
        return fits(sizeof(qbditrace::qbditrace_event_head_t)) ? std::optional<size_t>(sizeof(qbditrace::qbditrace_event_head_t)) : std::nullopt;
    case qbditrace::QBDITRACE_REC_SVC:
        return fits(sizeof(qbditrace::qbditrace_svc_head_t)) ? std::optional<size_t>(sizeof(qbditrace::qbditrace_svc_head_t)) : std::nullopt;
    case qbditrace::QBDITRACE_REC_OBJC:
        if (!fits(is_v8 ? sizeof(qbditrace::qbditrace_objc_head_v8_t) : sizeof(qbditrace::qbditrace_objc_head_t))) return std::nullopt;
        break;
    case qbditrace::QBDITRACE_REC_CODE:
        if (remaining < 2) return std::nullopt;
        break;
    case qbditrace::QBDITRACE_REC_CAPICALL: {
        const size_t header_size = is_v8 ? sizeof(qbditrace::qbditrace_capicall_head_v8_t) : sizeof(qbditrace::qbditrace_capicall_head_t);
        if (!fits(header_size)) return std::nullopt;
        const uint8_t str_count = is_v8 ? reinterpret_cast<const qbditrace::qbditrace_capicall_head_v8_t*>(ptr)->str_count : reinterpret_cast<const qbditrace::qbditrace_capicall_head_t*>(ptr)->str_count;
        size_t size = header_size;
        for (uint8_t i = 0; i < str_count; ++i) {
            if (remaining - size < sizeof(qbditrace::qbditrace_capicall_str_t)) return std::nullopt;
            const auto* string_header = reinterpret_cast<const qbditrace::qbditrace_capicall_str_t*>(ptr + size);
            size += sizeof(*string_header) + ((static_cast<size_t>(string_header->str_len) + 1u + 3u) & ~size_t{3});
            if (!fits(size)) return std::nullopt;
        }
        return size;
    }
    case qbditrace::QBDITRACE_REC_RETVAL:
        if (!fits(sizeof(qbditrace::qbditrace_retval_t))) return std::nullopt;
        break;
    case qbditrace::QBDITRACE_REC_MEMIMG:
        if (!fits(sizeof(qbditrace::qbditrace_memimg_t))) return std::nullopt;
        break;
    default:
        return size_t{1};
    }

    const size_t size = raw_record_size(ptr, num_gpr, is_v5, is_v6, is_v7, is_v8);
    return fits(size) ? std::optional<size_t>(size) : std::nullopt;
}

}  // namespace

// ─── StreamingIndex ───────────────────────────────────────────────────────

StreamingIndex::StreamingIndex() : cfg_({}) {}
StreamingIndex::StreamingIndex(const Config& cfg) : cfg_(cfg) {}

StreamingIndex::~StreamingIndex() {
    stop();
}

bool StreamingIndex::start(const std::string& trace_path,
                            TraceIndex& index,
                            StreamProgressCallback on_progress,
                            StreamCompleteCallback on_complete) {
    if (running_.load()) return false;

    on_progress_ = std::move(on_progress);
    on_complete_  = std::move(on_complete);
    stop_requested_.store(false);
    complete_.store(false, std::memory_order_release);

    // Seed inst_count from what TraceIndex already indexed
    inst_count_.store(index.inst_count(), std::memory_order_release);

    running_.store(true, std::memory_order_release);
    worker_ = std::thread([this, trace_path, &index] {
        tail_thread_func(trace_path, &index);
        running_.store(false, std::memory_order_release);
    });

    return true;
}

void StreamingIndex::stop() {
    stop_requested_.store(true, std::memory_order_release);
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool StreamingIndex::wait_for_inst(uint64_t target_id, uint32_t timeout_ms) const {
    if (inst_count_.load(std::memory_order_acquire) >= target_id) return true;

    std::unique_lock<std::mutex> lock(cv_mutex_);
    auto pred = [this, target_id] {
        return inst_count_.load(std::memory_order_acquire) >= target_id
            || !running_.load(std::memory_order_acquire);
    };

    if (timeout_ms == 0) {
        cv_.wait(lock, pred);
    } else {
        cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), pred);
    }
    return inst_count_.load(std::memory_order_acquire) >= target_id;
}

void StreamingIndex::tail_thread_func(const std::string& trace_path, TraceIndex* index) {
    // Track last known file size to detect new data
    uint64_t last_file_size = 0;
    {
        struct stat st{};
        if (::stat(trace_path.c_str(), &st) == 0) {
            last_file_size = static_cast<uint64_t>(st.st_size);
            file_bytes_seen_.store(last_file_size, std::memory_order_relaxed);
        }
    }

    using clock = std::chrono::steady_clock;
    auto last_growth = clock::now();
    uint64_t new_insts_since_last_index = 0;
    // The initial file contents were already indexed before start().  From
    // here on, this marks the first record that has not been fully validated
    // and accounted for.  It intentionally remains at an incomplete record
    // until a later poll contains all of that record's bytes.
    uint64_t record_checkpoint = last_file_size;

    while (!stop_requested_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(cfg_.poll_interval_ms));

        if (stop_requested_.load(std::memory_order_relaxed)) break;

        // Check current file size
        struct stat st{};
        if (::stat(trace_path.c_str(), &st) != 0) continue;

        uint64_t current_size = static_cast<uint64_t>(st.st_size);
        file_bytes_seen_.store(current_size, std::memory_order_relaxed);

        if (current_size <= last_file_size) {
            // No new data — check idle timeout
            auto idle = clock::now() - last_growth;
            auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(idle).count();
            if (idle_ms >= static_cast<long long>(cfg_.idle_timeout_ms)) {
                // Recording appears complete
                complete_.store(true, std::memory_order_release);
                cv_.notify_all();
                if (on_complete_) on_complete_();
                break;
            }
            continue;
        }

        last_growth = clock::now();
        uint64_t new_bytes = current_size - last_file_size;
        last_file_size = current_size;
        if (record_checkpoint > current_size) {
            record_checkpoint = current_size;
        }

        // Reopen TraceReader to see new bytes (it uses mmap — re-map needed)
        // For simplicity: run incremental scan over the new byte range.
        // In production this would use mremap() or POSIX file mapping extension.
        // Here we open the file raw and scan the new segment.
        {
            auto reader_result = TraceReader::open(trace_path);
            if (!reader_result) continue;
            auto& reader = *reader_result;

            // Rough estimate: 6 bytes per v5 INST record (header only, no diffs)
            // This tells us how many new instructions to expect, for batch logic
            uint64_t estimated_new_insts = new_bytes / 8;
            new_insts_since_last_index += estimated_new_insts;

            // Flush when batch size threshold reached
            if (new_insts_since_last_index >= cfg_.batch_size) {
                // Re-index incremental: TraceIndex doesn't currently support
                // incremental append, so we rebuild only the new suffix using
                // a lightweight counting scan.
                // Future: add TraceIndex::append_range(from_offset, to_offset)
                uint64_t prev_count = inst_count_.load(std::memory_order_relaxed);

                // Count new INST records in the new file segment.
                // Use raw_record_size() to correctly advance past each record
                // based on its kind (INST, ANCHOR, CODE, etc.) and the trace's
                // format flags (v4/v5/v6/v7). The previous fixed += 6 advance
                // (v5 minimum INST header) caused record desynchronization:
                // it would land in the middle of variable-length records,
                // miscount INST records, and silently corrupt the inst_count.
                const auto& hdr = reader.header();
                uint32_t num_gpr = hdr.num_gpr;
                bool is_v5 = (hdr.flags & qbditrace::QBDITRACE_HF_PC_DELTA) != 0;
                bool is_v6 = (hdr.flags & qbditrace::QBDITRACE_HF_OLD_VALUE) != 0;
                bool is_v7 = (hdr.flags & qbditrace::QBDITRACE_HF_HAS_FPR) != 0;
                bool is_v8 = (hdr.flags & qbditrace::QBDITRACE_HF_CALL_META) != 0;

                uint64_t new_inst_count = 0;
                uint64_t scan_offset = record_checkpoint;
                uint64_t file_end = reader.file_size();

                reader.pin_all();
                while (scan_offset < file_end) {
                    const uint8_t* rec_ptr = reader.data_at(scan_offset);
                    // Validate the fixed header, variable payload, and final record
                    // size before committing either count or checkpoint.
                    auto rec_size = complete_record_size(rec_ptr, file_end - scan_offset,
                                                         num_gpr, is_v5, is_v6, is_v7, is_v8);
                    if (!rec_size) break;

                    if (rec_ptr[0] == 0) {  // REC_INST
                        new_inst_count++;
                    }
                    scan_offset += *rec_size;
                    record_checkpoint = scan_offset;
                    if (cfg_.max_inst_count > 0 &&
                        prev_count + new_inst_count >= cfg_.max_inst_count) {
                        complete_.store(true, std::memory_order_release);
                        stop_requested_.store(true, std::memory_order_release);
                        break;
                    }
                }
                reader.unpin_all();

                uint64_t updated_count = prev_count + new_inst_count;
                inst_count_.store(updated_count, std::memory_order_release);
                new_insts_since_last_index = 0;

                cv_.notify_all();
                if (on_progress_) {
                    on_progress_(updated_count, current_size);
                }
            }
        }
    }

    // Final notification
    cv_.notify_all();
}

// ─── YaraRuleWatcher ─────────────────────────────────────────────────────

YaraRuleWatcher::YaraRuleWatcher(const std::string& dir,
                                  ReloadCallback cb,
                                  uint32_t poll_ms)
    : dir_(dir), cb_(std::move(cb)), poll_ms_(poll_ms) {}

YaraRuleWatcher::~YaraRuleWatcher() {
    stop();
}

void YaraRuleWatcher::start() {
    if (running_.load()) return;
    running_.store(true);
    worker_ = std::thread([this] { watch_thread_func(); });
}

void YaraRuleWatcher::stop() {
    running_.store(false);
    if (worker_.joinable()) worker_.join();
}

void YaraRuleWatcher::watch_thread_func() {
    namespace fs = std::filesystem;

    // Record initial mtimes
    std::unordered_map<std::string, fs::file_time_type> last_mtimes;
    auto snapshot = [&] {
        if (!fs::exists(dir_)) return;
        for (const auto& e : fs::directory_iterator(dir_)) {
            if (e.path().extension() == ".yar") {
                last_mtimes[e.path().string()] = e.last_write_time();
            }
        }
    };
    snapshot();

    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms_));
        if (!running_.load()) break;
        if (!fs::exists(dir_)) continue;

        bool changed = false;
        std::unordered_map<std::string, fs::file_time_type> current;
        for (const auto& e : fs::directory_iterator(dir_)) {
            if (e.path().extension() != ".yar") continue;
            auto p = e.path().string();
            auto mtime = e.last_write_time();
            current[p] = mtime;
            auto it = last_mtimes.find(p);
            if (it == last_mtimes.end() || it->second != mtime) {
                changed = true;
            }
        }
        // Check for deleted files
        for (const auto& [p, _] : last_mtimes) {
            if (current.find(p) == current.end()) changed = true;
        }

        if (changed) {
            last_mtimes = std::move(current);
            if (cb_) cb_();
        }
    }
}

// ─── unordered_map include for YaraRuleWatcher ──────────────────────────

}  // namespace tenet
