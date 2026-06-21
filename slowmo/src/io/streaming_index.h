#pragma once

#include "common/types.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

namespace tenet {

// ─── StreamingIndex ───────────────────────────────────────────────────────
//
// Enables incremental / live trace analysis:
//
//   • qbditrace writes records to the trace file while the target runs.
//   • A background "tail" thread watches the file for new bytes.
//   • When enough new records arrive (batch_size), the tail thread calls
//     TraceIndex to index the new segment and notifies waiting consumers.
//   • Consumers call wait_for_inst(target_id) which blocks until at least
//     target_id instructions have been indexed — then returns immediately.
//
// This architecture lets the GUI/TUI start displaying the trace in real time
// even before the target process finishes, matching the UX of rr's
// "replay while recording" mode and QIRA's live trace display.
//
// Protocol for live recording:
//   1. qbditrace writes a special STREAM_START sentinel at offset 0 after
//      the file header (reserved byte in header: flags bit HF_STREAMING).
//   2. After each batch it writes a STREAM_CHECKPOINT sentinel with
//      (inst_count_so_far, file_offset_so_far).
//   3. When recording ends, qbditrace writes STREAM_END.
//
// StreamingIndex does NOT require qbditrace cooperation:
//   • It can also tail a *static* .bin file by polling file size and running
//     the incremental indexer on newly-appended bytes.
//   • For static files it degrades to a background indexer with progress.
//
// Thread safety:
//   • wait_for_inst() and inst_count() are thread-safe.
//   • stop() is thread-safe and idempotent.

/// Callback invoked by the streaming indexer when new records are processed.
/// Parameters: (indexed_inst_count, total_file_bytes_so_far)
using StreamProgressCallback = std::function<void(uint64_t, uint64_t)>;

/// Called when recording is complete (STREAM_END sentinel seen, or file
/// has not grown for `idle_timeout_ms` milliseconds).
using StreamCompleteCallback = std::function<void()>;

class StreamingIndex {
public:
    struct Config {
        /// How many new INST records to accumulate before triggering an
        /// incremental index flush. Smaller = lower latency, higher overhead.
        uint64_t batch_size = 1000;

        /// Poll interval for file size change (milliseconds).
        uint32_t poll_interval_ms = 100;

        /// If the file hasn't grown for this many ms, treat recording as done.
        uint32_t idle_timeout_ms = 3000;

        /// Maximum number of instructions to index (0 = unlimited).
        uint64_t max_inst_count = 0;
    };

    explicit StreamingIndex();
    explicit StreamingIndex(const Config& cfg);
    ~StreamingIndex();

    // Non-copyable
    StreamingIndex(const StreamingIndex&) = delete;
    StreamingIndex& operator=(const StreamingIndex&) = delete;

    // ── Lifecycle ─────────────────────────────────────────────────────

    /// Attach to a (possibly still-growing) trace file and start the tail thread.
    ///
    /// `index` must already be open (call TraceIndex::open_or_build() first;
    /// it will build from whatever bytes exist at open time, then this class
    /// handles new bytes as they arrive).
    ///
    /// Returns false if the file cannot be opened or the tail thread fails to start.
    bool start(const std::string& trace_path,
               TraceIndex& index,
               StreamProgressCallback on_progress = nullptr,
               StreamCompleteCallback on_complete = nullptr);

    /// Stop the tail thread. Blocks until the thread exits.
    void stop();

    // ── Consumer API ──────────────────────────────────────────────────

    /// Current number of indexed instructions (atomic, updated after each batch).
    uint64_t inst_count() const { return inst_count_.load(std::memory_order_acquire); }

    /// Block until at least `target_id` instructions have been indexed,
    /// or until `timeout_ms` elapses (0 = wait indefinitely).
    /// Returns true if target was reached; false on timeout or stop.
    bool wait_for_inst(uint64_t target_id, uint32_t timeout_ms = 0) const;

    /// Returns true once recording is considered complete (STREAM_END or idle).
    bool is_complete() const { return complete_.load(std::memory_order_acquire); }

    /// Returns true if the tail thread is running.
    bool is_running() const { return running_.load(std::memory_order_acquire); }

    /// Total file bytes seen so far (for progress display).
    uint64_t file_bytes_seen() const { return file_bytes_seen_.load(std::memory_order_relaxed); }

private:
    void tail_thread_func(const std::string& trace_path, TraceIndex* index);

    Config cfg_;
    std::atomic<uint64_t> inst_count_{0};
    std::atomic<uint64_t> file_bytes_seen_{0};
    std::atomic<bool>     complete_{false};
    std::atomic<bool>     running_{false};
    std::atomic<bool>     stop_requested_{false};

    mutable std::mutex              cv_mutex_;
    mutable std::condition_variable cv_;

    StreamProgressCallback on_progress_;
    StreamCompleteCallback on_complete_;
    std::thread            worker_;
};

// ─── Streaming YARA rule file watcher ────────────────────────────────────
// (Separate utility: watch a directory for new .yar files and reload rules.)

/// Watches a directory for new/modified .yar files.
/// When a change is detected, calls the reload callback.
class YaraRuleWatcher {
public:
    using ReloadCallback = std::function<void()>;

    explicit YaraRuleWatcher(const std::string& dir, ReloadCallback cb,
                              uint32_t poll_ms = 2000);
    ~YaraRuleWatcher();

    void start();
    void stop();

private:
    void watch_thread_func();

    std::string     dir_;
    ReloadCallback  cb_;
    uint32_t        poll_ms_;
    std::atomic<bool> running_{false};
    std::thread     worker_;
};

}  // namespace tenet
