#pragma once

// ─── TraceFileLock: single-writer exclusivity for an open trace ──────────
//
// Problem: multiple tenet instances (GUI/TUI/batch/RPC/MCP) must not open
// the same trace file concurrently — they'd race on the same RocksDB index
// directory (RocksDB itself refuses a second DB::Open with an opaque low
// level LOCK-file error), and interactive mode assumes exclusive ownership
// of navigation/bookmark state persisted in the index's META column family.
//
// Design: advisory flock(2) on a small lock file kept inside the trace's
// index directory (`<trace>.tenet/session.lock`), i.e. "the trace's database
// directory" — so the lock always lives next to the data it protects and
// never touches the (possibly read-only) trace file itself.
//
// Why flock and not "PID in a file + kill(pid, 0)":
//   - flock's lock lives on the struct file* held by the kernel. It is
//     released automatically when every fd referencing it is closed —
//     which the kernel guarantees happens on process exit, *including*
//     crashes, SIGKILL, and OOM-killer termination. There is no window
//     where a dead process leaves a "locked" file behind.
//   - PID-based liveness checks are unreliable: PIDs are recycled by the
//     OS, so `kill(old_pid, 0)` can return "alive" for a completely
//     unrelated process that reused the PID after a crash, causing a false
//     "already open" report that never goes away without manual cleanup.
//
// The lock file's *contents* (pid, host, mode, timestamp) are therefore
// purely informational — used only to print a friendly diagnostic when
// try_acquire() fails. They are never used to decide whether the trace is
// actually in use; that decision is made solely by the flock() syscall
// result.

#include <sys/types.h>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace tenet {

/// Information about the process currently holding the lock, extracted
/// from the lock file for display purposes only (see header comment on
/// why this is never used to make the acquire/deny decision).
struct TraceLockHolderInfo {
    pid_t       pid = 0;
    std::string host;
    std::string mode;        ///< e.g. "gui", "tui", "batch", "rpc", "mcp"
    std::string opened_at;   ///< human-readable local time
    std::string trace_path;  ///< best-effort, for cross-checking
};

/// RAII holder for an acquired exclusive trace lock. Destroying this object
/// (or letting it go out of scope, including via unwind on any return path,
/// or the kernel closing the fd on process termination) releases the lock.
class TraceFileLock {
public:
    TraceFileLock() = default;
    ~TraceFileLock();

    TraceFileLock(TraceFileLock&& other) noexcept;
    TraceFileLock& operator=(TraceFileLock&& other) noexcept;

    TraceFileLock(const TraceFileLock&) = delete;
    TraceFileLock& operator=(const TraceFileLock&) = delete;

    /// Try to acquire the exclusive lock for a trace whose index directory
    /// is `index_dir` (created if missing). `mode` and `trace_path` are
    /// stored in the lock file purely for diagnostics shown to whoever
    /// fails to acquire the lock next.
    ///
    /// On success, returns an engaged TraceFileLock holding the lock for
    /// its entire lifetime.
    /// On failure (already held elsewhere), returns std::nullopt and fills
    /// `out_holder` with best-effort information about the current holder.
    /// On unexpected I/O error (e.g. cannot create the lock file), also
    /// returns std::nullopt with `out_holder` left at its default (pid==0);
    /// callers should treat that case as non-fatal and proceed without a
    /// lock rather than blocking normal usage on lock-file I/O issues.
    static std::optional<TraceFileLock> try_acquire(
        const std::filesystem::path& index_dir,
        const std::string& trace_path,
        const std::string& mode,
        TraceLockHolderInfo* out_holder);

    /// Explicitly release the lock early (also called by the destructor).
    void release();

    bool valid() const { return fd_ >= 0; }

private:
    std::string lock_path_;
    int fd_ = -1;
};

}  // namespace tenet
