#include "io/trace_lock.h"
#include "common/logger.h"
#include "common/platform_compat.h"
#include "common/platform_file_lock.h"
#include "common/platform_paths.h"

#include <fmt/core.h>

#include <cstdint>
#include <cstring>
#include <ctime>
#include <utility>

namespace tenet {

namespace {

constexpr uint32_t kTraceLockMagic = 0x544c4b31;  // "TLK1"
constexpr const char* kLockFileName = "session.lock";

// Fixed-layout struct persisted to the lock file. Purely informational —
// see trace_lock.h for why this is never used to gate acquisition.
struct TraceLockFileData {
    uint32_t magic = kTraceLockMagic;
    platform::pid_t_compat pid = 0;
    uint64_t opened_at_epoch = 0;   // seconds since epoch
    char host[128] = {};
    char mode[32] = {};
    char trace_path[400] = {};
};

std::string format_epoch(uint64_t epoch_secs) {
    std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm_buf{};
#if defined(_WIN32)
    if (::localtime_s(&tm_buf, &t) != 0) return {};
#else
    if (::localtime_r(&t, &tm_buf) == nullptr) return {};
#endif
    char buf[64] = {};
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) return {};
    return std::string(buf);
}

}  // namespace

TraceFileLock::~TraceFileLock() {
    release();
}

TraceFileLock::TraceFileLock(TraceFileLock&& other) noexcept
    : lock_path_(std::move(other.lock_path_)), lock_(std::move(other.lock_)) {}

TraceFileLock& TraceFileLock::operator=(TraceFileLock&& other) noexcept {
    if (this != &other) {
        release();
        lock_path_ = std::move(other.lock_path_);
        lock_ = std::move(other.lock_);
    }
    return *this;
}

void TraceFileLock::release() {
    if (lock_.valid()) {
        lock_.release();
        LOG_INFO_M(log::Module::Io, "trace-lock: released {}", lock_path_);
    }
}

std::optional<TraceFileLock> TraceFileLock::try_acquire(
    const std::filesystem::path& index_dir,
    const std::string& trace_path,
    const std::string& mode,
    TraceLockHolderInfo* out_holder) {

    if (out_holder) *out_holder = TraceLockHolderInfo{};

    // If directory creation fails (e.g. read-only parent), try_acquire below
    // fails too and we report a soft, non-blocking failure (pid stays 0).
    platform::ensure_directory(index_dir);

    std::string lock_path = (index_dir / kLockFileName).string();
    auto [file_lock, result] = platform::FileLock::try_acquire(lock_path);

    if (result == platform::FileLock::Result::HeldElsewhere) {
        // Someone else holds the lock. Read their info for diagnostics only —
        // this has no bearing on the acquire/deny decision, which was already
        // made by the platform lock attempt above.
        if (out_holder) {
            TraceLockFileData data{};
            size_t n = file_lock.read_at_start(&data, sizeof(data));
            if (n == sizeof(data) && data.magic == kTraceLockMagic) {
                out_holder->pid = data.pid;
                out_holder->host = data.host;
                out_holder->mode = data.mode;
                out_holder->opened_at = format_epoch(data.opened_at_epoch);
                out_holder->trace_path = data.trace_path;
            }
        }
        return std::nullopt;
    }

    if (result == platform::FileLock::Result::IoError) {
        LOG_WARN_M(log::Module::Io,
                   "trace-lock: acquiring {} failed — proceeding without a lock",
                   lock_path);
        return std::nullopt;
    }

    // We hold the lock — stamp our info for the next contender to read.
    TraceLockFileData data{};
    data.pid = platform::current_pid();
    data.opened_at_epoch = static_cast<uint64_t>(std::time(nullptr));
    auto host = platform::local_hostname();
    std::strncpy(data.host, host.c_str(), sizeof(data.host) - 1);
    std::strncpy(data.mode, mode.c_str(), sizeof(data.mode) - 1);
    std::strncpy(data.trace_path, trace_path.c_str(), sizeof(data.trace_path) - 1);

    file_lock.write_at_start(&data, sizeof(data));

    LOG_INFO_M(log::Module::Io, "trace-lock: acquired {} (pid={}, mode={})",
               lock_path, data.pid, mode);

    TraceFileLock lock;
    lock.lock_path_ = std::move(lock_path);
    lock.lock_ = std::move(file_lock);
    return lock;
}

}  // namespace tenet
