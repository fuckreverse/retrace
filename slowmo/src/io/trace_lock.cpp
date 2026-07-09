#include "io/trace_lock.h"
#include "common/logger.h"

#include <fmt/core.h>

#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <ctime>

namespace tenet {

namespace {

constexpr uint32_t kTraceLockMagic = 0x544c4b31;  // "TLK1"
constexpr const char* kLockFileName = "session.lock";

// Fixed-layout struct persisted to the lock file. Purely informational —
// see trace_lock.h for why this is never used to gate acquisition.
struct TraceLockFileData {
    uint32_t magic = kTraceLockMagic;
    pid_t    pid = 0;
    uint64_t opened_at_epoch = 0;   // seconds since epoch
    char     host[128] = {};
    char     mode[32] = {};
    char     trace_path[400] = {};
};

std::string local_hostname() {
    char buf[256] = {};
    if (::gethostname(buf, sizeof(buf) - 1) != 0) {
        return "unknown-host";
    }
    return std::string(buf);
}

std::string format_epoch(uint64_t epoch_secs) {
    std::time_t t = static_cast<std::time_t>(epoch_secs);
    std::tm tm_buf{};
    localtime_r(&t, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

}  // namespace

TraceFileLock::~TraceFileLock() {
    release();
}

TraceFileLock::TraceFileLock(TraceFileLock&& other) noexcept
    : lock_path_(std::move(other.lock_path_)), fd_(other.fd_) {
    other.fd_ = -1;
}

TraceFileLock& TraceFileLock::operator=(TraceFileLock&& other) noexcept {
    if (this != &other) {
        release();
        lock_path_ = std::move(other.lock_path_);
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

void TraceFileLock::release() {
    if (fd_ >= 0) {
        // Best-effort: truncate so a stale reader never sees a half-written
        // record from a previous session once we let go of the lock.
        ::ftruncate(fd_, 0);
        ::flock(fd_, LOCK_UN);
        ::close(fd_);
        fd_ = -1;
        LOG_INFO_M(log::Module::Io, "trace-lock: released {}", lock_path_);
    }
}

std::optional<TraceFileLock> TraceFileLock::try_acquire(
    const std::filesystem::path& index_dir,
    const std::string& trace_path,
    const std::string& mode,
    TraceLockHolderInfo* out_holder) {

    if (out_holder) *out_holder = TraceLockHolderInfo{};

    std::error_code ec;
    std::filesystem::create_directories(index_dir, ec);
    // If create_directories fails (e.g. read-only parent), open() below will
    // fail too and we report a soft, non-blocking failure (pid stays 0).

    std::string lock_path = (index_dir / kLockFileName).string();

    int fd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        LOG_WARN_M(log::Module::Io, "trace-lock: open({}) failed: {} — proceeding without a lock",
                   lock_path, strerror(errno));
        return std::nullopt;
    }

    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // Someone else holds the lock. Read their info for diagnostics
            // only — this has no bearing on the acquire/deny decision,
            // which was already made by the flock() call above.
            if (out_holder) {
                TraceLockFileData data{};
                ssize_t n = ::pread(fd, &data, sizeof(data), 0);
                if (n == static_cast<ssize_t>(sizeof(data)) && data.magic == kTraceLockMagic) {
                    out_holder->pid = data.pid;
                    out_holder->host = data.host;
                    out_holder->mode = data.mode;
                    out_holder->opened_at = format_epoch(data.opened_at_epoch);
                    out_holder->trace_path = data.trace_path;
                }
            }
            ::close(fd);
            return std::nullopt;
        }
        LOG_WARN_M(log::Module::Io, "trace-lock: flock({}) failed: {} — proceeding without a lock",
                   lock_path, strerror(errno));
        ::close(fd);
        return std::nullopt;
    }

    // We hold the lock — stamp our info for the next contender to read.
    TraceLockFileData data{};
    data.pid = ::getpid();
    data.opened_at_epoch = static_cast<uint64_t>(::time(nullptr));
    auto host = local_hostname();
    std::strncpy(data.host, host.c_str(), sizeof(data.host) - 1);
    std::strncpy(data.mode, mode.c_str(), sizeof(data.mode) - 1);
    std::strncpy(data.trace_path, trace_path.c_str(), sizeof(data.trace_path) - 1);

    ::ftruncate(fd, 0);
    ::pwrite(fd, &data, sizeof(data), 0);
    ::fsync(fd);

    LOG_INFO_M(log::Module::Io, "trace-lock: acquired {} (pid={}, mode={})",
               lock_path, data.pid, mode);

    TraceFileLock lock;
    lock.lock_path_ = std::move(lock_path);
    lock.fd_ = fd;
    return lock;
}

}  // namespace tenet
