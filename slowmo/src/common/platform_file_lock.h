#pragma once

// ─── tenet cross-platform advisory exclusive file lock ──────────────────────
//
// Thin, non-reentrant wrapper around the platform's "advisory exclusive,
// non-blocking, auto-released on process death" file lock primitive:
//
//   POSIX   : flock(fd, LOCK_EX | LOCK_NB)
//   Windows : LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, ...)
//
// Both primitives share the crucial property that made flock the right
// choice in the first place (see trace_lock.h's original header comment):
// the lock is tied to the OS-level open-file object and is *guaranteed* to
// be released by the kernel when every handle referencing it is closed —
// including on crash / SIGKILL / TerminateProcess. There is never a stale
// "locked" file left behind by a dead process.
//
// This header only wraps the raw exclusive-lock primitive; the surrounding
// "write pid/host/mode for diagnostics" logic (trace_lock.cpp, mcp_hub.cpp)
// stays platform-independent by using tenet::platform::pid_t_compat and
// local_hostname() from platform_paths.h / platform_compat.h.

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/file.h>
#  include <unistd.h>
#  include <cerrno>
#endif

namespace tenet::platform {

/// RAII advisory exclusive file lock. Move-only.
class FileLock {
public:
    FileLock() = default;
    ~FileLock() { release(); }

    FileLock(FileLock&& other) noexcept { *this = std::move(other); }
    FileLock& operator=(FileLock&& other) noexcept {
        if (this != &other) {
            release();
#if defined(_WIN32)
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
#else
            fd_ = other.fd_;
            other.fd_ = -1;
#endif
            owns_lock_ = other.owns_lock_;
            other.owns_lock_ = false;
        }
        return *this;
    }
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;

    /// Result of a lock attempt.
    enum class Result {
        Acquired,      ///< lock is now held by this process
        HeldElsewhere, ///< another process holds it (non-blocking, would-block)
        IoError,       ///< could not even open/create the lock file
    };

    /// Opens (creating if needed) `path` and tries to acquire an exclusive,
    /// non-blocking lock on it. `path`'s parent directory must already
    /// exist (callers typically call platform::ensure_directory() first).
    static std::pair<FileLock, Result> try_acquire(const std::string& path) {
        FileLock lock;
#if defined(_WIN32)
        std::wstring wpath = utf8_to_wide(path);
        HANDLE h = ::CreateFileW(wpath.c_str(),
                                  GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE,  // allow others to open+read for diagnostics
                                  nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            return {std::move(lock), Result::IoError};
        }
        OVERLAPPED ov{};
        BOOL ok = ::LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                                0, MAXDWORD, MAXDWORD, &ov);
        if (!ok) {
            DWORD err = ::GetLastError();
            if (err == ERROR_LOCK_VIOLATION || err == ERROR_IO_PENDING) {
                lock.handle_ = h;
                return {std::move(lock), Result::HeldElsewhere};
            }
            ::CloseHandle(h);
            return {std::move(lock), Result::IoError};
        }
        lock.handle_ = h;
        lock.owns_lock_ = true;
        return {std::move(lock), Result::Acquired};
#else
        int fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0644);
        if (fd < 0) {
            return {std::move(lock), Result::IoError};
        }
        if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
            bool held = (errno == EWOULDBLOCK || errno == EAGAIN);
            if (held) {
                lock.fd_ = fd;
                return {std::move(lock), Result::HeldElsewhere};
            }
            ::close(fd);
            return {std::move(lock), Result::IoError};
        }
        lock.fd_ = fd;
        lock.owns_lock_ = true;
        return {std::move(lock), Result::Acquired};
#endif
    }

    bool valid() const {
#if defined(_WIN32)
        return handle_ != INVALID_HANDLE_VALUE;
#else
        return fd_ >= 0;
#endif
    }

    /// Read up to `size` bytes from offset 0 of the open lock file (used to
    /// read a previous holder's diagnostic payload before giving up, or to
    /// read back our own payload). Returns bytes read (0 on error/empty).
    size_t read_at_start(void* buf, size_t size) const {
#if defined(_WIN32)
        if (handle_ == INVALID_HANDLE_VALUE) return 0;
        OVERLAPPED ov{};
        DWORD n = 0;
        if (!::ReadFile(handle_, buf, static_cast<DWORD>(size), &n, &ov)) {
            // ReadFile with OVERLAPPED on a synchronous handle still usually
            // completes synchronously for local files; fall back to 0 on error.
            return 0;
        }
        return static_cast<size_t>(n);
#else
        if (fd_ < 0) return 0;
        ssize_t n = ::pread(fd_, buf, size, 0);
        return n > 0 ? static_cast<size_t>(n) : 0;
#endif
    }

    /// Truncate to zero and write `data` at offset 0, then flush to disk.
    /// Used to stamp diagnostic info (pid/host/mode/timestamp) once we hold
    /// the lock.
    bool write_at_start(const void* data, size_t size) {
#if defined(_WIN32)
        if (handle_ == INVALID_HANDLE_VALUE) return false;
        ::SetFilePointer(handle_, 0, nullptr, FILE_BEGIN);
        ::SetEndOfFile(handle_);
        DWORD written = 0;
        BOOL ok = ::WriteFile(handle_, data, static_cast<DWORD>(size), &written, nullptr);
        ::FlushFileBuffers(handle_);
        return ok && written == size;
#else
        if (fd_ < 0) return false;
        ::ftruncate(fd_, 0);
        ssize_t n = ::pwrite(fd_, data, size, 0);
        ::fsync(fd_);
        return n == static_cast<ssize_t>(size);
#endif
    }

    void release() {
#if defined(_WIN32)
        if (handle_ != INVALID_HANDLE_VALUE) {
            if (owns_lock_) {
                ::SetFilePointer(handle_, 0, nullptr, FILE_BEGIN);
                ::SetEndOfFile(handle_);
                OVERLAPPED ov{};
                ::UnlockFileEx(handle_, 0, MAXDWORD, MAXDWORD, &ov);
            }
            ::CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            owns_lock_ = false;
        }
#else
        if (fd_ >= 0) {
            if (owns_lock_) {
                ::ftruncate(fd_, 0);  // best-effort: don't leave stale payload for next reader
                ::flock(fd_, LOCK_UN);
            }
            ::close(fd_);
            fd_ = -1;
            owns_lock_ = false;
        }
#endif
    }

private:
#if defined(_WIN32)
    static std::wstring utf8_to_wide(const std::string& s) {
        if (s.empty()) return std::wstring();
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        std::wstring w(static_cast<size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
        return w;
    }
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
    bool owns_lock_ = false;
};

}  // namespace tenet::platform
