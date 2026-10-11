#pragma once

// ─── tenet cross-platform read-only file mapping ────────────────────────────
//
// RAII wrapper around a read-only whole-file memory mapping. Replaces the
// hand-rolled open()/fstat()/mmap()/munmap()/close() sequences that used to
// be duplicated in trace_reader.cpp and code_table.cpp.
//
//   POSIX : open() + fstat() + mmap(PROT_READ, MAP_PRIVATE) + munmap()/close()
//   Windows: CreateFileW() + GetFileSizeEx() + CreateFileMappingW() +
//            MapViewOfFile(FILE_MAP_READ) + UnmapViewOfFile()/CloseHandle()
//
// Access-pattern hints (sequential / random) map to madvise() on POSIX and
// are a no-op on Windows (no exact equivalent for read-only file-backed
// views without PrefetchVirtualMemory, which needs Win8+ and a page list —
// not worth the complexity for a hint).

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  include <cerrno>
#  include <cstring>
#endif

namespace tenet::platform {

enum class AccessHint {
    Normal,
    Sequential,  ///< caller will read the mapping mostly front-to-back
    Random,      ///< caller will do lots of scattered random access
};

/// Read-only mapping of an entire file. Move-only, RAII.
class MappedFile {
public:
    MappedFile() = default;

    MappedFile(MappedFile&& other) noexcept { *this = std::move(other); }
    MappedFile& operator=(MappedFile&& other) noexcept {
        if (this != &other) {
            reset();
            data_ = other.data_;
            size_ = other.size_;
#if defined(_WIN32)
            file_handle_ = other.file_handle_;
            mapping_handle_ = other.mapping_handle_;
            other.file_handle_ = INVALID_HANDLE_VALUE;
            other.mapping_handle_ = nullptr;
#else
            fd_ = other.fd_;
            other.fd_ = -1;
#endif
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    ~MappedFile() { reset(); }

    /// Opens and maps `path` read-only. On failure, returns a default-
    /// constructed (invalid) MappedFile and fills `out_error` if non-null.
    static MappedFile open(const std::string& path, std::string* out_error = nullptr) {
        MappedFile m;
#if defined(_WIN32)
        // Widen path via MultiByteToWideChar-free simple conversion: paths in
        // this codebase are UTF-8; use the *W API with a manual conversion to
        // avoid pulling in extra dependencies.
        std::wstring wpath = utf8_to_wide(path);
        // Live traces keep growing while mapped; permit append writers and
        // the same rename/delete lifecycle available with POSIX mappings.
        HANDLE fh = ::CreateFileW(wpath.c_str(), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fh == INVALID_HANDLE_VALUE) {
            if (out_error) *out_error = "CreateFileW failed (err=" + std::to_string(::GetLastError()) + ")";
            return m;
        }
        LARGE_INTEGER sz{};
        if (!::GetFileSizeEx(fh, &sz)) {
            if (out_error) *out_error = "GetFileSizeEx failed";
            ::CloseHandle(fh);
            return m;
        }
        if (sz.QuadPart == 0) {
            // Zero-length files can't be mapped; treat as an empty-but-valid mapping.
            m.file_handle_ = fh;
            m.mapping_handle_ = nullptr;
            m.data_ = nullptr;
            m.size_ = 0;
            return m;
        }
        HANDLE mh = ::CreateFileMappingW(fh, nullptr, PAGE_READONLY,
                                          static_cast<DWORD>(sz.QuadPart >> 32),
                                          static_cast<DWORD>(sz.QuadPart & 0xFFFFFFFFu),
                                          nullptr);
        if (!mh) {
            if (out_error) *out_error = "CreateFileMappingW failed (err=" + std::to_string(::GetLastError()) + ")";
            ::CloseHandle(fh);
            return m;
        }
        void* base = ::MapViewOfFile(mh, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart));
        if (!base) {
            if (out_error) *out_error = "MapViewOfFile failed (err=" + std::to_string(::GetLastError()) + ")";
            ::CloseHandle(mh);
            ::CloseHandle(fh);
            return m;
        }
        m.file_handle_ = fh;
        m.mapping_handle_ = mh;
        m.data_ = base;
        m.size_ = static_cast<size_t>(sz.QuadPart);
        return m;
#else
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) {
            if (out_error) *out_error = std::string("open() failed: ") + ::strerror(errno);
            return m;
        }
        struct stat st{};
        if (::fstat(fd, &st) != 0) {
            if (out_error) *out_error = std::string("fstat() failed: ") + ::strerror(errno);
            ::close(fd);
            return m;
        }
        size_t size = static_cast<size_t>(st.st_size);
        if (size == 0) {
            m.fd_ = fd;
            m.data_ = nullptr;
            m.size_ = 0;
            return m;
        }
        void* base = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (base == MAP_FAILED) {
            if (out_error) *out_error = std::string("mmap() failed: ") + ::strerror(errno);
            ::close(fd);
            return m;
        }
        m.fd_ = fd;
        m.data_ = base;
        m.size_ = size;
        return m;
#endif
    }

    bool valid() const {
#if defined(_WIN32)
        return file_handle_ != INVALID_HANDLE_VALUE;
#else
        return fd_ >= 0;
#endif
    }

    const uint8_t* data() const { return static_cast<const uint8_t*>(data_); }
    size_t size() const { return size_; }

    /// Advise the OS about the intended access pattern. Best-effort; failures
    /// are silently ignored (this is purely a performance hint).
    ///
    /// Uses posix_madvise()/POSIX_MADV_* rather than the BSD madvise()/MADV_*
    /// pair: the latter's constants are gated behind
    /// `!defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)` in Apple's
    /// <sys/mman.h> (and are simply absent in strict-POSIX glibc builds), so
    /// they can silently disappear depending on which headers a translation
    /// unit happens to pull in first (e.g. via a third-party dependency that
    /// defines _POSIX_C_SOURCE). posix_madvise()/POSIX_MADV_* are plain POSIX
    /// and available unconditionally on both Linux and macOS.
    void advise(AccessHint hint) const {
        if (!data_ || size_ == 0) return;
#if !defined(_WIN32)
        int advice = POSIX_MADV_NORMAL;
        switch (hint) {
            case AccessHint::Sequential: advice = POSIX_MADV_SEQUENTIAL; break;
            case AccessHint::Random:     advice = POSIX_MADV_RANDOM;     break;
            default: break;
        }
        ::posix_madvise(data_, size_, advice);
#else
        (void)hint;  // No cheap equivalent for read-only mapped views; no-op.
#endif
    }

    void reset() {
#if defined(_WIN32)
        if (data_) ::UnmapViewOfFile(data_);
        if (mapping_handle_) ::CloseHandle(mapping_handle_);
        if (file_handle_ != INVALID_HANDLE_VALUE) ::CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        mapping_handle_ = nullptr;
#else
        if (data_ && size_ > 0) ::munmap(data_, size_);
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
#endif
        data_ = nullptr;
        size_ = 0;
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
    HANDLE file_handle_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle_ = nullptr;
#else
    int fd_ = -1;
#endif
    void* data_ = nullptr;
    size_t size_ = 0;
};

}  // namespace tenet::platform
