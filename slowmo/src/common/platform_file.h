#pragma once
#include <cstdio>
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#if defined(_WIN32)
#include <io.h>
#include <fcntl.h>
#include <share.h>
#include <sys/stat.h>
#include <atomic>
#include <process.h>
#else
#include <unistd.h>
#endif
namespace tenet::platform {
inline FILE* open_file(const std::filesystem::path& path, const char* mode) {
#if defined(_WIN32)
    std::wstring wide_mode(mode, mode + std::char_traits<char>::length(mode));
    return ::_wfopen(path.c_str(), wide_mode.c_str());
#else
    return ::fopen(path.c_str(), mode);
#endif
}
inline int create_temp_file(const std::filesystem::path& directory, std::filesystem::path& path) {
#if defined(_WIN32)
    static std::atomic<unsigned long long> next{0};
    for (int attempt = 0; attempt < 128; ++attempt) {
        path = directory / (".tenet-decomp-" + std::to_string(::_getpid()) + "-" + std::to_string(next.fetch_add(1)));
        int fd = -1;
        auto error = ::_wsopen_s(&fd, path.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY,
                                _SH_DENYRW, _S_IREAD | _S_IWRITE);
        if (!error) return fd;
        if (error != EEXIST) { errno = error; return -1; }
    }
    errno = EEXIST;
    return -1;
#else
    auto pattern = (directory / ".tenet-decomp-XXXXXX").string();
    int fd = ::mkstemp(pattern.data());
    path = pattern;
    return fd;
#endif
}
inline bool write_file(int fd, const void* data, size_t size) {
    auto bytes = static_cast<const char*>(data);
    while (size) {
#if defined(_WIN32)
        int n = ::_write(fd, bytes, static_cast<unsigned int>(std::min<size_t>(size, 0x7fffffff)));
#else
        auto n = ::write(fd, bytes, size);
#endif
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        bytes += n;
        size -= static_cast<size_t>(n);
    }
    return true;
}
inline void close_file(int fd) {
#if defined(_WIN32)
    ::_close(fd);
#else
    ::close(fd);
#endif
}
} // namespace tenet::platform
