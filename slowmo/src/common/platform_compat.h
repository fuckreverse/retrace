#pragma once

// ─── tenet cross-platform socket/process compatibility shim ────────────────
//
// This header centralizes the small but pervasive POSIX/Winsock differences
// (socket handle type, close(), send() flags, errno access, process id) so
// that call sites in rpc_server.cpp / mcp_hub.cpp / mcp_http_sse.cpp /
// mcp_http.cpp can stay almost textually identical across platforms instead
// of scattering `#ifdef _WIN32` everywhere.
//
// It intentionally does NOT try to abstract away the whole BSD sockets API
// (bind/listen/accept/send/recv/select/poll signatures are close enough
// between Winsock and POSIX to use directly) — only the handful of points
// where the two diverge:
//
//   - socket handle type:      int (POSIX)          vs SOCKET (Winsock, unsigned)
//   - invalid handle value:    -1                    vs INVALID_SOCKET
//   - close:                   ::close(fd)           vs ::closesocket(fd)
//   - "don't raise SIGPIPE":   MSG_NOSIGNAL flag      vs not needed (no SIGPIPE on Windows)
//   - last error:              errno                  vs WSAGetLastError()
//   - non-blocking mode:       fcntl(O_NONBLOCK)      vs ioctlsocket(FIONBIO)
//   - process id type:         pid_t                  vs DWORD
//   - global init/teardown:    none needed             vs WSAStartup/WSACleanup
//
// Usage: include this header instead of <sys/socket.h> etc. directly, and
// replace raw ::close(fd) on a socket fd with tenet::platform::close_socket(fd).

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <poll.h>
#  include <errno.h>
#  include <signal.h>   // kill()
#  include <cstring>    // strerror()
#endif

// ssize_t is POSIX-only; MSVC's CRT has no signed size type (MinGW does
// provide one via sys/types.h, so guard on _MSC_VER specifically rather
// than _WIN32). Declared at global scope (matching POSIX) so existing call
// sites that write `ssize_t n = ::recv(...)` keep compiling unmodified.
#if defined(_MSC_VER) && !defined(_SSIZE_T_DEFINED)
#  include <basetsd.h>
using ssize_t = SSIZE_T;
#  define _SSIZE_T_DEFINED
#endif

namespace tenet::platform {

// ─── Socket handle type ─────────────────────────────────────────────────────

#if defined(_WIN32)
using socket_t = SOCKET;
inline constexpr socket_t kInvalidSocket = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t kInvalidSocket = -1;
#endif

inline bool socket_valid(socket_t s) { return s != kInvalidSocket; }

// ─── socklen_t equivalent for accept()/getsockname()/getsockopt() ─────────
//
// POSIX and Winsock both accept a pointer to an integer length, but the
// integer type differs (socklen_t vs int) and MSVC has no socklen_t at
// all (MinGW's <ws2tcpip.h> does typedef one, but don't rely on that).
// Use this type for the length out-param at every call site instead of
// each .cpp guessing socklen_t vs int under its own #ifdef.

#if defined(_WIN32)
using socklen_compat_t = int;
#else
using socklen_compat_t = socklen_t;
#endif

// ─── send() flag that suppresses SIGPIPE on POSIX (no-op on Windows,
//     which never raises SIGPIPE for socket sends) ─────────────────────────

#if defined(_WIN32)
inline constexpr int kNoSignal = 0;
#elif defined(MSG_NOSIGNAL)
inline constexpr int kNoSignal = MSG_NOSIGNAL;
#else
inline constexpr int kNoSignal = 0;  // macOS: no MSG_NOSIGNAL — SIGPIPE is
                                      // globally ignored by
                                      // ensure_sockets_initialized() instead
                                      // (see below), since SO_NOSIGPIPE
                                      // would have to be set on every
                                      // individual socket right after
                                      // creation and it's easy to miss one.
#endif

// ─── close a socket handle (NOT a regular file descriptor) ─────────────────

inline void close_socket(socket_t s) {
    if (!socket_valid(s)) return;
#if defined(_WIN32)
    ::closesocket(s);
#else
    ::close(s);
#endif
}

// ─── shutdown both directions ──────────────────────────────────────────────

inline void shutdown_both(socket_t s) {
    if (!socket_valid(s)) return;
#if defined(_WIN32)
    ::shutdown(s, SD_BOTH);
#else
    ::shutdown(s, SHUT_RDWR);
#endif
}

// ─── set a socket to non-blocking mode ─────────────────────────────────────

inline bool set_nonblocking(socket_t s) {
#if defined(_WIN32)
    u_long mode = 1;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

// ─── set a socket back to blocking mode ────────────────────────────────────
//
// Used by the "temporarily non-blocking connect() with a poll-based
// timeout" pattern: set_nonblocking() -> connect() -> poll for writable ->
// set_blocking() to restore the socket's default blocking semantics for
// the rest of its lifetime.

inline bool set_blocking(socket_t s) {
#if defined(_WIN32)
    u_long mode = 0;
    return ::ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return ::fcntl(s, F_SETFL, flags & ~O_NONBLOCK) == 0;
#endif
}

// ─── setsockopt() wrappers ──────────────────────────────────────────────
//
// Winsock's setsockopt() signature takes `const char*` for optval instead
// of POSIX's `const void*`, so passing an `int*`/`struct timeval*`
// directly does not compile under MSVC. Centralize the handful of options
// actually used by tenet's servers here instead of scattering
// reinterpret_cast<const char*> + #ifdef at each call site.

/// SO_REUSEADDR (POSIX) — lets a restarted server rebind a port still in
/// TIME_WAIT. Not set on Windows: Windows' SO_REUSEADDR has looser
/// semantics than POSIX's (it permits multiple *unrelated* sockets to bind
/// the same address concurrently, not just "rebind after close"), so we
/// deliberately skip it there rather than introduce a security-relevant
/// behavior difference; loopback-only listeners rebinding immediately
/// after a clean stop() is rare enough that the OS's default TIME_WAIT
/// handling is acceptable.
inline bool set_reuseaddr(socket_t s) {
#if defined(_WIN32)
    (void)s;
    return true;
#else
    int one = 1;
    return ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0;
#endif
}

/// SO_RCVTIMEO — receive timeout in milliseconds. POSIX takes a
/// `struct timeval`; Winsock takes a plain DWORD milliseconds count, so
/// the two aren't just a pointer-cast apart — the payload differs too.
inline bool set_keepalive(socket_t s) {
    int enabled = 1;
    return ::setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
                       reinterpret_cast<const char*>(&enabled), sizeof(enabled)) == 0;
}

inline bool set_recv_timeout(socket_t s, int timeout_ms) {
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(timeout_ms);
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                         reinterpret_cast<const char*>(&tv), sizeof(tv)) == 0;
#else
    struct timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
#endif
}

// ─── poll() a single socket for readability/writability ───────────────────
//
// POSIX poll() and Winsock WSAPoll() share the same `struct pollfd` layout
// and POLLIN/POLLOUT flag values, but the function name differs. This
// wraps the common "wait on exactly one socket fd" pattern used throughout
// mcp_hub.cpp / mcp_http.cpp / mcp_http_sse.cpp / rpc_server.cpp so call
// sites don't need their own #ifdef.
//
// Returns: >0 if the requested event(s) fired, 0 on timeout, <0 on error
// (mirrors poll()/WSAPoll() return value semantics).

#if defined(_WIN32)
using pollfd_t = WSAPOLLFD;
inline constexpr short kPollIn  = POLLRDNORM;
inline constexpr short kPollOut = POLLWRNORM;
#else
using pollfd_t = struct pollfd;
inline constexpr short kPollIn  = POLLIN;
inline constexpr short kPollOut = POLLOUT;
#endif

inline int poll_one(socket_t fd, short events, int timeout_ms) {
    pollfd_t pfd{};
    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;
#if defined(_WIN32)
    return ::WSAPoll(&pfd, 1, timeout_ms);
#else
    return ::poll(&pfd, 1, timeout_ms);
#endif
}

// ─── last socket error (errno vs WSAGetLastError), stringified ─────────────

inline int last_socket_error() {
#if defined(_WIN32)
    return ::WSAGetLastError();
#else
    return errno;
#endif
}

inline std::string last_socket_error_string() {
#if defined(_WIN32)
    int err = ::WSAGetLastError();
    char buf[256] = {};
    ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                      nullptr, err, 0, buf, sizeof(buf), nullptr);
    return buf[0] ? std::string(buf) : ("WSA error " + std::to_string(err));
#else
    return std::string(::strerror(errno));
#endif
}

// ─── portable socket-error-code constants ──────────────────────────────────
//
// errno's EINTR/EAGAIN/EWOULDBLOCK/EINPROGRESS have differently-named
// Winsock counterparts returned via WSAGetLastError(), not errno (Windows
// has no separate "would block" vs "again" distinction — both map to
// WSAEWOULDBLOCK). Compare last_socket_error() against these instead of
// raw errno macros so socket error-handling call sites stay
// platform-agnostic.

#if defined(_WIN32)
inline constexpr int kEIntr       = WSAEINTR;
inline constexpr int kEAgain      = WSAEWOULDBLOCK;
inline constexpr int kEWouldBlock = WSAEWOULDBLOCK;
inline constexpr int kEInProgress = WSAEWOULDBLOCK;  // non-blocking connect() pending
#else
inline constexpr int kEIntr       = EINTR;
inline constexpr int kEAgain      = EAGAIN;
inline constexpr int kEWouldBlock = EWOULDBLOCK;
inline constexpr int kEInProgress = EINPROGRESS;
#endif

/// True if the last socket op merely needs a retry (interrupted or would
/// block) rather than a hard failure.
inline bool socket_error_is_retryable(int err) {
    return err == kEIntr || err == kEAgain || err == kEWouldBlock;
}

/// Loop send() until all `len` bytes are sent, a hard error occurs, or the
/// peer disconnects. TCP send() (POSIX and Winsock alike) may accept fewer
/// bytes than requested even on a blocking socket; callers that only send
/// once and ignore the return value can silently truncate the message.
/// Retries on EINTR instead of treating it as a hard failure.
inline bool send_all(socket_t s, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int chunk = static_cast<int>(std::min(len - sent, static_cast<size_t>(1 << 20)));
        int n = ::send(s, data + sent, chunk, kNoSignal);
        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && last_socket_error() == kEIntr) continue;
        return false;  // hard error or peer closed (n == 0)
    }
    return true;
}

// ─── process id (pid_t vs DWORD) ───────────────────────────────────────────

#if defined(_WIN32)
using pid_t_compat = DWORD;
#else
using pid_t_compat = pid_t;
#endif

inline pid_t_compat current_pid() {
#if defined(_WIN32)
    return ::GetCurrentProcessId();
#else
    return ::getpid();
#endif
}

/// Best-effort liveness probe. On POSIX this is kill(pid, 0); on Windows it
/// opens the process and checks it hasn't signalled/exited. This is only
/// ever used for *diagnostics* (e.g. "is the previous hub still alive"),
/// never to gate correctness-critical decisions — see trace_lock.h for why.
inline bool process_alive(pid_t_compat pid) {
#if defined(_WIN32)
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD exit_code = 0;
    bool alive = ::GetExitCodeProcess(h, &exit_code) && exit_code == STILL_ACTIVE;
    ::CloseHandle(h);
    return alive;
#else
    return ::kill(pid, 0) == 0;
#endif
}

// ─── Winsock global init/teardown (no-op on POSIX) ─────────────────────────
//
// Construct one WinsockGuard early in main() (or a function-local static)
// before creating any sockets; WSACleanup() runs automatically at process
// exit via the static's destructor. POSIX builds compile this to nothing.

struct WinsockGuard {
#if defined(_WIN32)
    bool ok = false;
    WinsockGuard() {
        WSADATA wsa;
        ok = (::WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
        if (!ok) {
            // Nothing sensible to do but leave `ok` false so callers can
            // at least log a diagnostic; every socket call made afterwards
            // will fail fast with WSANOTINITIALISED anyway.
            ::fprintf(stderr, "tenet: WSAStartup failed (err=%d)\n",
                      ::WSAGetLastError());
        }
    }
    ~WinsockGuard() { if (ok) ::WSACleanup(); }
#else
    bool ok = true;
    WinsockGuard() {
        // TCP sends to a peer that has already closed its end raise
        // SIGPIPE by default on POSIX, which terminates the whole process
        // unless every socket send() passes MSG_NOSIGNAL. Linux supports
        // that flag (see kNoSignal above); macOS does not define
        // MSG_NOSIGNAL at all, so instead ignore SIGPIPE process-wide here
        // — send()/write() will then just return -1/EPIPE like on Linux,
        // which is what all call sites already check for.
        ::signal(SIGPIPE, SIG_IGN);
    }
    ~WinsockGuard() = default;
#endif
    WinsockGuard(const WinsockGuard&) = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;
};

/// Call once before using any BSD-socket API. Idempotent, thread-safe
/// (Meyer's singleton). On POSIX this initializes global SIGPIPE handling;
/// on Windows it performs WSAStartup().
inline void ensure_sockets_initialized() {
    static WinsockGuard guard;
    (void)guard;
}

}  // namespace tenet::platform
