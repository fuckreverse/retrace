#pragma once

// ─── tenet lightweight logger ─────────────────────────────────────────────
//
// 设计目标
//   • 零开销（级别不满足时无 fmt 调用）
//   • 方便定位时间/空间性能瓶颈：内置 ScopedTimer RAII
//   • 不干扰 stdout（CLI 分析结果走 stdout，日志走 stderr）
//   • 通过环境变量控制：TENET_LOG=0/1/2/3/4  (OFF/INFO/DEBUG/TRACE)
//     或 TENET_LOG=INFO / DEBUG / TRACE
//   • 线程安全（fmt+mutex 串行化写 stderr）
//   • 纯头文件，无需额外编译单元
//
// 快速开始
//   #include "common/logger.h"
//
//   LOG_INFO("Loading trace: {}", path);
//   LOG_DEBUG("anchor_count={} inst_count={}", a, b);
//   {
//       TENET_SCOPE_TIMER("xref_pass");     // 作用域结束时自动打印耗时
//       ...
//   }
//   auto mem = tenet::log::rss_mb();        // 进程当前 RSS（MB）
// ──────────────────────────────────────────────────────────────────────────

#include <fmt/core.h>
#include <fmt/color.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#if defined(__APPLE__)
#  include <mach/mach.h>
#elif defined(__linux__)
#  include <sys/resource.h>
#endif

namespace tenet {
namespace log {

// ─── Log level ────────────────────────────────────────────────────────────

enum class Level : int {
    Off   = 0,
    Error = 1,
    Warn  = 2,
    Info  = 3,
    Debug = 4,
    Trace = 5,
};

// ─── Global state (header-only singletons via inline) ─────────────────────

inline std::mutex& global_mutex() {
    static std::mutex m;
    return m;
}

inline std::atomic<Level>& global_level() {
    static std::atomic<Level> lv{Level::Off};
    return lv;
}

inline bool& initialized() {
    static bool flag = false;
    return flag;
}

// ─── GUI ring-buffer sink ─────────────────────────────────────────────────
// Collects log entries for the GUI log panel. Thread-safe.

struct LogEntry {
    Level       level;
    double      timestamp;   // seconds since first log call
    double      rss_mb;      // process RSS at log time
    std::string message;     // formatted message text
};

/// Access the GUI log buffer (singleton). Protected by gui_log_mutex().
inline std::deque<LogEntry>& gui_log_buffer() {
    static std::deque<LogEntry> buf;
    return buf;
}

inline std::mutex& gui_log_mutex() {
    static std::mutex m;
    return m;
}

/// Maximum entries kept in the GUI log buffer.
inline constexpr size_t kMaxGuiLogEntries = 4096;

/// Push a log entry into the GUI ring buffer (called from detail::write).
inline void gui_log_push(Level lv, double ts, double mem, const std::string& msg) {
    std::lock_guard<std::mutex> lk(gui_log_mutex());
    auto& buf = gui_log_buffer();
    buf.push_back({lv, ts, mem, msg});
    while (buf.size() > kMaxGuiLogEntries) {
        buf.pop_front();
    }
}

/// Drain all current entries from the GUI log buffer into `out`.
/// This is called on the UI thread each frame.
inline void gui_log_drain(std::vector<LogEntry>& out) {
    std::lock_guard<std::mutex> lk(gui_log_mutex());
    auto& buf = gui_log_buffer();
    out.insert(out.end(),
               std::make_move_iterator(buf.begin()),
               std::make_move_iterator(buf.end()));
    buf.clear();
}

// ─── Init from environment ────────────────────────────────────────────────

inline Level level_from_env() {
    const char* env = std::getenv("TENET_LOG");
    if (!env || env[0] == '\0') return Level::Off;

    // Numeric
    if (env[0] >= '0' && env[0] <= '9') {
        int v = std::atoi(env);
        if (v <= 0) return Level::Off;
        if (v == 1) return Level::Info;
        if (v == 2) return Level::Debug;
        return Level::Trace;  // 3+
    }

    // String (case-insensitive prefix match)
    if (std::strncmp(env, "TRACE", 5) == 0 || std::strncmp(env, "trace", 5) == 0)
        return Level::Trace;
    if (std::strncmp(env, "DEBUG", 5) == 0 || std::strncmp(env, "debug", 5) == 0)
        return Level::Debug;
    if (std::strncmp(env, "INFO",  4) == 0 || std::strncmp(env, "info",  4) == 0)
        return Level::Info;
    if (std::strncmp(env, "WARN",  4) == 0 || std::strncmp(env, "warn",  4) == 0)
        return Level::Warn;
    if (std::strncmp(env, "ERROR", 5) == 0 || std::strncmp(env, "error", 5) == 0)
        return Level::Error;

    return Level::Off;
}

/// Call once at startup (main.cpp). Also safe to call repeatedly.
/// \p default_level is used when TENET_LOG is not set (defaults to Info so
/// that the GUI log panel shows output without requiring an env variable).
inline void init(Level default_level = Level::Info) {
    if (!initialized()) {
        initialized() = true;
        const char* env = std::getenv("TENET_LOG");
        Level lv = (env && env[0] != '\0') ? level_from_env() : default_level;
        global_level().store(lv, std::memory_order_relaxed);
    }
}

/// Set the log level at runtime (e.g. from a GUI dropdown).
inline void set_level(Level lv) {
    global_level().store(lv, std::memory_order_relaxed);
}

inline bool is_enabled(Level lv) {
    return lv <= global_level().load(std::memory_order_relaxed);
}

// ─── Memory helpers ───────────────────────────────────────────────────────

/// Returns current process RSS in megabytes (approximate).
inline double rss_mb() {
#if defined(__APPLE__)
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
        return static_cast<double>(info.resident_size) / (1024.0 * 1024.0);
    }
#elif defined(__linux__)
    struct rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        // Linux: ru_maxrss is in kilobytes
        return static_cast<double>(usage.ru_maxrss) / 1024.0;
    }
#endif
    return 0.0;
}

// ─── Clock helpers ────────────────────────────────────────────────────────

using Clock     = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

inline TimePoint now() { return Clock::now(); }

inline double elapsed_ms(TimePoint t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

inline double elapsed_sec(TimePoint t0) {
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

// ─── Formatted write (thread-safe, to stderr) ─────────────────────────────

namespace detail {

inline const char* level_tag(Level lv) {
    switch (lv) {
        case Level::Error: return "ERROR";
        case Level::Warn:  return "WARN ";
        case Level::Info:  return "INFO ";
        case Level::Debug: return "DEBUG";
        case Level::Trace: return "TRACE";
        default:           return "     ";
    }
}

// Monotonic elapsed since first log call, in seconds (helps correlate events).
inline double wall_sec() {
    static auto t0 = Clock::now();
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

template<typename... Args>
inline void write(Level lv, fmt::format_string<Args...> fmt_str, Args&&... args) {
    std::string msg = fmt::format(fmt_str, std::forward<Args>(args)...);
    double t = wall_sec();
    double mem = rss_mb();
    // Always push to GUI ring buffer (regardless of stderr output)
    gui_log_push(lv, t, mem, msg);
    std::lock_guard<std::mutex> lk(global_mutex());
    // Format: [+  0.123s  42.1MB] INFO  <message>
    fmt::print(stderr, fmt::fg(fmt::color::gray),
               "[+{:7.3f}s {:6.1f}MB] ", t, mem);
    switch (lv) {
        case Level::Error:
            fmt::print(stderr, fmt::fg(fmt::color::red), "{}", level_tag(lv));
            break;
        case Level::Warn:
            fmt::print(stderr, fmt::fg(fmt::color::orange), "{}", level_tag(lv));
            break;
        case Level::Info:
            fmt::print(stderr, fmt::fg(fmt::color::cyan), "{}", level_tag(lv));
            break;
        case Level::Debug:
            fmt::print(stderr, fmt::fg(fmt::color::green), "{}", level_tag(lv));
            break;
        case Level::Trace:
            fmt::print(stderr, fmt::fg(fmt::color::silver), "{}", level_tag(lv));
            break;
        default:
            break;
    }
    fmt::print(stderr, "  {}\n", msg);
}

}  // namespace detail

/// Push a log entry from external code (e.g. MCP status, analysis events)
/// without going through the LOG_* macros. Always captured regardless of
/// the TENET_LOG environment variable level.
inline void gui_log_external(Level lv, const std::string& msg) {
    gui_log_push(lv, detail::wall_sec(), rss_mb(), msg);
}

template<typename... Args>
inline void error(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Error))
        detail::write(Level::Error, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void warn(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Warn))
        detail::write(Level::Warn, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void info(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Info))
        detail::write(Level::Info, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void debug(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Debug))
        detail::write(Level::Debug, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void trace(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Trace))
        detail::write(Level::Trace, fmt_str, std::forward<Args>(args)...);
}

// ─── RAII scope timer ─────────────────────────────────────────────────────

/// Prints "scope_name done in X.XXXms (+Y.YMB)" on destruction.
/// Enabled only when level >= Info.
struct ScopedTimer {
    std::string_view name;
    TimePoint        t0;
    double           mem0;
    bool             active;

    explicit ScopedTimer(std::string_view n)
        : name(n), t0(now()), mem0(rss_mb()),
          active(is_enabled(Level::Info)) {
        if (active) {
            detail::write(Level::Info, ">> {}", name);
        }
    }

    ~ScopedTimer() {
        if (!active) return;
        double ms  = elapsed_ms(t0);
        double mem1 = rss_mb();
        double dmem = mem1 - mem0;
        if (ms >= 1000.0) {
            detail::write(Level::Info,
                "<< {} done in {:.3f}s  mem={:.1f}MB ({:+.1f}MB)",
                name, ms / 1000.0, mem1, dmem);
        } else {
            detail::write(Level::Info,
                "<< {} done in {:.1f}ms  mem={:.1f}MB ({:+.1f}MB)",
                name, ms, mem1, dmem);
        }
    }

    // Non-copyable
    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;
};

}  // namespace log
}  // namespace tenet

// ─── Convenience macros ───────────────────────────────────────────────────

#define LOG_ERROR(...) ::tenet::log::error(__VA_ARGS__)
#define LOG_WARN(...)  ::tenet::log::warn(__VA_ARGS__)
#define LOG_INFO(...)  ::tenet::log::info(__VA_ARGS__)
#define LOG_DEBUG(...) ::tenet::log::debug(__VA_ARGS__)
#define LOG_TRACE(...) ::tenet::log::trace(__VA_ARGS__)

/// RAII scope timer: prints entry/exit with elapsed time and memory delta.
/// Usage: TENET_SCOPE_TIMER("my_operation");
#define TENET_SCOPE_TIMER(name) \
    ::tenet::log::ScopedTimer _scope_timer_##__LINE__{(name)}

/// One-shot timer: capture start time.
/// Usage: auto t = TENET_TIMER_START(); ... LOG_INFO("done in {:.1f}ms", TENET_TIMER_MS(t));
#define TENET_TIMER_START() ::tenet::log::now()
#define TENET_TIMER_MS(t0)  ::tenet::log::elapsed_ms(t0)
#define TENET_TIMER_SEC(t0) ::tenet::log::elapsed_sec(t0)
