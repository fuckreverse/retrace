#pragma once

// ─── tenet lightweight logger ─────────────────────────────────────────────
//
// 设计目标
//   • 零开销（级别/模块不满足时无 fmt 调用）
//   • 方便定位时间/空间性能瓶颈：内置 ScopedTimer RAII
//   • 不干扰 stdout（CLI 分析结果走 stdout，日志走 stderr）
//   • 通过环境变量控制级别：TENET_LOG=0/1/2/3/4  (OFF/INFO/DEBUG/TRACE)
//     或 TENET_LOG=INFO / DEBUG / TRACE
//   • 通过环境变量控制模块过滤：TENET_LOG_MODULES=mcp,io,analysis
//     （逗号分隔白名单；不设置 = 全部模块开启，向后兼容）
//   • 线程安全（fmt+mutex 串行化写 stderr）
//   • 纯头文件，无需额外编译单元
//
// 快速开始（不区分模块，等价于 module=General，行为与之前完全一致）
//   #include "common/logger.h"
//
//   LOG_INFO("Loading trace: {}", path);
//   LOG_DEBUG("anchor_count={} inst_count={}", a, b);
//
// 带模块标签（推荐用于新代码，尤其是需要单独开关的子系统，如 MCP）
//   LOG_INFO_M(Module::Mcp, "tools/call {} in {:.1f}ms", tool_name, ms);
//   LOG_DEBUG_M(Module::Io, "index cache hit: {} instructions", n);
//
//   {
//       TENET_SCOPE_TIMER("xref_pass");     // 作用域结束时自动打印耗时
//       ...
//   }
//   auto mem = tenet::log::rss_mb();        // 进程当前 RSS（MB）
//
// 模块化过滤原则："不干扰，但必要"
//   • 默认（不设置 TENET_LOG_MODULES）：所有模块日志均按 TENET_LOG 级别输出，
//     行为与引入模块系统之前完全一致 —— 不给现有用户增加任何噪音。
//   • 需要聚焦某个子系统时（例如只看 MCP 请求处理），设置
//     TENET_LOG_MODULES=mcp 即可屏蔽其余模块的输出，无需重新编译。
//   • GUI 的 Output 面板始终接收全部模块的日志（不受 TENET_LOG_MODULES 过滤，
//     因为面板本身已提供级别/文本过滤 UI），环境变量只影响 stderr 输出。
// ──────────────────────────────────────────────────────────────────────────

#include <fmt/core.h>
#include <fmt/color.h>

#include <atomic>
#include <cctype>
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

// ─── Log module ─────────────────────────────────────────────────────────
//
// 按子系统划分日志来源，便于通过 TENET_LOG_MODULES 单独聚焦某个模块（例如
// 只看 MCP 请求处理，屏蔽 IO/Analysis 的海量索引构建日志）。新增模块时：
//   1. 在此枚举追加一项（保持 <= 31，位掩码用 uint32_t 存储）
//   2. 在 module_name()/module_from_name() 补充名称映射
//   3. 新代码用 LOG_*_M(Module::Xxx, ...) 打日志；老代码不受影响（General）
enum class Module : int {
    General  = 0,  ///< 未归类 / main.cpp 启动流程（默认，兼容旧调用）
    Mcp      = 1,  ///< MCP server：stdio/HTTP/SSE 传输、tools/call 请求处理
    Io       = 2,  ///< TraceReader、TraceIndex(RocksDB)、CodeTable 等 IO 层
    Core     = 3,  ///< RegisterFile、MemoryModel、TritonBridge 等核心层
    Analysis = 4,  ///< PassManager 及各 Pass（xref/taint/cfg/pattern/...）
    Gui      = 5,  ///< ImGui GUI（面板、渲染、交互）
    Tui      = 6,  ///< FTXUI TUI
    Batch    = 7,  ///< 批量分析 CLI（--taint/--export-cfg 等一次性命令）
    Count    = 8,  ///< 哨兵，模块总数
};

inline constexpr const char* module_name(Module m) {
    switch (m) {
        case Module::General:  return "general";
        case Module::Mcp:      return "mcp";
        case Module::Io:       return "io";
        case Module::Core:     return "core";
        case Module::Analysis: return "analysis";
        case Module::Gui:      return "gui";
        case Module::Tui:      return "tui";
        case Module::Batch:    return "batch";
        default:                return "?";
    }
}

/// Case-insensitive name → Module. Returns false if unrecognised.
inline bool module_from_name(std::string_view name, Module& out) {
    auto eq = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); i++)
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
                return false;
        return true;
    };
    for (int i = 0; i < static_cast<int>(Module::Count); i++) {
        auto m = static_cast<Module>(i);
        if (eq(name, module_name(m))) { out = m; return true; }
    }
    return false;
}

// ─── Global state (header-only singletons via inline) ─────────────────────

inline std::mutex& global_mutex() {
    static std::mutex m;
    return m;
}

inline std::atomic<Level>& global_level() {
    static std::atomic<Level> lv{Level::Off};
    return lv;
}

/// Bitmask of enabled modules (bit i = Module with value i). All-ones by
/// default so that, without TENET_LOG_MODULES, every module behaves exactly
/// like before the module system was introduced (no extra noise, no
/// surprises for existing users/scripts).
inline std::atomic<uint32_t>& module_mask() {
    static std::atomic<uint32_t> mask{0xFFFFFFFFu};
    return mask;
}

inline bool& initialized() {
    static bool flag = false;
    return flag;
}

inline bool is_module_enabled(Module m) {
    uint32_t mask = module_mask().load(std::memory_order_relaxed);
    return (mask & (1u << static_cast<int>(m))) != 0;
}

/// Enable only the given modules (whitelist). Call with an empty vector to
/// re-enable everything (default state).
inline void set_enabled_modules(const std::vector<Module>& mods) {
    if (mods.empty()) {
        module_mask().store(0xFFFFFFFFu, std::memory_order_relaxed);
        return;
    }
    uint32_t mask = 0;
    for (Module m : mods) mask |= (1u << static_cast<int>(m));
    module_mask().store(mask, std::memory_order_relaxed);
}

/// Parse TENET_LOG_MODULES (comma/space separated module names) into a mask.
/// Unset or empty => all modules enabled (0xFFFFFFFF). Unknown tokens are
/// ignored (keeps behavior forward-compatible with future module additions).
inline uint32_t module_mask_from_env() {
    const char* env = std::getenv("TENET_LOG_MODULES");
    if (!env || env[0] == '\0') return 0xFFFFFFFFu;

    uint32_t mask = 0;
    std::string_view sv(env);
    size_t start = 0;
    while (start <= sv.size()) {
        size_t end = sv.find_first_of(", \t", start);
        if (end == std::string_view::npos) end = sv.size();
        if (end > start) {
            std::string_view tok = sv.substr(start, end - start);
            Module m;
            if (module_from_name(tok, m)) mask |= (1u << static_cast<int>(m));
        }
        start = end + 1;
    }
    // If every token was unrecognised, fall back to "all enabled" rather
    // than silently going silent.
    return mask == 0 ? 0xFFFFFFFFu : mask;
}

// ─── GUI ring-buffer sink ─────────────────────────────────────────────────
// Collects log entries for the GUI log panel. Thread-safe.

struct LogEntry {
    Level       level;
    Module      module = Module::General;
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
/// Always captured regardless of TENET_LOG_MODULES (that env var only
/// affects the stderr sink) — the GUI panel provides its own module filter.
inline void gui_log_push(Level lv, Module mod, double ts, double mem, const std::string& msg) {
    std::lock_guard<std::mutex> lk(gui_log_mutex());
    auto& buf = gui_log_buffer();
    buf.push_back({lv, mod, ts, mem, msg});
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
/// Also parses TENET_LOG_MODULES (see module_mask_from_env()).
inline void init(Level default_level = Level::Info) {
    if (!initialized()) {
        initialized() = true;
        const char* env = std::getenv("TENET_LOG");
        Level lv = (env && env[0] != '\0') ? level_from_env() : default_level;
        global_level().store(lv, std::memory_order_relaxed);
        module_mask().store(module_mask_from_env(), std::memory_order_relaxed);
    }
}

/// Set the log level at runtime (e.g. from a GUI dropdown).
inline void set_level(Level lv) {
    global_level().store(lv, std::memory_order_relaxed);
}

inline bool is_enabled(Level lv) {
    return lv <= global_level().load(std::memory_order_relaxed);
}

inline bool is_enabled(Level lv, Module mod) {
    return is_enabled(lv) && is_module_enabled(mod);
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

// module_tag: e.g. "[mcp] " for non-General modules, empty for General so
// existing (non-modularized) log lines keep their exact original format.
inline std::string module_tag(Module mod) {
    if (mod == Module::General) return std::string();
    return fmt::format("[{}] ", module_name(mod));
}

template<typename... Args>
inline void write(Level lv, Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    std::string msg = fmt::format(fmt_str, std::forward<Args>(args)...);
    double t = wall_sec();
    double mem = rss_mb();
    // Always push to GUI ring buffer (regardless of stderr output / module filter)
    gui_log_push(lv, mod, t, mem, msg);
    // TENET_LOG_MODULES gates the stderr sink only — the GUI panel above
    // already received the entry and can filter independently.
    if (!is_module_enabled(mod)) return;
    std::lock_guard<std::mutex> lk(global_mutex());
    // Format: [+  0.123s  42.1MB] INFO  [mcp] <message>
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
    if (mod == Module::General) {
        fmt::print(stderr, "  {}\n", msg);
    } else {
        fmt::print(stderr, fmt::fg(fmt::color::gray), "  {}", module_tag(mod));
        fmt::print(stderr, "{}\n", msg);
    }
}

}  // namespace detail

/// Push a log entry from external code (e.g. MCP status, analysis events)
/// without going through the LOG_* macros. Always captured regardless of
/// the TENET_LOG environment variable level.
inline void gui_log_external(Level lv, const std::string& msg) {
    gui_log_push(lv, Module::General, detail::wall_sec(), rss_mb(), msg);
}

inline void gui_log_external(Level lv, Module mod, const std::string& msg) {
    gui_log_push(lv, mod, detail::wall_sec(), rss_mb(), msg);
}

// ── Module-less overloads: module = General (100% backward compatible) ────

template<typename... Args>
inline void error(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Error))
        detail::write(Level::Error, Module::General, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void warn(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Warn))
        detail::write(Level::Warn, Module::General, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void info(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Info))
        detail::write(Level::Info, Module::General, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void debug(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Debug))
        detail::write(Level::Debug, Module::General, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void trace(fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Trace))
        detail::write(Level::Trace, Module::General, fmt_str, std::forward<Args>(args)...);
}

// ── Module-tagged overloads: for new code (esp. MCP) that wants to be
//    selectively filterable via TENET_LOG_MODULES ─────────────────────────

template<typename... Args>
inline void error(Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Error, mod))
        detail::write(Level::Error, mod, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void warn(Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Warn, mod))
        detail::write(Level::Warn, mod, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void info(Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Info, mod))
        detail::write(Level::Info, mod, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void debug(Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Debug, mod))
        detail::write(Level::Debug, mod, fmt_str, std::forward<Args>(args)...);
}
template<typename... Args>
inline void trace(Module mod, fmt::format_string<Args...> fmt_str, Args&&... args) {
    if (is_enabled(Level::Trace, mod))
        detail::write(Level::Trace, mod, fmt_str, std::forward<Args>(args)...);
}

// ─── RAII scope timer ─────────────────────────────────────────────────────

/// Prints "scope_name done in X.XXXms (+Y.YMB)" on destruction.
/// Enabled only when level >= Info (and, if given, the module is enabled).
struct ScopedTimer {
    std::string_view name;
    Module           mod;
    TimePoint        t0;
    double           mem0;
    bool             active;

    explicit ScopedTimer(std::string_view n, Module m = Module::General)
        : name(n), mod(m), t0(now()), mem0(rss_mb()),
          active(is_enabled(Level::Info, m)) {
        if (active) {
            detail::write(Level::Info, mod, ">> {}", name);
        }
    }

    ~ScopedTimer() {
        if (!active) return;
        double ms  = elapsed_ms(t0);
        double mem1 = rss_mb();
        double dmem = mem1 - mem0;
        if (ms >= 1000.0) {
            detail::write(Level::Info, mod,
                "<< {} done in {:.3f}s  mem={:.1f}MB ({:+.1f}MB)",
                name, ms / 1000.0, mem1, dmem);
        } else {
            detail::write(Level::Info, mod,
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
//
// Two families:
//   LOG_INFO(...)              — module=General, identical to pre-existing
//                                 behavior (used by ~10 existing call sites).
//   LOG_INFO_M(Module::X, ...) — module-tagged, filterable via
//                                 TENET_LOG_MODULES=x. Use for new code.

#define LOG_ERROR(...) ::tenet::log::error(__VA_ARGS__)
#define LOG_WARN(...)  ::tenet::log::warn(__VA_ARGS__)
#define LOG_INFO(...)  ::tenet::log::info(__VA_ARGS__)
#define LOG_DEBUG(...) ::tenet::log::debug(__VA_ARGS__)
#define LOG_TRACE(...) ::tenet::log::trace(__VA_ARGS__)

#define LOG_ERROR_M(mod, ...) ::tenet::log::error((mod), __VA_ARGS__)
#define LOG_WARN_M(mod, ...)  ::tenet::log::warn((mod), __VA_ARGS__)
#define LOG_INFO_M(mod, ...)  ::tenet::log::info((mod), __VA_ARGS__)
#define LOG_DEBUG_M(mod, ...) ::tenet::log::debug((mod), __VA_ARGS__)
#define LOG_TRACE_M(mod, ...) ::tenet::log::trace((mod), __VA_ARGS__)

/// RAII scope timer: prints entry/exit with elapsed time and memory delta.
/// Usage: TENET_SCOPE_TIMER("my_operation");
#define TENET_SCOPE_TIMER(name) \
    ::tenet::log::ScopedTimer _scope_timer_##__LINE__{(name)}

/// Module-tagged RAII scope timer.
/// Usage: TENET_SCOPE_TIMER_M("tools/call:taint", ::tenet::log::Module::Mcp);
#define TENET_SCOPE_TIMER_M(name, mod) \
    ::tenet::log::ScopedTimer _scope_timer_##__LINE__{(name), (mod)}

/// One-shot timer: capture start time.
/// Usage: auto t = TENET_TIMER_START(); ... LOG_INFO("done in {:.1f}ms", TENET_TIMER_MS(t));
#define TENET_TIMER_START() ::tenet::log::now()
#define TENET_TIMER_MS(t0)  ::tenet::log::elapsed_ms(t0)
#define TENET_TIMER_SEC(t0) ::tenet::log::elapsed_sec(t0)
