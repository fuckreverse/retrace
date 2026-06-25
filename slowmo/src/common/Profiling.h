#pragma once

// ─── tenet profiling infrastructure ─────────────────────────────────────────
//
// Compile-time integration with Tracy Profiler for low-overhead runtime
// performance instrumentation. When TENET_HAS_TRACY is defined and non-zero,
// all macros expand to actual Tracy calls (~2-5 ns per zone on M1); otherwise
// they compile to nothing.
//
// Usage:
//   #include "common/Profiling.h"
//
//   void hot_function() {
//       TENET_ZONE;                         // auto-named zone (function name)
//       TENET_ZONE_NAMED("custom name");    // explicit name
//       ...
//       TENET_ZONE_TEXT("processing inst #{}", inst_id);  // dynamic text
//   }
//
//   void alloc_heavy() {
//       auto* p = malloc(sz);
//       TENET_ALLOC(p, sz);                 // track allocation
//       free(p);
//       TENET_FREE(p);                      // track deallocation
//   }
//
//   TENET_FRAME_MARK;                       // mark GUI frame boundary
//
// Build:
//   cmake .. -DTENET_ENABLE_TRACY=ON        // enable (works with any build type)
//   cmake ..                                // disable (default, zero overhead)
//
// Connect:
//   Run the Tracy profiler GUI (https://github.com/wolfpld/tracy) and connect
//   to the tenet process for real-time visualization, or let it write a
//   .tracy capture file for offline analysis.
// ──────────────────────────────────────────────────────────────────────────────

#if TENET_HAS_TRACY

#include <tracy/Tracy.hpp>
#include <fmt/format.h>

// ─── Zone macros ────────────────────────────────────────────────────────────

/// Instrument the current scope with Tracy. Zone name = function name.
#define TENET_ZONE                  ZoneScoped

/// Instrument with an explicit name (must be a string literal).
#define TENET_ZONE_NAMED(name)      ZoneScopedN(name)

/// Instrument with a color (useful for distinguishing pass categories).
/// color is a 0xRRGGBB uint32_t.
#define TENET_ZONE_COLOR(name, color) ZoneScopedNC(name, color)

/// Attach dynamic text to the current zone (formatted string).
/// Example: TENET_ZONE_TEXT("inst_count={}", count);
/// Note: the text is only sent if a Tracy profiler is connected.
#define TENET_ZONE_TEXT(fmt_str, ...)                              \
    do {                                                           \
        auto _zt_str = fmt::format(fmt_str, ##__VA_ARGS__);       \
        ZoneText(_zt_str.c_str(), _zt_str.size());                \
    } while (0)

/// Attach a numeric value to the current zone for plotting.
#define TENET_ZONE_VALUE(val)       ZoneValue(static_cast<int64_t>(val))

// ─── Frame marks ────────────────────────────────────────────────────────────

/// Mark a frame boundary (GUI main loop).
#define TENET_FRAME_MARK            FrameMark

/// Mark a secondary frame boundary with a name (e.g. "render", "logic").
#define TENET_FRAME_MARK_NAMED(name) FrameMarkNamed(name)

// ─── Memory tracking ────────────────────────────────────────────────────────

/// Track a heap allocation.
#define TENET_ALLOC(ptr, size)      TracyAlloc(ptr, size)

/// Track a heap deallocation.
#define TENET_FREE(ptr)             TracyFree(ptr)

// ─── Plots (time-series values) ─────────────────────────────────────────────

/// Plot a named scalar value over time (e.g. RSS, queue depth).
#define TENET_PLOT(name, val)       TracyPlot(name, static_cast<double>(val))

// ─── Messages (log to Tracy timeline) ───────────────────────────────────────

/// Send a message to the Tracy timeline.
#define TENET_MESSAGE(msg, len)     TracyMessage(msg, len)

/// Send a formatted message.
#define TENET_MESSAGE_FMT(fmt_str, ...)                            \
    do {                                                           \
        auto _tm_str = fmt::format(fmt_str, ##__VA_ARGS__);       \
        TracyMessage(_tm_str.c_str(), _tm_str.size());            \
    } while (0)

// ─── Lockable wrappers ──────────────────────────────────────────────────────

/// Use TracyLockable(std::mutex) instead of std::mutex to track contention.
/// Example:
///   TracyLockable(std::mutex, my_mutex_);
///   std::lock_guard<LockableBase(std::mutex)> lock(my_mutex_);
// (These are already provided by Tracy.hpp, documented here for reference.)

#else  // !TENET_HAS_TRACY

// ─── No-op stubs (zero overhead when Tracy is disabled) ─────────────────────

#define TENET_ZONE                      (void)0
#define TENET_ZONE_NAMED(name)          (void)0
#define TENET_ZONE_COLOR(name, color)   (void)0
#define TENET_ZONE_TEXT(fmt_str, ...)    (void)0
#define TENET_ZONE_VALUE(val)           (void)0
#define TENET_FRAME_MARK                (void)0
#define TENET_FRAME_MARK_NAMED(name)    (void)0
#define TENET_ALLOC(ptr, size)          (void)0
#define TENET_FREE(ptr)                 (void)0
#define TENET_PLOT(name, val)           (void)0
#define TENET_MESSAGE(msg, len)         (void)0
#define TENET_MESSAGE_FMT(fmt_str, ...) (void)0

#endif  // TENET_HAS_TRACY
