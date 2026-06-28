#pragma once

// ─── tenet profiling infrastructure ─────────────────────────────────────────
//
// Lightweight runtime instrumentation using Apple's os_signpost API.
// When TENET_ENABLE_PROFILING is defined and the target is macOS/iOS,
// macros expand to os_signpost calls that appear in Instruments.app
// (Points of Interest / os_signpost instrument). Otherwise they compile
// to nothing.
//
// Usage:
//   #include "common/Profiling.h"
//
//   void hot_function() {
//       TENET_ZONE;                         // auto-named zone (function name)
//       TENET_ZONE_NAMED("custom name");    // explicit name
//   }
//
//   void pass_entry() {
//       TENET_ZONE_NAMED("CfgPass::run");
//       ...
//   }
//
// Profile:
//   xcrun xctrace record --template 'Time Profiler' \
//       --output tenet.trace --launch -- ./tenet trace.bin
//   open tenet.trace
//
// The os_signpost intervals appear under "os_signpost" instrument or
// "Points of Interest" in Instruments, providing per-Pass timing with
// zero cost when not profiling (signposts are compiled in but only
// captured when Instruments is attached).
// ──────────────────────────────────────────────────────────────────────────────

#if defined(__APPLE__) && TENET_ENABLE_PROFILING

#include <os/log.h>
#include <os/signpost.h>

namespace tenet::profiling {

/// Subsystem log handle for all tenet signposts.
inline os_log_t log_handle() {
    // "OS_LOG_CATEGORY_POINTS_OF_INTEREST" makes these appear in Instruments
    // without needing to add the os_signpost instrument manually.
    static os_log_t handle = os_log_create("com.tenet.profiler", OS_LOG_CATEGORY_POINTS_OF_INTEREST);
    return handle;
}

/// Detailed log handle (shows under separate "tenet.detail" category).
inline os_log_t log_handle_detail() {
    static os_log_t handle = os_log_create("com.tenet.profiler", "detail");
    return handle;
}

/// RAII signpost interval — begins on construction, ends on destruction.
class SignpostInterval {
public:
    explicit SignpostInterval(const char* name, os_log_t log = log_handle())
        : log_(log), id_(os_signpost_id_generate(log)) {
        os_signpost_interval_begin(log_, id_, "tenet", "%s", name);
    }

    ~SignpostInterval() {
        os_signpost_interval_end(log_, id_, "tenet");
    }

    // Non-copyable, non-movable.
    SignpostInterval(const SignpostInterval&) = delete;
    SignpostInterval& operator=(const SignpostInterval&) = delete;

private:
    os_log_t log_;
    os_signpost_id_t id_;
};

}  // namespace tenet::profiling

// ─── Zone macros ────────────────────────────────────────────────────────────

/// Instrument the current scope. Zone name = function name.
#define TENET_ZONE \
    ::tenet::profiling::SignpostInterval _tenet_signpost_##__LINE__(__FUNCTION__)

/// Instrument with an explicit name (must be a string literal).
#define TENET_ZONE_NAMED(name) \
    ::tenet::profiling::SignpostInterval _tenet_signpost_named_##__LINE__(name)

/// Instrument with a color — on os_signpost there's no color concept,
/// so this is equivalent to TENET_ZONE_NAMED.
#define TENET_ZONE_COLOR(name, color) TENET_ZONE_NAMED(name)

// ─── No-op stubs for features without os_signpost equivalent ────────────────
// These were Tracy-specific and have no meaningful os_signpost counterpart.
// They remain as no-ops so existing call sites compile cleanly.

#define TENET_ZONE_TEXT(fmt_str, ...)    (void)0
#define TENET_ZONE_VALUE(val)           (void)0
#define TENET_FRAME_MARK                (void)0
#define TENET_FRAME_MARK_NAMED(name)    (void)0
#define TENET_ALLOC(ptr, size)          (void)0
#define TENET_FREE(ptr)                 (void)0
#define TENET_PLOT(name, val)           (void)0
#define TENET_MESSAGE(msg, len)         (void)0
#define TENET_MESSAGE_FMT(fmt_str, ...) (void)0

#else  // !(__APPLE__ && TENET_ENABLE_PROFILING)

// ─── No-op stubs (zero overhead) ─────────────────────────────────────────────

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

#endif  // __APPLE__ && TENET_ENABLE_PROFILING
