#pragma once

// ─── tenet cross-platform user paths ────────────────────────────────────────
//
// Centralizes "where does tenet keep its per-user config/state files"
// (previously duplicated ad-hoc across recent_files.cpp, vm_profiles.cpp,
// mcp_hub.h, trace_lock usage sites, main.cpp) into a
// single set of helpers, with sane per-platform defaults:
//
//   Windows     : %APPDATA%\tenet\ (falls back to %TEMP%\tenet\, then system temp)
//   macOS       : $HOME/Library/Application Support/tenet/ (falls back to system temp)
//   Linux/POSIX : absolute $XDG_CONFIG_HOME/tenet/, or $HOME/.config/tenet/
//                   (falls back to system temp)
//
// This mirrors the Rust `dirs::config_dir()` used by the Tauri frontend
// (tools/tenet/web/src-tauri/src/lib.rs) closely enough that both processes
// agree on where settings/recent.json live.

#include <cstdlib>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <unistd.h>
#endif

namespace tenet::platform {

/// Root directory for tenet's per-user config/state files. This function only
/// computes the path; call `ensure_directory()` when the directory must exist.
/// Equivalent to Rust `dirs::config_dir().join("tenet")`.
inline std::filesystem::path user_config_dir() {
    std::filesystem::path base;
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata && appdata[0] != '\0') {
        base = appdata;
    } else if (const char* temp = std::getenv("TEMP"); temp && temp[0] != '\0') {
        base = std::filesystem::path(temp);
    } else {
        base = std::filesystem::temp_directory_path();
    }
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME")) {
        base = std::filesystem::path(home) / "Library" / "Application Support";
    } else {
        base = std::filesystem::temp_directory_path();
    }
#else  // Linux and other POSIX
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    const std::filesystem::path xdg_path = xdg ? std::filesystem::path(xdg) : std::filesystem::path{};
    if (xdg && xdg[0] != '\0' && xdg_path.is_absolute()) {
        base = xdg_path;
    } else if (const char* home = std::getenv("HOME")) {
        base = std::filesystem::path(home) / ".config";
    } else {
        base = std::filesystem::temp_directory_path();
    }
#endif
    return base / "tenet";
}

/// Ensures `dir` exists (creates all missing parent directories). Returns
/// true on success or if it already exists; false on I/O error (non-fatal
/// for callers — they should degrade gracefully, e.g. skip persistence).
inline bool ensure_directory(const std::filesystem::path& dir) {
    std::error_code ec;
    if (std::filesystem::exists(dir, ec)) return true;
    return std::filesystem::create_directories(dir, ec) || !ec;
}

/// A directory suitable for scratch/lock files that don't need to survive
/// reboots (used by RpcServer's default socket path, MCP hub lock dir, etc).
inline std::filesystem::path temp_dir() {
    return std::filesystem::temp_directory_path();
}

/// Local hostname, best-effort (used for diagnostics only, e.g. trace lock
/// holder info) — never used to make correctness decisions.
inline std::string local_hostname() {
    char buf[256] = {};
#if defined(_WIN32)
    DWORD len = sizeof(buf);
    if (::GetComputerNameA(buf, &len)) return std::string(buf, len);
    return "unknown-host";
#else
    if (::gethostname(buf, sizeof(buf) - 1) != 0) return "unknown-host";
    return std::string(buf);
#endif
}

}  // namespace tenet::platform
