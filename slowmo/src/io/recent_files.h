#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace tenet {

/// Metadata for one recently-opened trace file.
struct RecentEntry {
    std::string  path;          ///< Absolute path to the .bin trace file
    std::string  module_name;   ///< Module name from the trace header (for display)
    uint64_t     inst_count = 0; ///< Total instruction count
    int64_t      last_opened = 0; ///< Unix timestamp (seconds since epoch)
};

/// Manages the list of recently-opened trace files.
/// Entries are persisted to ~/.config/tenet/recent.json using JSON (nlohmann/json).
class RecentFiles {
public:
    static constexpr size_t MAX_ENTRIES = 20;

    /// Load the recent-files list from disk.
    /// Returns an empty list if the file does not exist or is malformed.
    static RecentFiles load();

    /// Save the recent-files list to disk.
    void save() const;

    /// Add or update an entry for `path`. Moves it to the front of the list.
    /// @param path         Absolute path to the trace file.
    /// @param module_name  Module name (from TraceReader header).
    /// @param inst_count   Total instruction count (from TraceIndex stats).
    void push(const std::string& path,
              const std::string& module_name,
              uint64_t inst_count);

    /// Remove an entry by path.
    void remove(const std::string& path);

    /// Read-only access to the sorted (most-recent-first) entry list.
    const std::vector<RecentEntry>& entries() const { return entries_; }

    /// True if the list is empty.
    bool empty() const { return entries_.empty(); }

    /// Default path: ~/.config/tenet/recent.json
    static std::string default_path();

private:
    std::vector<RecentEntry> entries_;
};

}  // namespace tenet
