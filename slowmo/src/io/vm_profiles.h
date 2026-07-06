#pragma once
// ═══════════════════════════════════════════════════════════════════════════
// VMProfiles — Persisted VM configuration associations
//
// Remembers which hints file + decoder file were used for a given trace
// module, so re-opening the same (or similar) binary auto-populates the
// VM hints / decoder paths instead of requiring the user to browse again.
//
// Storage: ~/.config/tenet/vm_profiles.json
//
// JSON schema (array of entries, newest-first):
// [
//   {
//     "module_name": "CtripApp",
//     "hints_file":  "/path/to/hints.json",
//     "decoder_file": "/path/to/bncode_v1.json",
//     "last_used":   1720300000
//   },
//   ...
// ]
//
// Keyed by module_name (from TraceReader header).  Each module keeps at most
// one profile entry; updating the hints/decoder for a module replaces the
// previous entry.  Total entries capped at 32.
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <string>
#include <vector>

namespace tenet {

/// One persisted VM configuration profile.
struct VMProfileEntry {
    std::string module_name;    ///< Module name from trace header
    std::string hints_file;     ///< Absolute path to hints JSON (may be empty)
    std::string decoder_file;   ///< Absolute path to decoder JSON (may be empty)
    int64_t     last_used = 0;  ///< Unix timestamp (seconds)
};

/// Manages the persisted list of VM configuration profiles.
class VMProfiles {
public:
    static constexpr size_t MAX_ENTRIES = 32;

    /// Load profiles from disk.  Returns empty on missing/malformed file.
    static VMProfiles load();

    /// Save profiles to disk (creates directory if needed).
    void save() const;

    /// Find the profile for `module_name`.  Returns nullptr if not found.
    const VMProfileEntry* find(const std::string& module_name) const;

    /// Update (or insert) a profile for `module_name`.
    /// Only non-empty fields in the update overwrite existing values —
    /// passing an empty `hints_file` preserves the previously stored hints path.
    void upsert(const std::string& module_name,
                const std::string& hints_file,
                const std::string& decoder_file);

    /// Remove a profile by module name.
    void remove(const std::string& module_name);

    /// All entries (newest-first).
    const std::vector<VMProfileEntry>& entries() const { return entries_; }

    /// Default path: ~/.config/tenet/vm_profiles.json
    static std::string default_path();

private:
    std::vector<VMProfileEntry> entries_;
};

}  // namespace tenet
