#include "io/recent_files.h"

#include "common/platform_paths.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace tenet {

using json = nlohmann::json;

// ─── Default path ────────────────────────────────────────────────────────────

std::string RecentFiles::default_path() {
    return (platform::user_config_dir() / "recent.json").string();
}

// ─── Load ─────────────────────────────────────────────────────────────────────

RecentFiles RecentFiles::load() {
    RecentFiles rf;
    std::string path = default_path();

    std::ifstream f(path);
    if (!f.is_open()) return rf;

    try {
        json j = json::parse(f);
        if (!j.is_array()) return rf;

        for (const auto& item : j) {
            if (!item.is_object()) continue;
            RecentEntry e;
            if (item.contains("path") && item["path"].is_string())
                e.path = item["path"].get<std::string>();
            if (item.contains("module_name") && item["module_name"].is_string())
                e.module_name = item["module_name"].get<std::string>();
            if (item.contains("inst_count") && item["inst_count"].is_number_unsigned())
                e.inst_count = item["inst_count"].get<uint64_t>();
            if (item.contains("last_opened") && item["last_opened"].is_number_integer())
                e.last_opened = item["last_opened"].get<int64_t>();
            if (!e.path.empty()) {
                rf.entries_.push_back(std::move(e));
            }
            if (rf.entries_.size() >= MAX_ENTRIES) break;
        }
    } catch (...) {
        // Malformed JSON – return whatever we parsed so far
    }
    return rf;
}

// ─── Save ─────────────────────────────────────────────────────────────────────

void RecentFiles::save() const {
    const std::filesystem::path path = default_path();
    platform::ensure_directory(path.parent_path());

    json j = json::array();
    for (const auto& e : entries_) {
        json item;
        item["path"]        = e.path;
        item["module_name"] = e.module_name;
        item["inst_count"]  = e.inst_count;
        item["last_opened"] = e.last_opened;
        j.push_back(std::move(item));
    }

    std::ofstream out(path);
    if (!out.is_open()) return;
    out << j.dump(2);
}

// ─── push ─────────────────────────────────────────────────────────────────────

void RecentFiles::push(const std::string& path,
                        const std::string& module_name,
                        uint64_t inst_count) {
    // Remove existing entry for this path (if any) so we can re-insert at front
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const RecentEntry& e) { return e.path == path; }),
        entries_.end());

    RecentEntry e;
    e.path        = path;
    e.module_name = module_name;
    e.inst_count  = inst_count;
    e.last_opened = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    entries_.insert(entries_.begin(), std::move(e));

    // Trim to max size
    if (entries_.size() > MAX_ENTRIES) {
        entries_.resize(MAX_ENTRIES);
    }
}

// ─── remove ───────────────────────────────────────────────────────────────────

void RecentFiles::remove(const std::string& path) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const RecentEntry& e) { return e.path == path; }),
        entries_.end());
}

}  // namespace tenet
