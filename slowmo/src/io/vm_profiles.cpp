#include "io/vm_profiles.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>

namespace tenet {

using json = nlohmann::json;

// ─── Default path ────────────────────────────────────────────────────────────

std::string VMProfiles::default_path() {
    std::string home;
    if (const char* h = std::getenv("HOME"))
        home = h;
    else
        home = "/tmp";
    return home + "/.config/tenet/vm_profiles.json";
}

// ─── Load ─────────────────────────────────────────────────────────────────────

VMProfiles VMProfiles::load() {
    VMProfiles vp;
    std::string path = default_path();

    std::ifstream f(path);
    if (!f.is_open()) return vp;

    try {
        json j = json::parse(f);
        if (!j.is_array()) return vp;

        for (const auto& item : j) {
            if (!item.is_object()) continue;
            VMProfileEntry e;
            if (item.contains("module_name") && item["module_name"].is_string())
                e.module_name = item["module_name"].get<std::string>();
            if (item.contains("hints_file") && item["hints_file"].is_string())
                e.hints_file = item["hints_file"].get<std::string>();
            if (item.contains("decoder_file") && item["decoder_file"].is_string())
                e.decoder_file = item["decoder_file"].get<std::string>();
            if (item.contains("last_used") && item["last_used"].is_number_integer())
                e.last_used = item["last_used"].get<int64_t>();
            if (!e.module_name.empty()) {
                vp.entries_.push_back(std::move(e));
            }
            if (vp.entries_.size() >= MAX_ENTRIES) break;
        }
    } catch (...) {
        // Malformed JSON — return whatever we parsed
    }
    return vp;
}

// ─── Save ─────────────────────────────────────────────────────────────────────

void VMProfiles::save() const {
    std::string path = default_path();

    // Ensure directory exists
    auto sep = path.rfind('/');
    if (sep != std::string::npos) {
        std::string dir = path.substr(0, sep);
        if (!dir.empty()) mkdir(dir.c_str(), 0755);
    }

    json j = json::array();
    for (const auto& e : entries_) {
        json item;
        item["module_name"]  = e.module_name;
        item["hints_file"]   = e.hints_file;
        item["decoder_file"] = e.decoder_file;
        item["last_used"]    = e.last_used;
        j.push_back(std::move(item));
    }

    std::ofstream out(path);
    if (!out.is_open()) return;
    out << j.dump(2);
}

// ─── find ─────────────────────────────────────────────────────────────────────

const VMProfileEntry* VMProfiles::find(const std::string& module_name) const {
    for (const auto& e : entries_) {
        if (e.module_name == module_name) return &e;
    }
    return nullptr;
}

// ─── upsert ───────────────────────────────────────────────────────────────────

void VMProfiles::upsert(const std::string& module_name,
                         const std::string& hints_file,
                         const std::string& decoder_file) {
    // Find existing
    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&](const VMProfileEntry& e) { return e.module_name == module_name; });

    VMProfileEntry entry;
    if (it != entries_.end()) {
        entry = *it;                     // preserve existing fields
        entries_.erase(it);
    } else {
        entry.module_name = module_name;
    }

    // Only overwrite non-empty fields
    if (!hints_file.empty())   entry.hints_file   = hints_file;
    if (!decoder_file.empty()) entry.decoder_file  = decoder_file;

    entry.last_used = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    // Insert at front (MRU ordering)
    entries_.insert(entries_.begin(), std::move(entry));

    // Trim
    if (entries_.size() > MAX_ENTRIES)
        entries_.resize(MAX_ENTRIES);
}

// ─── remove ───────────────────────────────────────────────────────────────────

void VMProfiles::remove(const std::string& module_name) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
            [&](const VMProfileEntry& e) { return e.module_name == module_name; }),
        entries_.end());
}

}  // namespace tenet
