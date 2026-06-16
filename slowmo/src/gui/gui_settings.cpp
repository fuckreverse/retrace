#include "gui/gui_settings.h"

#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdlib>
#include <sys/stat.h>

namespace tenet {

using json = nlohmann::json;

// ─── JSON serialization helpers ─────────────────────────────────────────────

static json color_to_json(const float c[4]) {
    return json::array({c[0], c[1], c[2], c[3]});
}

static void json_to_color(const json& j, float c[4]) {
    if (j.is_array() && j.size() == 4) {
        for (int i = 0; i < 4; i++)
            c[i] = j[i].get<float>();
    }
}

// ─── Load ───────────────────────────────────────────────────────────────────

bool GuiSettings::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    try {
        json j = json::parse(f);

        if (j.contains("font_path"))    font_path = j["font_path"].get<std::string>();
        if (j.contains("font_size"))    font_size = j["font_size"].get<float>();
        if (j.contains("oversample_h")) oversample_h = j["oversample_h"].get<int>();
        if (j.contains("pixel_snap"))   pixel_snap = j["pixel_snap"].get<bool>();

        if (j.contains("theme")) {
            std::string t = j["theme"].get<std::string>();
            if (t == "light")   theme = Theme::Light;
            else if (t == "classic") theme = Theme::Classic;
            else                theme = Theme::Dark;
        }

        if (j.contains("row_spacing"))      row_spacing = j["row_spacing"].get<float>();
        if (j.contains("show_inst_index"))  show_inst_index = j["show_inst_index"].get<bool>();
        if (j.contains("show_address"))     show_address = j["show_address"].get<bool>();

        if (j.contains("colors")) {
            auto& c = j["colors"];
            if (c.contains("branch"))      json_to_color(c["branch"], colors.branch);
            if (c.contains("call"))        json_to_color(c["call"], colors.call);
            if (c.contains("ret"))         json_to_color(c["ret"], colors.ret);
            if (c.contains("load"))        json_to_color(c["load"], colors.load);
            if (c.contains("store"))       json_to_color(c["store"], colors.store);
            if (c.contains("syscall"))     json_to_color(c["syscall"], colors.syscall);
            if (c.contains("arith"))       json_to_color(c["arith"], colors.arith);
            if (c.contains("cmp"))         json_to_color(c["cmp"], colors.cmp);
            if (c.contains("mov"))         json_to_color(c["mov"], colors.mov);
            if (c.contains("reg_operand")) json_to_color(c["reg_operand"], colors.reg_operand);
            if (c.contains("imm_operand")) json_to_color(c["imm_operand"], colors.imm_operand);
        }

        return true;
    } catch (...) {
        return false;
    }
}

// ─── Save ───────────────────────────────────────────────────────────────────

bool GuiSettings::save(const std::string& path) const {
    // Ensure directory exists
    std::string dir = path.substr(0, path.rfind('/'));
    if (!dir.empty()) {
        mkdir(dir.c_str(), 0755);
    }

    json j;
    j["font_path"] = font_path;
    j["font_size"] = font_size;
    j["oversample_h"] = oversample_h;
    j["pixel_snap"] = pixel_snap;

    switch (theme) {
        case Theme::Dark:    j["theme"] = "dark"; break;
        case Theme::Light:   j["theme"] = "light"; break;
        case Theme::Classic: j["theme"] = "classic"; break;
    }

    j["row_spacing"] = row_spacing;
    j["show_inst_index"] = show_inst_index;
    j["show_address"] = show_address;

    json c;
    c["branch"]      = color_to_json(colors.branch);
    c["call"]        = color_to_json(colors.call);
    c["ret"]         = color_to_json(colors.ret);
    c["load"]        = color_to_json(colors.load);
    c["store"]       = color_to_json(colors.store);
    c["syscall"]     = color_to_json(colors.syscall);
    c["arith"]       = color_to_json(colors.arith);
    c["cmp"]         = color_to_json(colors.cmp);
    c["mov"]         = color_to_json(colors.mov);
    c["reg_operand"] = color_to_json(colors.reg_operand);
    c["imm_operand"] = color_to_json(colors.imm_operand);
    j["colors"] = c;

    std::ofstream out(path);
    if (!out.is_open()) return false;
    out << j.dump(2);
    return out.good();
}

// ─── Default path ───────────────────────────────────────────────────────────

std::string GuiSettings::default_path() {
    std::string home;
    if (const char* h = std::getenv("HOME")) {
        home = h;
    } else {
        home = "/tmp";
    }
    return home + "/.config/tenet/settings.json";
}

// ─── Available mono fonts ───────────────────────────────────────────────────

std::vector<std::string> GuiSettings::available_mono_fonts() {
    std::vector<std::string> result;

    // Common monospace font paths on macOS
    static const char* candidates[] = {
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/Library/Fonts/SF-Mono-Regular.otf",
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Monaco.dfont",
        "/System/Library/Fonts/Courier.dfont",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "/System/Library/Fonts/Supplemental/Andale Mono.ttf",
        // Common user-installed fonts
        "/Library/Fonts/JetBrainsMono-Regular.ttf",
        "/Library/Fonts/FiraCode-Regular.ttf",
        "/Library/Fonts/Hack-Regular.ttf",
        "/Library/Fonts/SourceCodePro-Regular.ttf",
        "/Library/Fonts/Inconsolata-Regular.ttf",
        nullptr
    };

    for (int i = 0; candidates[i] != nullptr; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0) {
            result.emplace_back(candidates[i]);
        }
    }

    // Also check ~/Library/Fonts for user-installed fonts
    std::string user_fonts_dir;
    if (const char* h = std::getenv("HOME")) {
        user_fonts_dir = std::string(h) + "/Library/Fonts";
    }
    if (!user_fonts_dir.empty()) {
        static const char* user_names[] = {
            "JetBrainsMono-Regular.ttf",
            "JetBrainsMonoNerdFont-Regular.ttf",
            "FiraCode-Regular.ttf",
            "Hack-Regular.ttf",
            "SourceCodePro-Regular.ttf",
            "Inconsolata-Regular.ttf",
            "CascadiaCode.ttf",
            "CascadiaMono.ttf",
            nullptr
        };
        for (int i = 0; user_names[i] != nullptr; i++) {
            std::string p = user_fonts_dir + "/" + user_names[i];
            struct stat st;
            if (stat(p.c_str(), &st) == 0) {
                result.emplace_back(p);
            }
        }
    }

    return result;
}

}  // namespace tenet
