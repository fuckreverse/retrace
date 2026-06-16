#pragma once

#include <string>
#include <vector>

namespace tenet {

/// Persistent GUI settings (serialized to JSON).
struct GuiSettings {
    // ─── Font ──────────────────────────────────────────────────────────
    std::string font_path;      // Empty = auto-detect system mono font
    float font_size = 14.0f;    // Base size before DPI scaling
    int oversample_h = 2;       // Horizontal oversampling (1-3)
    bool pixel_snap = true;     // Snap to pixel grid

    // ─── Theme ─────────────────────────────────────────────────────────
    enum class Theme { Dark, Light, Classic };
    Theme theme = Theme::Dark;

    // ─── Highlight Colors (stored as RGBA floats) ───────────────────
    struct HighlightColors {
        float branch[4]     = {1.0f, 1.0f, 0.0f, 1.0f};    // yellow
        float call[4]       = {1.0f, 0.6f, 0.2f, 1.0f};    // orange
        float ret[4]        = {1.0f, 0.4f, 1.0f, 1.0f};    // magenta
        float load[4]       = {0.4f, 0.85f, 1.0f, 1.0f};   // cyan
        float store[4]      = {1.0f, 0.45f, 0.4f, 1.0f};   // salmon
        float syscall[4]    = {0.4f, 1.0f, 0.4f, 1.0f};    // green
        float arith[4]      = {0.92f, 0.92f, 0.95f, 1.0f}; // white
        float cmp[4]        = {0.6f, 0.75f, 1.0f, 1.0f};   // light blue
        float mov[4]        = {0.75f, 0.65f, 1.0f, 1.0f};   // purple
        float reg_operand[4]= {0.5f, 0.9f, 0.5f, 1.0f};    // green
        float imm_operand[4]= {0.9f, 0.7f, 0.3f, 1.0f};    // amber
    };
    HighlightColors colors;

    // ─── UI Layout ─────────────────────────────────────────────────────
    float row_spacing = 3.0f;       // Item spacing Y
    bool show_inst_index = true;    // Show instruction # column
    bool show_address = true;       // Show address column

    // ─── Persistence ───────────────────────────────────────────────────
    /// Load settings from JSON file. Returns true if loaded, false otherwise (uses defaults).
    bool load(const std::string& path);

    /// Save settings to JSON file. Returns true on success.
    bool save(const std::string& path) const;

    /// Get default settings file path (~/.config/tenet/settings.json)
    static std::string default_path();

    /// List of system monospace fonts available on this machine
    static std::vector<std::string> available_mono_fonts();
};

}  // namespace tenet
