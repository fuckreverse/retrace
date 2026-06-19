// gui_colors.cpp — operand syntax highlighting + mnemonic/register colour helpers.
//
// Split out of gui_app.mm. These are pure rendering helpers with no ObjC/Metal
// dependency, so they compile as plain C++.

#include "gui/gui_app.h"

#include <imgui.h>

#include <cstring>
#include <string>

namespace tenet {

// ─── Operand Syntax Highlighting ────────────────────────────────────────────

void GuiApp::render_operands_highlighted(const std::string& operands) {
    // Color scheme for operand tokens (from settings):
    const auto& sc = settings_.colors;
    const ImVec4 col_reg     = ImVec4(sc.reg_operand[0], sc.reg_operand[1], sc.reg_operand[2], sc.reg_operand[3]);
    const ImVec4 col_imm     = ImVec4(sc.imm_operand[0], sc.imm_operand[1], sc.imm_operand[2], sc.imm_operand[3]);
    const ImVec4 col_bracket = ImVec4(0.8f, 0.8f, 0.9f, 1.0f);  // white-ish
    const ImVec4 col_punct   = ImVec4(0.5f, 0.5f, 0.55f, 1.0f); // dim
    const ImVec4 col_default = ImVec4(0.82f, 0.82f, 0.85f, 1.0f);

    const char* p = operands.c_str();
    const char* end = p + operands.size();
    bool first_token = true;

    while (p < end) {
        // Skip leading spaces
        if (*p == ' ') { p++; continue; }

        // Determine token type and extent
        const char* tok_start = p;
        ImVec4 color = col_default;

        if (*p == '#') {
            // Immediate value: #0x... or #decimal
            color = col_imm;
            p++;
            while (p < end && *p != ',' && *p != ']' && *p != ' ' && *p != '!') p++;
        } else if (*p == '[' || *p == ']') {
            color = col_bracket;
            p++;
        } else if (*p == ',' || *p == '!') {
            color = col_punct;
            p++;
        } else if ((*p == 'x' || *p == 'w' || *p == 'q' || *p == 'd' || *p == 's' ||
                    *p == 'b' || *p == 'h' || *p == 'v') &&
                   (p + 1 < end) && (p[1] >= '0' && p[1] <= '9')) {
            // Register: x0-x30, w0-w30, q0-q31, d0-d31, s0-s31, etc.
            color = col_reg;
            p++;
            while (p < end && *p >= '0' && *p <= '9') p++;
        } else if ((p + 1 < end) && (
                   (p[0] == 's' && p[1] == 'p') ||
                   (p[0] == 'l' && p[1] == 'r') ||
                   (p[0] == 'f' && p[1] == 'p') ||
                   (p[0] == 'p' && p[1] == 'c'))) {
            // Named registers: sp, lr, fp, pc
            // Check it's not part of a longer word
            const char* check = p + 2;
            if (check >= end || *check == ',' || *check == ']' || *check == ' ' ||
                *check == '!' || *check == '\0') {
                color = col_reg;
                p += 2;
            } else {
                // Part of a label/symbol, use default
                while (p < end && *p != ',' && *p != ' ' && *p != ']' && *p != '[') p++;
            }
        } else if (p + 2 < end && p[0] == 'x' && p[1] == 'z' && p[2] == 'r') {
            color = col_reg;
            p += 3;
        } else if (p + 2 < end && p[0] == 'w' && p[1] == 'z' && p[2] == 'r') {
            color = col_reg;
            p += 3;
        } else if (*p == '0' && p + 1 < end && p[1] == 'x') {
            // Bare hex number (address)
            color = col_imm;
            while (p < end && *p != ',' && *p != ']' && *p != ' ' && *p != '!') p++;
        } else {
            // Default: read until delimiter
            while (p < end && *p != ',' && *p != ' ' && *p != ']' && *p != '[' && *p != '!') p++;
        }

        // Render the token
        size_t tok_len = static_cast<size_t>(p - tok_start);
        if (tok_len > 0) {
            if (!first_token) ImGui::SameLine(0, 0);
            first_token = false;

            // For comma+space, add a space after
            char buf[128];
            if (tok_len < sizeof(buf) - 1) {
                memcpy(buf, tok_start, tok_len);
                buf[tok_len] = '\0';
                ImGui::TextColored(color, "%s", buf);
            } else {
                std::string s(tok_start, tok_len);
                ImGui::TextColored(color, "%s", s.c_str());
            }
        }

        // Insert space between tokens where needed
        if (p < end && *p == ' ') {
            if (!first_token) ImGui::SameLine(0, 0);
            first_token = false;
            ImGui::TextColored(col_default, " ");
            p++;
        }
    }

    // If operands was empty, render nothing visible (avoid blank line issues)
    if (operands.empty()) {
        ImGui::TextDisabled("-");
    }
}

// ─── Color helpers ──────────────────────────────────────────────────────────

ImVec4 GuiApp::inst_color(const std::string& mnemonic) const {
    if (mnemonic.empty()) return ImVec4(0.5f, 0.5f, 0.5f, 1.0f);

    const auto& c = settings_.colors;
    auto to_vec = [](const float v[4]) { return ImVec4(v[0], v[1], v[2], v[3]); };

    // Conditional branches
    if (mnemonic.find("b.") == 0 || mnemonic == "b" ||
        mnemonic.find("cb") == 0 || mnemonic.find("tb") == 0)
        return to_vec(c.branch);
    // Direct calls (bl)
    if (mnemonic == "bl")
        return to_vec(c.call);
    // Returns/indirect branches
    if (mnemonic == "ret" || mnemonic == "blr" || mnemonic == "br")
        return to_vec(c.ret);
    // Loads
    if (mnemonic.find("ldr") == 0 || mnemonic.find("ldp") == 0 ||
        mnemonic.find("ldur") == 0 || mnemonic.find("lda") == 0 ||
        mnemonic.find("ldx") == 0)
        return to_vec(c.load);
    // Stores
    if (mnemonic.find("str") == 0 || mnemonic.find("stp") == 0 ||
        mnemonic.find("stur") == 0 || mnemonic.find("stl") == 0 ||
        mnemonic.find("stx") == 0)
        return to_vec(c.store);
    // Syscalls/exceptions
    if (mnemonic == "svc" || mnemonic == "brk" || mnemonic == "hvc")
        return to_vec(c.syscall);
    // Arithmetic/logic
    if (mnemonic.find("add") == 0 || mnemonic.find("sub") == 0 ||
        mnemonic.find("mul") == 0 || mnemonic.find("and") == 0 ||
        mnemonic.find("orr") == 0 || mnemonic.find("eor") == 0 ||
        mnemonic.find("lsl") == 0 || mnemonic.find("lsr") == 0 ||
        mnemonic.find("asr") == 0 || mnemonic.find("ror") == 0 ||
        mnemonic.find("neg") == 0 || mnemonic.find("mvn") == 0)
        return to_vec(c.arith);
    // Comparison/test
    if (mnemonic == "cmp" || mnemonic == "cmn" || mnemonic == "tst" || mnemonic == "ccmp")
        return to_vec(c.cmp);
    // Move/data transfer
    if (mnemonic.find("mov") == 0 || mnemonic == "mvn" ||
        mnemonic.find("fmov") == 0)
        return to_vec(c.mov);
    // NOP - very dim
    if (mnemonic == "nop")
        return ImVec4(0.4f, 0.4f, 0.4f, 1.0f);
    // Default - light gray
    return ImVec4(0.82f, 0.82f, 0.85f, 1.0f);
}

ImVec4 GuiApp::reg_color_read() {
    return ImVec4(0.4f, 1.0f, 0.4f, 1.0f);  // Green
}

ImVec4 GuiApp::reg_color_write() {
    return ImVec4(1.0f, 0.4f, 0.4f, 1.0f);  // Red
}

ImVec4 GuiApp::reg_color_both() {
    return ImVec4(1.0f, 1.0f, 0.0f, 1.0f);  // Yellow
}

}  // namespace tenet
