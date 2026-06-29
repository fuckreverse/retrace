// panels_memory.cpp — memory access panel, hex dump panel, memory context menu,
// structured memory view (C struct overlay), and open_hex_dump_at helper.
//
// Split out of gui_app.mm. Pure C++ (no ObjC/Metal).

#include "gui/gui_app.h"
#include "analysis/passes/xref_pass.h"

#include <imgui.h>

#include <fmt/core.h>

#include <cstring>
#include <string>
#include <sstream>
#include <charconv>

namespace tenet {

// ─── Open hex dump at address ────────────────────────────────────────────────

void GuiApp::open_hex_dump_at(uint64_t addr) {
    show_hex_dump_ = true;
    // Store the address for hex dump to display
    // We'll use the hex_dump_addr_ field (to be shown in render_hex_dump_panel)
    // For now, re-purpose ctx_mem_addr_ as the hex dump target
    ctx_mem_addr_ = addr;
}

// ─── Memory Panel ───────────────────────────────────────────────────────────

void GuiApp::render_memory_panel() {
    if (!ImGui::Begin("Memory Accesses", &show_memory_)) {
        ImGui::End();
        return;
    }

    auto [offset, seed_pc_mem] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec = reader_.record_at(offset, seed_pc_mem);
    if (rec.kind != RecordKind::Inst) {
        ImGui::TextDisabled("(no instruction)");
        ImGui::End();
        return;
    }

    auto inst = rec.as_inst();
    if (inst.mem_access_count == 0) {
        ImGui::TextDisabled("(no memory access)");
        ImGui::End();
        return;
    }

    // Hint text
    ImGui::TextDisabled("Double-click addr to open Hex Dump  |  Right-click for menu");
    ImGui::Separator();

    for (uint8_t i = 0; i < inst.mem_access_count; i++) {
        auto mem = inst.mem_access(i);
        bool is_write = (mem.type & 2) != 0;

        ImVec4 type_color = is_write ? ImVec4(1.0f, 0.3f, 0.3f, 1.0f)
                                     : ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        const char* type_label = is_write ? "WRITE" : "READ ";

        ImGui::TextColored(type_color, "%s", type_label);
        ImGui::SameLine();

        // ── Clickable address ──────────────────────────────────────
        char addr_label[48];
        snprintf(addr_label, sizeof(addr_label), "0x%016llx##memaddr%u",
                 (unsigned long long)mem.addr, i);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
        ImGui::Text("addr=");
        ImGui::SameLine(0, 0);

        // Use Selectable for click/double-click handling
        char sel_label[64];
        snprintf(sel_label, sizeof(sel_label), "0x%016llx##memsel%u",
                 (unsigned long long)mem.addr, i);
        ImGui::PopStyleColor();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.8f, 1.0f, 1.0f));
        if (ImGui::Selectable(sel_label, false,
                ImGuiSelectableFlags_AllowDoubleClick |
                ImGuiSelectableFlags_AllowOverlap,
                ImVec2(0, 0))) {
            // Single click: select (no action yet)
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Double-click: open in Hex Dump\nRight-click: context menu");
            if (ImGui::IsMouseDoubleClicked(0)) {
                open_hex_dump_at(mem.addr);
            }
        }
        if (ImGui::BeginPopupContextItem(nullptr)) {
            ctx_mem_addr_    = mem.addr;
            ctx_mem_inst_id_ = current_inst_;
            ImGui::TextDisabled("addr: 0x%016llx", (unsigned long long)mem.addr);
            ImGui::Separator();
            if (ImGui::MenuItem("Open in Hex Dump")) {
                open_hex_dump_at(mem.addr);
            }
            if (ImGui::MenuItem("Copy Address")) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mem.addr);
                ImGui::SetClipboardText(buf);
            }
            if (mem.size <= 8) {
                if (ImGui::MenuItem("Copy Value")) {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)mem.value);
                    ImGui::SetClipboardText(buf);
                }
            }
            ImGui::EndPopup();
        }
        ImGui::PopStyleColor();

        ImGui::SameLine();
        ImGui::Text("  size=%u", mem.size);

        if (mem.size <= 8) {
            ImGui::TextDisabled("  val =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value);
        } else {
            ImGui::TextDisabled("  lo  =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value);
            ImGui::TextDisabled("  hi  =");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                "0x%016llx", (unsigned long long)mem.value_hi);
        }

        // Hex bytes
        {
            uint8_t bytes[16];
            std::memcpy(bytes, &mem.value, 8);
            std::memcpy(bytes + 8, &mem.value_hi, 8);
            size_t n = (mem.size <= 16) ? mem.size : 8;
            std::string hex_str = "  hex: ";
            for (size_t b = 0; b < n; b++) {
                hex_str += fmt::format("{:02x} ", bytes[b]);
            }
            ImGui::TextDisabled("%s", hex_str.c_str());
        }

        // Quick action button: "Open in Hex Dump"
        ImGui::SameLine();
        char btn_label[32];
        snprintf(btn_label, sizeof(btn_label), "[Hex]##hd%u", i);
        if (ImGui::SmallButton(btn_label)) {
            open_hex_dump_at(mem.addr);
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Open address 0x%llx in Hex Dump",
                              (unsigned long long)mem.addr);
        }

        if (i + 1 < inst.mem_access_count) {
            ImGui::Separator();
        }
    }

    // Render context menu if requested
    render_mem_context_menu();

    ImGui::End();
}

// ─── Struct field definition ─────────────────────────────────────────────────
// A minimal C-style struct layout parser for field-aware hex display.
// Supported types: u8/u16/u32/u64/i8/i16/i32/i64/char/ptr/f32/f64/bytes[N]

namespace {

struct StructField {
    std::string name;
    uint32_t offset;   // byte offset from struct start
    uint32_t size;     // byte size
    enum class Type { U8, U16, U32, U64, I8, I16, I32, I64, F32, F64, Char, Ptr, Bytes } type;
};

struct StructLayout {
    std::string name;
    std::vector<StructField> fields;
    uint32_t total_size = 0;
};

/// Parse a simple C-struct-like definition:
///   struct Foo { u32 len; ptr buf; u8 flags[4]; }
/// Returns empty layout on parse error.
static StructLayout parse_struct_def(const std::string& text) {
    StructLayout layout;
    // Extract struct name
    size_t struct_pos = text.find("struct");
    if (struct_pos == std::string::npos) return layout;
    size_t name_start = text.find_first_not_of(" \t", struct_pos + 6);
    if (name_start == std::string::npos) return layout;
    size_t name_end = text.find_first_of(" \t{", name_start);
    if (name_end == std::string::npos) return layout;
    layout.name = text.substr(name_start, name_end - name_start);

    size_t brace_open  = text.find('{', name_end);
    size_t brace_close = text.rfind('}');
    if (brace_open == std::string::npos || brace_close == std::string::npos) return layout;

    std::string body = text.substr(brace_open + 1, brace_close - brace_open - 1);
    std::istringstream ss(body);
    std::string line;
    uint32_t offset = 0;

    while (std::getline(ss, line, ';')) {
        // Trim whitespace
        auto trim = [](const std::string& s) {
            size_t b = s.find_first_not_of(" \t\r\n");
            size_t e = s.find_last_not_of(" \t\r\n");
            return (b == std::string::npos) ? std::string{} : s.substr(b, e - b + 1);
        };
        line = trim(line);
        if (line.empty()) continue;

        // Parse "type name" or "type name[N]"
        std::istringstream ls(line);
        std::string type_str, name_str;
        ls >> type_str >> name_str;
        if (type_str.empty() || name_str.empty()) continue;

        StructField field;
        field.offset = offset;

        // Check for array syntax: name[N]
        uint32_t array_n = 1;
        size_t bracket = name_str.find('[');
        if (bracket != std::string::npos) {
            size_t end_bracket = name_str.find(']', bracket);
            if (end_bracket != std::string::npos) {
                std::string n_str = name_str.substr(bracket + 1, end_bracket - bracket - 1);
                try { array_n = static_cast<uint32_t>(std::stoul(n_str)); } catch(...) {}
            }
            field.name = name_str.substr(0, bracket);
        } else {
            field.name = name_str;
        }

        uint32_t element_size = 0;
        if (type_str == "u8"  || type_str == "uint8_t"  || type_str == "char" || type_str == "bool")
            { field.type = StructField::Type::U8;  element_size = 1; }
        else if (type_str == "u16" || type_str == "uint16_t")
            { field.type = StructField::Type::U16; element_size = 2; }
        else if (type_str == "u32" || type_str == "uint32_t")
            { field.type = StructField::Type::U32; element_size = 4; }
        else if (type_str == "u64" || type_str == "uint64_t")
            { field.type = StructField::Type::U64; element_size = 8; }
        else if (type_str == "i8"  || type_str == "int8_t")
            { field.type = StructField::Type::I8;  element_size = 1; }
        else if (type_str == "i16" || type_str == "int16_t")
            { field.type = StructField::Type::I16; element_size = 2; }
        else if (type_str == "i32" || type_str == "int32_t" || type_str == "int")
            { field.type = StructField::Type::I32; element_size = 4; }
        else if (type_str == "i64" || type_str == "int64_t" || type_str == "long")
            { field.type = StructField::Type::I64; element_size = 8; }
        else if (type_str == "f32" || type_str == "float")
            { field.type = StructField::Type::F32; element_size = 4; }
        else if (type_str == "f64" || type_str == "double")
            { field.type = StructField::Type::F64; element_size = 8; }
        else if (type_str == "ptr" || type_str == "void*" || type_str == "uintptr_t")
            { field.type = StructField::Type::Ptr; element_size = 8; }
        else if (type_str == "bytes")
            { field.type = StructField::Type::Bytes; element_size = array_n; array_n = 1; }
        else
            continue;  // unknown type

        field.size = element_size * array_n;
        layout.fields.push_back(field);
        offset += field.size;
    }

    layout.total_size = offset;
    return layout;
}

/// Get a display-friendly interpretation of field bytes
static std::string format_field_value(const StructField& f, const uint8_t* bytes, size_t avail) {
    if (avail < f.size) return "<?>";
    switch (f.type) {
        case StructField::Type::U8:  return fmt::format("{} (0x{:02x})", bytes[0], bytes[0]);
        case StructField::Type::U16: {
            uint16_t v; std::memcpy(&v, bytes, 2);
            return fmt::format("{} (0x{:04x})", v, v);
        }
        case StructField::Type::U32: {
            uint32_t v; std::memcpy(&v, bytes, 4);
            return fmt::format("{} (0x{:08x})", v, v);
        }
        case StructField::Type::U64: {
            uint64_t v; std::memcpy(&v, bytes, 8);
            return fmt::format("{} (0x{:016x})", v, v);
        }
        case StructField::Type::I8: {
            int8_t v = static_cast<int8_t>(bytes[0]);
            return fmt::format("{}", v);
        }
        case StructField::Type::I32: {
            int32_t v; std::memcpy(&v, bytes, 4);
            return fmt::format("{}", v);
        }
        case StructField::Type::I64: {
            int64_t v; std::memcpy(&v, bytes, 8);
            return fmt::format("{}", v);
        }
        case StructField::Type::F32: {
            float v; std::memcpy(&v, bytes, 4);
            return fmt::format("{:.6g}", v);
        }
        case StructField::Type::F64: {
            double v; std::memcpy(&v, bytes, 8);
            return fmt::format("{:.10g}", v);
        }
        case StructField::Type::Ptr: {
            uint64_t v; std::memcpy(&v, bytes, 8);
            return fmt::format("0x{:016x}", v);
        }
        case StructField::Type::Char: {
            char c = static_cast<char>(bytes[0]);
            if (c >= 0x20 && c < 0x7F) return fmt::format("'{}'", c);
            return fmt::format("0x{:02x}", bytes[0]);
        }
        default: {
            std::string s;
            for (size_t i = 0; i < std::min(f.size, 8u); i++) {
                if (i) s += ' ';
                s += fmt::format("{:02x}", bytes[i]);
            }
            if (f.size > 8) s += "...";
            return s;
        }
    }
}

// Field color palette (cycling)
static const ImVec4 kFieldColors[] = {
    ImVec4(0.40f, 0.80f, 1.00f, 1.0f),   // cyan
    ImVec4(0.40f, 1.00f, 0.55f, 1.0f),   // green
    ImVec4(1.00f, 0.75f, 0.35f, 1.0f),   // amber
    ImVec4(0.90f, 0.45f, 0.90f, 1.0f),   // magenta
    ImVec4(1.00f, 0.55f, 0.45f, 1.0f),   // salmon
    ImVec4(0.65f, 0.75f, 1.00f, 1.0f),   // periwinkle
    ImVec4(0.50f, 1.00f, 0.90f, 1.0f),   // aqua
    ImVec4(1.00f, 0.90f, 0.50f, 1.0f),   // gold
};
static constexpr int kNumFieldColors = static_cast<int>(sizeof(kFieldColors)/sizeof(kFieldColors[0]));

}  // namespace

// ─── Hex Dump Panel ─────────────────────────────────────────────────────────
// Enhanced with:
//  - Write-history heatmap: bytes that were recently written are tinted orange
//  - Structured overlay: paste a C struct definition to get field-aware display
//  - Per-byte write age badge (how many instructions ago was this byte written)
//  - Struct field table below the hex dump

void GuiApp::render_hex_dump_panel() {
    if (!ImGui::Begin("Hex Dump", &show_hex_dump_)) {
        ImGui::End();
        return;
    }

    // ── Address / navigation header ──────────────────────────────────
    uint64_t display_addr = 0;
    bool has_addr = false;

    if (ctx_mem_addr_ != 0) {
        display_addr = ctx_mem_addr_;
        has_addr = true;
    } else {
        auto [offset, seed_pc_da] = index_.offset_of_with_pc(current_inst_, reader_);
        auto rec = reader_.record_at(offset, seed_pc_da);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            if (inst.mem_access_count > 0) {
                display_addr = inst.mem_access(0).addr;
                has_addr = true;
            }
        }
    }

    ImGui::Text("Address:");
    ImGui::SameLine();
    static char hex_addr_buf[32] = {};
    ImGui::SetNextItemWidth(180.0f);
    if (ImGui::InputText("##hexaddr", hex_addr_buf, sizeof(hex_addr_buf),
            ImGuiInputTextFlags_EnterReturnsTrue |
            ImGuiInputTextFlags_CharsHexadecimal)) {
        try {
            uint64_t addr = std::stoull(hex_addr_buf, nullptr, 16);
            display_addr = addr;
            ctx_mem_addr_ = addr;
            has_addr = true;
        } catch (...) {}
    }
    ImGui::SameLine();
    if (ImGui::Button("From Inst")) {
        ctx_mem_addr_ = 0;
        std::memset(hex_addr_buf, 0, sizeof(hex_addr_buf));
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Follow current instruction's memory access");
    ImGui::SameLine();
    if (ImGui::Button("Watch\xe2\x8c\x95##watchaddr") && has_addr) {  // ⌕ U+2315 (was 🔭 U+1F52D emoji)
        timeline_watch_addr_ = display_addr;
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Show write activity for this address in the Timeline");

    if (!has_addr) {
        ImGui::Separator();
        ImGui::TextDisabled("(no address — enter one above, or navigate to an instruction with memory access)");
        ImGui::End();
        return;
    }

    ImGui::SameLine(0, 16);
    if (timeline_watch_addr_ == display_addr) {
        ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.2f, 1.0f), "\xe2\x97\x89 Watching in Timeline");
    } else if (timeline_watch_addr_ != 0) {
        ImGui::TextDisabled("(watching 0x%llx)", (unsigned long long)timeline_watch_addr_);
    }

    // ── Struct definition input ───────────────────────────────────────
    static char struct_def_buf[1024] = {};
    static StructLayout struct_layout;
    static bool struct_dirty = false;

    if (ImGui::CollapsingHeader("Struct Overlay (optional)")) {
        ImGui::TextDisabled("Paste a C struct definition below for field-aware display:");
        ImGui::TextDisabled("  e.g.  struct Foo { u32 len; ptr data; u8 flags[4]; }");
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputTextMultiline("##structdef", struct_def_buf, sizeof(struct_def_buf),
                ImVec2(-1, 80))) {
            struct_dirty = true;
        }
        ImGui::SameLine();
        if (struct_dirty || ImGui::Button("Apply")) {
            struct_layout = parse_struct_def(std::string(struct_def_buf));
            struct_dirty = false;
        }
        if (!struct_layout.name.empty()) {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                "struct %s (%u bytes, %zu fields)",
                struct_layout.name.c_str(), struct_layout.total_size,
                struct_layout.fields.size());
        }
    }

    ImGui::Separator();
    ImGui::Text("0x%016llx", (unsigned long long)display_addr);

    uint64_t base_addr = display_addr & ~0xFULL;  // Align to 16 bytes

    // Pre-fetch write history for all bytes in range (for heatmap)
    // Fetch 256 bytes (16 rows × 16 bytes) of write ages
    const int kRows = 16;
    const size_t kTotalBytes = kRows * 16;
    std::vector<uint64_t> write_age(kTotalBytes, UINT64_MAX);  // dist in inst_ids from now

    // Fetch in a batch: use write_history for the range start
    // We use a simpler heuristic: call last_writer per byte but limit to first 32 bytes
    // to avoid performance hits on large scans
    for (size_t bi = 0; bi < std::min(kTotalBytes, size_t(64)); bi++) {
        uint64_t baddr = base_addr + bi;
        uint64_t writer = memory_.last_writer(baddr, 1, current_inst_);
        if (writer > 0 && current_inst_ >= writer) {
            write_age[bi] = current_inst_ - writer;
        }
    }

    // Build field-byte mapping for struct overlay
    // field_idx_at[byte_offset_from_base] → field index (-1 if no struct)
    std::vector<int> field_idx_at(kTotalBytes, -1);
    if (!struct_layout.fields.empty()) {
        uint64_t struct_base = display_addr;  // struct starts at display address
        for (int fi = 0; fi < static_cast<int>(struct_layout.fields.size()); fi++) {
            const auto& f = struct_layout.fields[fi];
            uint64_t field_addr = struct_base + f.offset;
            for (uint32_t fb = 0; fb < f.size; fb++) {
                if (field_addr + fb >= base_addr && field_addr + fb < base_addr + kTotalBytes) {
                    size_t idx = static_cast<size_t>(field_addr + fb - base_addr);
                    field_idx_at[idx] = fi;
                }
            }
        }
    }

    // ── Column header ─────────────────────────────────────────────────
    ImGui::Separator();
    {
        ImDrawList* draw = ImGui::GetWindowDrawList();
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.50f, 0.65f, 1.0f));
        ImGui::Text("          Address          | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII | Age");
        ImGui::PopStyleColor();
        ImVec2 sep_p = ImGui::GetCursorScreenPos();
        draw->AddLine(sep_p, ImVec2(sep_p.x + ImGui::GetContentRegionAvail().x, sep_p.y),
                      IM_COL32(60, 65, 90, 180), 1.0f);
        ImGui::Dummy(ImVec2(0, 1));
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();

    for (int row = -2; row < kRows - 2; row++) {
        uint64_t row_addr = base_addr + static_cast<uint64_t>(row) * 16;
        bool is_active_row = (display_addr >= row_addr && display_addr < row_addr + 16);

        // Row address
        if (is_active_row) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.4f, 1.0f),
                "0x%016llx:", (unsigned long long)row_addr);
        } else {
            ImGui::TextColored(ImVec4(0.38f, 0.42f, 0.58f, 1.0f),
                "0x%016llx:", (unsigned long long)row_addr);
        }
        ImGui::SameLine();

        // ── Hex bytes ────────────────────────────────────────────────
        uint64_t min_age_in_row = UINT64_MAX;
        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            size_t buf_idx = (byte_addr >= base_addr && byte_addr < base_addr + kTotalBytes)
                ? static_cast<size_t>(byte_addr - base_addr) : SIZE_MAX;

            auto byte_val = memory_.byte_at(byte_addr, current_inst_);
            bool is_highlighted = (byte_addr == display_addr);

            if (b == 8) { ImGui::SameLine(0, 0); ImGui::TextDisabled(" "); }
            if (b > 0)    ImGui::SameLine(0, 0);

            char byte_str[8];
            if (byte_val.has_value()) {
                snprintf(byte_str, sizeof(byte_str), "%02x ", *byte_val);
            } else {
                snprintf(byte_str, sizeof(byte_str), "?? ");
            }

            ImGui::PushID(static_cast<int>(row * 16 + b));

            // Determine color: struct field > highlighted > write-hot > normal
            ImVec4 byte_color;
            int fi = (buf_idx < kTotalBytes) ? field_idx_at[buf_idx] : -1;
            uint64_t age = (buf_idx < kTotalBytes) ? write_age[buf_idx] : UINT64_MAX;
            if (min_age_in_row > age && age != UINT64_MAX) min_age_in_row = age;

            if (is_highlighted) {
                byte_color = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
            } else if (fi >= 0) {
                byte_color = kFieldColors[fi % kNumFieldColors];
                // Add subtle write-hot tint on top of field color
                if (age != UINT64_MAX && age < 50) {
                    byte_color.x = std::min(1.0f, byte_color.x + 0.2f);
                    byte_color.y = std::min(1.0f, byte_color.y + 0.1f);
                }
            } else if (age != UINT64_MAX && age < 200) {
                // Write-hot heatmap: recently written bytes are warm
                float heat = 1.0f - std::min(1.0f, static_cast<float>(age) / 200.0f);
                byte_color = ImVec4(0.3f + heat * 0.7f, 0.65f - heat * 0.35f, 0.3f, 1.0f);
            } else if (is_active_row) {
                byte_color = ImVec4(0.78f, 0.80f, 0.90f, 1.0f);
            } else if (!byte_val.has_value()) {
                byte_color = ImVec4(0.28f, 0.28f, 0.32f, 1.0f);
            } else {
                byte_color = ImVec4(0.55f, 0.60f, 0.72f, 1.0f);
            }

            // Draw field background highlight
            if (fi >= 0) {
                ImVec2 bpos = ImGui::GetCursorScreenPos();
                float bh = ImGui::GetTextLineHeight();
                float bw = ImGui::CalcTextSize(byte_str).x;
                ImVec4 fc = kFieldColors[fi % kNumFieldColors];
                draw->AddRectFilled(bpos, ImVec2(bpos.x + bw, bpos.y + bh),
                    IM_COL32(static_cast<int>(fc.x*40), static_cast<int>(fc.y*40),
                             static_cast<int>(fc.z*40), 100));
            }

            ImGui::TextColored(byte_color, "%s", byte_str);

            // Interactions
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                if (writer > 0) navigate_to(writer);
            }
            if (ImGui::IsItemClicked()) {
                display_addr = byte_addr;
                ctx_mem_addr_ = byte_addr;
            }
            if (ImGui::IsItemHovered()) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                std::string tip = fmt::format("0x{:016x}", byte_addr);
                if (byte_val.has_value()) tip += fmt::format("  =  0x{:02x} ({:d})", *byte_val, *byte_val);
                if (writer > 0) tip += fmt::format("\nLast written: inst #{} ({} ago)", writer,
                    current_inst_ >= writer ? current_inst_ - writer : 0);
                else tip += "\nNo known writer";
                if (fi >= 0) {
                    const auto& f = struct_layout.fields[fi];
                    tip += fmt::format("\n[struct] .{} @ +{}", f.name, f.offset);
                }
                tip += "\nDbl-click: jump to writer";
                ImGui::SetTooltip("%s", tip.c_str());
            }

            ImGui::PopID();
        }

        // ASCII column
        ImGui::SameLine();
        char ascii_part[20] = {};
        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            auto byte_val = memory_.byte_at(byte_addr, current_inst_);
            if (byte_val.has_value()) {
                uint8_t v = *byte_val;
                ascii_part[b] = (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '.';
            } else {
                ascii_part[b] = '?';
            }
        }
        ascii_part[16] = '\0';
        ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.65f, 1.0f), "| %s", ascii_part);

        // Age column (smallest write age in row)
        ImGui::SameLine();
        if (min_age_in_row == UINT64_MAX) {
            ImGui::TextDisabled(" |  ---");
        } else if (min_age_in_row == 0) {
            ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f), " | now");
        } else if (min_age_in_row < 10) {
            ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), " |%+4lld", (long long)min_age_in_row);
        } else {
            ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.65f, 1.0f), " |%+4lld", (long long)min_age_in_row);
        }
    }

    ImGui::Separator();

    // ── Struct field table (when struct overlay is active) ────────────
    if (!struct_layout.fields.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.7f, 0.8f, 1.0f, 1.0f),
            "struct %s layout:", struct_layout.name.c_str());
        ImGui::Separator();

        if (ImGui::BeginTable("##structfields", 5,
                ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY,
                ImVec2(0, 120))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Field",   ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("+Offset", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Size",    ImGuiTableColumnFlags_WidthFixed, 40.0f);
            ImGui::TableSetupColumn("Value",   ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Writer",  ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableHeadersRow();

            // Read struct bytes from memory
            std::vector<uint8_t> struct_bytes(struct_layout.total_size, 0);
            std::vector<bool> known(struct_layout.total_size, false);
            for (uint32_t i = 0; i < struct_layout.total_size; i++) {
                auto v = memory_.byte_at(display_addr + i, current_inst_);
                if (v.has_value()) { struct_bytes[i] = *v; known[i] = true; }
            }

            for (int fi = 0; fi < static_cast<int>(struct_layout.fields.size()); fi++) {
                const auto& f = struct_layout.fields[fi];
                ImVec4 fc = kFieldColors[fi % kNumFieldColors];

                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextColored(fc, "%s", f.name.c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(ImVec4(0.55f, 0.60f, 0.75f, 1.0f), "+0x%02x", f.offset);

                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%u", f.size);

                ImGui::TableSetColumnIndex(3);
                bool all_known = true;
                for (uint32_t bi = 0; bi < f.size && f.offset + bi < struct_layout.total_size; bi++) {
                    if (!known[f.offset + bi]) { all_known = false; break; }
                }
                if (all_known && f.offset + f.size <= struct_layout.total_size) {
                    std::string val = format_field_value(f, struct_bytes.data() + f.offset,
                                                        struct_layout.total_size - f.offset);
                    ImGui::TextColored(fc, "%s", val.c_str());
                } else {
                    ImGui::TextDisabled("<?>");
                }

                ImGui::TableSetColumnIndex(4);
                uint64_t writer = (f.offset < struct_layout.total_size)
                    ? memory_.last_writer(display_addr + f.offset, 1, current_inst_) : 0;
                if (writer > 0) {
                    char wlbl[32];
                    snprintf(wlbl, sizeof(wlbl), "#%llu##fw%d", (unsigned long long)writer, fi);
                    if (ImGui::SmallButton(wlbl)) navigate_to(writer);
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Jump to writer inst #%llu", (unsigned long long)writer);
                } else {
                    ImGui::TextDisabled("---");
                }
            }
            ImGui::EndTable();
        }
    }

    ImGui::Separator();
    ImGui::TextDisabled(
        "Click: select byte | Dbl-click: jump to writer | Watch\xe2\x8c\x95: mark in Timeline | Struct Overlay: field-aware display");  // ⌕ (was 🔭)

    ImGui::End();
}

// ─── Context menu helpers (memory) ──────────────────────────────────────────

void GuiApp::render_mem_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_memory_panel().
    if (ImGui::BeginPopup("##mem_ctx")) {
        ImGui::TextDisabled("addr: 0x%016llx", (unsigned long long)ctx_mem_addr_);
        ImGui::Separator();
        if (ImGui::MenuItem("Open in Hex Dump")) {
            open_hex_dump_at(ctx_mem_addr_);
        }
        if (ImGui::MenuItem("Copy Address")) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_mem_addr_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Goto Instruction")) {
            navigate_to(ctx_mem_inst_id_);
        }
        if (xref_result_) {
            ImGui::Separator();
            // Show how many times this address was accessed
            auto row = fetch_row(ctx_mem_inst_id_);
            auto count = xref_result_->execution_count(row.pc);
            if (count > 0) {
                ImGui::TextDisabled("PC executed %llu times", (unsigned long long)count);
                if (ImGui::MenuItem("Next Xref (x)")) {
                    auto xrefs = xref_result_->inst_ids_at(row.pc);
                    if (!xrefs.empty()) {
                        xref_cursor_++;
                        if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
                        navigate_to(xrefs[xref_cursor_]);
                    }
                }
            }
        }
        ImGui::EndPopup();
    }
}

}  // namespace tenet
