// gui_app.mm — GUI application core: SDL3/Metal platform bootstrap, ImGui
// lifecycle, style/font setup, main run loop, and the top-level render_frame
// that hosts the dockspace and dispatches to the panels.
//
// This is the ONLY Objective-C++ translation unit in the GUI layer (it needs
// Metal/`__bridge`). All panel/popup/analysis/navigation logic has been split
// into sibling .cpp files (panels_*.cpp, popups.cpp, navigation.cpp,
// gui_chrome.cpp, gui_colors.cpp). They communicate purely through the
// GuiApp member-function declarations in gui_app.h + the linker.

#include "gui/gui_app.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/xref_pass.h"

#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_sdl3.h>
#include <imgui_impl_metal.h>

#include <SDL3/SDL.h>
#include <SDL3/SDL_metal.h>

#include <fmt/core.h>

#include <algorithm>
#include <cstring>
#include <string>

// Metal/ObjC interop (this file is compiled as Objective-C++)
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <AppKit/AppKit.h>     // NSMenu, NSMenuItem, NSMenuDelegate, NSApp

namespace tenet {

// ─── Constructor / Destructor ───────────────────────────────────────────────

GuiApp::GuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
               InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory) {
    total_inst_ = index.inst_count();

    // Restore bookmarks from the index (persisted in RocksDB META CF)
    bookmarks_ = index_.load_bookmarks();

    // Restore last cursor position ("continue where you left off")
    uint64_t last = index_.load_last_inst();
    if (last > 0 && last < total_inst_) {
        current_inst_ = last;
    }
}

GuiApp::~GuiApp() {
    shutdown();
}

// ─── SDL3 Initialization ────────────────────────────────────────────────────

bool GuiApp::init_sdl() {
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fmt::print(stderr, "SDL_Init failed: {}\n", SDL_GetError());
        return false;
    }

    // Create window with Metal support
    window_ = SDL_CreateWindow(
        "Tenet - Trace Explorer",
        1600, 1000,
        SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY | SDL_WINDOW_METAL
    );
    if (!window_) {
        fmt::print(stderr, "SDL_CreateWindow failed: {}\n", SDL_GetError());
        return false;
    }

    // Create Metal renderer (SDL3 manages the Metal layer and command encoder)
    renderer_ = SDL_CreateRenderer(window_, "metal");
    if (!renderer_) {
        fmt::print(stderr, "SDL_CreateRenderer failed: {}\n", SDL_GetError());
        return false;
    }

    // Get DPI scale
    dpi_scale_ = SDL_GetWindowDisplayScale(window_);
    if (dpi_scale_ <= 0.0f) dpi_scale_ = 1.0f;

    return true;
}

// ─── ImGui Initialization ───────────────────────────────────────────────────

bool GuiApp::init_imgui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

    // Pin imgui.ini to ~/.config/tenet/ so it doesn't land in the CWD
    {
        std::string dir = GuiSettings::default_path();
        auto sep = dir.rfind('/');
        if (sep != std::string::npos) dir.resize(sep);
        imgui_ini_path_ = dir + "/imgui.ini";
        io.IniFilename = imgui_ini_path_.c_str();
    }

    // Setup platform/renderer backends
    ImGui_ImplSDL3_InitForMetal(window_);

    // Get CAMetalLayer from SDL renderer and init ImGui Metal backend
    CAMetalLayer* layer = (__bridge CAMetalLayer*)SDL_GetRenderMetalLayer(renderer_);
    if (!layer) {
        fmt::print(stderr, "Failed to get CAMetalLayer from SDL renderer\n");
        return false;
    }
    layer.pixelFormat = MTLPixelFormatBGRA8Unorm;

    ImGui_ImplMetal_Init(layer.device);

    // Create our own command queue for ImGui rendering
    metal_command_queue_ = [layer.device newCommandQueue];
    metal_render_pass_desc_ = [MTLRenderPassDescriptor new];

    // Load persistent settings
    settings_.load(GuiSettings::default_path());
    available_fonts_ = GuiSettings::available_mono_fonts();

    setup_style();
    setup_fonts();

    return true;
}

// ─── Shutdown ───────────────────────────────────────────────────────────────

void GuiApp::shutdown() {
if (!window_) return;  // Already shut down

// Stop analysis worker + startup thread before destroying anything else.
stop_analysis_worker();

// Persist bookmarks and last cursor position to the index database
index_.save_bookmarks(bookmarks_);
index_.save_last_inst(current_inst_);

    ImGui_ImplMetal_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();

    if (renderer_) {
        SDL_DestroyRenderer(renderer_);
        renderer_ = nullptr;
    }
    if (window_) {
        SDL_DestroyWindow(window_);
        window_ = nullptr;
    }
    SDL_Quit();
}

// ─── Style Setup ────────────────────────────────────────────────────────────
// Inspired by IDA Pro / Binary Ninja dark themes — clean, dense, low-eye-strain

void GuiApp::setup_style() {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();

    // ── Spacing & sizing: dense like IDA, but not cramped ─────────────
    style.WindowPadding      = ImVec2(8.0f, 8.0f);
    style.FramePadding       = ImVec2(5.0f, 3.0f);
    style.CellPadding        = ImVec2(4.0f, 2.0f);
    style.ItemSpacing        = ImVec2(6.0f, 4.0f);
    style.ItemInnerSpacing   = ImVec2(4.0f, 4.0f);
    style.TouchExtraPadding  = ImVec2(0.0f, 0.0f);
    style.IndentSpacing      = 18.0f;
    style.ScrollbarSize      = 11.0f;
    style.GrabMinSize        = 8.0f;

    // ── Borders & rounding: subtle — like Binary Ninja/Ghidra ─────────
    style.WindowBorderSize   = 1.0f;
    style.ChildBorderSize    = 1.0f;
    style.PopupBorderSize    = 1.0f;
    style.FrameBorderSize    = 0.0f;
    style.TabBorderSize      = 0.0f;
    style.WindowRounding     = 6.0f;
    style.ChildRounding      = 4.0f;
    style.FrameRounding      = 3.0f;
    style.PopupRounding      = 4.0f;
    style.ScrollbarRounding  = 3.0f;
    style.GrabRounding       = 3.0f;
    style.TabRounding        = 4.0f;

    // ── Alignment ─────────────────────────────────────────────────────
    style.WindowTitleAlign   = ImVec2(0.0f, 0.5f);
    style.ButtonTextAlign    = ImVec2(0.5f, 0.5f);

    // ── Colors: "Tenet Dark" — deep navy + accent blue, IDA-inspired ──
    ImVec4* c = style.Colors;

    // Base background layers (darkest → lightest)
    c[ImGuiCol_WindowBg]              = ImVec4(0.075f, 0.078f, 0.095f, 1.00f);  // main bg
    c[ImGuiCol_ChildBg]               = ImVec4(0.060f, 0.063f, 0.078f, 1.00f);  // child panels
    c[ImGuiCol_PopupBg]               = ImVec4(0.095f, 0.098f, 0.120f, 0.97f);  // dropdowns/popups

    // Borders: very subtle separation lines
    c[ImGuiCol_Border]                = ImVec4(0.22f, 0.22f, 0.30f, 0.55f);
    c[ImGuiCol_BorderShadow]          = ImVec4(0.00f, 0.00f, 0.00f, 0.30f);

    // Frame backgrounds (input fields, etc.)
    c[ImGuiCol_FrameBg]               = ImVec4(0.11f, 0.11f, 0.14f, 1.00f);
    c[ImGuiCol_FrameBgHovered]        = ImVec4(0.17f, 0.18f, 0.23f, 1.00f);
    c[ImGuiCol_FrameBgActive]         = ImVec4(0.22f, 0.23f, 0.30f, 1.00f);

    // Title bar
    c[ImGuiCol_TitleBg]               = ImVec4(0.055f, 0.057f, 0.072f, 1.00f);
    c[ImGuiCol_TitleBgActive]         = ImVec4(0.090f, 0.095f, 0.130f, 1.00f);
    c[ImGuiCol_TitleBgCollapsed]      = ImVec4(0.055f, 0.057f, 0.072f, 0.75f);

    // Menu & toolbar
    c[ImGuiCol_MenuBarBg]             = ImVec4(0.085f, 0.088f, 0.110f, 1.00f);

    // Scrollbars
    c[ImGuiCol_ScrollbarBg]           = ImVec4(0.04f, 0.04f, 0.055f, 0.90f);
    c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.28f, 0.29f, 0.38f, 1.00f);
    c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.38f, 0.39f, 0.50f, 1.00f);
    c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.50f, 0.51f, 0.64f, 1.00f);

    // Check / radio marks
    c[ImGuiCol_CheckMark]             = ImVec4(0.40f, 0.75f, 1.00f, 1.00f);

    // Sliders & grabs
    c[ImGuiCol_SliderGrab]            = ImVec4(0.35f, 0.60f, 0.90f, 1.00f);
    c[ImGuiCol_SliderGrabActive]      = ImVec4(0.45f, 0.70f, 1.00f, 1.00f);

    // Buttons — muted steel blue (like IDA action buttons)
    c[ImGuiCol_Button]                = ImVec4(0.17f, 0.22f, 0.35f, 1.00f);
    c[ImGuiCol_ButtonHovered]         = ImVec4(0.23f, 0.32f, 0.52f, 1.00f);
    c[ImGuiCol_ButtonActive]          = ImVec4(0.28f, 0.40f, 0.65f, 1.00f);

    // Headers (TreeNode, CollapsingHeader, Table header cells)
    c[ImGuiCol_Header]                = ImVec4(0.16f, 0.18f, 0.26f, 1.00f);
    c[ImGuiCol_HeaderHovered]         = ImVec4(0.22f, 0.28f, 0.42f, 1.00f);
    c[ImGuiCol_HeaderActive]          = ImVec4(0.28f, 0.36f, 0.54f, 1.00f);

    // Separators
    c[ImGuiCol_Separator]             = ImVec4(0.22f, 0.22f, 0.30f, 0.80f);
    c[ImGuiCol_SeparatorHovered]      = ImVec4(0.35f, 0.50f, 0.75f, 1.00f);
    c[ImGuiCol_SeparatorActive]       = ImVec4(0.45f, 0.62f, 0.90f, 1.00f);

    // Resize grips
    c[ImGuiCol_ResizeGrip]            = ImVec4(0.25f, 0.35f, 0.55f, 0.30f);
    c[ImGuiCol_ResizeGripHovered]     = ImVec4(0.35f, 0.50f, 0.75f, 0.70f);
    c[ImGuiCol_ResizeGripActive]      = ImVec4(0.45f, 0.62f, 0.90f, 0.95f);

    // Tabs — IDA-style: inactive tabs are very dark, active has a colored underline feel
    c[ImGuiCol_Tab]                   = ImVec4(0.09f, 0.09f, 0.12f, 1.00f);
    c[ImGuiCol_TabHovered]            = ImVec4(0.20f, 0.32f, 0.52f, 1.00f);
    c[ImGuiCol_TabSelected]           = ImVec4(0.15f, 0.26f, 0.44f, 1.00f);
    c[ImGuiCol_TabSelectedOverline]   = ImVec4(0.40f, 0.70f, 1.00f, 1.00f);  // accent line on active tab
    c[ImGuiCol_TabDimmed]             = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
    c[ImGuiCol_TabDimmedSelected]     = ImVec4(0.11f, 0.16f, 0.26f, 1.00f);

    // Docking
    c[ImGuiCol_DockingPreview]        = ImVec4(0.25f, 0.45f, 0.75f, 0.65f);
    c[ImGuiCol_DockingEmptyBg]        = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);

    // Plot lines
    c[ImGuiCol_PlotLines]             = ImVec4(0.45f, 0.75f, 0.45f, 1.00f);
    c[ImGuiCol_PlotLinesHovered]      = ImVec4(0.60f, 1.00f, 0.60f, 1.00f);
    c[ImGuiCol_PlotHistogram]         = ImVec4(0.35f, 0.60f, 0.90f, 1.00f);
    c[ImGuiCol_PlotHistogramHovered]  = ImVec4(0.50f, 0.75f, 1.00f, 1.00f);

    // Table
    c[ImGuiCol_TableHeaderBg]         = ImVec4(0.09f, 0.09f, 0.13f, 1.00f);
    c[ImGuiCol_TableBorderStrong]     = ImVec4(0.20f, 0.20f, 0.28f, 1.00f);
    c[ImGuiCol_TableBorderLight]      = ImVec4(0.14f, 0.14f, 0.19f, 1.00f);
    c[ImGuiCol_TableRowBg]            = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    c[ImGuiCol_TableRowBgAlt]         = ImVec4(1.00f, 1.00f, 1.00f, 0.025f);  // very subtle stripe

    // Text selection
    c[ImGuiCol_TextSelectedBg]        = ImVec4(0.22f, 0.42f, 0.72f, 0.55f);

    // Drag & drop
    c[ImGuiCol_DragDropTarget]        = ImVec4(0.40f, 0.75f, 1.00f, 0.90f);

    // Nav highlight
    c[ImGuiCol_NavHighlight]          = ImVec4(0.40f, 0.65f, 1.00f, 1.00f);
    c[ImGuiCol_NavWindowingHighlight] = ImVec4(1.00f, 1.00f, 1.00f, 0.70f);
    c[ImGuiCol_NavWindowingDimBg]     = ImVec4(0.80f, 0.80f, 0.80f, 0.20f);

    // Modal dimming
    c[ImGuiCol_ModalWindowDimBg]      = ImVec4(0.05f, 0.05f, 0.08f, 0.55f);

    // Scale for HiDPI
    style.ScaleAllSizes(dpi_scale_);
}

// ─── Font Setup ─────────────────────────────────────────────────────────────

void GuiApp::setup_fonts() {
    ImGuiIO& io = ImGui::GetIO();

    float font_size = settings_.font_size * dpi_scale_;

    // Determine which font path to use
    std::string font_to_load = settings_.font_path;

    // If no font specified in settings, auto-detect
    if (font_to_load.empty()) {
        static const char* auto_paths[] = {
            "/System/Library/Fonts/SFNSMono.ttf",       // macOS 11+ SF Mono
            "/System/Library/Fonts/SFMono-Regular.otf",
            "/Library/Fonts/SF-Mono-Regular.otf",
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/Monaco.ttf",
            "/System/Library/Fonts/Monaco.dfont",
            nullptr
        };
        for (int i = 0; auto_paths[i] != nullptr; i++) {
            if (FILE* f = fopen(auto_paths[i], "rb")) {
                fclose(f);
                font_to_load = auto_paths[i];
                break;
            }
        }
    }

    bool font_loaded = false;
    if (!font_to_load.empty()) {
        if (FILE* f = fopen(font_to_load.c_str(), "rb")) {
            fclose(f);
            ImFontConfig config;
            config.OversampleH = settings_.oversample_h;
            config.OversampleV = 1;
            config.PixelSnapH = settings_.pixel_snap;
            io.Fonts->AddFontFromFileTTF(font_to_load.c_str(), font_size, &config);
            font_loaded = true;
        }
    }

    if (!font_loaded) {
        ImFontConfig config;
        config.SizePixels = font_size;
        io.Fonts->AddFontDefault(&config);
    }

    // ── Merge Unicode symbol ranges from Apple Symbols ───────────────────
    // The primary monospace font (SF Mono / Menlo) only covers ASCII + Latin-1.
    // UI chrome uses Unicode glyphs: arrows (←→▲▼↺↳↵⇆), geometric shapes
    // (▶▷◁▸), stars (★☆), dingbats (⚠✂), punctuation (…—) etc.
    // We merge these ranges from Apple Symbols so they render correctly.
    static const char* symbol_font = "/System/Library/Fonts/Apple Symbols.ttf";
    if (FILE* sf = fopen(symbol_font, "rb")) {
        fclose(sf);

        // Custom glyph range table covering all UI symbols used in tenet:
        //   U+00D7        × (multiplication sign, used for close button)
        //   U+2013–U+2026 General Punctuation (—, …)
        //   U+2190–U+21FF Arrows (←→↑↓↺↳↵⇆ and friends)
        //   U+2395        ⌕ (APL search icon)
        //   U+25A0–U+25FF Geometric Shapes (▶▷◁▲▼▸ etc.)
        //   U+2600–U+26FF Misc Symbols (★☆⚠ etc.)
        //   U+2700–U+27BF Dingbats (✂ etc.)
        static const ImWchar symbol_ranges[] = {
            0x00D7, 0x00D7,   // ×
            0x2013, 0x2026,   // —…
            0x2190, 0x21FF,   // Arrows
            0x2395, 0x2395,   // ⌕
            0x25A0, 0x25FF,   // Geometric Shapes
            0x2600, 0x26FF,   // Misc Symbols
            0x2700, 0x27BF,   // Dingbats
            0,
        };

        ImFontConfig sym_cfg;
        sym_cfg.MergeMode   = true;   // merge into the already-loaded font
        sym_cfg.OversampleH = 1;      // symbols don't need sub-pixel AA
        sym_cfg.OversampleV = 1;
        sym_cfg.GlyphOffset = ImVec2(0.0f, 1.0f);  // minor baseline alignment
        io.Fonts->AddFontFromFileTTF(symbol_font, font_size, &sym_cfg, symbol_ranges);
    }

    io.FontGlobalScale = 1.0f;
    io.Fonts->Build();
}

// ─── Rebuild fonts (called when settings change) ────────────────────────────

void GuiApp::rebuild_fonts() {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    setup_fonts();
    // The Metal backend will pick up new font atlas on next frame
    ImGui_ImplMetal_DestroyFontsTexture();
}

// ─── Apply settings (theme + style) ────────────────────────────────────────

void GuiApp::apply_settings() {
    // Apply theme
    switch (settings_.theme) {
        case GuiSettings::Theme::Dark:    ImGui::StyleColorsDark(); break;
        case GuiSettings::Theme::Light:   ImGui::StyleColorsLight(); break;
        case GuiSettings::Theme::Classic: ImGui::StyleColorsClassic(); break;
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.ItemSpacing.y = settings_.row_spacing;

    // Re-apply our custom dark modifications if dark theme
    if (settings_.theme == GuiSettings::Theme::Dark) {
        style.WindowPadding = ImVec2(6.0f, 6.0f);
        style.FramePadding = ImVec2(4.0f, 2.0f);
        style.ItemSpacing.x = 6.0f;
        style.ItemInnerSpacing = ImVec2(4.0f, 4.0f);
        style.ScrollbarSize = 12.0f;
        style.GrabMinSize = 8.0f;
        style.WindowRounding = 4.0f;
        style.FrameRounding = 2.0f;
        style.ScrollbarRounding = 2.0f;
        style.GrabRounding = 2.0f;
        style.TabRounding = 2.0f;

        ImVec4* colors = style.Colors;
        colors[ImGuiCol_WindowBg]             = ImVec4(0.08f, 0.08f, 0.10f, 1.00f);
        colors[ImGuiCol_ChildBg]              = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);
        colors[ImGuiCol_PopupBg]              = ImVec4(0.10f, 0.10f, 0.12f, 0.95f);
        colors[ImGuiCol_Border]               = ImVec4(0.25f, 0.25f, 0.30f, 0.60f);
        colors[ImGuiCol_FrameBg]              = ImVec4(0.12f, 0.12f, 0.15f, 1.00f);
        colors[ImGuiCol_FrameBgHovered]       = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
        colors[ImGuiCol_FrameBgActive]        = ImVec4(0.22f, 0.22f, 0.28f, 1.00f);
        colors[ImGuiCol_TitleBg]              = ImVec4(0.06f, 0.06f, 0.08f, 1.00f);
        colors[ImGuiCol_TitleBgActive]        = ImVec4(0.10f, 0.10f, 0.14f, 1.00f);
        colors[ImGuiCol_MenuBarBg]            = ImVec4(0.10f, 0.10f, 0.12f, 1.00f);
    }

    style.ScaleAllSizes(dpi_scale_);

    // NOTE: Font rebuild is intentionally NOT done here.
    // It is deferred to the start of the next frame (before ImGui::NewFrame())
    // because rebuilding fonts mid-frame invalidates the current ImFont pointer,
    // causing crashes in any subsequent ImGui text rendering calls within this frame.
}

}  // namespace tenet  (temporarily close to allow ObjC class definitions below)

// ─── Native macOS Menu Bar ───────────────────────────────────────────────────
//
// Placed OUTSIDE namespace tenet because Objective-C @interface / @implementation
// declarations must appear at global (file) scope.  The C++ member functions
// (GuiApp::_post_native_action etc.) are defined with full tenet:: qualification.
//
// Architecture:
//  • TenetMenuTarget    — NSObject action target; each NSMenuItem fires menuAction:
//                         which calls GuiApp::_post_native_action(tag).
//  • TenetMenuDelegate  — NSMenuDelegate; -menuNeedsUpdate: fires just before the
//                         menu opens and calls GuiApp::_update_native_menu(menu)
//                         to refresh enabled/checkmark state.
//  • GuiApp::_post_native_action — posts a lambda into pending_native_actions_.
//  • GuiApp::consume_native_actions — drained at the top of every render frame.
//  • GuiApp::setup_native_menu — builds the NSMenu tree and calls [NSApp setMainMenu:].

// ── Integer tag for each menu item (visible to both ObjC and C++) ────────────
enum MenuTag : NSInteger {
    kTagFileQuit          = 100,
    kTagEditSettings      = 200,
    kTagViewRegisters     = 300,
    kTagViewMemory        = 301,
    kTagViewCallStack     = 302,
    kTagViewAnalysis      = 303,
    kTagViewHexDump       = 304,
    kTagViewStrings       = 305,
    kTagViewFunctions     = 306,
    kTagViewThreads       = 307,
    kTagViewMinimap       = 310,
    kTagViewLoops         = 311,
    kTagViewCFG           = 312,
    kTagViewObjC          = 320,
    kTagViewLoopSemantics = 321,
    kTagViewPatterns      = 322,
    kTagViewConstants     = 323,
    kTagViewAlgoSummary   = 324,
    kTagViewCallGraph          = 325,
    kTagViewObjCCrypto        = 326,
    kTagViewMemStrings        = 327,
    kTagViewSyscallIntercept  = 328,
    kTagViewCacheSim          = 329,
    kTagViewRegTimeline       = 330,
    kTagViewDwarf             = 331,
    kTagViewTraceDiff         = 332,
    kTagViewTraceFold         = 333,
    kTagNavGoto           = 400,
    kTagNavSearch         = 401,
    kTagNavBack           = 402,
    kTagNavForward        = 403,
    kTagNavFirst          = 404,
    kTagNavLast           = 405,
    kTagNavBookmark       = 406,
    kTagNavFollowCall     = 407,
    kTagNavFollowReturn   = 408,
    kTagAnaTaint          = 500,
    kTagAnaBackTaint      = 501,
    kTagAnaSlice          = 502,
    kTagAnaFunction       = 510,
    kTagAnaXref           = 511,
    kTagAnaStrings        = 512,
    kTagAnaThread         = 513,
    kTagAnaCallGraph      = 514,
    kTagAnaLoop           = 515,
    kTagAnaCFG            = 516,
    kTagAnaClear          = 520,
};

// ── ObjC action target ────────────────────────────────────────────────────────
@interface TenetMenuTarget : NSObject
@property (assign, nonatomic) tenet::GuiApp* app;
- (void)menuAction:(NSMenuItem*)sender;
@end

@implementation TenetMenuTarget
- (void)menuAction:(NSMenuItem*)sender {
    if (!self.app) return;
    self.app->_post_native_action(static_cast<long>(sender.tag));
}
@end

// ── ObjC delegate: update enabled/checkmarks before menu opens ───────────────
@interface TenetMenuDelegate : NSObject <NSMenuDelegate>
@property (assign, nonatomic) tenet::GuiApp* app;
@end

@implementation TenetMenuDelegate
- (void)menuNeedsUpdate:(NSMenu*)menu {
    if (!self.app) return;
    self.app->_update_native_menu((__bridge void*)menu);
}
@end

// ── Static helper: make a tagged menu item ───────────────────────────────────
static NSMenuItem* tenet_make_item(NSString* title, NSString* key,
                                    NSUInteger mods, NSInteger tag,
                                    TenetMenuTarget* target) {
    NSMenuItem* it = [[NSMenuItem alloc] initWithTitle:title
                                                action:@selector(menuAction:)
                                         keyEquivalent:key];
    it.keyEquivalentModifierMask = mods;
    it.tag    = tag;
    it.target = target;
    return it;
}

// ── Static helper: make a submenu with delegate ───────────────────────────────
static NSMenu* tenet_make_submenu(NSString* title, TenetMenuDelegate* delegate) {
    NSMenu* m = [[NSMenu alloc] initWithTitle:title];
    m.autoenablesItems = NO;
    m.delegate = delegate;
    return m;
}

// ── C++ member-function implementations ──────────────────────────────────────

void tenet::GuiApp::_post_native_action(long tag) {
    std::function<void()> action;
    switch (static_cast<MenuTag>(tag)) {
        case kTagFileQuit:          action = [this]{ running_ = false; }; break;
        case kTagEditSettings:      action = [this]{ show_settings_ = true; }; break;

        case kTagViewRegisters:     action = [this]{ show_registers_         = !show_registers_;         }; break;
        case kTagViewMemory:        action = [this]{ show_memory_             = !show_memory_;             }; break;
        case kTagViewCallStack:     action = [this]{ show_callstack_          = !show_callstack_;          }; break;
        case kTagViewAnalysis:      action = [this]{ show_analysis_           = !show_analysis_;           }; break;
        case kTagViewHexDump:       action = [this]{ show_hex_dump_           = !show_hex_dump_;           }; break;
        case kTagViewStrings:       action = [this]{ show_strings_            = !show_strings_;            }; break;
        case kTagViewFunctions:     action = [this]{ show_functions_          = !show_functions_;          }; break;
        case kTagViewThreads:       action = [this]{ show_threads_            = !show_threads_;            }; break;
        case kTagViewMinimap:       action = [this]{ show_minimap_            = !show_minimap_;            }; break;
        case kTagViewLoops:         action = [this]{ show_loops_              = !show_loops_;              }; break;
        case kTagViewCFG:           action = [this]{ show_cfg_                = !show_cfg_;                }; break;
        case kTagViewObjC:          action = [this]{ show_objc_               = !show_objc_;               }; break;
        case kTagViewLoopSemantics: action = [this]{ show_loop_semantics_     = !show_loop_semantics_;     }; break;
        case kTagViewPatterns:      action = [this]{ show_pattern_            = !show_pattern_;            }; break;
        case kTagViewConstants:     action = [this]{ show_constant_           = !show_constant_;           }; break;
        case kTagViewAlgoSummary:   action = [this]{ show_algorithm_summary_  = !show_algorithm_summary_;  }; break;
        case kTagViewCallGraph:          action = [this]{ show_call_graph_         = !show_call_graph_;         }; break;
        case kTagViewObjCCrypto:       action = [this]{ show_objc_crypto_        = !show_objc_crypto_;        }; break;
        case kTagViewMemStrings:       action = [this]{ show_mem_strings_        = !show_mem_strings_;        }; break;
        case kTagViewSyscallIntercept: action = [this]{ show_syscall_intercept_  = !show_syscall_intercept_;  }; break;
        case kTagViewCacheSim:         action = [this]{ show_cache_sim_          = !show_cache_sim_;          }; break;
        case kTagViewTraceFold:        action = [this]{ show_trace_fold_         = !show_trace_fold_;         }; break;
        case kTagViewRegTimeline:      action = [this]{ show_reg_timeline_       = !show_reg_timeline_;       }; break;
        case kTagViewDwarf:         action = [this]{ show_dwarf_panel_        = !show_dwarf_panel_;        }; break;
        case kTagViewTraceDiff:     action = [this]{ show_trace_diff_         = !show_trace_diff_;         }; break;

        case kTagNavGoto:           action = [this]{ show_goto_popup_   = true; }; break;
        case kTagNavSearch:         action = [this]{ show_search_popup_ = true; }; break;
        case kTagNavBack:           action = [this]{ nav_back();   }; break;
        case kTagNavForward:        action = [this]{ nav_forward(); }; break;
        case kTagNavFirst:          action = [this]{ navigate_to(0); }; break;
        case kTagNavLast:           action = [this]{ navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0); }; break;
        case kTagNavBookmark:       action = [this]{ toggle_bookmark(); }; break;
        case kTagNavFollowCall:
            action = [this]{
                if (function_result_) {
                    auto* evt = function_result_->call_at(current_inst_);
                    if (evt && evt->call_inst_id + 1 < total_inst_)
                        navigate_to(evt->call_inst_id + 1);
                }
            };
            break;
        case kTagNavFollowReturn:
            action = [this]{
                if (function_result_) {
                    auto* evt = function_result_->return_at(current_inst_);
                    if (evt) {
                        navigate_to(evt->call_inst_id);
                    } else {
                        const auto& stk = current_call_stack();
                        if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
                    }
                }
            };
            break;

        case kTagAnaTaint:          action = [this]{ run_taint_analysis(); }; break;
        case kTagAnaBackTaint:      action = [this]{ run_backward_taint_analysis(); }; break;
        case kTagAnaSlice:          action = [this]{ run_slice_analysis(); }; break;
        case kTagAnaFunction:       action = [this]{ run_pass_by_name("function"); }; break;
        case kTagAnaXref:           action = [this]{ run_pass_by_name("xref"); }; break;
        case kTagAnaStrings:        action = [this]{ run_pass_by_name("strings"); }; break;
        case kTagAnaThread:         action = [this]{ run_pass_by_name("thread"); }; break;
        case kTagAnaCallGraph:      action = [this]{ run_call_graph_analysis(); }; break;
        case kTagAnaLoop:           action = [this]{ run_pass_by_name("loop"); }; break;
        case kTagAnaCFG:            action = [this]{ run_cfg_layout(); }; break;
        case kTagAnaClear:          action = [this]{ clear_analysis(); }; break;

        default: return;
    }
    if (action) {
        std::lock_guard<std::mutex> lk(native_action_mutex_);
        pending_native_actions_.push_back(std::move(action));
    }
}

void tenet::GuiApp::_update_native_menu(void* menuPtr) {
    NSMenu* menu = (__bridge NSMenu*)menuPtr;
    for (NSMenuItem* it in menu.itemArray) {
        switch (static_cast<MenuTag>(it.tag)) {
            case kTagNavBack:
                it.enabled = can_nav_back(); break;
            case kTagNavForward:
                it.enabled = can_nav_forward(); break;
            case kTagNavFollowCall:
                it.enabled = (function_result_ != nullptr &&
                               function_result_->call_at(current_inst_) != nullptr); break;
            case kTagNavFollowReturn:
                it.enabled = (function_result_ != nullptr &&
                               (function_result_->return_at(current_inst_) != nullptr ||
                                !current_call_stack().empty())); break;

            case kTagViewRegisters:     it.state = show_registers_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMemory:        it.state = show_memory_             ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCallStack:     it.state = show_callstack_          ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewAnalysis:      it.state = show_analysis_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewHexDump:       it.state = show_hex_dump_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewStrings:       it.state = show_strings_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewFunctions:     it.state = show_functions_          ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewThreads:       it.state = show_threads_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMinimap:       it.state = show_minimap_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewLoops:         it.state = show_loops_              ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCFG:           it.state = show_cfg_                ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewObjC:          it.state = show_objc_               ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewLoopSemantics: it.state = show_loop_semantics_     ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewPatterns:      it.state = show_pattern_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewConstants:     it.state = show_constant_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewAlgoSummary:   it.state = show_algorithm_summary_  ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCallGraph:          it.state = show_call_graph_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewObjCCrypto:       it.state = show_objc_crypto_        ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMemStrings:       it.state = show_mem_strings_        ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewSyscallIntercept: it.state = show_syscall_intercept_  ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCacheSim:         it.state = show_cache_sim_          ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewTraceFold:        it.state = show_trace_fold_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewRegTimeline:      it.state = show_reg_timeline_       ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewDwarf:         it.state = show_dwarf_panel_        ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewTraceDiff:     it.state = show_trace_diff_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            default: break;
        }
    }
}

void tenet::GuiApp::consume_native_actions() {
    std::vector<std::function<void()>> local;
    {
        std::lock_guard<std::mutex> lk(native_action_mutex_);
        local.swap(pending_native_actions_);
    }
    for (auto& fn : local) fn();
}

void tenet::GuiApp::setup_native_menu() {
    TenetMenuTarget*   target   = [[TenetMenuTarget alloc] init];
    target.app = this;
    TenetMenuDelegate* delegate = [[TenetMenuDelegate alloc] init];
    delegate.app = this;

    const NSUInteger Cmd   = NSEventModifierFlagCommand;
    const NSUInteger Shift = NSEventModifierFlagShift;

    auto mk = [&](NSString* title, NSString* key, NSUInteger mods, NSInteger tag) -> NSMenuItem* {
        return tenet_make_item(title, key, mods, tag, target);
    };
    auto sep = []() -> NSMenuItem* { return [NSMenuItem separatorItem]; };
    auto sub = [&](NSString* title) -> NSMenu* {
        return tenet_make_submenu(title, delegate);
    };

    NSMenu* bar = [[NSMenu alloc] initWithTitle:@"MainMenu"];

    // ── App menu ────────────────────────────────────────────────────
    {
        NSMenuItem* appItem = [[NSMenuItem alloc] initWithTitle:@"Tenet" action:nil keyEquivalent:@""];
        NSMenu* appMenu = sub(@"Tenet");
        NSMenuItem* about = [[NSMenuItem alloc] initWithTitle:@"About Tenet"
                                                       action:@selector(orderFrontStandardAboutPanel:)
                                                keyEquivalent:@""];
        about.target = NSApp;
        [appMenu addItem:about];
        [appMenu addItem:sep()];
        [appMenu addItem:mk(@"Settings\u2026", @",", Cmd, kTagEditSettings)];
        [appMenu addItem:sep()];
        [appMenu addItem:mk(@"Quit Tenet", @"q", Cmd, kTagFileQuit)];
        appItem.submenu = appMenu;
        [bar addItem:appItem];
    }

    // ── File menu ────────────────────────────────────────────────────
    {
        NSMenuItem* fileItem = [[NSMenuItem alloc] initWithTitle:@"File" action:nil keyEquivalent:@""];
        NSMenu* fileMenu = sub(@"File");
        NSMenuItem* openItem = [[NSMenuItem alloc] initWithTitle:@"Open Trace\u2026"
                                                          action:nil
                                                   keyEquivalent:@"o"];
        openItem.keyEquivalentModifierMask = Cmd;
        openItem.enabled = NO;
        [fileMenu addItem:openItem];
        fileItem.submenu = fileMenu;
        [bar addItem:fileItem];
    }

    // ── View menu ────────────────────────────────────────────────────
    {
        NSMenuItem* viewItem = [[NSMenuItem alloc] initWithTitle:@"View" action:nil keyEquivalent:@""];
        NSMenu* viewMenu = sub(@"View");
        [viewMenu addItem:mk(@"Registers",            @"r", Cmd, kTagViewRegisters)];
        [viewMenu addItem:mk(@"Memory",               @"m", Cmd, kTagViewMemory)];
        [viewMenu addItem:mk(@"Call Stack",           @"",  0,   kTagViewCallStack)];
        [viewMenu addItem:mk(@"Analysis",             @"",  0,   kTagViewAnalysis)];
        [viewMenu addItem:mk(@"Hex Dump",             @"",  0,   kTagViewHexDump)];
        [viewMenu addItem:mk(@"Strings",              @"",  0,   kTagViewStrings)];
        [viewMenu addItem:mk(@"Functions",            @"",  0,   kTagViewFunctions)];
        [viewMenu addItem:mk(@"Threads",              @"",  0,   kTagViewThreads)];
        [viewMenu addItem:sep()];
        [viewMenu addItem:mk(@"Minimap",              @"",  0,   kTagViewMinimap)];
        [viewMenu addItem:mk(@"Loop Highlight",       @"",  0,   kTagViewLoops)];
        [viewMenu addItem:mk(@"CFG View",             @"",  0,   kTagViewCFG)];
        [viewMenu addItem:sep()];
        [viewMenu addItem:mk(@"ObjC Messages",        @"",  0,   kTagViewObjC)];
        [viewMenu addItem:mk(@"Loop Semantics",       @"",  0,   kTagViewLoopSemantics)];
        [viewMenu addItem:mk(@"Patterns",             @"",  0,   kTagViewPatterns)];
        [viewMenu addItem:mk(@"Constants",            @"",  0,   kTagViewConstants)];
        [viewMenu addItem:mk(@"Algorithm Summary",    @"",  0,   kTagViewAlgoSummary)];
        [viewMenu addItem:mk(@"Call Graph",           @"",  0,   kTagViewCallGraph)];
        [viewMenu addItem:mk(@"ObjC Crypto",          @"",  0,   kTagViewObjCCrypto)];
        [viewMenu addItem:mk(@"Memory Strings",       @"",  0,   kTagViewMemStrings)];
        [viewMenu addItem:mk(@"API Intercepts",       @"",  0,   kTagViewSyscallIntercept)];
        [viewMenu addItem:mk(@"Cache Sim",            @"",  0,   kTagViewCacheSim)];
        [viewMenu addItem:mk(@"Trace Fold",           @"",  0,   kTagViewTraceFold)];
        [viewMenu addItem:sep()];
        [viewMenu addItem:mk(@"Register Timeline",    @"",  0,   kTagViewRegTimeline)];
        [viewMenu addItem:mk(@"Symbol Info (DWARF)",  @"",  0,   kTagViewDwarf)];
        [viewMenu addItem:mk(@"Trace Diff",           @"",  0,   kTagViewTraceDiff)];
        viewItem.submenu = viewMenu;
        [bar addItem:viewItem];
    }

    // ── Navigate menu ────────────────────────────────────────────────
    {
        NSMenuItem* navItem = [[NSMenuItem alloc] initWithTitle:@"Navigate" action:nil keyEquivalent:@""];
        NSMenu* navMenu = sub(@"Navigate");
        [navMenu addItem:mk(@"Go to Instruction\u2026", @"g", Cmd, kTagNavGoto)];
        [navMenu addItem:mk(@"Search\u2026",            @"f", Cmd, kTagNavSearch)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Back",               @"[", Cmd, kTagNavBack)];
        [navMenu addItem:mk(@"Forward",            @"]", Cmd, kTagNavForward)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"First Instruction",  @"",  0,   kTagNavFirst)];
        [navMenu addItem:mk(@"Last Instruction",   @"",  0,   kTagNavLast)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Toggle Bookmark",    @"b", Cmd, kTagNavBookmark)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Follow Call",        @"",  0,   kTagNavFollowCall)];
        [navMenu addItem:mk(@"Follow Return",      @"",  0,   kTagNavFollowReturn)];
        navItem.submenu = navMenu;
        [bar addItem:navItem];
    }

    // ── Analysis menu ────────────────────────────────────────────────
    {
        NSMenuItem* anaItem = [[NSMenuItem alloc] initWithTitle:@"Analysis" action:nil keyEquivalent:@""];
        NSMenu* anaMenu = sub(@"Analysis");
        [anaMenu addItem:mk(@"Forward Taint",    @"t", Cmd,         kTagAnaTaint)];
        [anaMenu addItem:mk(@"Backward Taint",   @"t", Cmd | Shift, kTagAnaBackTaint)];
        [anaMenu addItem:mk(@"Slice",            @"s", Cmd,         kTagAnaSlice)];
        [anaMenu addItem:sep()];
        [anaMenu addItem:mk(@"Function Analysis",  @"", 0, kTagAnaFunction)];
        [anaMenu addItem:mk(@"Xref Analysis",      @"", 0, kTagAnaXref)];
        [anaMenu addItem:mk(@"String Analysis",    @"", 0, kTagAnaStrings)];
        [anaMenu addItem:mk(@"Thread Analysis",    @"", 0, kTagAnaThread)];
        [anaMenu addItem:mk(@"Call Graph",         @"", 0, kTagAnaCallGraph)];
        [anaMenu addItem:mk(@"Loop Analysis",      @"", 0, kTagAnaLoop)];
        [anaMenu addItem:mk(@"CFG Layout",         @"", 0, kTagAnaCFG)];
        [anaMenu addItem:sep()];
        [anaMenu addItem:mk(@"Clear All Analysis", @"", 0, kTagAnaClear)];
        anaItem.submenu = anaMenu;
        [bar addItem:anaItem];
    }

    [NSApp setMainMenu:bar];
}

// Re-open namespace for the rest of the file (run loop, render_frame, etc.)
namespace tenet {

// ─── Main Run Loop ──────────────────────────────────────────────────────────

int GuiApp::run() {
    if (!init_sdl()) return 1;
    if (!init_imgui()) return 1;

    // Build native macOS menu bar and assign to [NSApp mainMenu].
    // Must be called after SDL/ImGui are initialised (NSApp is ready).
    setup_native_menu();

    // Start the background analysis worker thread (processes manual triggers).
    start_analysis_worker();

    // Kick off background startup analysis immediately after UI is ready.
    // The analyses run in a separate thread; results are delivered via
    // pending_apply_ and applied on the UI thread each frame.
    run_startup_analysis();

    while (running_) {
        // ─── 1. Poll SDL events ─────────────────────────────────────
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL3_ProcessEvent(&event);

            if (event.type == SDL_EVENT_QUIT) {
                running_ = false;
            }
            if (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                event.window.windowID == SDL_GetWindowID(window_)) {
                running_ = false;
            }
        }

        // ─── 1.5. Apply pending analysis results on the UI thread ────
        // Worker threads post result-pointer assignments here; draining
        // them on the UI thread eliminates data races.
        apply_pending_results();

        // ─── 2. Acquire Metal drawable and begin render pass ─────────
        @autoreleasepool {
            CAMetalLayer* layer = (__bridge CAMetalLayer*)SDL_GetRenderMetalLayer(renderer_);
            id<CAMetalDrawable> drawable = [layer nextDrawable];
            if (!drawable) {
                // If we just applied analysis results but couldn't get a
                // drawable, we need to render them in the next iteration.
                // Nothing special to do — results_applied_this_frame_ will
                // remain true and the main loop will retry immediately.
                continue;
            }

            // Configure render pass descriptor
            metal_render_pass_desc_.colorAttachments[0].texture = drawable.texture;
            metal_render_pass_desc_.colorAttachments[0].loadAction = MTLLoadActionClear;
            metal_render_pass_desc_.colorAttachments[0].storeAction = MTLStoreActionStore;
            metal_render_pass_desc_.colorAttachments[0].clearColor = MTLClearColorMake(0.098, 0.098, 0.118, 1.0);

            id<MTLCommandBuffer> commandBuffer = [metal_command_queue_ commandBuffer];
            id<MTLRenderCommandEncoder> renderEncoder =
                [commandBuffer renderCommandEncoderWithDescriptor:metal_render_pass_desc_];

            // ─── 2.5. Rebuild fonts if needed (must happen before NewFrame) ──
            // Font rebuilding is deferred here from render_settings_window()
            // because calling rebuild_fonts() mid-frame destroys the active ImFont,
            // causing SIGSEGV in subsequent ImGui text rendering calls.
            if (settings_font_dirty_) {
                rebuild_fonts();
                settings_font_dirty_ = false;
            }

            // ─── 3. Start ImGui frame ────────────────────────────────
            ImGui_ImplMetal_NewFrame(metal_render_pass_desc_);
            ImGui_ImplSDL3_NewFrame();
            ImGui::NewFrame();

            // ─── 4. Render application content (DockSpace + panels) ──
            render_frame();

            // ─── 5. Finalize ImGui rendering ─────────────────────────
            ImGui::Render();
            ImGui_ImplMetal_RenderDrawData(
                ImGui::GetDrawData(), commandBuffer, renderEncoder);

            // ─── 6. End encoding and present ─────────────────────────
            [renderEncoder endEncoding];
            [commandBuffer presentDrawable:drawable];
            [commandBuffer commit];
        }
    }

    return 0;
}

// ─── Main Frame Render ──────────────────────────────────────────────────────
// Layout inspired by IDA Pro / Binary Ninja:
//  ┌──────────────────────────────────────────────────────────┐
//  │ Menu Bar                                                  │
//  ├──────────────────────────────────────────────────────────┤
//  │ Toolbar (fixed height, not docked)                       │
//  ├──────────────────────────────────────────────────────────┤
//  │ Timeline (fixed height, execution progress bar)          │
//  ├────────────┬──────────────────────────┬──────────────────┤
//  │ Functions  │  Instructions / CFG /    │  Registers       │
//  │ Threads    │  Strings (main, ~65%)    │  Memory Accesses │
//  │  (~15%)    │  [default: Instructions] │  (~20%)          │
//  │            ├──────────────────────────┤                  │
//  │            │  Analysis / Call Stack / │                  │
//  │            │  Hex Dump  (~22%)        │                  │
//  ├────────────┴──────────────────────────┴──────────────────┤
//  │ Status Bar (fixed height, not docked)                    │
//  └──────────────────────────────────────────────────────────┘
//
// (kToolbarHeight / kTimelineHeight / kStatusBarHeight are now class-level
//  static constexpr members declared in gui_app.h, shared with the toolbar
//  and status bar translation units.)

void GuiApp::render_frame() {
    // Drain any menu-item actions posted by the native macOS menu bar callbacks.
    // Must happen before any ImGui calls to avoid state corruption.
    consume_native_actions();

    ImGuiViewport* viewport = ImGui::GetMainViewport();

    // ─── Toolbar (fixed at top, above dockspace) ─────────────────────
    const float toolbar_y  = viewport->WorkPos.y;
    const float timeline_y = toolbar_y + kToolbarHeight;
    const float dockspace_y = timeline_y + kTimelineHeight;
    const float status_y   = viewport->WorkPos.y + viewport->WorkSize.y - kStatusBarHeight;
    const float dockspace_h = status_y - dockspace_y;

    // ─── Create a DockSpace covering the area between timeline and status bar ──
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, dockspace_y));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, dockspace_h));
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags dock_flags =
        ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("DockSpaceHost", nullptr, dock_flags);
    ImGui::PopStyleVar(3);

    // Create the DockSpace
    ImGuiID dockspace_id = ImGui::GetID("TenetDockSpace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f),
        ImGuiDockNodeFlags_PassthruCentralNode);

    // ─── Default layout (first frame only) ───────────────────────────
    // Layout proportions tuned to match IDA Pro's information density:
//   - Left  15% : Functions/Threads sidebar (narrow, just enough for names)
//   - Center 65%: Instructions+CFG+Strings (core analysis area, max width)
//                  Default active tab: Instructions
    //   - Right  20%: Registers+Memory (compact but readable)
    if (first_frame_) {
        first_frame_ = false;

        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, ImVec2(viewport->WorkSize.x, dockspace_h));

        // ── Step 1: carve off left sidebar (15%) ──
        ImGuiID dock_left_sidebar, dock_rest;
        ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.15f,
                                    &dock_left_sidebar, &dock_rest);

        // ── Step 2: carve off right panel (≈24% of total = 20% visible) ──
        ImGuiID dock_center, dock_right;
        ImGui::DockBuilderSplitNode(dock_rest, ImGuiDir_Right, 0.24f,
                                    &dock_right, &dock_center);

        // ── Step 3: split center vertically: main (78%) | output (22%) ──
        ImGuiID dock_center_main, dock_center_bottom;
        ImGui::DockBuilderSplitNode(dock_center, ImGuiDir_Down, 0.22f,
                                    &dock_center_bottom, &dock_center_main);

        // ── Step 4: split right vertically: registers (62%) | memory (38%) ──
        ImGuiID dock_right_regs, dock_right_mem;
        ImGui::DockBuilderSplitNode(dock_right, ImGuiDir_Down, 0.38f,
                                    &dock_right_mem, &dock_right_regs);

        // ── Assign windows to nodes ──

        // Left sidebar: Threads first, then Functions (last = default active tab)
        ImGui::DockBuilderDockWindow("Threads",   dock_left_sidebar);
        ImGui::DockBuilderDockWindow("Functions", dock_left_sidebar);

        // Center main: CFG + Strings first, then Instructions (last = default active tab)
        // ImGui DockBuilder: the last DockBuilderDockWindow call wins as active tab.
        ImGui::DockBuilderDockWindow("CFG",          dock_center_main);
        ImGui::DockBuilderDockWindow("Strings",      dock_center_main);
        ImGui::DockBuilderDockWindow("Instructions", dock_center_main);

        // Center bottom output: Call Stack + Hex Dump + Minimap first,
        // then Analysis last (default active tab)
        ImGui::DockBuilderDockWindow("Call Stack",    dock_center_bottom);
        ImGui::DockBuilderDockWindow("Hex Dump",      dock_center_bottom);
        ImGui::DockBuilderDockWindow("Minimap",       dock_center_bottom);
        ImGui::DockBuilderDockWindow("Analysis",      dock_center_bottom);

        // Right column: Registers on top (more important), Memory below
        ImGui::DockBuilderDockWindow("Registers",       dock_right_regs);
        ImGui::DockBuilderDockWindow("Memory Accesses", dock_right_mem);

        ImGui::DockBuilderFinish(dockspace_id);
    }

    // ─── Activate panels whose analysis results just became available ─────
    // When apply_pass_result_pointers() enqueues a panel name in
    // pending_focus_windows_, we call SetWindowFocus here (inside the
    // DockSpaceHost Begin/End scope) so ImGui brings that dock tab to the
    // front.  We only do this once per notification to avoid fighting the
    // user's own tab selection.
    if (!pending_focus_windows_.empty()) {
        for (const auto& wname : pending_focus_windows_) {
            ImGui::SetWindowFocus(wname.c_str());
        }
        pending_focus_windows_.clear();
    }

    // ─── Menu bar: rendered inside the host window ───────────────────
    // NOTE: We removed the MenuBar from the host window flags, so we render
    //       the menu bar separately as a standalone menu bar window.
    ImGui::End();

    // ─── Toolbar ────────────────────────────────────────────────────
    // Note: the application menu bar is now the native macOS NSMenu
    // (set up in setup_native_menu()). The ImGui ##MainMenuBar window
    // has been removed. Toolbar is now pinned at the very top of the
    // SDL window area (WorkPos.y).
    render_toolbar();

    // ─── Global keyboard shortcuts ───────────────────────────────────
    // Dispatch when no text input is focused, OR on Escape
    // Follows IDA Pro / Binary Ninja conventions
    {
        bool want_kb = ImGui::GetIO().WantCaptureKeyboard;
        bool ctrl  = ImGui::GetIO().KeyCtrl;
        bool alt   = ImGui::GetIO().KeyAlt;
        bool shift = ImGui::GetIO().KeyShift;
        bool super = ImGui::GetIO().KeySuper;  // Cmd on macOS

        // Escape: close any active popup / search
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            if (search_active_) {
                search_active_ = false;
                search_results_.clear();
            }
            show_goto_popup_   = false;
            show_search_popup_ = false;
        }

        // ── Actions that should work even with keyboard focused ───────────
        // (Cmd+Q: quit)
        if ((super || ctrl) && ImGui::IsKeyPressed(ImGuiKey_Q)) {
            running_ = false;
        }
        // (Cmd+,: settings)
        if ((super || ctrl) && ImGui::IsKeyPressed(ImGuiKey_Comma)) {
            show_settings_ = !show_settings_;
            if (!show_settings_) pending_font_.initialized = false;
        }

        // ── Non-text-input shortcuts ──────────────────────────────────────
        if (!want_kb) {
            // Navigation history: Alt+Left / Alt+Right (Binary Ninja / IDA)
            if (alt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) {
                nav_back();
            }
            if (alt && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) {
                nav_forward();
            }

            // Step with arrow keys (no modifier)
            if (!alt && !shift && !ctrl && !super) {
                if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
                    if (current_inst_ + 1 < total_inst_) navigate_to(current_inst_ + 1);
                }
                if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
                    if (current_inst_ > 0) navigate_to(current_inst_ - 1);
                }
            }

            // Page Up/Down: jump ±100 instructions
            if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
                uint64_t step = 100;
                uint64_t next = (current_inst_ + step < total_inst_) ? current_inst_ + step : total_inst_ - 1;
                navigate_to(next);
            }
            if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) {
                uint64_t step = 100;
                navigate_to(current_inst_ > step ? current_inst_ - step : 0);
            }

            // Home: first instruction
            if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_Home)) {
                navigate_to(0);
            }
            // End: last instruction
            if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_End)) {
                navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
            }

            // G → Goto popup
            if (ImGui::IsKeyPressed(ImGuiKey_G) && !show_goto_popup_) {
                show_goto_popup_ = true;
            }

            // / or Ctrl+F → Search popup
            if (ImGui::IsKeyPressed(ImGuiKey_Slash) || (ctrl && ImGui::IsKeyPressed(ImGuiKey_F))) {
                show_search_popup_ = true;
            }

            // F3 → Next search result
            if (ImGui::IsKeyPressed(ImGuiKey_F3)) {
                if (search_active_ && !search_results_.empty()) {
                    if (shift) {
                        // Shift+F3: previous result
                        if (search_current_ > 0) search_current_--;
                        else search_current_ = search_results_.size() - 1;
                    } else {
                        // F3: next result
                        search_current_++;
                        if (search_current_ >= search_results_.size()) search_current_ = 0;
                    }
                    navigate_to(search_results_[search_current_]);
                }
            }

            // B → toggle bookmark
            if (ImGui::IsKeyPressed(ImGuiKey_B) && !shift && !ctrl && !alt) {
                toggle_bookmark();
            }

            // Taint jump: [ and ]
            if (!shift && ImGui::IsKeyPressed(ImGuiKey_RightBracket)) {
                if (show_taint_ && taint_result_) jump_taint_next();
                else if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_next();
            }
            if (!shift && ImGui::IsKeyPressed(ImGuiKey_LeftBracket)) {
                if (show_taint_ && taint_result_) jump_taint_prev();
                else if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_prev();
            }
            if (shift && ImGui::IsKeyPressed(ImGuiKey_RightBracket)) {
                if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_next();
            }
            if (shift && ImGui::IsKeyPressed(ImGuiKey_LeftBracket)) {
                if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_prev();
            }

            // E → follow call (enter callee)
            if (ImGui::IsKeyPressed(ImGuiKey_E) && function_result_) {
                auto* evt = function_result_->call_at(current_inst_);
                if (evt && evt->call_inst_id + 1 < total_inst_)
                    navigate_to(evt->call_inst_id + 1);
            }

            // Backspace → follow return (back to call site)
            if (ImGui::IsKeyPressed(ImGuiKey_Backspace) && function_result_) {
                auto* ret = function_result_->return_at(current_inst_);
                if (ret) {
                    navigate_to(ret->call_inst_id);
                } else {
                    const auto& stk = current_call_stack();
                    if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
                }
            }

            // F5 / Space → toggle CFG view
            if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
                show_cfg_ = !show_cfg_;
            }

            // + / - for CFG zoom (when CFG is visible)
            if (show_cfg_) {
                if (ImGui::IsKeyPressed(ImGuiKey_Equal) && (shift || ctrl)) {
                    // Shift+= is "+" on most keyboards
                    cfg_zoom_ = std::min(cfg_zoom_ * 1.2f, 8.0f);
                }
                if (ImGui::IsKeyPressed(ImGuiKey_Minus) && (ctrl || true)) {
                    cfg_zoom_ = std::max(cfg_zoom_ * 0.8f, 0.05f);
                }
            }

            // X → run xref analysis
            if (ImGui::IsKeyPressed(ImGuiKey_X) && !ctrl) {
                if (!xref_result_) run_pass_by_name("xref");
                else {
                    // cycle through xrefs at current PC
                    auto row = fetch_row(current_inst_);
                    auto xrefs = xref_result_->inst_ids_at(row.pc);
                    if (!xrefs.empty()) {
                        xref_cursor_++;
                        if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
                        navigate_to(xrefs[xref_cursor_]);
                    }
                }
            }

            // Ctrl+C / Cmd+C → copy current instruction address
            if ((ctrl || super) && ImGui::IsKeyPressed(ImGuiKey_C)) {
                auto row = fetch_row(current_inst_);
                char buf[24];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)row.static_pc);
                ImGui::SetClipboardText(buf);
            }
        }
    }

    // ─── Panels ─────────────────────────────────────────────────────
    if (show_minimap_) {
        render_minimap_panel();
    }
    render_progress_overlay();   // Always-on progress bar in toolbar area
    render_instruction_panel();

    if (show_registers_) {
        render_register_panel();
    }
    if (show_memory_) {
        render_memory_panel();
    }
    if (show_callstack_) {
        render_callstack_panel();
    }
    if (show_analysis_) {
        render_analysis_panel();
    }
    if (show_hex_dump_) {
        render_hex_dump_panel();
    }
    if (show_functions_) {
        render_functions_panel();
    }
    if (show_strings_) {
        render_strings_panel();
    }
    if (show_threads_) {
        render_thread_panel();
    }
    if (show_cfg_) {
        render_cfg_panel();
    }

    if (show_mem_strings_) {
        render_memory_strings_panel();
    }
    if (show_syscall_intercept_) {
        render_syscall_intercept_panel();
    }
    if (show_objc_crypto_) {
        render_objc_crypto_panel();
    }
    if (show_cache_sim_) {
        render_cache_sim_panel();
    }
    if (show_trace_fold_) {
        render_trace_fold_panel();
    }

    // ─── P2 panels ──────────────────────────────────────────────────
    if (show_reg_timeline_) {
        render_reg_timeline_panel();
    }
    if (show_dwarf_panel_) {
        render_dwarf_panel();
    }
    if (show_trace_diff_) {
        render_trace_diff_panel();
    }

    // ─── Status bar (always rendered at bottom) ─────────────────────
    render_status_bar();

    // ─── Popups / Settings ──────────────────────────────────────────
    render_goto_popup();
    render_search_popup();
    if (show_settings_) {
        render_settings_window();
    }

    // ─── Demo window (debug) ────────────────────────────────────────
    if (show_demo_window_) {
        ImGui::ShowDemoWindow(&show_demo_window_);
    }
}

}  // namespace tenet
