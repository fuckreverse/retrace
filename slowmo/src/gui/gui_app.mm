#include "gui/gui_app.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"

#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_sdl3.h>
#include <imgui_impl_metal.h>

#include <SDL3/SDL.h>
#include <SDL3/SDL_metal.h>

#include <fmt/core.h>

#include <algorithm>
#include <cstring>

// Metal/ObjC interop (this file is compiled as Objective-C++)
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>

namespace tenet {

// ─── Helper: register name ──────────────────────────────────────────────────

static std::string reg_name(uint8_t idx) {
    if (idx <= 28) return fmt::format("x{}", idx);
    if (idx == 29) return "fp";
    if (idx == 30) return "lr";
    if (idx == 31) return "sp";
    if (idx == 32) return "nzcv";
    if (idx == 33) return "pc";
    return "??";
}

// ─── Constructor / Destructor ───────────────────────────────────────────────

GuiApp::GuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
               InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory) {
    total_inst_ = index.inst_count();
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
            "/System/Library/Fonts/SFMono-Regular.otf",
            "/Library/Fonts/SF-Mono-Regular.otf",
            "/System/Library/Fonts/Menlo.ttc",
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

// ─── Main Run Loop ──────────────────────────────────────────────────────────

int GuiApp::run() {
    if (!init_sdl()) return 1;
    if (!init_imgui()) return 1;

    // Kick off background startup analysis immediately after UI is ready.
    // The analyses run in a detached thread; results are written atomically
    // and the render loop will display them as they complete.
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

        // ─── 2. Acquire Metal drawable and begin render pass ─────────
        @autoreleasepool {
            CAMetalLayer* layer = (__bridge CAMetalLayer*)SDL_GetRenderMetalLayer(renderer_);
            id<CAMetalDrawable> drawable = [layer nextDrawable];
            if (!drawable) continue;

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
//  │ Functions  │  Instructions / CFG      │  Registers       │
//  │ Strings    │  (main content, ~65%)    │  Memory Accesses │
//  │  (~15%)    │                          │  (~20%)          │
//  │            ├──────────────────────────┤                  │
//  │            │  Analysis / Call Stack / │                  │
//  │            │  Hex Dump  (~22%)        │                  │
//  ├────────────┴──────────────────────────┴──────────────────┤
//  │ Status Bar (fixed height, not docked)                    │
//  └──────────────────────────────────────────────────────────┘

static const float kToolbarHeight  = 30.0f;   // toolbar window height
static const float kTimelineHeight = 22.0f;   // execution timeline height
static const float kStatusBarHeight = 22.0f;  // bottom status bar height

void GuiApp::render_frame() {
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
    //   - Left  15% : Functions/Strings sidebar (narrow, just enough for names)
    //   - Center 65%: Instructions+CFG (core analysis area, maximum width)
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

        // Left sidebar: Functions (primary tab, shown first) + Strings
        ImGui::DockBuilderDockWindow("Functions", dock_left_sidebar);
        ImGui::DockBuilderDockWindow("Strings",   dock_left_sidebar);
        ImGui::DockBuilderDockWindow("Threads",   dock_left_sidebar);

        // Center main: Instructions (primary) + CFG tab (IDA-style disasm/graph toggle)
        ImGui::DockBuilderDockWindow("Instructions", dock_center_main);
        ImGui::DockBuilderDockWindow("CFG",          dock_center_main);

        // Center bottom output: Analysis (primary) + supplementary tabs
        ImGui::DockBuilderDockWindow("Analysis",      dock_center_bottom);
        ImGui::DockBuilderDockWindow("Call Stack",    dock_center_bottom);
        ImGui::DockBuilderDockWindow("Hex Dump",      dock_center_bottom);
        ImGui::DockBuilderDockWindow("Minimap",       dock_center_bottom);

        // Right column: Registers on top (more important), Memory below
        ImGui::DockBuilderDockWindow("Registers",       dock_right_regs);
        ImGui::DockBuilderDockWindow("Memory Accesses", dock_right_mem);

        ImGui::DockBuilderFinish(dockspace_id);
    }

    // ─── Menu bar: rendered inside the host window ───────────────────
    // NOTE: We removed the MenuBar from the host window flags, so we render
    //       the menu bar separately as a standalone menu bar window.
    ImGui::End();

    // ─── Actual menu bar (rendered as top-most, full-width strip) ────
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, 0.0f));  // auto-height
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##MainMenuBar", nullptr,
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_MenuBar |
        ImGuiWindowFlags_NoSavedSettings);
    ImGui::PopStyleVar(3);
    render_menu_bar();
    ImGui::End();

    // ─── Toolbar ────────────────────────────────────────────────────
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
                    auto stk = function_result_->call_stack_at(current_inst_);
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
                if (!xref_result_) run_xref_analysis();
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

// ─── Menu Bar ───────────────────────────────────────────────────────────────

void GuiApp::render_menu_bar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Trace...", "Cmd+O")) {
                // TODO: file dialog integration
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Quit", "Cmd+Q")) {
                running_ = false;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Settings...", "Cmd+,")) {
                show_settings_ = true;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Registers", "R", &show_registers_);
            ImGui::MenuItem("Memory", "M", &show_memory_);
            ImGui::MenuItem("Call Stack", "F", &show_callstack_);
            ImGui::MenuItem("Analysis", "A", &show_analysis_);
            ImGui::MenuItem("Hex Dump", "H", &show_hex_dump_);
            ImGui::MenuItem("Strings", "I", &show_strings_);
            ImGui::MenuItem("Functions", "L", &show_functions_);
            ImGui::MenuItem("Threads", "T", &show_threads_);
            ImGui::Separator();
            ImGui::MenuItem("Minimap", "V", &show_minimap_);
            ImGui::MenuItem("Loop Highlight", "O", &show_loops_);
            ImGui::MenuItem("CFG View", "K", &show_cfg_);
            ImGui::Separator();
            ImGui::MenuItem("ImGui Demo", nullptr, &show_demo_window_);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Navigate")) {
            if (ImGui::MenuItem("Goto Instruction...", "G")) {
                show_goto_popup_ = true;
            }
            if (ImGui::MenuItem("Search...", "/")) {
                show_search_popup_ = true;
            }
            ImGui::Separator();
            // Navigation history
            {
                bool can_back = can_nav_back();
                bool can_fwd  = can_nav_forward();
                if (!can_back) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Back", "Alt+Left")) {
                    nav_back();
                }
                if (!can_back) ImGui::EndDisabled();
                if (!can_fwd) ImGui::BeginDisabled();
                if (ImGui::MenuItem("Forward", "Alt+Right")) {
                    nav_forward();
                }
                if (!can_fwd) ImGui::EndDisabled();
                // Show history size
                if (!nav_history_.empty()) {
                    ImGui::TextDisabled("  History: [%zu/%zu]",
                        nav_history_pos_ + 1, nav_history_.size());
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("First Instruction", "Home")) {
                navigate_to(0);
            }
            if (ImGui::MenuItem("Last Instruction", "End")) {
                navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Toggle Bookmark", "B")) {
                toggle_bookmark();
            }
            ImGui::Separator();
            // Follow call/return
            if (ImGui::MenuItem("Follow Call (enter callee)", "E")) {
                if (function_result_) {
                    auto* evt = function_result_->call_at(current_inst_);
                    if (evt && evt->call_inst_id + 1 < total_inst_) {
                        navigate_to(evt->call_inst_id + 1);
                    }
                }
            }
            if (ImGui::MenuItem("Follow Return (back to caller)", "R")) {
                if (function_result_) {
                    auto* evt = function_result_->return_at(current_inst_);
                    if (evt) {
                        navigate_to(evt->call_inst_id);
                    } else {
                        auto stk = function_result_->call_stack_at(current_inst_);
                        if (!stk.empty()) {
                            navigate_to(stk.back()->call_inst_id);
                        }
                    }
                }
            }
            ImGui::Separator();
            // Taint jump
            if (show_taint_ && taint_result_) {
                if (ImGui::MenuItem("Next Tainted Inst", "]")) {
                    jump_taint_next();
                }
                if (ImGui::MenuItem("Prev Tainted Inst", "[")) {
                    jump_taint_prev();
                }
            }
            if (show_backward_taint_ && backward_taint_result_) {
                if (ImGui::MenuItem("Next Backward-Tainted Inst", "Shift+]")) {
                    jump_backward_taint_next();
                }
                if (ImGui::MenuItem("Prev Backward-Tainted Inst", "Shift+[")) {
                    jump_backward_taint_prev();
                }
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Analysis")) {
            if (ImGui::MenuItem("Forward Taint", "T")) {
                run_taint_analysis();
            }
            if (ImGui::MenuItem("Backward Taint", "Shift+B")) {
                run_backward_taint_analysis();
            }
            if (ImGui::MenuItem("Slice", "S")) {
                run_slice_analysis();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Function Analysis", "Shift+F")) {
                run_function_analysis();
            }
            if (ImGui::MenuItem("Xref Analysis", "X")) {
                run_xref_analysis();
            }
            if (ImGui::MenuItem("String Analysis", "I")) {
                run_string_analysis();
            }
            if (ImGui::MenuItem("Thread Analysis", "T")) {
                run_thread_analysis();
            }
            if (ImGui::MenuItem("Call Graph Analysis")) {
                run_call_graph_analysis();
            }
            if (ImGui::MenuItem("Loop Analysis", "O")) {
                run_loop_analysis();
            }
            if (ImGui::MenuItem("CFG Layout", "K")) {
                run_cfg_layout();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Clear All Analysis", "C")) {
                clear_analysis();
            }
            ImGui::EndMenu();
        }

        // Status indicator on the right side of menu bar
        {
            std::string status = fmt::format("  inst {}/{} ", current_inst_, total_inst_);
            float text_width = ImGui::CalcTextSize(status.c_str()).x;
            ImGui::SameLine(ImGui::GetWindowWidth() - text_width - 10.0f);
            ImGui::TextDisabled("%s", status.c_str());
        }

        ImGui::EndMenuBar();
    }
}

// ─── Toolbar ────────────────────────────────────────────────────────────────
// Redesigned: clear icon-like labels, logical grouping with visual separators,
// status badges on the right (Binary Ninja / IDA style)

void GuiApp::render_toolbar() {
    // ── Fixed position: pinned below menu bar, full width ─────────────
    ImGuiViewport* vp = ImGui::GetMainViewport();
    // Menu bar auto-height: use GetFrameHeight (approx) + padding
    const float menu_h = ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.y * 2.0f;
    const float toolbar_y = vp->WorkPos.y + menu_h;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, toolbar_y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, kToolbarHeight));
    ImGui::SetNextWindowViewport(vp->ID);

    // Style overrides for toolbar: tighter frame padding for compact buttons
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,    ImVec2(5.0f, 3.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,     ImVec2(3.0f, 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(4.0f, 3.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    // Slightly different bg than main windows to distinguish toolbar area
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.085f, 0.090f, 0.115f, 1.0f));

    ImGui::Begin("##Toolbar", nullptr,
        ImGuiWindowFlags_NoTitleBar    | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove        | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoDocking     | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus);

    const float btn_h = ImGui::GetFrameHeight();

    // ── GROUP 1: History navigation ───────────────────────────────────
    {
        bool can_back = can_nav_back();
        bool can_fwd  = can_nav_forward();

        if (!can_back) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\x90##navback", ImVec2(26.0f, btn_h)))  // ← (UTF-8 U+2190)
            nav_back();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Back  Alt+\xe2\x86\x90\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        if (!can_back) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!can_fwd) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\x92##navfwd", ImVec2(26.0f, btn_h)))   // → (UTF-8 U+2192)
            nav_forward();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Forward  Alt+\xe2\x86\x92\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        if (!can_fwd) ImGui::EndDisabled();
    }

    // ── Separator ─────────────────────────────────────────────────────
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::PopStyleColor();
    ImGui::SameLine();

    // ── GROUP 2: Step / seek ─────────────────────────────────────────
    if (ImGui::Button("|<##seek0", ImVec2(26.0f, btn_h)))
        navigate_to(0);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("First instruction  Home");
    ImGui::SameLine();

    if (ImGui::Button("\xe2\x96\xb2##stepup", ImVec2(26.0f, btn_h))) {  // ▲
        if (current_inst_ > 0) navigate_to(current_inst_ - 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous instruction  \xe2\x86\x91");
    ImGui::SameLine();

    if (ImGui::Button("\xe2\x96\xbc##stepdn", ImVec2(26.0f, btn_h))) {  // ▼
        navigate_to(current_inst_ + 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next instruction  \xe2\x86\x93");
    ImGui::SameLine();

    if (ImGui::Button(">|##seekend", ImVec2(26.0f, btn_h)))
        navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Last instruction  End");

    // ── Separator ─────────────────────────────────────────────────────
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
    ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
    ImGui::PopStyleColor();
    ImGui::SameLine();

    // ── GROUP 3: Call/Return follow (only when function analysis available) ──
    if (function_result_) {
        bool has_call = (function_result_->call_at(current_inst_) != nullptr);
        bool has_ret  = (function_result_->return_at(current_inst_) != nullptr ||
                         !function_result_->call_stack_at(current_inst_).empty());

        if (!has_call) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\xb3 Enter", ImVec2(0, btn_h))) {  // ↳
            auto* evt = function_result_->call_at(current_inst_);
            if (evt && evt->call_inst_id + 1 < total_inst_)
                navigate_to(evt->call_inst_id + 1);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Follow call into callee (E)");
        if (!has_call) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!has_ret) ImGui::BeginDisabled();
        if (ImGui::Button("\xe2\x86\xb5 Return", ImVec2(0, btn_h))) {  // ↵
            auto* evt = function_result_->return_at(current_inst_);
            if (evt) {
                navigate_to(evt->call_inst_id);
            } else {
                auto stk = function_result_->call_stack_at(current_inst_);
                if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
            }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Follow return to call site (R)");
        if (!has_ret) ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::PopStyleColor();
        ImGui::SameLine();
    }

    // ── GROUP 4: Taint navigation (only when active) ─────────────────
    bool has_taint_nav = (show_taint_ && taint_result_) ||
                         (show_backward_taint_ && backward_taint_result_);
    if (has_taint_nav) {
        if (show_taint_ && taint_result_) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.28f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.40f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.15f, 0.50f, 0.20f, 1.0f));
            if (ImGui::Button("\xe2\x97\x81 T", ImVec2(0, btn_h))) jump_taint_prev();  // ◁
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev tainted inst ([)");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.28f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f, 0.40f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.15f, 0.50f, 0.20f, 1.0f));
            if (ImGui::Button("T \xe2\x96\xb7", ImVec2(0, btn_h))) jump_taint_next();  // ▷
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next tainted inst (])");
            ImGui::SameLine();
        }
        if (show_backward_taint_ && backward_taint_result_) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("\xe2\x97\x81 BT", ImVec2(0, btn_h))) jump_backward_taint_prev();  // ◁
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev backward-tainted inst");
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.40f, 0.12f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.50f, 0.15f, 0.15f, 1.0f));
            if (ImGui::Button("BT \xe2\x96\xb7", ImVec2(0, btn_h))) jump_backward_taint_next();  // ▷
            ImGui::PopStyleColor(3);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next backward-tainted inst");
            ImGui::SameLine();
        }
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f, 0.30f, 0.40f, 0.80f));
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::PopStyleColor();
        ImGui::SameLine();
    }

    // ── GROUP 5: Current instruction info ────────────────────────────
    auto row = fetch_row(current_inst_);
    // PC in dimmed monospace style
    ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.70f, 1.0f),
        "0x%llx", (unsigned long long)row.static_pc);
    ImGui::SameLine(0, 8.0f);
    // Mnemonic colored
    ImGui::TextColored(inst_color(row.mnemonic), "%s", row.mnemonic.c_str());
    ImGui::SameLine(0, 4.0f);
    // Operands lighter
    ImGui::TextColored(ImVec4(0.78f, 0.78f, 0.84f, 1.0f), "%s", row.operands.c_str());

    // ── STATUS BADGES (right-aligned) ─────────────────────────────────
    // Compute total width for the right side to right-align it
    float win_w = ImGui::GetWindowWidth();

    // Build status string(s)
    bool has_status = analysis_running_.load() || show_taint_ || show_backward_taint_ ||
                      show_slice_ || (show_loops_ && loop_result_);

    if (has_status) {
        // estimate approx position
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine(0, 8.0f);

        if (analysis_running_.load()) {
            // Animated spinner character (cycle through ⣾⣽⣻⢿⡿⣟⣯⣷)
            static const char* spinner[] = {
                "\xe2\xa3\xbe","\xe2\xa3\xbd","\xe2\xa3\xbb","\xe2\xa2\xbf",
                "\xe2\xa1\xbf","\xe2\xa3\x9f","\xe2\xa3\xaf","\xe2\xa3\xb7"
            };
            static int spin_frame = 0;
            spin_frame = (spin_frame + 1) % 8;
            ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f),
                "%s Analyzing...", spinner[spin_frame]);
        } else {
            // Show active analysis mode badges
            bool first_badge = true;
            auto badge = [&](const char* label, ImVec4 col) {
                if (!first_badge) ImGui::SameLine(0, 4.0f);
                first_badge = false;
                ImGui::PushStyleColor(ImGuiCol_Button, col);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, col);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive,  col);
                ImGui::Button(label);
                ImGui::PopStyleColor(3);
            };
            if (show_backward_taint_ && backward_taint_result_)
                badge("BACK-TAINT", ImVec4(0.55f, 0.10f, 0.10f, 0.90f));
            else if (show_taint_ && taint_result_)
                badge("TAINT", ImVec4(0.10f, 0.40f, 0.12f, 0.90f));
            if (show_slice_ && slice_result_)
                badge("SLICE", ImVec4(0.40f, 0.10f, 0.42f, 0.90f));
            if (show_loops_ && loop_result_) {
                char loop_label[32];
                snprintf(loop_label, sizeof(loop_label), "\xe2\x86\xba %zu LOOPS",
                         loop_result_->loops.size());  // ↺
                badge(loop_label, ImVec4(0.38f, 0.20f, 0.03f, 0.90f));
            }
        }
    }

    // ── Right side: progress ─────────────────────────────────────────
    if (total_inst_ > 0) {
        // Right-align the counter
        char counter[48];
        snprintf(counter, sizeof(counter), "%llu / %llu",
                 (unsigned long long)(current_inst_ + 1),
                 (unsigned long long)total_inst_);
        float counter_w = ImGui::CalcTextSize(counter).x + 8.0f;
        float bar_w = 160.0f;
        float right_x = win_w - counter_w - bar_w - 16.0f;
        if (right_x > ImGui::GetCursorPosX()) {
            ImGui::SameLine(right_x);
        } else {
            ImGui::SameLine();
        }
        float progress = static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1);
        // Colored progress bar: accent blue fill
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.28f, 0.52f, 0.85f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg,       ImVec4(0.08f, 0.09f, 0.12f, 1.0f));
        ImGui::SetNextItemWidth(bar_w);
        ImGui::ProgressBar(progress, ImVec2(bar_w, btn_h), "");
        ImGui::PopStyleColor(2);
        ImGui::SameLine(0, 4.0f);
        ImGui::TextDisabled("%s", counter);
    }

    ImGui::End();
    ImGui::PopStyleColor(1);  // WindowBg
    ImGui::PopStyleVar(5);    // FramePadding, ItemSpacing, WindowPadding, WindowRounding, WindowBorderSize
}

// ─── Instruction Panel ──────────────────────────────────────────────────────
// Redesigned: richer row markers, cleaner column headers, IDA-style current
// line indicator, search-result navigation strip, and bookmark count badge.

void GuiApp::render_instruction_panel() {
    ImGui::Begin("Instructions");

    // ── Header strip: search result nav + bookmark count ──────────────
    if (search_active_ && !search_results_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.08f, 0.15f, 0.12f, 1.0f));
        ImGui::BeginChild("##search_strip", ImVec2(0, ImGui::GetFrameHeightWithSpacing()), false,
                          ImGuiWindowFlags_NoScrollbar);
        ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f),
            "\xE2\x8C\x95  %zu results", search_results_.size());  // ⌕
        ImGui::SameLine(0, 10.0f);
        if (ImGui::SmallButton("\xe2\x97\x81##sprev")) {  // ◁
            if (search_current_ > 0) search_current_--;
            else search_current_ = search_results_.size() - 1;
            navigate_to(search_results_[search_current_]);
        }
        ImGui::SameLine(0, 2.0f);
        ImGui::TextDisabled("%zu / %zu", search_current_ + 1, search_results_.size());
        ImGui::SameLine(0, 2.0f);
        if (ImGui::SmallButton("\xe2\x96\xb7##snext")) {  // ▷
            search_current_++;
            if (search_current_ >= search_results_.size()) search_current_ = 0;
            navigate_to(search_results_[search_current_]);
        }
        ImGui::SameLine(0, 12.0f);
        if (ImGui::SmallButton("  \xc3\x97  ")) {  // ×
            search_active_ = false;
            search_results_.clear();
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear search");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    if (!bookmarks_.empty()) {
        // Small right-aligned bookmark count
        char bm_label[32];
        snprintf(bm_label, sizeof(bm_label), "\xe2\x98\x86 %zu bookmarks", bookmarks_.size());  // ☆
        float text_w = ImGui::CalcTextSize(bm_label).x;
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - text_w + ImGui::GetCursorPosX());
        ImGui::TextColored(ImVec4(1.0f, 0.80f, 0.20f, 0.70f), "%s", bm_label);
    }

    // ── Instruction table ────────────────────────────────────────────────
    // Flags: scroll, alternating row bg, inner vertical borders, fixed columns
    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_NoHostExtendX;

    // Reserve the full remaining height
    float table_height = ImGui::GetContentRegionAvail().y;

    if (ImGui::BeginTable("InstTable", 5, table_flags, ImVec2(0, table_height))) {
        ImGui::TableSetupScrollFreeze(0, 1);  // Freeze header row
        // Col 0: narrow gutter (marker/bookmark/arrow)
        ImGui::TableSetupColumn(" ",        ImGuiTableColumnFlags_WidthFixed |
                                            ImGuiTableColumnFlags_NoResize, 22.0f);
        // Col 1: instruction index — fixed but wide enough for 7-digit numbers
        ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 64.0f);
        // Col 2: address — fixed monospace
        ImGui::TableSetupColumn("Address",  ImGuiTableColumnFlags_WidthFixed, 132.0f);
        // Col 3: mnemonic — fixed, auto-fitted to longest common mnemonic
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 72.0f);
        // Col 4: operands — stretches to fill remaining space
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);

        // Custom styled header row (slightly taller, blue-tinted)
        ImGui::PushStyleColor(ImGuiCol_TableHeaderBg, ImVec4(0.10f, 0.12f, 0.20f, 1.0f));
        ImGui::TableHeadersRow();
        ImGui::PopStyleColor();

        // ── Virtual list clipper for performance ─────────────────────────
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(total_inst_));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                uint64_t inst_id = static_cast<uint64_t>(i);
                auto row = fetch_row(inst_id);

                bool is_current   = (inst_id == current_inst_);
                bool is_bookmarked= row.has_bookmark;
                bool is_tainted   = show_taint_ && taint_result_ &&
                                    taint_result_->has_event_at(inst_id);
                bool is_sliced    = show_slice_ && slice_result_ &&
                                    slice_result_->is_in_slice(inst_id);
                bool is_back_taint= show_backward_taint_ && backward_taint_result_ &&
                                    backward_taint_result_->is_contributing(inst_id);
                bool is_search_hit= search_active_ &&
                                    std::binary_search(search_results_.begin(),
                                                       search_results_.end(), inst_id);

                // Loop state
                bool is_loop_header = show_loops_ && loop_result_ &&
                                      loop_result_->is_loop_header(row.pc);
                uint32_t loop_depth = (show_loops_ && loop_result_) ?
                                      loop_result_->loop_depth_at(row.pc) : 0;
                bool is_in_loop     = loop_depth > 0;

                ImGui::TableNextRow();

                // ── Row background priority (high → low) ─────────────────
                // 1) current instruction: bright blue-white
                // 2) analysis overlays: taint/slice/backward-taint
                // 3) loop markers
                // 4) search hits: subtle gold
                if (is_current) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(30, 70, 145, 175));
                } else if (is_back_taint) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(110, 22, 22, 115));
                } else if (is_sliced) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(80, 22, 110, 115));
                } else if (is_tainted) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(20, 80, 28, 115));
                } else if (is_search_hit) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(90, 75, 10, 120));
                } else if (is_loop_header) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        IM_COL32(140, 62, 4, 200));
                } else if (is_in_loop) {
                    float d = std::min(static_cast<float>(loop_depth - 1) * 0.06f, 0.18f);
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.26f + d, 0.13f, 0.02f, 0.38f)));
                }

                // ── Column 0: Gutter marker + invisible full-row hit-area ──
                // Pattern: render gutter text first, then SameLine + Selectable
                // with SpanAllColumns so it covers the entire row for click/hover
                // detection without shifting any column layout.
                ImGui::TableNextColumn();
                if (is_current && is_bookmarked) {
                    ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.15f, 1.0f), "\xe2\x98\x85\xe2\x96\xb6");  // ★▶
                } else if (is_current) {
                    ImGui::TextColored(ImVec4(0.45f, 0.82f, 1.0f, 1.0f), " \xe2\x96\xb6");  // ▶
                } else if (is_bookmarked) {
                    ImGui::TextColored(ImVec4(1.0f, 0.82f, 0.15f, 1.0f), "\xe2\x98\x85 ");  // ★
                } else if (is_loop_header) {
                    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.1f, 1.0f), "\xe2\x87\x86 ");   // ⇆
                } else if (is_in_loop) {
                    ImGui::TextColored(ImVec4(0.72f, 0.43f, 0.1f, 0.75f), "\xe2\x86\xba ");  // ↺
                } else {
                    ImGui::TextDisabled("  ");
                }
                // Overlay: transparent full-row Selectable for click & hover
                ImGui::SameLine(0, 0);
                ImGui::SetCursorPosX(ImGui::GetCursorPosX()
                                     - ImGui::GetItemRectSize().x
                                     - ImGui::GetStyle().ItemSpacing.x);
                {
                    char sel_id[32];
                    snprintf(sel_id, sizeof(sel_id), "##irow%llu", (unsigned long long)inst_id);
                    // Push transparent colors so Selectable is invisible
                    ImGui::PushStyleColor(ImGuiCol_Header,        ImVec4(0,0,0,0));
                    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(1,1,1,0.06f));
                    ImGui::PushStyleColor(ImGuiCol_HeaderActive,  ImVec4(1,1,1,0.10f));
                    ImGui::Selectable(sel_id, false,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowOverlap,
                        ImVec2(0, ImGui::GetTextLineHeight()));
                    ImGui::PopStyleColor(3);

                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                        navigate_to(inst_id);
                    }
                    if (ImGui::IsItemHovered()) {
                        std::string tip;
                        tip += fmt::format("inst #{}\n", inst_id);
                        tip += fmt::format("addr: 0x{:016x}\n", row.static_pc);
                        tip += fmt::format("{} {}", row.mnemonic, row.operands);
                        if (row.mem_access_count > 0) {
                            tip += fmt::format("\n{} memory access(es)", row.mem_access_count);
                        }
                        tip += "\nRight-click for more options";
                        ImGui::SetTooltip("%s", tip.c_str());
                    }

                    // Right-click context menu: BeginPopupContextItem is the
                    // most reliable ImGui API - it both opens and renders the popup.
                    if (ImGui::BeginPopupContextItem(nullptr)) {
                        // Capture context on first open
                        ctx_inst_id_        = inst_id;
                        ctx_inst_pc_        = row.pc;
                        ctx_inst_static_pc_ = row.static_pc;
                        ctx_inst_disasm_    = fmt::format("{} {}", row.mnemonic, row.operands);
                        // Delegate rendering to the shared function
                        render_inst_context_menu_contents();
                        ImGui::EndPopup();
                    }
                }

                // ── Column 1: Instruction index ───────────────────────────
                ImGui::TableNextColumn();
                if (is_current) {
                    ImGui::TextColored(ImVec4(0.7f, 0.82f, 1.0f, 1.0f),
                        "%llu", (unsigned long long)inst_id);
                } else {
                    ImGui::TextDisabled("%llu", (unsigned long long)inst_id);
                }

                // ── Column 2: Address ─────────────────────────────────────
                ImGui::TableNextColumn();
                if (is_current) {
                    ImGui::TextColored(ImVec4(0.65f, 0.72f, 0.95f, 1.0f),
                        "%016llx", (unsigned long long)row.static_pc);
                } else {
                    ImGui::TextColored(ImVec4(0.50f, 0.52f, 0.65f, 1.0f),
                        "%016llx", (unsigned long long)row.static_pc);
                }

                // ── Column 3: Mnemonic (syntax-colored) ───────────────────
                ImGui::TableNextColumn();
                ImVec4 mnem_color = inst_color(row.mnemonic);
                ImGui::TextColored(mnem_color, "%s", row.mnemonic.c_str());

                // ── Column 4: Operands (tokenized highlighting) ───────────
                ImGui::TableNextColumn();
                render_operands_highlighted(row.operands);

            }
        }
        clipper.End();

        // ── Auto-scroll: keep current instruction centered ────────────
        // Only scroll if the current instruction changed this frame
        static uint64_t last_scrolled_inst = UINT64_MAX;
        if (current_inst_ != last_scrolled_inst && current_inst_ < total_inst_) {
            last_scrolled_inst = current_inst_;
            float item_h    = ImGui::GetTextLineHeightWithSpacing();
            float panel_h   = ImGui::GetWindowHeight();
            float target_y  = static_cast<float>(current_inst_) * item_h - panel_h * 0.45f;
            if (target_y < 0.0f) target_y = 0.0f;
            ImGui::SetScrollY(target_y);
        }

        ImGui::EndTable();
    }

    // Render instruction context menu (must be called before End())
    render_inst_context_menu();

    ImGui::End();
}

// ─── Register Panel ─────────────────────────────────────────────────────────

void GuiApp::render_register_panel() {
    if (!ImGui::Begin("Registers", &show_registers_)) {
        ImGui::End();
        return;
    }

    const auto& state = regfile_.state_before(current_inst_);

    // Get previous state for delta highlighting
    const bool has_prev = (current_inst_ > 0);
    RegState prev_state{};
    if (has_prev) {
        prev_state = regfile_.state_before(current_inst_ - 1);
    }

    // Determine read/written registers for current instruction
    std::vector<uint8_t> read_regs, write_regs;
    {
        auto [offset, seed_pc_rw] = index_.offset_of_with_pc(current_inst_, reader_);
        auto rec = reader_.record_at(offset, seed_pc_rw);
        if (rec.kind == RecordKind::Inst) {
            auto inst = rec.as_inst();
            for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
                write_regs.push_back(inst.reg_diff(i).index);
            }
            auto opcode = code_table_.opcode_at(inst.pc);
            if (opcode) {
                auto d = decoder_.decode(inst.pc, *opcode);
                if (d) {
                    read_regs.assign(d->regs_read.begin(),
                                     d->regs_read.begin() + d->regs_read_count);
                }
            }
        }
    }

    auto is_in = [](const std::vector<uint8_t>& vec, uint8_t idx) {
        for (auto v : vec) if (v == idx) return true;
        return false;
    };

    enum class RegHighlight { Normal, Read, Write, ReadWrite };
    auto get_reg_state = [&](uint8_t idx) -> RegHighlight {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return RegHighlight::ReadWrite;
        if (w)      return RegHighlight::Write;
        if (r)      return RegHighlight::Read;
        return RegHighlight::Normal;
    };

    auto state_to_color = [](RegHighlight s) -> ImVec4 {
        switch (s) {
            case RegHighlight::Read:      return reg_color_read();
            case RegHighlight::Write:     return reg_color_write();
            case RegHighlight::ReadWrite: return reg_color_both();
            default:                      return ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
        }
    };

    // ── Compact header: legend + instruction count ──────────────────
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 2));

    // Colored legend dots
    ImDrawList* draw = ImGui::GetWindowDrawList();
    auto draw_dot = [&](ImVec4 col) {
        ImVec2 p = ImGui::GetCursorScreenPos();
        p.x += 5.0f; p.y += ImGui::GetTextLineHeight() * 0.5f - 3.0f;
        draw->AddCircleFilled(p, 4.0f, ImGui::ColorConvertFloat4ToU32(col));
        ImGui::Dummy(ImVec2(12, ImGui::GetTextLineHeight()));
    };

    draw_dot(reg_color_read());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("R");
    ImGui::SameLine(0, 8);
    draw_dot(reg_color_write());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("W");
    ImGui::SameLine(0, 8);
    draw_dot(reg_color_both());
    ImGui::SameLine(0, 2);
    ImGui::TextDisabled("RW");
    ImGui::SameLine();
    ImGui::TextDisabled("  |  inst #%llu", (unsigned long long)current_inst_);

    ImGui::PopStyleVar();

    // Thin separator with slightly different shade
    ImVec2 sep_p0 = ImGui::GetCursorScreenPos();
    sep_p0.y += 2.0f;
    draw->AddLine(sep_p0, ImVec2(sep_p0.x + ImGui::GetContentRegionAvail().x, sep_p0.y),
                  IM_COL32(70, 78, 110, 200), 1.0f);
    ImGui::Dummy(ImVec2(0, 4));

    // ── Render a register cell (name col + value col) ──────────────
    // Returns true if right-clicked
    auto render_reg_cell = [&](uint8_t idx, const char* name, uint64_t value,
                                uint64_t prev_value, bool changed_vs_prev) -> bool {
        RegHighlight rs  = get_reg_state(idx);
        ImVec4 color = state_to_color(rs);

        // Background tint for written registers
        ImVec2 cell_pos = ImGui::GetCursorScreenPos();
        float cell_w = ImGui::GetContentRegionAvail().x;
        float cell_h = ImGui::GetTextLineHeightWithSpacing();

        if (rs == RegHighlight::Write || rs == RegHighlight::ReadWrite) {
            // Strong highlight for written registers
            ImU32 bg = (rs == RegHighlight::ReadWrite)
                ? IM_COL32(80, 60, 20, 80)
                : IM_COL32(20, 70, 50, 80);
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + cell_w, cell_pos.y + cell_h - 1), bg);
        } else if (changed_vs_prev) {
            // Subtle change indicator (compared to previous instruction)
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + cell_w, cell_pos.y + cell_h - 1),
                                IM_COL32(40, 40, 70, 60));
        }

        // State indicator bar on the left edge
        if (rs != RegHighlight::Normal) {
            ImU32 bar_col = ImGui::ColorConvertFloat4ToU32(color);
            bar_col = (bar_col & 0x00FFFFFF) | 0xCC000000; // 80% alpha
            draw->AddRectFilled(cell_pos, ImVec2(cell_pos.x + 2.5f, cell_pos.y + cell_h - 1), bar_col);
        }

        // Name (fixed-width, dimmed)
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
        ImGui::SetNextItemWidth(32.0f);
        ImGui::Text("%-4s", name);
        ImGui::PopStyleColor();
        ImGui::SameLine(0, 4);

        // Value (colored by state)
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        char val_str[24];
        snprintf(val_str, sizeof(val_str), "%016llx", (unsigned long long)value);

        char sel_id[32];
        snprintf(sel_id, sizeof(sel_id), "##reg%u", idx);
        ImGui::Selectable((std::string(val_str) + sel_id).c_str(),
                          false, ImGuiSelectableFlags_AllowOverlap, ImVec2(0, 0));
        ImGui::PopStyleColor();

        // Tooltip
        if (ImGui::IsItemHovered()) {
            if (changed_vs_prev || rs != RegHighlight::Normal) {
                char tip[128];
                if (changed_vs_prev && has_prev) {
                    int64_t delta = (int64_t)(value - prev_value);
                    snprintf(tip, sizeof(tip),
                             "%s = 0x%016llx\n\u0394 = %+lld (0x%llx)\nRight-click for options",
                             name, (unsigned long long)value,
                             (long long)delta, (unsigned long long)(value - prev_value));
                } else {
                    snprintf(tip, sizeof(tip),
                             "%s = 0x%016llx\nRight-click for options", name, (unsigned long long)value);
                }
                ImGui::SetTooltip("%s", tip);
            }
        }
        // BeginPopupContextItem is the most reliable right-click menu API.
        // It checks IsItemHovered internally on mouse release.
        bool right_clicked = ImGui::IsItemClicked(ImGuiMouseButton_Right);
        if (ImGui::BeginPopupContextItem(nullptr)) {
            ctx_reg_idx_   = idx;
            ctx_reg_value_ = value;
            // ── Register context menu contents ────────────────────────
            std::string rname;
            if (idx <= 28) rname = fmt::format("x{}", idx);
            else if (idx == 29) rname = "fp";
            else if (idx == 30) rname = "lr";
            else if (idx == 31) rname = "sp";
            else rname = fmt::format("reg{}", idx);
            ImGui::TextDisabled("%s = 0x%016llx", rname.c_str(), (unsigned long long)value);
            ImGui::Separator();
            if (ImGui::MenuItem("Open Value in Hex Dump")) {
                open_hex_dump_at(value);
            }
            if (ImGui::MenuItem("Copy Value")) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)value);
                ImGui::SetClipboardText(buf);
            }
            if (idx == 30 && function_result_) {
                ImGui::Separator();
                if (ImGui::MenuItem("Follow LR (jump to call site)")) {
                    auto stack = function_result_->call_stack_at(current_inst_);
                    if (!stack.empty()) navigate_to(stack.back()->call_inst_id);
                }
            }
            if ((idx == 29 || idx == 31) && function_result_) {
                ImGui::Separator();
                ImGui::TextDisabled("(stack pointer/frame pointer)");
            }
            ImGui::EndPopup();
        }
        return right_clicked;
    };

    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(4, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,  ImVec2(4, 1));

    // ── GPR table: 2 columns, x0-x28 ──────────────────────────────
    const float col_w = (ImGui::GetContentRegionAvail().x - 8.0f) * 0.5f;
    ImGuiTableFlags tbl_flags = ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoPadOuterX;
    if (ImGui::BeginTable("GPR", 2, tbl_flags)) {
        ImGui::TableSetupColumn("Col0", ImGuiTableColumnFlags_WidthFixed, col_w);
        ImGui::TableSetupColumn("Col1", ImGuiTableColumnFlags_WidthFixed, col_w);

        for (int i = 0; i < 29; i += 2) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            {
                uint8_t ri = static_cast<uint8_t>(i);
                bool changed = has_prev && (state.gpr[i] != prev_state.gpr[i]);
                if (render_reg_cell(ri, reg_name(ri).c_str(), state.gpr[i],
                                    has_prev ? prev_state.gpr[i] : 0, changed)) {
                    ctx_reg_idx_   = ri;
                    ctx_reg_value_ = state.gpr[i];
                }
            }
            ImGui::TableNextColumn();
            if (i + 1 < 29) {
                uint8_t ri = static_cast<uint8_t>(i + 1);
                bool changed = has_prev && (state.gpr[i+1] != prev_state.gpr[i+1]);
                if (render_reg_cell(ri, reg_name(ri).c_str(), state.gpr[i+1],
                                    has_prev ? prev_state.gpr[i+1] : 0, changed)) {
                    ctx_reg_idx_   = ri;
                    ctx_reg_value_ = state.gpr[i+1];
                }
            }
        }
        ImGui::EndTable();
    }

    // ── Special registers ──────────────────────────────────────────
    // Thin divider
    ImVec2 sp_p0 = ImGui::GetCursorScreenPos();
    draw->AddLine(sp_p0, ImVec2(sp_p0.x + ImGui::GetContentRegionAvail().x, sp_p0.y),
                  IM_COL32(50, 55, 80, 180), 1.0f);
    ImGui::Dummy(ImVec2(0, 3));

    struct SpecReg { uint8_t idx; const char* name; uint64_t value; uint64_t prev; };
    SpecReg spec_regs[] = {
        { IDX_FP,   "fp",   state.fp(),   has_prev ? prev_state.fp()   : 0 },
        { IDX_LR,   "lr",   state.lr(),   has_prev ? prev_state.lr()   : 0 },
        { IDX_SP,   "sp",   state.sp(),   has_prev ? prev_state.sp()   : 0 },
        { IDX_PC,   "pc",   state.pc(),   has_prev ? prev_state.pc()   : 0 },
    };

    if (ImGui::BeginTable("SpecRegs", 2, tbl_flags)) {
        ImGui::TableSetupColumn("Col0", ImGuiTableColumnFlags_WidthFixed, col_w);
        ImGui::TableSetupColumn("Col1", ImGuiTableColumnFlags_WidthFixed, col_w);
        for (int si = 0; si < 4; si += 2) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            bool changed = has_prev && (spec_regs[si].value != spec_regs[si].prev);
            if (render_reg_cell(spec_regs[si].idx, spec_regs[si].name,
                                spec_regs[si].value, spec_regs[si].prev, changed)) {
                ctx_reg_idx_   = spec_regs[si].idx;
                ctx_reg_value_ = spec_regs[si].value;
            }
            ImGui::TableNextColumn();
            if (si + 1 < 4) {
                bool ch2 = has_prev && (spec_regs[si+1].value != spec_regs[si+1].prev);
                if (render_reg_cell(spec_regs[si+1].idx, spec_regs[si+1].name,
                                    spec_regs[si+1].value, spec_regs[si+1].prev, ch2)) {
                    ctx_reg_idx_   = spec_regs[si+1].idx;
                    ctx_reg_value_ = spec_regs[si+1].value;
                }
            }
        }
        ImGui::EndTable();
    }

    // NZCV flags — special display with individual flag bits
    {
        uint32_t nzcv = state.nzcv();
        bool nzcv_changed = has_prev && (nzcv != prev_state.nzcv());
        ImVec4 nzcv_col = get_reg_state(IDX_NZCV) != RegHighlight::Normal
            ? state_to_color(get_reg_state(IDX_NZCV))
            : (nzcv_changed ? ImVec4(0.85f, 0.75f, 0.40f, 1.0f) : ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
        // Bit labels: N Z C V (bits 31,30,29,28 of NZCV)
        bool N = (nzcv >> 31) & 1, Z = (nzcv >> 30) & 1;
        bool C = (nzcv >> 29) & 1, V = (nzcv >> 28) & 1;
        ImGui::TextColored(ImVec4(0.55f, 0.62f, 0.80f, 1.0f), "nzcv");
        ImGui::SameLine(0, 4);
        auto flag_label = [&](bool set, const char* name) {
            if (set)
                ImGui::TextColored(nzcv_col, "%s", name);
            else
                ImGui::TextDisabled("%s", name);
            ImGui::SameLine(0, 3);
        };
        flag_label(N, "N"); flag_label(Z, "Z"); flag_label(C, "C"); flag_label(V, "V");
        ImGui::TextDisabled("(0x%x)", nzcv);
    }

    ImGui::PopStyleVar(2);

    // Render register context menu
    render_reg_context_menu();

    ImGui::End();
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

// ─── Call Stack Panel ───────────────────────────────────────────────────────

void GuiApp::render_callstack_panel() {
    if (!ImGui::Begin("Call Stack", &show_callstack_)) {
        ImGui::End();
        return;
    }

    if (!function_result_) {
        ImGui::TextDisabled("(not computed - use Analysis > Function Analysis)");
        if (ImGui::Button("Run Function Analysis")) {
            run_function_analysis();
        }
        ImGui::End();
        return;
    }

    // Navigation buttons
    if (ImGui::Button("Follow Call (e)")) {
        auto* evt = function_result_->call_at(current_inst_);
        if (evt && evt->call_inst_id + 1 < total_inst_) {
            navigate_to(evt->call_inst_id + 1);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Follow Return (F)")) {
        auto* evt = function_result_->return_at(current_inst_);
        if (evt) {
            navigate_to(evt->call_inst_id);
        } else {
            auto stack = function_result_->call_stack_at(current_inst_);
            if (!stack.empty()) {
                navigate_to(stack.back()->call_inst_id);
            }
        }
    }

    ImGui::Separator();

    auto stack = function_result_->call_stack_at(current_inst_);
    if (stack.empty()) {
        ImGui::TextDisabled("<top-level>");
    } else {
        // Show call stack as clickable items with right-click menu
        for (size_t i = 0; i < stack.size(); i++) {
            auto* evt = stack[i];
            uint64_t static_target = evt->target_pc - reader_.header().module_slide;
            std::string label;

            auto it = function_result_->functions.find(evt->target_pc);
            if (it != function_result_->functions.end()) {
                label = it->second.name;
            } else {
                label = fmt::format("sub_{:x}", static_target);
            }

            bool is_deepest = (i == stack.size() - 1);
            std::string indent(i * 2, ' ');
            std::string selectable_label = fmt::format("{}{} {}  @{}##frame{}",
                indent,
                is_deepest ? ">" : " ",
                label,
                evt->call_inst_id,
                i);

            // Clickable frame
            if (ImGui::Selectable(selectable_label.c_str(), is_deepest,
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // Double-click → jump to function ENTRY (first inst in callee)
                    navigate_to(evt->call_inst_id + 1);
                } else {
                    // Single click → jump to the CALL SITE instruction
                    navigate_to(evt->call_inst_id);
                }
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip(
                    "Single-click: jump to call site @%llu\n"
                    "Double-click: jump to function entry\n"
                    "Right-click: more options\n"
                    "Target: 0x%llx",
                    (unsigned long long)evt->call_inst_id,
                    (unsigned long long)static_target);
            }
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                ctx_callstack_frame_ = i;
            }
            ImGui::OpenPopupOnItemClick("##cs_ctx", ImGuiPopupFlags_MouseButtonRight);
        }
    }

    // Render callstack context menu
    render_callstack_context_menu();

    ImGui::Separator();
    auto* func = function_result_->function_at(current_inst_);
    if (func) {
        ImGui::Text("In:");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "%s", func->name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(calls=%llu, insts=%llu)",
            (unsigned long long)func->total_calls,
            (unsigned long long)func->total_instructions);
    }

    // Xref info
    if (xref_result_) {
        auto row = fetch_row(current_inst_);
        auto exec_count = xref_result_->execution_count(row.pc);
        if (exec_count > 0) {
            ImGui::Separator();
            ImGui::Text("PC xrefs:");
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 1.0f, 1.0f),
                "%llu executions [%zu]",
                (unsigned long long)exec_count, xref_cursor_ + 1);
            ImGui::SameLine();
            if (ImGui::Button("Prev##xref")) {
                auto xrefs = xref_result_->inst_ids_at(row.pc);
                if (!xrefs.empty()) {
                    if (xref_cursor_ == 0) xref_cursor_ = xrefs.size() - 1;
                    else xref_cursor_--;
                    navigate_to(xrefs[xref_cursor_]);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Next##xref")) {
                auto xrefs = xref_result_->inst_ids_at(row.pc);
                if (!xrefs.empty()) {
                    xref_cursor_++;
                    if (xref_cursor_ >= xrefs.size()) xref_cursor_ = 0;
                    navigate_to(xrefs[xref_cursor_]);
                }
            }
        }
    }

    ImGui::End();
}

// ─── Analysis Panel ─────────────────────────────────────────────────────────

void GuiApp::render_analysis_panel() {
    if (!ImGui::Begin("Analysis", &show_analysis_)) {
        ImGui::End();
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    float panel_w = ImGui::GetContentRegionAvail().x;

    // ── Status banner ───────────────────────────────────────────────
    if (analysis_running_.load()) {
        // Animated busy indicator — full-width colored banner
        static const char* spinner[] = {
            "\xe2\xa3\xbe","\xe2\xa3\xbd","\xe2\xa3\xbb","\xe2\xa2\xbf",
            "\xe2\xa1\xbf","\xe2\xa3\x9f","\xe2\xa3\xaf","\xe2\xa3\xb7"
        };
        static int spin_frame = 0;
        spin_frame = (spin_frame + 1) % 8;

        ImVec2 banner_p0 = ImGui::GetCursorScreenPos();
        float banner_h = ImGui::GetFrameHeightWithSpacing();
        draw->AddRectFilled(banner_p0,
            ImVec2(banner_p0.x + panel_w, banner_p0.y + banner_h),
            IM_COL32(140, 110, 0, 80));

        ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.2f, 1.0f),
            " %s  Running...", spinner[spin_frame]);

        std::lock_guard<std::mutex> lock(analysis_mutex_);
        if (!analysis_status_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", analysis_status_.c_str());
        }
    } else {
        // Idle or active analysis indicator
        bool any_active = show_taint_ || show_slice_ || show_backward_taint_
                       || (show_loops_ && loop_result_)
                       || function_result_ || string_result_;
        if (any_active) {
            ImVec2 b0 = ImGui::GetCursorScreenPos();
            float bh = ImGui::GetFrameHeightWithSpacing();
            draw->AddRectFilled(b0, ImVec2(b0.x + panel_w, b0.y + bh),
                                IM_COL32(20, 80, 30, 60));
            ImGui::TextColored(ImVec4(0.35f, 0.90f, 0.45f, 1.0f), " \xe2\x9c\x93  Analysis active");
        } else {
            ImGui::TextDisabled(" \xe2\x80\x94  Idle (no analysis loaded)");
        }
    }

    ImGui::Dummy(ImVec2(0, 3));

    // ── Section helper ──────────────────────────────────────────────
    auto section_header = [&](const char* title, ImVec4 color) {
        ImVec2 hp = ImGui::GetCursorScreenPos();
        draw->AddRectFilled(hp, ImVec2(hp.x + panel_w, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(
                                ImVec4(color.x*0.4f, color.y*0.4f, color.z*0.4f, 0.55f)));
        draw->AddRectFilled(hp, ImVec2(hp.x + 3.0f, hp.y + ImGui::GetFrameHeight()),
                            ImGui::ColorConvertFloat4ToU32(color));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 6.0f);
        ImGui::TextColored(color, "%s", title);
    };

    // ── GROUP 1: Taint analysis ─────────────────────────────────────
    section_header("  Taint Analysis", ImVec4(0.20f, 0.82f, 0.35f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 3));

    // Forward taint
    {
        bool active = show_taint_ && taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f, 0.35f, 0.12f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.10f, 0.45f, 0.15f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.12f, 0.55f, 0.18f, 1.0f));
        }
        if (ImGui::Button("Run Taint##fwd")) {
            run_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Forward taint from selected register\nAnalysis > Taint to choose source");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.25f, 0.85f, 0.35f, 1.0f), "\xe2\x9c\x93");
            ImGui::SameLine(0, 4);
            ImGui::Text("%llu tainted", (unsigned long long)taint_result_->tainted_inst_count());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrtaint")) {
                show_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Backward taint
    {
        bool active = show_backward_taint_ && backward_taint_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.08f, 0.08f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.10f, 0.10f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.12f, 0.12f, 1.0f));
        }
        if (ImGui::Button("Run BackTaint")) {
            run_backward_taint_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Backward taint from current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.90f, 0.25f, 0.25f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrbt")) {
                show_backward_taint_ = false;
            }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear backward-taint overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // Slice
    {
        bool active = show_slice_ && slice_result_;
        if (ImGui::Button("Run Slice##slc")) {
            run_slice_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Program slice for current instruction");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.80f, 0.25f, 0.80f, 1.0f), "\xe2\x9c\x93 active");
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrslc")) { show_slice_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear slice overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 2: Code Structure ─────────────────────────────────────
    section_header("  Code Structure", ImVec4(0.35f, 0.62f, 1.0f, 1.0f));

    // Functions
    {
        bool active = (function_result_ != nullptr);
        if (ImGui::Button("Run Functions##fn")) {
            run_function_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Discover call/return pairs, build function list");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.4f, 0.75f, 1.0f, 1.0f),
                "\xe2\x9c\x93 %zu functions", function_result_->functions.size());
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // Loops
    {
        bool active = show_loops_ && loop_result_;
        if (active) {
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.35f, 0.18f, 0.02f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.25f, 0.03f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.55f, 0.30f, 0.04f, 1.0f));
        }
        if (ImGui::Button("Run Loops##lp")) {
            run_loop_analysis();
        }
        if (active) ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Detect loops (back-edges in CFG)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(1.0f, 0.62f, 0.12f, 1.0f),
                "\xe2\x9c\x93 %zu loops", loop_result_->loops.size());
            ImGui::SameLine();
            if (ImGui::SmallButton("x##clrlp")) { show_loops_ = false; }
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear loop overlay");
        } else {
            ImGui::TextDisabled("(not active)");
        }
    }

    // XRef
    {
        bool active = (xref_result_ != nullptr);
        if (ImGui::Button("Run XRef##xref")) {
            run_xref_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build cross-reference index (PC → inst_ids)");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.65f, 0.75f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    // CFG
    {
        bool active = (cfg_result_ != nullptr);
        if (ImGui::Button("Run CFG##cfg")) {
            run_cfg_layout();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Compute control-flow graph + layout for CFG view");
        ImGui::SameLine();
        if (active) {
            ImGui::TextColored(ImVec4(0.55f, 0.80f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 4));

    // ── GROUP 3: String & Call Graph ───────────────────────────────
    section_header("  Strings / Calls", ImVec4(0.75f, 0.55f, 1.0f, 1.0f));

    {
        bool has_str = (string_result_ != nullptr);
        if (ImGui::Button("Run Strings##str")) {
            run_string_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Find string accesses in the trace");
        ImGui::SameLine();
        if (has_str) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    {
        bool has_cg = (call_graph_result_ != nullptr);
        if (ImGui::Button("Run CallGraph##cg")) {
            run_call_graph_analysis();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Build call graph across functions");
        ImGui::SameLine();
        if (has_cg) {
            ImGui::TextColored(ImVec4(0.78f, 0.62f, 1.0f, 1.0f), "\xe2\x9c\x93 ready");
        } else {
            ImGui::TextDisabled("(not run)");
        }
    }

    ImGui::Dummy(ImVec2(0, 6));

    // ── Clear All ───────────────────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f, 0.10f, 0.10f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.60f, 0.15f, 0.15f, 1.0f));
    if (ImGui::Button("  \xe2\x9c\x95  Clear All  ")) {  // ✕
        clear_analysis();
    }
    ImGui::PopStyleColor(3);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Clear all analysis results and overlays");

    ImGui::PopStyleVar();  // ItemSpacing
    ImGui::End();
}

// ─── Hex Dump Panel ─────────────────────────────────────────────────────────

void GuiApp::render_hex_dump_panel() {
    if (!ImGui::Begin("Hex Dump", &show_hex_dump_)) {
        ImGui::End();
        return;
    }

    // Determine which address to display:
    // 1) If ctx_mem_addr_ was set (via open_hex_dump_at), use that
    // 2) Otherwise use the first memory access of current instruction
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

    // Header with address input
    ImGui::Text("Jump to Address:");
    ImGui::SameLine();
    static char hex_addr_buf[32] = {};
    ImGui::SetNextItemWidth(160.0f);
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
        // Reset to follow current instruction's memory access
        ctx_mem_addr_ = 0;
        std::memset(hex_addr_buf, 0, sizeof(hex_addr_buf));
    }
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Show hex dump for current instruction's memory access");
    }

    if (!has_addr) {
        ImGui::Separator();
        ImGui::TextDisabled("(no memory access — enter an address above, or navigate to an instruction with memory access)");
        ImGui::End();
        return;
    }

    ImGui::Separator();
    ImGui::Text("Address: 0x%016llx", (unsigned long long)display_addr);

    uint64_t base_addr = display_addr & ~0xFULL;  // Align to 16 bytes

    // Get memory bytes from MemoryModel
    // We display 16 rows × 16 bytes
    const int kRows = 16;
    ImGui::Separator();

    // Column header
    ImGui::TextDisabled("           Address           | 00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | ASCII");
    ImGui::Separator();

    for (int row = -2; row < kRows - 2; row++) {
        uint64_t row_addr = base_addr + static_cast<uint64_t>(row) * 16;
        bool is_active_row = (display_addr >= row_addr && display_addr < row_addr + 16);

        // Address
        if (is_active_row) {
            ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f),
                "0x%016llx:", (unsigned long long)row_addr);
        } else {
            ImGui::TextDisabled("0x%016llx:", (unsigned long long)row_addr);
        }
        ImGui::SameLine();

        // Hex bytes — each byte is individually clickable
        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            auto byte_val = memory_.byte_at(byte_addr, current_inst_);

            bool is_highlighted = (byte_addr == display_addr);

            if (b == 8) {
                ImGui::SameLine(0, 0);
                ImGui::TextDisabled(" ");
            }
            if (b > 0) ImGui::SameLine(0, 0);

            char byte_str[8];
            if (byte_val.has_value()) {
                snprintf(byte_str, sizeof(byte_str), "%02x ", *byte_val);
            } else {
                snprintf(byte_str, sizeof(byte_str), "?? ");
            }

            // Push unique ID for each byte so ImGui can track them
            ImGui::PushID(static_cast<int>(row * 16 + b));

            if (is_highlighted) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", byte_str);
            } else if (is_active_row) {
                ImGui::TextColored(ImVec4(0.8f, 0.8f, 0.8f, 1.0f), "%s", byte_str);
            } else {
                ImGui::TextDisabled("%s", byte_str);
            }

            // Double-click: jump to the instruction that last wrote this byte
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                if (writer > 0) {
                    navigate_to(writer);
                }
            }
            // Single-click: update display address to this byte
            if (ImGui::IsItemClicked()) {
                display_addr = byte_addr;
                ctx_mem_addr_ = byte_addr;
            }
            // Tooltip on hover
            if (ImGui::IsItemHovered()) {
                uint64_t writer = memory_.last_writer(byte_addr, 1, current_inst_);
                if (writer > 0) {
                    ImGui::SetTooltip("0x%llx: last written by inst #%llu\nDouble-click to jump",
                        (unsigned long long)byte_addr, (unsigned long long)writer);
                } else {
                    ImGui::SetTooltip("0x%llx: no known writer",
                        (unsigned long long)byte_addr);
                }
            }

            ImGui::PopID();
        }

        // ASCII part
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
        ImGui::TextDisabled("| %s", ascii_part);
    }

    ImGui::Separator();
    ImGui::TextDisabled("Click: select byte  |  Double-click: jump to writer  |  'From Inst': follow current instruction");

    ImGui::End();
}

// ─── Popups ─────────────────────────────────────────────────────────────────

// ─── Goto helpers ────────────────────────────────────────────────────────────

/// Rebuild the autocomplete candidate list from the function result.
/// Sorted by call count descending (most used functions first).
void GuiApp::rebuild_goto_candidates() {
    goto_candidates_.clear();
    if (!function_result_) return;

    // Build candidates from function map
    for (const auto& [pc, info] : function_result_->functions) {
        // Find the first inst_id for this function entry
        uint64_t inst_id = 0;
        bool found = false;
        // Look up the first call event that enters this function
        for (const auto& idx : info.call_event_indices) {
            if (idx < function_result_->call_events.size()) {
                const auto& evt = function_result_->call_events[idx];
                if (!found || evt.call_inst_id + 1 < inst_id) {
                    inst_id = evt.call_inst_id + 1;
                    found = true;
                }
            }
        }
        if (!found) inst_id = 0; // fallback

        // Format display: "func_name (0x1234abcd)"
        char disp[192];
        snprintf(disp, sizeof(disp), "%s  (0x%llx)",
                 info.name.c_str(), (unsigned long long)pc);

        goto_candidates_.push_back({disp, info.name, pc, inst_id});
    }

    // Sort by call count descending (most frequently called first)
    std::sort(goto_candidates_.begin(), goto_candidates_.end(),
              [&](const GotoCandidate& a, const GotoCandidate& b) {
                  auto it_a = function_result_->functions.find(a.pc);
                  auto it_b = function_result_->functions.find(b.pc);
                  uint64_t ca = (it_a != function_result_->functions.end()) ? it_a->second.total_calls : 0;
                  uint64_t cb = (it_b != function_result_->functions.end()) ? it_b->second.total_calls : 0;
                  if (ca != cb) return ca > cb;
                  return a.name < b.name;
              });

    goto_candidates_dirty_ = false;
}

/// Parse the input string and navigate:
///   - "0x..." → treat as runtime address, find first xref
///   - pure digits → treat as instruction ID
///   - otherwise → search function names
void GuiApp::goto_commit(const char* buf) {
    if (!buf || buf[0] == '\0') return;

    std::string s(buf);

    // Trim whitespace
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
    if (s.empty()) return;

    // 1. Hex address? starts with "0x" or "0X"
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        try {
            uint64_t addr = std::stoull(s.substr(2), nullptr, 16);
            // Try xref lookup first (PC → inst_id)
            if (xref_result_) {
                auto ids = xref_result_->inst_ids_at(addr);
                if (!ids.empty()) {
                    navigate_to(ids[0]);
                    return;
                }
            }
            // Fall back: treat as instruction count / address raw
            // Try decoding address as a static PC (add slide if known)
            // We don't know the slide here, so just warn with a candidate search
            // If the xref has slide info we could subtract; for now skip.
        } catch (...) {}
        return;
    }

    // 2. Pure numeric? → instruction ID
    bool all_digits = !s.empty();
    for (char c : s) {
        if (c < '0' || c > '9') { all_digits = false; break; }
    }
    if (all_digits) {
        try {
            uint64_t target = std::stoull(s);
            if (target < total_inst_) navigate_to(target);
        } catch (...) {}
        return;
    }

    // 3. Function name lookup (exact match, then prefix/contains)
    if (!goto_candidates_.empty()) {
        // Lowercase query for case-insensitive matching
        std::string query = s;
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        // Exact match first
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower == query) {
                navigate_to(c.inst_id);
                return;
            }
        }
        // Prefix match
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.compare(0, query.size(), query) == 0) {
                navigate_to(c.inst_id);
                return;
            }
        }
        // Contains match
        for (const auto& c : goto_candidates_) {
            std::string lower = c.name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find(query) != std::string::npos) {
                navigate_to(c.inst_id);
                return;
            }
        }
    }
}

void GuiApp::render_goto_popup() {
    if (!show_goto_popup_) return;

    // Rebuild candidates if function result is available and dirty
    if (goto_candidates_dirty_ && function_result_) {
        rebuild_goto_candidates();
    }

    // Widen the popup when we have function candidates to show
    bool has_candidates = !goto_candidates_.empty();
    if (has_candidates) {
        ImGui::SetNextWindowSize(ImVec2(480.0f, 0.0f), ImGuiCond_Appearing);
    }

    ImGui::OpenPopup("Go to...");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Go to...", &show_goto_popup_,
                               ImGuiWindowFlags_AlwaysAutoResize)) {

        // ─── Hint text ──────────────────────────────────────────────────
        ImGui::TextDisabled("Instruction ID, 0x<address>, or function name:");
        ImGui::Spacing();

        // ─── Input field ────────────────────────────────────────────────
        ImGui::SetNextItemWidth(has_candidates ? 440.0f : 280.0f);
        bool enter_pressed = ImGui::InputText("##goto_input", goto_buf_, sizeof(goto_buf_),
                                              ImGuiInputTextFlags_EnterReturnsTrue |
                                              ImGuiInputTextFlags_AutoSelectAll);

        // Auto-focus on first appearance
        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere(-1);
        }

        // Down arrow in input → move to candidate list
        bool arrow_down = ImGui::IsItemFocused() && ImGui::IsKeyPressed(ImGuiKey_DownArrow);

        // ─── Commit on Enter ────────────────────────────────────────────
        if (enter_pressed) {
            // goto_buf_ always contains the best text to navigate to:
            // - user typed it directly, OR
            // - single-click on candidate filled it with the function name
            // goto_commit() handles hex/decimal/function-name parsing
            goto_commit(goto_buf_);
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return;
        }

        // ─── Autocomplete candidate list ────────────────────────────────
        if (has_candidates) {
            std::string query(goto_buf_);
            // Lowercase
            std::string ql = query;
            std::transform(ql.begin(), ql.end(), ql.begin(), ::tolower);

            // Collect matching candidates (limit display to 12)
            std::vector<const GotoCandidate*> visible;
            if (ql.empty()) {
                // Show top-N by call count
                for (size_t i = 0; i < goto_candidates_.size() && visible.size() < 12; i++) {
                    visible.push_back(&goto_candidates_[i]);
                }
            } else {
                // Filter: prefix first, then contains
                for (const auto& c : goto_candidates_) {
                    std::string cl = c.name;
                    std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
                    if (cl.compare(0, ql.size(), ql) == 0) {
                        visible.push_back(&c);
                        if (visible.size() >= 12) break;
                    }
                }
                if (visible.size() < 12) {
                    for (const auto& c : goto_candidates_) {
                        std::string cl = c.name;
                        std::transform(cl.begin(), cl.end(), cl.begin(), ::tolower);
                        if (cl.find(ql) != std::string::npos &&
                            cl.compare(0, ql.size(), ql) != 0) {
                            visible.push_back(&c);
                            if (visible.size() >= 12) break;
                        }
                    }
                }
            }

            if (!visible.empty()) {
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextDisabled("Functions (%zu):", visible.size());
                ImGui::Spacing();

                // Keyboard navigation in list
                if (arrow_down || ImGui::IsItemFocused()) {
                    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow) && goto_selected_candidate_ < (int)visible.size() - 1)
                        goto_selected_candidate_++;
                    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow) && goto_selected_candidate_ > 0)
                        goto_selected_candidate_--;
                }

                // List child window for scrolling
                float list_h = std::min((int)visible.size(), 10) * ImGui::GetTextLineHeightWithSpacing() + 4.0f;
                ImGui::BeginChild("##goto_list", ImVec2(440.0f, list_h), false,
                                  ImGuiWindowFlags_NoScrollbar);

                for (int i = 0; i < (int)visible.size(); i++) {
                    const auto* c = visible[i];
                    bool selected = (goto_selected_candidate_ == i);

                    // Get call count for display
                    uint64_t calls = 0;
                    if (function_result_) {
                        auto it = function_result_->functions.find(c->pc);
                        if (it != function_result_->functions.end())
                            calls = it->second.total_calls;
                    }

                    // Format entry: name + address + call count
                    char row_buf[220];
                    snprintf(row_buf, sizeof(row_buf), "%-40s  %5llu calls",
                             c->display.c_str(), (unsigned long long)calls);

                    // Color: dim non-selected, highlight selected
                    if (selected) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.85f, 0.3f, 1.0f));
                    } else {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.75f, 0.75f, 0.75f, 1.0f));
                    }

                    if (ImGui::Selectable(row_buf, selected,
                                          ImGuiSelectableFlags_AllowDoubleClick)) {
                        if (ImGui::IsMouseDoubleClicked(0)) {
                            navigate_to(c->inst_id);
                            show_goto_popup_ = false;
                            goto_selected_candidate_ = -1;
                            std::memset(goto_buf_, 0, sizeof(goto_buf_));
                            ImGui::PopStyleColor();
                            ImGui::EndChild();
                            ImGui::EndPopup();
                            return;
                        }
                        goto_selected_candidate_ = i;
                        // Single-click: copy name into input field
                        std::strncpy(goto_buf_, c->name.c_str(), sizeof(goto_buf_) - 1);
                        goto_buf_[sizeof(goto_buf_) - 1] = '\0';
                    }
                    ImGui::PopStyleColor();
                }

                ImGui::EndChild();
            } else if (!ql.empty()) {
                ImGui::Separator();
                ImGui::Spacing();
                ImGui::TextDisabled("(no matching functions)");
                ImGui::Spacing();
            }
        }

        // ─── Bottom buttons ─────────────────────────────────────────────
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Go", ImVec2(80, 0))) {
            // goto_buf_ is always authoritative: user typed it or click filled it
            goto_commit(goto_buf_);
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_goto_popup_ = false;
            goto_selected_candidate_ = -1;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }

        // ─── Keyboard tip ───────────────────────────────────────────────
        ImGui::SameLine();
        ImGui::TextDisabled("  Enter=go  ↑↓=select  DblClick=jump");

        ImGui::EndPopup();
    }
}

void GuiApp::render_search_popup() {
    if (!show_search_popup_) return;

    ImGui::OpenPopup("Search");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Search", &show_search_popup_,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Search disassembly:");

        bool enter_pressed = ImGui::InputText("##search", search_buf_, sizeof(search_buf_),
                                              ImGuiInputTextFlags_EnterReturnsTrue);

        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere(-1);
        }

        if (enter_pressed || ImGui::Button("Find")) {
            // Execute search
            std::string query(search_buf_);
            search_results_.clear();
            search_current_ = 0;
            search_active_ = false;

            if (!query.empty()) {
                // Linear search (limited to first 1M instructions for responsiveness)
                for (uint64_t i = 0; i < total_inst_ && i < 1000000; i++) {
                    auto row = fetch_row(i);
                    if (row.disasm.find(query) != std::string::npos) {
                        search_results_.push_back(i);
                    }
                }
                if (!search_results_.empty()) {
                    search_active_ = true;
                    navigate_to(search_results_[0]);
                }
            }

            show_search_popup_ = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_search_popup_ = false;
            ImGui::CloseCurrentPopup();
        }

        if (search_active_ && !search_results_.empty()) {
            ImGui::Text("Results: %zu found (showing %zu/%zu)",
                search_results_.size(), search_current_ + 1, search_results_.size());
        }

        ImGui::EndPopup();
    }
}

// ─── Data helpers ───────────────────────────────────────────────────────────

InstructionRow GuiApp::fetch_row(uint64_t inst_id) {
    auto cached = row_cache_.get(inst_id);
    if (cached) return *cached;

    InstructionRow row{};
    row.inst_id = inst_id;

    auto [offset, seed_pc] = index_.offset_of_with_pc(inst_id, reader_);
    // Pass seed_pc: record_at(offset, seed_pc) sets resolved_pc so as_inst()
    // uses the correct 6-byte v5 header layout (vs 16-byte v4) when needed.
    auto rec = reader_.record_at(offset, seed_pc);
    if (rec.kind != RecordKind::Inst) {
        row.disasm = "<not an instruction>";
        row_cache_.put(inst_id, row);
        return row;
    }

    auto inst = rec.as_inst();
    row.pc = inst.pc;
    row.static_pc = inst.pc - reader_.header().module_slide;
    row.nzcv = inst.nzcv;
    row.reg_diff_count = inst.reg_diff_count;
    row.mem_access_count = inst.mem_access_count;

    auto opcode = code_table_.opcode_at(inst.pc);
    if (opcode) {
        auto d = decoder_.decode(inst.pc, *opcode);
        if (d) {
            row.mnemonic = d->mnemonic;
            row.operands = d->op_str;
            row.disasm = fmt::format("{} {}", d->mnemonic, d->op_str);
        } else {
            row.mnemonic = ".word";
            row.operands = fmt::format("0x{:08x}", *opcode);
            row.disasm = fmt::format(".word 0x{:08x}", *opcode);
        }
    } else {
        row.mnemonic = "";
        row.operands = "";
        row.disasm = "<no code>";
    }

    row.has_bookmark = std::binary_search(bookmarks_.begin(), bookmarks_.end(), inst_id);

    row_cache_.put(inst_id, row);
    return row;
}

// ─── Navigation History ─────────────────────────────────────────────────────

void GuiApp::nav_push(uint64_t inst_id) {
    if (nav_history_navigating_) return;
    // If we're in the middle of the history (after going back), truncate forward history
    if (!nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1) {
        nav_history_.erase(nav_history_.begin() + static_cast<ptrdiff_t>(nav_history_pos_) + 1,
                           nav_history_.end());
    }
    // Avoid duplicate consecutive entries
    if (!nav_history_.empty() && nav_history_.back() == inst_id) return;
    nav_history_.push_back(inst_id);
    if (nav_history_.size() > kMaxNavHistory) {
        nav_history_.erase(nav_history_.begin());
    }
    nav_history_pos_ = nav_history_.size() - 1;
}

void GuiApp::nav_back() {
    if (!can_nav_back()) return;
    nav_history_navigating_ = true;
    nav_history_pos_--;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

void GuiApp::nav_forward() {
    if (!can_nav_forward()) return;
    nav_history_navigating_ = true;
    nav_history_pos_++;
    navigate_to(nav_history_[nav_history_pos_]);
    nav_history_navigating_ = false;
}

bool GuiApp::can_nav_back() const {
    return nav_history_pos_ > 0;
}

bool GuiApp::can_nav_forward() const {
    return !nav_history_.empty() && nav_history_pos_ < nav_history_.size() - 1;
}

void GuiApp::navigate_to(uint64_t inst_id) {
    if (inst_id >= total_inst_) inst_id = total_inst_ > 0 ? total_inst_ - 1 : 0;
    nav_push(inst_id);
    current_inst_ = inst_id;
    // Mark taint sorted list dirty so next jump recomputes
    taint_sorted_ids_dirty_ = true;
}

void GuiApp::toggle_bookmark() {
    auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), current_inst_);
    if (it != bookmarks_.end() && *it == current_inst_) {
        bookmarks_.erase(it);
    } else {
        bookmarks_.insert(it, current_inst_);
    }
    // Invalidate cache for this row so bookmark state is refreshed
    row_cache_.put(current_inst_, fetch_row(current_inst_));
}

// ─── Analysis helpers ───────────────────────────────────────────────────────

void GuiApp::ensure_pass_manager() {
    if (!pass_manager_) {
        pass_manager_ = std::make_unique<PassManager>();
        pass_manager_->set_reader(&reader_);
        pass_manager_->set_index(&index_);
        pass_manager_->set_code_table(&code_table_);
        pass_manager_->set_decoder(&decoder_);
        pass_manager_->set_regfile(&regfile_);
        pass_manager_->set_memory(&memory_);
    }
}

// ─── Startup Analysis ───────────────────────────────────────────────────────
// Runs a curated set of "always-useful" analyses in a background thread so
// the UI is immediately responsive while analysis proceeds.
// Order matters: Function → XRef → String → CallGraph
// (XRef is needed by CFG/CallGraph; Function populates the call-stack panel)

void GuiApp::run_startup_analysis() {
    // Guard: don't double-launch
    if (analysis_running_.exchange(true)) return;

    // Ensure pass manager is ready on the main thread before handing off
    ensure_pass_manager();

    startup_analysis_thread_ = std::thread([this]() {
        auto set_status = [this](const char* msg) {
            std::lock_guard<std::mutex> lock(analysis_mutex_);
            analysis_status_ = msg;
        };

        // ── 1. Function analysis ──────────────────────────────────────
        set_status("Functions...");
        {
            pass_manager_->register_pass(std::make_unique<FunctionPass>());
            auto& r = pass_manager_->require("function");
            if (r.ok()) {
                function_result_ = &r.get<FunctionResult>();
                show_callstack_   = true;
                show_functions_   = true;
                goto_candidates_dirty_ = true;
            }
        }

        // ── 2. XRef analysis ─────────────────────────────────────────
        set_status("XRefs...");
        {
            pass_manager_->register_pass(std::make_unique<XrefPass>());
            auto& r = pass_manager_->require("xref");
            if (r.ok()) {
                xref_result_  = &r.get<XrefResult>();
                xref_cursor_  = 0;
            }
        }

        // ── 3. String analysis ───────────────────────────────────────
        set_status("Strings...");
        {
            pass_manager_->register_pass(std::make_unique<StringPass>());
            auto& r = pass_manager_->require("strings");
            if (r.ok()) {
                string_result_  = &r.get<StringResult>();
                show_strings_   = true;
                string_cursor_  = 0;
                string_filter_.clear();
                std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
            }
        }

        // ── 4. Call graph ─────────────────────────────────────────────
        set_status("Call graph...");
        {
            pass_manager_->register_pass(std::make_unique<CallGraphPass>());
            auto& r = pass_manager_->require("call_graph");
            if (r.ok()) {
                call_graph_result_ = &r.get<CallGraphResult>();
            }
        }

        // ── 5. CFG ───────────────────────────────────────────────────
        // Needed by loop_pass and loop_semantics_pass downstream.
        set_status("CFG...");
        {
            pass_manager_->register_pass(std::make_unique<CFGPass>());
            auto& r = pass_manager_->require("cfg");
            if (r.ok()) {
                cfg_result_ = &r.get<CFGResult>();
            }
        }

        // ── 6. Loop detection ────────────────────────────────────────
        set_status("Loops...");
        {
            pass_manager_->register_pass(std::make_unique<LoopPass>());
            auto& r = pass_manager_->require("loop");
            if (r.ok()) {
                loop_result_ = &r.get<LoopResult>();
                show_loops_  = true;
            }
        }

        // ── 7. Constant materialisation ──────────────────────────────
        // Identifies crypto/hash constants (SHA-256, SM4, ChaCha20, TEA…).
        set_status("Constants...");
        {
            pass_manager_->register_pass(std::make_unique<ConstantMaterializationPass>());
            auto& r = pass_manager_->require("constant_materialization");
            if (r.ok()) {
                constant_result_ = &r.get<ConstantMaterializationResult>();
            }
        }

        // ── 8. Pattern detection (YARA + mnemonic heuristics) ────────
        set_status("Patterns...");
        {
            pass_manager_->register_pass(std::make_unique<PatternPass>());
            auto& r = pass_manager_->require("pattern");
            if (r.ok()) {
                pattern_result_ = &r.get<PatternResult>();
            }
        }

        // ── 9. Loop semantics ────────────────────────────────────────
        // Classifies loops (Feistel, SPN, ARX, MemcpyLike, …).
        set_status("Loop semantics...");
        {
            pass_manager_->register_pass(std::make_unique<LoopSemanticsPass>());
            auto& r = pass_manager_->require("loop_semantics");
            if (r.ok()) {
                loop_semantics_result_ = &r.get<LoopSemanticsResult>();
            }
        }

        // ── 10. Algorithm summary ────────────────────────────────────
        // Cross-references constants + patterns + loop semantics to produce
        // a human-readable algorithm identification (AES, SHA-256, etc.).
        set_status("Algorithm summary...");
        {
            pass_manager_->register_pass(std::make_unique<AlgorithmSummaryPass>());
            auto& r = pass_manager_->require("algorithm_summary");
            if (r.ok()) {
                algorithm_summary_result_ = &r.get<AlgorithmSummaryResult>();
            }
        }

        // ── 11. Symbol annotation ────────────────────────────────────
        // Aggregates results from function/loop/constant/pattern passes
        // into a unified PC → label map used by the disassembly view.
        set_status("Annotations...");
        {
            pass_manager_->register_pass(std::make_unique<SymbolAnnotationPass>());
            auto& r = pass_manager_->require("symbol_annotation");
            if (r.ok()) {
                annotation_result_ = &r.get<AnnotationResult>();
            }
        }

        // Done
        {
            std::lock_guard<std::mutex> lock(analysis_mutex_);
            analysis_status_.clear();
        }
        analysis_running_.store(false);
    });
    startup_analysis_thread_.detach();
}

void GuiApp::run_taint_analysis() {
    ensure_pass_manager();

    // Configure taint: start with current instruction's modified registers as sources
    TaintConfig config;
    config.taint_from_memory = true;
    config.track_memory_sinks = true;
    config.propagate_arithmetic = true;
    config.propagate_moves = true;
    config.max_instructions = 100000;

    // Use current instruction's register diffs as initial taint sources
    auto [offset_ts, seed_pc_ts] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_ts = reader_.record_at(offset_ts, seed_pc_ts);
    if (rec_ts.kind == RecordKind::Inst) {
        auto inst = rec_ts.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_source_reg(diff.index);
        }
    }

    pass_manager_->register_pass(std::make_unique<TaintPass>(config));
    auto& result = pass_manager_->require("taint");
    if (result.ok()) {
        taint_result_ = &result.get<TaintResult>();
        show_taint_ = true;
        show_slice_ = false;
        show_backward_taint_ = false;
    }
}

void GuiApp::run_backward_taint_analysis() {
    ensure_pass_manager();

    // Configure backward taint: current instruction is the sink
    BackwardTaintConfig config;
    config.sink_inst_id = current_inst_;
    config.propagate_through_memory = true;
    config.max_steps = 500000;
    config.max_tainted_insts = 50000;

    // Use current instruction's register diffs as sink registers
    auto [offset_sk, seed_pc_sk] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sk = reader_.record_at(offset_sk, seed_pc_sk);
    if (rec_sk.kind == RecordKind::Inst) {
        auto inst = rec_sk.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.add_sink_reg(diff.index);
        }
    }

    if (config.sink_regs == 0) {
        // No reg diffs at this instruction - default to X0
        config.add_sink_reg(0);
    }

    pass_manager_->register_pass(std::make_unique<BackwardTaintPass>(std::move(config)));
    auto& result = pass_manager_->require("backward_taint");
    if (result.ok()) {
        backward_taint_result_ = &result.get<BackwardTaintResult>();
        show_backward_taint_ = true;
        show_taint_ = false;
        show_slice_ = false;
    }
}

void GuiApp::run_slice_analysis() {
    if (!taint_result_) {
        // Need taint first
        run_taint_analysis();
    }
    if (!taint_result_) return;

    ensure_pass_manager();

    // Determine which register to slice from current instruction
    uint8_t target_reg = 0;
    auto [offset_sl, seed_pc_sl] = index_.offset_of_with_pc(current_inst_, reader_);
    auto rec_sl = reader_.record_at(offset_sl, seed_pc_sl);
    if (rec_sl.kind == RecordKind::Inst) {
        auto inst = rec_sl.as_inst();
        if (inst.reg_diff_count > 0) {
            target_reg = inst.reg_diff(0).index;
        }
    }

    pass_manager_->register_pass(
        std::make_unique<SlicePass>(current_inst_, target_reg));
    auto& result = pass_manager_->require("slice");
    if (result.ok()) {
        slice_result_ = &result.get<SliceResult>();
        show_slice_ = true;
        show_taint_ = false;
        show_backward_taint_ = false;
    }
}

void GuiApp::run_function_analysis() {
    ensure_pass_manager();

    pass_manager_->register_pass(std::make_unique<FunctionPass>());
    auto& result = pass_manager_->require("function");
    if (result.ok()) {
        function_result_ = &result.get<FunctionResult>();
        show_callstack_ = true;
        goto_candidates_dirty_ = true;  // Rebuild goto autocomplete on next open
    }
}

void GuiApp::run_xref_analysis() {
    ensure_pass_manager();

    pass_manager_->register_pass(std::make_unique<XrefPass>());
    auto& result = pass_manager_->require("xref");
    if (result.ok()) {
        xref_result_ = &result.get<XrefResult>();
        xref_cursor_ = 0;
    }
}

void GuiApp::run_string_analysis() {
    ensure_pass_manager();

    pass_manager_->register_pass(std::make_unique<StringPass>());
    auto& result = pass_manager_->require("strings");
    if (result.ok()) {
        string_result_ = &result.get<StringResult>();
        show_strings_ = true;
        string_cursor_ = 0;
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    }
}

void GuiApp::run_thread_analysis() {
    ensure_pass_manager();

    pass_manager_->register_pass(std::make_unique<ThreadPass>());
    auto& result = pass_manager_->require("thread");
    if (result.ok()) {
        thread_result_ = &result.get<ThreadResult>();
        show_threads_ = true;
    }
}

// ─── Thread Panel ────────────────────────────────────────────────────────────

void GuiApp::render_thread_panel() {
    if (!ImGui::Begin("Threads", &show_threads_)) {
        ImGui::End();
        return;
    }

    if (!thread_result_) {
        if (ImGui::Button("Run Thread Analysis")) {
            run_thread_analysis();
        }
        ImGui::End();
        return;
    }

    // Summary
    ImGui::Text("Threads: %zu  |  Context Switches: %zu",
        thread_result_->thread_count(), thread_result_->switch_count());
    ImGui::Separator();

    // Active thread at current instruction
    uint64_t cur_tid = thread_result_->thread_at(current_inst_);
    if (cur_tid != 0) {
        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
            "Active Thread: tid=0x%llx", (unsigned long long)cur_tid);
    } else {
        ImGui::TextDisabled("Active Thread: unknown");
    }

    // Navigation buttons
    if (ImGui::Button("< Prev Switch")) {
        auto* ev = thread_result_->prev_switch_before(current_inst_);
        if (ev) navigate_to(ev->inst_id);
    }
    ImGui::SameLine();
    if (ImGui::Button("Next Switch >")) {
        auto* ev = thread_result_->next_switch_after(current_inst_);
        if (ev) navigate_to(ev->inst_id);
    }

    ImGui::Separator();

    // Thread list table
    if (ImGui::BeginTable("ThreadTable", 4,
            ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Thread ID", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Instructions", ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn("Switches", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Range", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& [tid, info] : thread_result_->threads) {
            ImGui::TableNextRow();
            bool is_active = (tid == cur_tid);

            // Thread ID
            ImGui::TableNextColumn();
            char label[64];
            snprintf(label, sizeof(label), "0x%llx", (unsigned long long)tid);
            if (is_active) {
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", label);
            } else {
                ImGui::Text("%s", label);
            }
            // Double-click to jump to first instruction of this thread
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                navigate_to(info.first_seen_inst);
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Double-click to jump to first instruction of this thread");
            }

            // Instructions
            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)info.total_instructions);

            // Switch count
            ImGui::TableNextColumn();
            ImGui::Text("%llu", (unsigned long long)info.switch_in_count);

            // Range
            ImGui::TableNextColumn();
            ImGui::TextDisabled("#%llu - #%llu",
                (unsigned long long)info.first_seen_inst,
                (unsigned long long)info.last_seen_inst);
        }
        ImGui::EndTable();
    }

    // Spans section (collapsible)
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Execution Spans", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Total spans: %zu", thread_result_->spans.size());
        // Show spans around current instruction
        auto* cur_span = thread_result_->span_at(current_inst_);
        if (cur_span) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f),
                "Current span: tid=0x%llx [#%llu - #%llu] (%llu insts)",
                (unsigned long long)cur_span->thread_id,
                (unsigned long long)cur_span->start_inst_id,
                (unsigned long long)cur_span->end_inst_id,
                (unsigned long long)cur_span->inst_count);
        }
    }

    ImGui::End();
}

// ─── Functions Panel ─────────────────────────────────────────────────────────

void GuiApp::render_functions_panel() {
    if (!ImGui::Begin("Functions", &show_functions_)) {
        ImGui::End();
        return;
    }

    if (!function_result_) {
        ImGui::TextDisabled("No function analysis performed.");
        if (ImGui::Button("Run Function Analysis")) {
            run_function_analysis();
        }
        ImGui::End();
        return;
    }

    // Header
    ImGui::Text("Discovered: %zu functions", function_result_->functions.size());

    // Filter
    ImGui::Separator();
    bool filter_changed = ImGui::InputText("Filter##func", function_filter_buf_, sizeof(function_filter_buf_));
    if (filter_changed) {
        function_filter_ = std::string(function_filter_buf_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##funcfilter")) {
        function_filter_.clear();
        std::memset(function_filter_buf_, 0, sizeof(function_filter_buf_));
    }
    ImGui::SameLine();
    if (ImGui::Button("Run Call Graph")) {
        run_call_graph_analysis();
    }

    ImGui::Separator();

    // Build display list (filter + sort)
    struct FuncEntry {
        uint64_t pc;
        const FunctionInfo* info;
    };
    std::vector<FuncEntry> entries;
    entries.reserve(function_result_->functions.size());

    std::string lower_filter = function_filter_;
    std::transform(lower_filter.begin(), lower_filter.end(), lower_filter.begin(), ::tolower);

    for (const auto& [pc, info] : function_result_->functions) {
        if (!function_filter_.empty()) {
            std::string lower_name = info.name;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            if (lower_name.find(lower_filter) == std::string::npos) continue;
        }
        entries.push_back({pc, &info});
    }

    // Sort
    switch (function_sort_col_) {
    case 0: // calls
        std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
            return function_sort_ascending_
                ? a.info->total_calls < b.info->total_calls
                : a.info->total_calls > b.info->total_calls;
        });
        break;
    case 1: // name
        std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
            return function_sort_ascending_
                ? a.info->name < b.info->name
                : a.info->name > b.info->name;
        });
        break;
    case 2: // address
        std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
            return function_sort_ascending_ ? a.pc < b.pc : a.pc > b.pc;
        });
        break;
    }

    ImGui::Text("Showing: %zu", entries.size());
    ImGui::Separator();

    // Table
    ImGuiTableFlags table_flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_Sortable;

    if (ImGui::BeginTable("FunctionsTable", 4, table_flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_DefaultSort, 0.0f, 1);
        ImGui::TableSetupColumn("Entry PC", ImGuiTableColumnFlags_WidthFixed, 120.0f, 2);
        ImGui::TableSetupColumn("Calls", ImGuiTableColumnFlags_WidthFixed, 50.0f, 0);
        ImGui::TableSetupColumn("Insts", ImGuiTableColumnFlags_WidthFixed, 60.0f, 3);
        ImGui::TableHeadersRow();

        // Handle sort specs
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
            if (sort_specs->SpecsDirty && sort_specs->SpecsCount > 0) {
                auto& spec = sort_specs->Specs[0];
                function_sort_ascending_ = (spec.SortDirection == ImGuiSortDirection_Ascending);
                function_sort_col_ = static_cast<int>(spec.ColumnUserID);
                sort_specs->SpecsDirty = false;
                // Re-sort entries
                switch (function_sort_col_) {
                case 0:
                    std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
                        return function_sort_ascending_
                            ? a.info->total_calls < b.info->total_calls
                            : a.info->total_calls > b.info->total_calls;
                    });
                    break;
                case 1:
                    std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
                        return function_sort_ascending_
                            ? a.info->name < b.info->name
                            : a.info->name > b.info->name;
                    });
                    break;
                case 2:
                    std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
                        return function_sort_ascending_ ? a.pc < b.pc : a.pc > b.pc;
                    });
                    break;
                case 3:
                    std::sort(entries.begin(), entries.end(), [&](const auto& a, const auto& b) {
                        return function_sort_ascending_
                            ? a.info->total_instructions < b.info->total_instructions
                            : a.info->total_instructions > b.info->total_instructions;
                    });
                    break;
                }
            }
        }

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(entries.size()));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const auto& entry = entries[i];
                uint64_t static_pc = entry.pc - reader_.header().module_slide;

                ImGui::TableNextRow();

                // Name column (clickable)
                ImGui::TableSetColumnIndex(0);
                char label[256];
                snprintf(label, sizeof(label), "%s##func%d", entry.info->name.c_str(), i);
                if (ImGui::Selectable(label, false, ImGuiSelectableFlags_SpanAllColumns)) {
                    // Jump to first invocation
                    if (!entry.info->call_event_indices.empty()) {
                        const auto& evt = function_result_->call_events[entry.info->call_event_indices[0]];
                        navigate_to(evt.call_inst_id + 1);
                    }
                }
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format("{}\n0x{:016x}\ncalls: {}, insts: {}",
                        entry.info->name, static_pc,
                        (unsigned long long)entry.info->total_calls,
                        (unsigned long long)entry.info->total_instructions);
                    if (call_graph_result_) {
                        auto* node = call_graph_result_->node_at(entry.pc);
                        if (node) {
                            tip += fmt::format("\ncallees: {}, callers: {}",
                                node->outgoing_edges.size(), node->incoming_edges.size());
                        }
                    }
                    tip += "\nRight-click for more options";
                    ImGui::SetTooltip("%s", tip.c_str());
                }
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ctx_func_pc_   = entry.pc;
                    ctx_func_name_ = entry.info->name;
                    uint64_t s_pc  = entry.pc - reader_.header().module_slide;
                    ImGui::TextDisabled("%s", ctx_func_name_.c_str());
                    ImGui::TextDisabled("0x%llx", (unsigned long long)s_pc);
                    ImGui::Separator();
                    if (ImGui::MenuItem("Jump to First Call")) {
                        if (!entry.info->call_event_indices.empty()) {
                            const auto& evt = function_result_->call_events[entry.info->call_event_indices[0]];
                            navigate_to(evt.call_inst_id + 1);
                        }
                    }
                    if (ImGui::MenuItem("Copy Name")) {
                        ImGui::SetClipboardText(ctx_func_name_.c_str());
                    }
                    if (ImGui::MenuItem("Copy Address")) {
                        char buf[24];
                        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)s_pc);
                        ImGui::SetClipboardText(buf);
                    }
                    ImGui::EndPopup();
                }

                // Entry PC column
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%llx", (unsigned long long)static_pc);

                // Calls column
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", (unsigned long long)entry.info->total_calls);

                // Instructions column
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%llu", (unsigned long long)entry.info->total_instructions);
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    // Call graph sub-view: show callers/callees for selected function
    // (shown below the table when call_graph is available)
    if (call_graph_result_ && ImGui::CollapsingHeader("Call Graph Info")) {
        auto* func = function_result_->function_at(current_inst_);
        if (func) {
            auto* node = call_graph_result_->node_at(func->entry_pc);
            if (node) {
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f),
                    "Current: %s", func->name.c_str());

                if (!node->outgoing_edges.empty()) {
                    ImGui::Text("Callees (%zu):", node->outgoing_edges.size());
                    ImGui::Indent();
                    for (size_t ei = 0; ei < std::min(node->outgoing_edges.size(), size_t(8)); ei++) {
                        const auto& edge = call_graph_result_->edges[node->outgoing_edges[ei]];
                        auto it = function_result_->functions.find(edge.callee_pc);
                        std::string name = it != function_result_->functions.end()
                            ? it->second.name
                            : fmt::format("sub_{:x}", edge.callee_pc - reader_.header().module_slide);
                        ImGui::BulletText("%s (x%llu)", name.c_str(), (unsigned long long)edge.call_count);
                    }
                    if (node->outgoing_edges.size() > 8) {
                        ImGui::TextDisabled("  ...+%zu more", node->outgoing_edges.size() - 8);
                    }
                    ImGui::Unindent();
                }
                if (!node->incoming_edges.empty()) {
                    ImGui::Text("Callers (%zu):", node->incoming_edges.size());
                    ImGui::Indent();
                    for (size_t ei = 0; ei < std::min(node->incoming_edges.size(), size_t(8)); ei++) {
                        const auto& edge = call_graph_result_->edges[node->incoming_edges[ei]];
                        auto it = function_result_->functions.find(edge.caller_pc);
                        std::string name = it != function_result_->functions.end()
                            ? it->second.name
                            : fmt::format("sub_{:x}", edge.caller_pc - reader_.header().module_slide);
                        ImGui::BulletText("%s (x%llu)", name.c_str(), (unsigned long long)edge.call_count);
                    }
                    if (node->incoming_edges.size() > 8) {
                        ImGui::TextDisabled("  ...+%zu more", node->incoming_edges.size() - 8);
                    }
                    ImGui::Unindent();
                }
            }
        } else {
            ImGui::TextDisabled("(navigate to a function to see call graph info)");
        }
    }

    // Function panel right-click menu
    render_func_context_menu();

    ImGui::End();
}

// ─── Strings Panel ──────────────────────────────────────────────────────────

void GuiApp::run_call_graph_analysis() {
    ensure_pass_manager();

    // CallGraphPass depends on function pass, ensure it's run first
    if (!function_result_) {
        run_function_analysis();
    }

    pass_manager_->register_pass(std::make_unique<CallGraphPass>());
    auto& result = pass_manager_->require("call_graph");
    if (result.ok()) {
        call_graph_result_ = &result.get<CallGraphResult>();
    }
}

void GuiApp::render_strings_panel() {
    if (!ImGui::Begin("Strings", &show_strings_)) {
        ImGui::End();
        return;
    }

    // Header with count
    if (string_result_) {
        ImGui::Text("Discovered: %zu strings", string_result_->total());
    } else {
        ImGui::TextDisabled("No string analysis performed.");
        if (ImGui::Button("Run String Analysis")) {
            run_string_analysis();
        }
        ImGui::End();
        return;
    }

    // Filter input
    ImGui::Separator();
    bool filter_changed = ImGui::InputText("Filter", string_filter_buf_, sizeof(string_filter_buf_));
    if (filter_changed) {
        string_filter_ = std::string(string_filter_buf_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        string_filter_.clear();
        std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    }

    ImGui::Separator();

    // Get filtered strings
    std::vector<const StringRef*> display_strings;
    if (string_filter_.empty()) {
        display_strings.reserve(string_result_->strings.size());
        for (const auto& s : string_result_->strings) {
            display_strings.push_back(&s);
        }
    } else {
        display_strings = string_result_->search(string_filter_);
    }

    ImGui::Text("Showing: %zu", display_strings.size());
    ImGui::Separator();

    // Table with string list
    if (ImGui::BeginTable("StringsTable", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_SizingStretchProp)) {

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Addr", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Enc", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Content", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Refs", ImGuiTableColumnFlags_WidthFixed, 40.0f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(display_strings.size()));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const StringRef* ref = display_strings[i];
                bool is_selected = (static_cast<size_t>(i) == string_cursor_);

                ImGui::TableNextRow();

                // Address column
                ImGui::TableSetColumnIndex(0);
                char label[64];
                snprintf(label, sizeof(label), "0x%llx##str%d",
                         (unsigned long long)ref->addr, i);
                if (ImGui::Selectable(label, is_selected,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    string_cursor_ = static_cast<size_t>(i);
                    // Jump to the instruction that discovered this string
                    navigate_to(ref->discovered_at);
                }
                if (ImGui::IsItemHovered()) {
                    std::string tip = fmt::format("\"{}\"\nDiscovered at inst #{}\nRight-click for options",
                        ref->content, ref->discovered_at);
                    ImGui::SetTooltip("%s", tip.c_str());
                    if (ImGui::IsMouseDoubleClicked(0)) {
                        navigate_to(ref->discovered_at);
                    }
                }
                if (ImGui::BeginPopupContextItem(nullptr)) {
                    ctx_string_inst_id_ = ref->discovered_at;
                    ctx_string_text_    = ref->content;
                    ImGui::TextDisabled("\"%s\"", ctx_string_text_.c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Jump to Discovery")) {
                        navigate_to(ctx_string_inst_id_);
                    }
                    if (ImGui::MenuItem("Copy String")) {
                        ImGui::SetClipboardText(ctx_string_text_.c_str());
                    }
                    ImGui::EndPopup();
                }

                // Encoding column
                ImGui::TableSetColumnIndex(1);
                const char* enc_str = "A";
                if (ref->encoding == StringRef::UTF16LE) enc_str = "U16";
                else if (ref->encoding == StringRef::UTF8) enc_str = "U8";
                else if (ref->encoding == StringRef::Wide) enc_str = "W";
                ImGui::TextUnformatted(enc_str);

                // Content column
                ImGui::TableSetColumnIndex(2);
                // Truncate for display
                std::string display = ref->content;
                if (display.size() > 64) {
                    display = display.substr(0, 61) + "...";
                }
                ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "\"%s\"",
                                   display.c_str());

                // References count column
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%zu", ref->references.size());
            }
        }
        clipper.End();
        ImGui::EndTable();
    }

    // String panel right-click menu
    render_string_context_menu();

    ImGui::End();
}

void GuiApp::clear_analysis() {
    taint_result_ = nullptr;
    slice_result_ = nullptr;
    backward_taint_result_ = nullptr;
    function_result_ = nullptr;
    xref_result_ = nullptr;
    string_result_ = nullptr;
    call_graph_result_ = nullptr;
    loop_result_ = nullptr;
    thread_result_ = nullptr;
    cfg_result_        = nullptr;
    cfg_layout_result_ = nullptr;
    cfg_func_result_.reset();
    cfg_func_layout_.reset();
    cfg_current_func_pc_ = 0;
    constant_result_          = nullptr;
    pattern_result_           = nullptr;
    loop_semantics_result_    = nullptr;
    algorithm_summary_result_ = nullptr;
    annotation_result_        = nullptr;
    show_taint_ = false;
    show_threads_ = false;
    show_slice_ = false;
    show_backward_taint_ = false;
    show_callstack_ = false;
    show_functions_ = false;
    show_strings_ = false;
    show_loops_ = false;
    xref_cursor_ = 0;
    string_cursor_ = 0;
    string_filter_.clear();
    std::memset(string_filter_buf_, 0, sizeof(string_filter_buf_));
    function_filter_.clear();
    std::memset(function_filter_buf_, 0, sizeof(function_filter_buf_));
    taint_sorted_ids_.clear();
    taint_sorted_ids_dirty_ = true;
    goto_candidates_.clear();
    goto_candidates_dirty_ = true;
    goto_selected_candidate_ = -1;
    if (pass_manager_) {
        pass_manager_->invalidate_all();
    }
}

// ─── Taint jump helpers ──────────────────────────────────────────────────────

void GuiApp::ensure_taint_sorted() {
    if (!taint_sorted_ids_dirty_) return;
    taint_sorted_ids_.clear();
    if (taint_result_) {
        for (uint64_t id : taint_result_->tainted_inst_ids) {
            taint_sorted_ids_.push_back(id);
        }
        std::sort(taint_sorted_ids_.begin(), taint_sorted_ids_.end());
    }
    taint_sorted_ids_dirty_ = false;
}

void GuiApp::jump_taint_next() {
    if (!taint_result_) return;
    ensure_taint_sorted();
    if (taint_sorted_ids_.empty()) return;
    auto it = std::upper_bound(taint_sorted_ids_.begin(), taint_sorted_ids_.end(), current_inst_);
    if (it == taint_sorted_ids_.end()) {
        // Wrap around
        navigate_to(taint_sorted_ids_.front());
    } else {
        navigate_to(*it);
    }
}

void GuiApp::jump_taint_prev() {
    if (!taint_result_) return;
    ensure_taint_sorted();
    if (taint_sorted_ids_.empty()) return;
    auto it = std::lower_bound(taint_sorted_ids_.begin(), taint_sorted_ids_.end(), current_inst_);
    if (it == taint_sorted_ids_.begin()) {
        // Wrap around
        navigate_to(taint_sorted_ids_.back());
    } else {
        --it;
        navigate_to(*it);
    }
}

void GuiApp::jump_backward_taint_next() {
    if (!backward_taint_result_) return;
    // Build sorted list on the fly from backward taint contributing inst_ids
    std::vector<uint64_t> ids;
    for (uint64_t id = 0; id < total_inst_; id++) {
        if (backward_taint_result_->is_contributing(id)) {
            ids.push_back(id);
        }
    }
    if (ids.empty()) return;
    auto it = std::upper_bound(ids.begin(), ids.end(), current_inst_);
    if (it == ids.end()) {
        navigate_to(ids.front());
    } else {
        navigate_to(*it);
    }
}

void GuiApp::jump_backward_taint_prev() {
    if (!backward_taint_result_) return;
    std::vector<uint64_t> ids;
    for (uint64_t id = 0; id < total_inst_; id++) {
        if (backward_taint_result_->is_contributing(id)) {
            ids.push_back(id);
        }
    }
    if (ids.empty()) return;
    auto it = std::lower_bound(ids.begin(), ids.end(), current_inst_);
    if (it == ids.begin()) {
        navigate_to(ids.back());
    } else {
        --it;
        navigate_to(*it);
    }
}

// ─── Open hex dump at address ────────────────────────────────────────────────

void GuiApp::open_hex_dump_at(uint64_t addr) {
    show_hex_dump_ = true;
    // Store the address for hex dump to display
    // We'll use the hex_dump_addr_ field (to be shown in render_hex_dump_panel)
    // For now, re-purpose ctx_mem_addr_ as the hex dump target
    ctx_mem_addr_ = addr;
}

// ─── Context menu helpers ────────────────────────────────────────────────────

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

void GuiApp::render_reg_context_menu() {
    // No-op: register cell now uses BeginPopupContextItem inline in render_reg_cell().
}

void GuiApp::render_callstack_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_callstack_panel().

    if (!function_result_) {
        ImGui::BeginPopup("##cs_ctx");
        ImGui::EndPopup();
        return;
    }

    auto stack = function_result_->call_stack_at(current_inst_);
    if (ImGui::BeginPopup("##cs_ctx")) {
        if (ctx_callstack_frame_ < stack.size()) {
            auto* evt = stack[ctx_callstack_frame_];
            ImGui::TextDisabled("Frame #%zu  @%llu",
                ctx_callstack_frame_, (unsigned long long)evt->call_inst_id);
            ImGui::Separator();
            if (ImGui::MenuItem("Jump to Call Site")) {
                navigate_to(evt->call_inst_id);
            }
            if (ImGui::MenuItem("Jump to Function Entry")) {
                navigate_to(evt->call_inst_id + 1);
            }
            if (ImGui::MenuItem("Run Xref on Target")) {
                if (!xref_result_) run_xref_analysis();
                if (xref_result_) {
                    auto xrefs = xref_result_->inst_ids_at(evt->target_pc);
                    if (!xrefs.empty()) {
                        xref_cursor_ = 0;
                        navigate_to(xrefs[0]);
                    }
                }
            }
        }
        ImGui::EndPopup();
    }
}

// ─── Instruction Panel Context Menu ─────────────────────────────────────────
// IDA-style per-instruction right-click menu with full analysis actions

void GuiApp::render_inst_context_menu_contents() {
    // ── Header: address + disasm ───────────────────────────────────────
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.62f, 0.80f, 1.0f));
    ImGui::Text("inst #%llu", (unsigned long long)ctx_inst_id_);
    ImGui::Text("0x%016llx", (unsigned long long)ctx_inst_static_pc_);
    ImGui::PopStyleColor();
    ImGui::TextColored(ImVec4(0.85f, 0.85f, 0.90f, 1.0f), "%s", ctx_inst_disasm_.c_str());
    ImGui::Separator();

    // ── Copy actions ──────────────────────────────────────────────────
    if (ImGui::BeginMenu("Copy")) {
        if (ImGui::MenuItem("Copy Address (hex)")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Copy Address (decimal)")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }
        if (ImGui::MenuItem("Copy Disassembly")) {
            ImGui::SetClipboardText(ctx_inst_disasm_.c_str());
        }
        if (ImGui::MenuItem("Copy Instruction ID")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "%llu", (unsigned long long)ctx_inst_id_);
            ImGui::SetClipboardText(buf);
        }
        ImGui::EndMenu();
    }

    ImGui::Separator();

    // ── Navigation ────────────────────────────────────────────────────
    if (ImGui::MenuItem("Navigate Here")) {
        navigate_to(ctx_inst_id_);
    }
    if (ImGui::MenuItem("Goto Instruction... (G)")) {
        show_goto_popup_ = true;
    }

    // Bookmark toggle
    bool is_bookmarked = std::binary_search(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
    if (is_bookmarked) {
        if (ImGui::MenuItem("\xe2\x98\x85 Remove Bookmark")) {  // ★
            auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
            if (it != bookmarks_.end() && *it == ctx_inst_id_) {
                bookmarks_.erase(it);
                row_cache_.invalidate(ctx_inst_id_);
            }
        }
    } else {
        if (ImGui::MenuItem("\xe2\x98\x86 Add Bookmark (B)")) {  // ☆
            auto it = std::lower_bound(bookmarks_.begin(), bookmarks_.end(), ctx_inst_id_);
            bookmarks_.insert(it, ctx_inst_id_);
            row_cache_.invalidate(ctx_inst_id_);
        }
    }

    ImGui::Separator();

    // ── Taint analysis from this instruction ──────────────────────────
    if (ImGui::BeginMenu("Taint Analysis")) {
        const auto& state = regfile_.state_before(ctx_inst_id_);
        if (ImGui::MenuItem("Forward Taint from x0")) {
            navigate_to(ctx_inst_id_);
            run_taint_analysis();
        }
        ImGui::Separator();
        static const struct { uint8_t idx; const char* name; } kArgRegs[] = {
            {0,"x0"},{1,"x1"},{2,"x2"},{3,"x3"},{4,"x4"},{5,"x5"}
        };
        for (auto& reg : kArgRegs) {
            char label[32];
            snprintf(label, sizeof(label), "Forward Taint from %s = 0x%llx",
                     reg.name, (unsigned long long)state.gpr[reg.idx]);
            if (ImGui::MenuItem(label)) {
                navigate_to(ctx_inst_id_);
                run_taint_analysis();
            }
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Backward Taint from here")) {
            navigate_to(ctx_inst_id_);
            run_backward_taint_analysis();
        }
        ImGui::EndMenu();
    }

    // ── Xref navigation ───────────────────────────────────────────────
    if (ImGui::BeginMenu("Xrefs")) {
        if (!xref_result_) {
            if (ImGui::MenuItem("Run Xref Analysis first")) {
                run_xref_analysis();
            }
        } else {
            auto xrefs = xref_result_->inst_ids_at(ctx_inst_pc_);
            uint64_t exec_count = xref_result_->execution_count(ctx_inst_pc_);
            ImGui::TextDisabled("0x%llx: %llu executions",
                (unsigned long long)ctx_inst_static_pc_,
                (unsigned long long)exec_count);
            ImGui::Separator();
            if (!xrefs.empty()) {
                size_t limit = std::min(xrefs.size(), size_t(20));
                for (size_t xi = 0; xi < limit; xi++) {
                    char lbl[48];
                    snprintf(lbl, sizeof(lbl), "  Jump to inst #%llu", (unsigned long long)xrefs[xi]);
                    if (ImGui::MenuItem(lbl)) {
                        xref_cursor_ = xi;
                        navigate_to(xrefs[xi]);
                    }
                }
                if (xrefs.size() > 20) {
                    ImGui::TextDisabled("  ... and %zu more", xrefs.size() - 20);
                }
            } else {
                ImGui::TextDisabled("  (no other executions)");
            }
        }
        ImGui::EndMenu();
    }

    // ── Function context ──────────────────────────────────────────────
    if (function_result_) {
        ImGui::Separator();
        auto* func = function_result_->function_at(ctx_inst_id_);
        if (func) {
            ImGui::TextDisabled("In: %s", func->name.c_str());
            if (ImGui::MenuItem("Jump to Function Entry")) {
                auto it = function_result_->functions.find(func->entry_pc);
                if (it != function_result_->functions.end() &&
                    !it->second.call_event_indices.empty()) {
                    const auto& evt = function_result_->call_events[
                        it->second.call_event_indices[0]];
                    navigate_to(evt.call_inst_id + 1);
                }
            }
            auto* call = function_result_->call_at(ctx_inst_id_);
            if (call) {
                if (ImGui::MenuItem("Follow Call (Enter)")) {
                    navigate_to(call->call_inst_id + 1);
                }
            }
            auto* ret = function_result_->return_at(ctx_inst_id_);
            if (ret) {
                if (ImGui::MenuItem("Follow Return")) {
                    navigate_to(ret->call_inst_id);
                }
            }
        }
    }

    // ── Hex dump ──────────────────────────────────────────────────────
    ImGui::Separator();
    if (ImGui::MenuItem("Open PC in Hex Dump")) {
        open_hex_dump_at(ctx_inst_pc_);
    }

    // ── CFG ───────────────────────────────────────────────────────────
    if (show_cfg_ && cfg_result_) {
        if (ImGui::MenuItem("Show Block in CFG")) {
            // Select the block in CFG and center on it
            const CFGResult* acfg = cfg_func_result_ ? cfg_func_result_.get() : cfg_result_;
            auto* blk = acfg->block_containing(ctx_inst_pc_);
            if (blk && cfg_layout_result_) {
                cfg_selected_block_ = blk->start_pc;
                cfg_block_cursor_ = 0;
                auto it = cfg_layout_result_->block_layouts.find(blk->start_pc);
                if (it != cfg_layout_result_->block_layouts.end()) {
                    const auto& lo = it->second;
                    // Approximate centering (actual window size may differ)
                    cfg_scroll_.x = 300.0f - (lo.x + lo.width  * 0.5f) * cfg_zoom_;
                    cfg_scroll_.y = 200.0f - (lo.y + lo.height * 0.5f) * cfg_zoom_;
                }
            }
        }
    }
}

void GuiApp::render_inst_context_menu() {
    // No-op: instruction panel now uses BeginPopupContextItem inline.
}

// ─── Function Panel Context Menu ─────────────────────────────────────────────

void GuiApp::render_func_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_function_panel().
    if (ImGui::BeginPopup("##func_ctx")) {
        ImGui::TextDisabled("%s", ctx_func_name_.c_str());
        uint64_t static_pc = ctx_func_pc_ - reader_.header().module_slide;
        ImGui::TextDisabled("0x%016llx", (unsigned long long)static_pc);
        ImGui::Separator();

        if (function_result_) {
            auto it = function_result_->functions.find(ctx_func_pc_);
            if (it != function_result_->functions.end()) {
                const auto& info = it->second;
                if (!info.call_event_indices.empty()) {
                    if (ImGui::MenuItem("Jump to First Invocation")) {
                        const auto& evt = function_result_->call_events[info.call_event_indices[0]];
                        navigate_to(evt.call_inst_id + 1);
                    }
                    if (info.call_event_indices.size() > 1) {
                        // Show jump to each invocation (up to 10)
                        if (ImGui::BeginMenu("Jump to Invocation...")) {
                            size_t limit = std::min(info.call_event_indices.size(), size_t(10));
                            for (size_t ci = 0; ci < limit; ci++) {
                                const auto& evt = function_result_->call_events[info.call_event_indices[ci]];
                                char lbl[48];
                                snprintf(lbl, sizeof(lbl), "  Call #%zu (@inst %llu)",
                                    ci + 1, (unsigned long long)evt.call_inst_id);
                                if (ImGui::MenuItem(lbl)) {
                                    navigate_to(evt.call_inst_id + 1);
                                }
                            }
                            if (info.call_event_indices.size() > 10) {
                                ImGui::TextDisabled("  ... and %zu more", info.call_event_indices.size() - 10);
                            }
                            ImGui::EndMenu();
                        }
                    }
                }
            }
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Copy Name")) {
            ImGui::SetClipboardText(ctx_func_name_.c_str());
        }
        if (ImGui::MenuItem("Copy Address")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)static_pc);
            ImGui::SetClipboardText(buf);
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Run Xref on this Function")) {
            if (!xref_result_) run_xref_analysis();
            if (xref_result_) {
                auto xrefs = xref_result_->inst_ids_at(ctx_func_pc_);
                if (!xrefs.empty()) {
                    xref_cursor_ = 0;
                    navigate_to(xrefs[0]);
                }
            }
        }

        if (call_graph_result_) {
            auto* node = call_graph_result_->node_at(ctx_func_pc_);
            if (node) {
                ImGui::Separator();
                ImGui::TextDisabled("Callers: %zu, Callees: %zu",
                    node->incoming_edges.size(), node->outgoing_edges.size());
            }
        }

        ImGui::EndPopup();
    }
}

// ─── String Panel Context Menu ────────────────────────────────────────────────

void GuiApp::render_string_context_menu() {
    // Popup opened via OpenPopupOnItemClick in render_string_panel().

    if (ImGui::BeginPopup("##str_ctx")) {
        ImGui::TextDisabled("\"%s\"", ctx_string_text_.c_str());
        ImGui::Separator();

        if (ImGui::MenuItem("Jump to Discovery")) {
            navigate_to(ctx_string_inst_id_);
        }

        ImGui::Separator();

        if (ImGui::MenuItem("Copy String")) {
            ImGui::SetClipboardText(ctx_string_text_.c_str());
        }

        if (ImGui::MenuItem("Search for This String")) {
            // Put the string into the search buffer and trigger search
            strncpy(search_buf_, ctx_string_text_.c_str(), sizeof(search_buf_) - 1);
            search_buf_[sizeof(search_buf_) - 1] = '\0';
            // Run search
            std::string query(search_buf_);
            search_results_.clear();
            search_current_ = 0;
            search_active_ = false;
            if (!query.empty()) {
                for (uint64_t i = 0; i < total_inst_ && i < 1000000; i++) {
                    auto row = fetch_row(i);
                    if (row.disasm.find(query) != std::string::npos) {
                        search_results_.push_back(i);
                    }
                }
                if (!search_results_.empty()) {
                    search_active_ = true;
                    navigate_to(search_results_[0]);
                }
            }
        }

        ImGui::Separator();

        if (xref_result_) {
            // Show xrefs for the instruction that found this string
            auto row = fetch_row(ctx_string_inst_id_);
            auto xrefs = xref_result_->inst_ids_at(row.pc);
            if (!xrefs.empty()) {
                if (ImGui::BeginMenu("Xrefs (Discovery PC)")) {
                    size_t limit = std::min(xrefs.size(), size_t(10));
                    for (size_t xi = 0; xi < limit; xi++) {
                        char lbl[48];
                        snprintf(lbl, sizeof(lbl), "  inst #%llu", (unsigned long long)xrefs[xi]);
                        if (ImGui::MenuItem(lbl)) {
                            navigate_to(xrefs[xi]);
                        }
                    }
                    ImGui::EndMenu();
                }
            }
        }

        ImGui::EndPopup();
    }
}

// ─── Settings Window ────────────────────────────────────────────────────────

void GuiApp::render_settings_window() {
    ImGui::SetNextWindowSize(ImVec2(550, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Settings", &show_settings_)) {
        ImGui::End();
        if (!show_settings_) pending_font_.initialized = false;
        return;
    }
    // If user clicked the X button, show_settings_ is now false
    if (!show_settings_) {
        pending_font_.initialized = false;
        ImGui::End();
        return;
    }

    bool changed = false;

    // Initialize pending font settings when window first opens
    if (!pending_font_.initialized) {
        pending_font_.font_path = settings_.font_path;
        pending_font_.font_size = settings_.font_size;
        pending_font_.oversample_h = settings_.oversample_h;
        pending_font_.pixel_snap = settings_.pixel_snap;
        pending_font_.initialized = true;
    }

    if (ImGui::BeginTabBar("SettingsTabs")) {

        // ─── Font Tab ──────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Font")) {
            ImGui::SeparatorText("Font Selection");

            // Font path combo (operates on pending settings)
            {
                std::string current_name = pending_font_.font_path.empty()
                    ? "Auto (system default)"
                    : pending_font_.font_path.substr(pending_font_.font_path.rfind('/') + 1);

                if (ImGui::BeginCombo("Font", current_name.c_str())) {
                    if (ImGui::Selectable("Auto (system default)", pending_font_.font_path.empty())) {
                        pending_font_.font_path.clear();
                    }
                    ImGui::Separator();

                    for (const auto& path : available_fonts_) {
                        std::string name = path.substr(path.rfind('/') + 1);
                        bool selected = (path == pending_font_.font_path);
                        if (ImGui::Selectable(name.c_str(), selected)) {
                            pending_font_.font_path = path;
                        }
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("%s", path.c_str());
                        }
                    }
                    ImGui::EndCombo();
                }
            }

            // Font size slider (operates on pending)
            ImGui::SliderFloat("Size", &pending_font_.font_size, 9.0f, 24.0f, "%.1f pt");

            // Oversampling
            ImGui::SliderInt("Oversampling H", &pending_font_.oversample_h, 1, 3);
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Higher = smoother text, more VRAM");
            }

            // Pixel snap
            ImGui::Checkbox("Pixel Snap", &pending_font_.pixel_snap);

            // Custom font path input
            ImGui::SeparatorText("Custom Font Path");
            static char custom_path_buf[512] = {};
            if (custom_path_buf[0] == '\0' && !pending_font_.font_path.empty()) {
                strncpy(custom_path_buf, pending_font_.font_path.c_str(), sizeof(custom_path_buf) - 1);
            }
            ImGui::SetNextItemWidth(-80.0f);
            ImGui::InputText("##CustomPath", custom_path_buf, sizeof(custom_path_buf));
            ImGui::SameLine();
            if (ImGui::Button("Apply##font_path")) {
                pending_font_.font_path = custom_path_buf;
            }
            ImGui::TextDisabled("Enter full path to .ttf/.otf file");

            // ─── Preview area ────────────────────────────────────────────
            ImGui::SeparatorText("Preview");
            // Use font scale to simulate the pending font size relative to current
            float preview_scale = pending_font_.font_size / settings_.font_size;
            ImGui::BeginChild("FontPreview", ImVec2(0, 100), ImGuiChildFlags_Borders);
            ImGui::SetWindowFontScale(preview_scale);
            ImGui::Text("AaBbCcDd 0123456789");
            ImGui::Text("mov x0, #0x1234; ldr x1, [sp, #0x10]");
            ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1.0f), "x0 x1 sp lr fp pc");
            ImGui::SetWindowFontScale(1.0f);
            ImGui::EndChild();

            // ─── Save / Cancel buttons for font changes ──────────────────
            ImGui::Spacing();
            bool font_differs = (pending_font_.font_path != settings_.font_path ||
                                 pending_font_.font_size != settings_.font_size ||
                                 pending_font_.oversample_h != settings_.oversample_h ||
                                 pending_font_.pixel_snap != settings_.pixel_snap);

            ImGui::BeginDisabled(!font_differs);
            if (ImGui::Button("Save Font Settings")) {
                settings_.font_path = pending_font_.font_path;
                settings_.font_size = pending_font_.font_size;
                settings_.oversample_h = pending_font_.oversample_h;
                settings_.pixel_snap = pending_font_.pixel_snap;
                settings_font_dirty_ = true;
                settings_.save(GuiSettings::default_path());
            }
            ImGui::EndDisabled();

            ImGui::SameLine();
            ImGui::BeginDisabled(!font_differs);
            if (ImGui::Button("Cancel##font")) {
                pending_font_.font_path = settings_.font_path;
                pending_font_.font_size = settings_.font_size;
                pending_font_.oversample_h = settings_.oversample_h;
                pending_font_.pixel_snap = settings_.pixel_snap;
            }
            ImGui::EndDisabled();

            if (font_differs) {
                ImGui::SameLine();
                ImGui::TextDisabled("(unsaved changes)");
            }

            ImGui::EndTabItem();
        }

        // ─── Theme Tab ─────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Theme")) {
            ImGui::SeparatorText("Color Theme");

            int theme_idx = static_cast<int>(settings_.theme);
            const char* theme_names[] = {"Dark", "Light", "Classic"};
            if (ImGui::Combo("Theme", &theme_idx, theme_names, 3)) {
                settings_.theme = static_cast<GuiSettings::Theme>(theme_idx);
                changed = true;
            }

            ImGui::SeparatorText("Row Spacing");
            if (ImGui::SliderFloat("Item Spacing Y", &settings_.row_spacing, 0.0f, 8.0f, "%.1f")) {
                changed = true;
            }

            ImGui::SeparatorText("Columns");
            if (ImGui::Checkbox("Show Instruction Index (#)", &settings_.show_inst_index)) {
                changed = true;
            }
            if (ImGui::Checkbox("Show Address Column", &settings_.show_address)) {
                changed = true;
            }

            ImGui::EndTabItem();
        }

        // ─── Colors Tab ────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Colors")) {
            ImGui::SeparatorText("Instruction Mnemonic Colors");

            auto color_edit = [&](const char* label, float col[4]) {
                if (ImGui::ColorEdit4(label, col, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_AlphaBar)) {
                    changed = true;
                }
            };

            color_edit("Branch (b, b.xx, cbz, tbz)", settings_.colors.branch);
            color_edit("Call (bl)", settings_.colors.call);
            color_edit("Return (ret, blr, br)", settings_.colors.ret);
            color_edit("Load (ldr, ldp, ...)", settings_.colors.load);
            color_edit("Store (str, stp, ...)", settings_.colors.store);
            color_edit("Syscall (svc, brk)", settings_.colors.syscall);
            color_edit("Arithmetic (add, sub, ...)", settings_.colors.arith);
            color_edit("Compare (cmp, tst)", settings_.colors.cmp);
            color_edit("Move (mov, mvn)", settings_.colors.mov);

            ImGui::SeparatorText("Operand Colors");
            color_edit("Registers (x0, sp, ...)", settings_.colors.reg_operand);
            color_edit("Immediates (#0x...)", settings_.colors.imm_operand);

            ImGui::Separator();
            if (ImGui::Button("Reset to Defaults")) {
                settings_.colors = GuiSettings::HighlightColors{};
                changed = true;
            }

            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::Separator();

    // ─── Apply non-font settings immediately ────────────────────────────
    if (changed) {
        apply_settings();
        settings_.save(GuiSettings::default_path());
    }

    ImGui::End();
}

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

// ─── Loop Analysis ──────────────────────────────────────────────────────────

void GuiApp::run_loop_analysis() {
    ensure_pass_manager();

    pass_manager_->register_pass(std::make_unique<LoopPass>());
    auto& result = pass_manager_->require("loop");
    if (result.ok()) {
        loop_result_ = &result.get<LoopResult>();
        show_loops_ = true;
    }
}

// ─── Progress Overlay / Timeline ──────────────────────────────────────────────
// Redesigned as a proper Binary Ninja-style execution timeline:
//  - Multi-lane rendering (top half: taint/BT overlay; bottom half: call events)
//  - Gradient fill for progress
//  - Bookmark diamonds, loop header notches, search-hit sparks
//  - Click + drag to seek; hover tooltip with full disasm preview
//  - No background window border — blends cleanly into the layout

void GuiApp::render_progress_overlay() {
    if (total_inst_ == 0) return;

    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float bar_height = 22.0f;   // slightly taller than before for more lanes
    const float bar_y = vp->WorkPos.y + ImGui::GetFrameHeight() * 2.2f;
    ImVec2 bar_pos(vp->WorkPos.x, bar_y);
    ImVec2 bar_size(vp->WorkSize.x, bar_height);

    ImGui::SetNextWindowPos(bar_pos);
    ImGui::SetNextWindowSize(bar_size);
    ImGui::SetNextWindowBgAlpha(0.0f);  // transparent window — we draw everything manually
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoDecoration;

    if (!ImGui::Begin("##Timeline", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    float W = ImGui::GetWindowWidth();
    float H = bar_height;

    // ── Track background ─────────────────────────────────────────────
    // Dark navy with subtle top/bottom gradient edges
    draw->AddRectFilled(p0, ImVec2(p0.x + W, p0.y + H), IM_COL32(18, 20, 28, 235));
    // Top subtle highlight line
    draw->AddLine(p0, ImVec2(p0.x + W, p0.y),
                  IM_COL32(80, 90, 130, 100), 1.0f);

    // ── Helper: inst_id → x ──────────────────────────────────────────
    auto inst_to_x = [&](uint64_t id) -> float {
        return p0.x + static_cast<float>(id) / static_cast<float>(total_inst_) * W;
    };

    // ── Lane constants ───────────────────────────────────────────────
    // Lane 0 (top):    taint / backward-taint overlays
    // Lane 1 (middle): loop headers, call events
    // Lane 2 (bottom): current-position fill + cursor
    const float lane_top_h   = H * 0.40f;
    const float lane_mid_top = H * 0.40f;
    const float lane_mid_bot = H * 0.72f;

    // ── Progress fill (gradient blue) ────────────────────────────────
    float progress = (total_inst_ > 1)
        ? static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1)
        : 0.0f;
    float fill_x = p0.x + progress * W;

    // Two-tone gradient: left part brighter, blending right to darker
    draw->AddRectFilledMultiColor(
        p0, ImVec2(fill_x, p0.y + H),
        IM_COL32(32, 60, 115, 140),   // TL
        IM_COL32(42, 85, 155, 170),   // TR
        IM_COL32(42, 85, 155, 170),   // BR
        IM_COL32(32, 60, 115, 140));  // BL

    // ── Taint overlays (top lane) ─────────────────────────────────────
    if (show_taint_ && taint_result_ && !taint_sorted_ids_.empty()) {
        const size_t kMax = 3000;
        size_t step = std::max(size_t(1), taint_sorted_ids_.size() / kMax);
        for (size_t ti = 0; ti < taint_sorted_ids_.size(); ti += step) {
            float tx = inst_to_x(taint_sorted_ids_[ti]);
            draw->AddLine(ImVec2(tx, p0.y + lane_mid_top),
                          ImVec2(tx, p0.y + H),
                          IM_COL32(42, 195, 82, 160), 1.0f);
        }
    }
    if (show_backward_taint_ && backward_taint_result_) {
        size_t shown = 0;
        for (uint64_t id = 0; id < total_inst_ && shown < 3000; id++) {
            if (backward_taint_result_->is_contributing(id)) {
                float tx = inst_to_x(id);
                draw->AddLine(ImVec2(tx, p0.y),
                              ImVec2(tx, p0.y + lane_top_h),
                              IM_COL32(215, 55, 55, 165), 1.0f);
                shown++;
            }
        }
    }

    // ── Loop header markers (orange notches in middle lane) ───────────
    if (show_loops_ && loop_result_ && xref_result_) {
        for (const auto& loop : loop_result_->loops) {
            auto inst_ids = xref_result_->inst_ids_at(loop.header_pc);
            if (!inst_ids.empty()) {
                float lx = inst_to_x(inst_ids.front());
                draw->AddRectFilled(
                    ImVec2(lx - 1.5f, p0.y + lane_mid_top),
                    ImVec2(lx + 1.5f, p0.y + lane_mid_bot),
                    IM_COL32(255, 138, 24, 225));
            }
        }
    }

    // ── Call event markers (small blue ticks) ────────────────────────
    if (function_result_) {
        const size_t kMaxCalls = 2000;
        size_t call_shown = 0;
        for (const auto& evt : function_result_->call_events) {
            if (call_shown++ >= kMaxCalls) break;
            float cx = inst_to_x(evt.call_inst_id);
            draw->AddLine(
                ImVec2(cx, p0.y + lane_mid_top),
                ImVec2(cx, p0.y + lane_mid_bot),
                IM_COL32(60, 145, 255, 130), 1.0f);
        }
    }

    // ── Search-hit sparks (gold) ─────────────────────────────────────
    if (search_active_ && !search_results_.empty()) {
        const size_t kMaxHits = 1000;
        size_t step = std::max(size_t(1), search_results_.size() / kMaxHits);
        for (size_t hi = 0; hi < search_results_.size(); hi += step) {
            float hx = inst_to_x(search_results_[hi]);
            draw->AddLine(ImVec2(hx, p0.y),
                          ImVec2(hx, p0.y + H),
                          IM_COL32(255, 200, 30, 200), 1.0f);
        }
    }

    // ── Bookmark diamonds ────────────────────────────────────────────
    for (uint64_t bid : bookmarks_) {
        float bx = inst_to_x(bid);
        float cy = p0.y + H * 0.5f;
        float r  = 4.0f;
        draw->AddQuadFilled(
            ImVec2(bx,     cy - r),   // top
            ImVec2(bx + r, cy),        // right
            ImVec2(bx,     cy + r),   // bottom
            ImVec2(bx - r, cy),        // left
            IM_COL32(255, 205, 45, 235));
        draw->AddQuad(
            ImVec2(bx,     cy - r),
            ImVec2(bx + r, cy),
            ImVec2(bx,     cy + r),
            ImVec2(bx - r, cy),
            IM_COL32(255, 240, 130, 180), 1.0f);
    }

    // ── Current position cursor ───────────────────────────────────────
    // Bright vertical line + small top triangle marker
    draw->AddLine(ImVec2(fill_x, p0.y), ImVec2(fill_x, p0.y + H),
                  IM_COL32(110, 175, 255, 255), 2.0f);
    // Small downward-pointing triangle at top
    draw->AddTriangleFilled(
        ImVec2(fill_x - 4.0f, p0.y),
        ImVec2(fill_x + 4.0f, p0.y),
        ImVec2(fill_x, p0.y + 6.0f),
        IM_COL32(140, 195, 255, 230));

    // ── Bottom separator ─────────────────────────────────────────────
    draw->AddLine(ImVec2(p0.x, p0.y + H - 0.5f),
                  ImVec2(p0.x + W, p0.y + H - 0.5f),
                  IM_COL32(50, 55, 80, 180), 1.0f);

    // ── Interaction: hover tooltip + click/drag to seek ──────────────
    // Use an invisible button over the entire bar for interaction
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::InvisibleButton("##timeline_btn", ImVec2(W, H),
        ImGuiButtonFlags_MouseButtonLeft);

    bool is_hovered = ImGui::IsItemHovered();
    bool is_active  = ImGui::IsItemActive();

    if ((is_active && ImGui::IsMouseDown(ImGuiMouseButton_Left)) || ImGui::IsItemClicked()) {
        float mx = ImGui::GetIO().MousePos.x;
        float rel = (mx - p0.x) / W;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t target = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (target >= total_inst_) target = total_inst_ - 1;
            navigate_to(target);
        }
    }

    if (is_hovered) {
        float mx = ImGui::GetIO().MousePos.x;
        float rel = (mx - p0.x) / W;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t hover_id = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (hover_id >= total_inst_) hover_id = total_inst_ - 1;
            auto hover_row = fetch_row(hover_id);
            ImGui::SetTooltip("#%llu  0x%llx\n%s\n(click or drag to seek)",
                (unsigned long long)hover_id,
                (unsigned long long)hover_row.static_pc,
                hover_row.disasm.c_str());
        }

        // Vertical hover line (dim)
        float mx_screen = ImGui::GetIO().MousePos.x;
        draw->AddLine(ImVec2(mx_screen, p0.y),
                      ImVec2(mx_screen, p0.y + H),
                      IM_COL32(200, 200, 200, 60), 1.0f);
    }

    ImGui::End();
    ImGui::PopStyleVar(2);
}

// ─── Minimap Panel ────────────────────────────────────────────────────────────
// Bird's-eye view of the entire trace. Each pixel row represents a bucket of
// N instructions. Colors encode instruction types and analysis results.
// Clicking navigates to the corresponding instruction.

void GuiApp::render_minimap_panel() {
    ImGuiWindowFlags win_flags = ImGuiWindowFlags_NoScrollbar;
    if (!ImGui::Begin("Minimap", &show_minimap_, win_flags)) {
        ImGui::End();
        return;
    }

    if (total_inst_ == 0) {
        ImGui::TextDisabled("(no trace)");
        ImGui::End();
        return;
    }

    ImVec2 avail = ImGui::GetContentRegionAvail();
    float panel_w = avail.x;
    float panel_h = avail.y;

    // Minimum usable size
    if (panel_w < 10.0f || panel_h < 10.0f) {
        ImGui::End();
        return;
    }

    // Reserve space for the minimap canvas
    ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##minimap_canvas", ImVec2(panel_w, panel_h));
    bool canvas_hovered = ImGui::IsItemHovered();
    bool canvas_clicked = ImGui::IsItemClicked();

    ImDrawList* draw = ImGui::GetWindowDrawList();

    // Background
    draw->AddRectFilled(canvas_pos, ImVec2(canvas_pos.x + panel_w, canvas_pos.y + panel_h),
                        IM_COL32(18, 18, 22, 255));

    // Instructions per pixel row
    int pixel_rows = static_cast<int>(panel_h);
    if (pixel_rows < 1) pixel_rows = 1;
    uint64_t bucket_size = std::max(uint64_t(1), total_inst_ / static_cast<uint64_t>(pixel_rows));

    for (int row = 0; row < pixel_rows; row++) {
        uint64_t bucket_start = static_cast<uint64_t>(row) * bucket_size;
        uint64_t bucket_end = std::min(bucket_start + bucket_size, total_inst_);
        if (bucket_start >= total_inst_) break;

        float y0 = canvas_pos.y + static_cast<float>(row);
        float y1 = y0 + 1.0f;

        // Classify this bucket by sampling a few instructions
        bool has_taint = false;
        bool has_back_taint = false;
        bool has_bookmark = false;
        bool has_loop_header = false;
        bool has_loop_body = false;
        bool has_call = false;
        bool has_branch = false;

        // Sample up to 4 instructions per bucket for efficiency
        uint64_t sample_step = std::max(uint64_t(1), bucket_size / 4);
        for (uint64_t sid = bucket_start; sid < bucket_end; sid += sample_step) {
            auto srow = fetch_row(sid);

            if (show_taint_ && taint_result_ && taint_result_->has_event_at(sid))
                has_taint = true;
            if (show_backward_taint_ && backward_taint_result_ &&
                backward_taint_result_->is_contributing(sid))
                has_back_taint = true;
            if (srow.has_bookmark) has_bookmark = true;
            if (show_loops_ && loop_result_) {
                if (loop_result_->is_loop_header(srow.pc)) has_loop_header = true;
                else if (loop_result_->is_in_loop(srow.pc)) has_loop_body = true;
            }
            if (function_result_ && function_result_->call_at(sid)) has_call = true;
            if (srow.disasm.size() > 0 &&
                (srow.disasm[0] == 'b' || srow.disasm.find("bl") == 0)) has_branch = true;
        }

        // Choose color based on analysis priority
        ImU32 col;
        if (has_bookmark)       col = IM_COL32(255, 220, 40,  255);
        else if (has_back_taint) col = IM_COL32(220, 60,  60,  200);
        else if (has_taint)      col = IM_COL32(40,  200, 80,  200);
        else if (has_loop_header) col = IM_COL32(255, 140, 30, 230);
        else if (has_loop_body)  col = IM_COL32(140, 80,  20,  180);
        else if (has_call)       col = IM_COL32(80,  140, 255, 150);
        else if (has_branch)     col = IM_COL32(200, 200, 60,  120);
        else                     col = IM_COL32(55,  58,  70,  255);

        draw->AddLine(ImVec2(canvas_pos.x, y0), ImVec2(canvas_pos.x + panel_w, y1), col, 1.0f);
    }

    // Current position indicator: bright horizontal line
    {
        float cur_y = canvas_pos.y +
            static_cast<float>(current_inst_) / static_cast<float>(total_inst_) * panel_h;
        draw->AddLine(ImVec2(canvas_pos.x, cur_y), ImVec2(canvas_pos.x + panel_w, cur_y),
                      IM_COL32(255, 255, 255, 240), 2.0f);
        // Viewport window indicator (yellow bracket)
        // Estimate visible range from instruction panel scroll
        uint64_t vis_rows = 40;  // conservative estimate
        float vis_start_y = canvas_pos.y +
            static_cast<float>(current_inst_ > vis_rows / 2 ? current_inst_ - vis_rows / 2 : 0) /
            static_cast<float>(total_inst_) * panel_h;
        float vis_end_y = canvas_pos.y +
            static_cast<float>(std::min(current_inst_ + vis_rows / 2, total_inst_)) /
            static_cast<float>(total_inst_) * panel_h;
        draw->AddRect(ImVec2(canvas_pos.x, vis_start_y),
                      ImVec2(canvas_pos.x + panel_w, vis_end_y),
                      IM_COL32(255, 220, 60, 160), 0.0f, 0, 1.5f);
    }

    // Handle click: navigate to clicked instruction
    if (canvas_clicked || (canvas_hovered && ImGui::IsMouseDown(0))) {
        float my = ImGui::GetIO().MousePos.y;
        float rel = (my - canvas_pos.y) / panel_h;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t target = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (target >= total_inst_) target = total_inst_ - 1;
            navigate_to(target);
        }
    }

    // Hover tooltip
    if (canvas_hovered) {
        float my = ImGui::GetIO().MousePos.y;
        float rel = (my - canvas_pos.y) / panel_h;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t hover_id = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (hover_id >= total_inst_) hover_id = total_inst_ - 1;
            auto hover_row = fetch_row(hover_id);
            ImGui::SetTooltip("inst %llu\n0x%llx  %s\n(click to navigate)",
                (unsigned long long)hover_id,
                (unsigned long long)hover_row.static_pc,
                hover_row.disasm.c_str());
        }
    }

    // Legend at bottom (only if panel is tall enough)
    if (panel_h > 80.0f) {
        float legend_y = canvas_pos.y + panel_h + 4.0f;
        if (ImGui::GetCursorScreenPos().y < legend_y) {
            ImGui::SetCursorScreenPos(ImVec2(canvas_pos.x, canvas_pos.y + panel_h - 36.0f));
        }
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.55f, 1.0f));
        ImGui::TextUnformatted("Click to navigate");
        ImGui::PopStyleColor();
    }

    ImGui::End();
}

// ─── CFG Layout Analysis ─────────────────────────────────────────────────────

void GuiApp::run_cfg_layout() {
    ensure_pass_manager();

    // Build full-trace CFG (needed by other passes: loop, loop_semantics, etc.)
    pass_manager_->register_pass(std::make_unique<XrefPass>());
    pass_manager_->register_pass(std::make_unique<CFGPass>());

    // Cache xref result so the CFG panel can use inst_ids_at() for jump navigation
    auto& xref_res = pass_manager_->require("xref");
    if (xref_res.ok()) {
        xref_result_ = &xref_res.get<XrefResult>();
    }

    auto& cfg_res = pass_manager_->require("cfg");
    if (cfg_res.ok()) {
        cfg_result_ = &cfg_res.get<CFGResult>();
    }

    show_cfg_ = true;

    // Force per-function CFG rebuild on next render frame
    // by resetting the tracked function PC.
    cfg_current_func_pc_ = 0;
    cfg_func_result_.reset();
    cfg_func_layout_.reset();
    cfg_layout_result_ = nullptr;
}

// ─── Per-function CFG rebuild ─────────────────────────────────────────────────
// Extract the sub-CFG for `func_entry_pc` from the full-trace CFG, compute
// layout with GraphGridLayout, and store owned copies in cfg_func_result_ /
// cfg_func_layout_.  The render_cfg_panel reads from these instead of the
// full-trace layout.

void GuiApp::rebuild_cfg_for_function(uint64_t func_entry_pc) {
    if (!cfg_result_ || func_entry_pc == 0) {
        cfg_func_result_.reset();
        cfg_func_layout_.reset();
        cfg_layout_result_ = nullptr;
        cfg_current_func_pc_ = 0;
        return;
    }

    // Extract function sub-graph
    auto sub = cfg_result_->extract_function(func_entry_pc);
    if (sub.blocks.empty()) {
        cfg_func_result_.reset();
        cfg_func_layout_.reset();
        cfg_layout_result_ = nullptr;
        cfg_current_func_pc_ = func_entry_pc;
        return;
    }

    cfg_func_result_ = std::make_unique<CFGResult>(std::move(sub));

    // Run GraphGridLayout directly (no PassManager needed)
    constexpr size_t LARGE_CFG_THRESHOLD = 2000;
    const size_t num_blocks = cfg_func_result_->blocks.size();

    Graph layout_graph;
    layout_graph.reserve(num_blocks);
    const int insn_height = 14;
    const int default_block_width = 200;
    const int default_block_height = 24;

    for (const auto& [pc, block] : cfg_func_result_->blocks) {
        GraphBlock gb;
        gb.entry  = pc;
        gb.width  = default_block_width;
        gb.height = insn_height * static_cast<int>(block.instructions.size() + 1);
        gb.height = std::max(gb.height, default_block_height);
        layout_graph[pc] = gb;
    }
    for (const auto& edge : cfg_func_result_->edges) {
        auto it = layout_graph.find(edge.from_block);
        if (it != layout_graph.end()) {
            it->second.edges.emplace_back(GraphEdge(edge.to_block));
        }
    }

    uint64_t entry = func_entry_pc;
    // If entry block not present, fallback to first block
    if (layout_graph.find(entry) == layout_graph.end()) {
        entry = cfg_func_result_->blocks.begin()->first;
    }

    auto lt = (num_blocks > LARGE_CFG_THRESHOLD)
        ? GraphGridLayout::LayoutType::Narrow
        : GraphGridLayout::LayoutType::Medium;
    GraphGridLayout layout_algo(lt);
    if (num_blocks > LARGE_CFG_THRESHOLD) {
        layout_algo.setLayoutOptimization(false);
    }

    auto func_layout = std::make_unique<CFGLayoutResult>();
    layout_algo.calculateLayout(layout_graph, entry,
                                func_layout->canvas_width, func_layout->canvas_height);

    for (const auto& [pc, gb] : layout_graph) {
        BlockLayout bl;
        bl.x = gb.x; bl.y = gb.y; bl.width = gb.width; bl.height = gb.height;
        func_layout->block_layouts[pc] = bl;
    }
    func_layout->edge_layouts.reserve(cfg_func_result_->edges.size());
    for (const auto& [pc, gb] : layout_graph) {
        for (const auto& ge : gb.edges) {
            EdgeLayout el;
            el.from_block = pc;
            el.to_block   = ge.target;
            el.polyline   = ge.polyline;
            el.arrow      = ge.arrow;
            func_layout->edge_layouts.push_back(std::move(el));
        }
    }

    cfg_func_layout_ = std::move(func_layout);
    cfg_layout_result_ = cfg_func_layout_.get();
    cfg_current_func_pc_ = func_entry_pc;

    // Reset pan/zoom and selection
    cfg_scroll_ = ImVec2(0.0f, 0.0f);
    cfg_zoom_   = 1.0f;
    cfg_selected_block_ = 0;
    cfg_block_cursor_   = 0;

    // Recompute heatmap max for this sub-graph
    cfg_max_exec_count_ = 1;
    cfg_max_edge_count_ = 1;
    for (const auto& [pc, blk] : cfg_func_result_->blocks) {
        if (blk.execution_count > cfg_max_exec_count_)
            cfg_max_exec_count_ = blk.execution_count;
    }
    for (const auto& edge : cfg_func_result_->edges) {
        if (edge.taken_count > cfg_max_edge_count_)
            cfg_max_edge_count_ = edge.taken_count;
    }

    // Auto-fit the graph into the available space
    // (will be applied on next render frame since we don't know avail size here;
    //  zoom=1 + scroll centered on entry block is a good default)
    if (!cfg_func_layout_->block_layouts.empty()) {
        auto it = cfg_func_layout_->block_layouts.find(func_entry_pc);
        if (it == cfg_func_layout_->block_layouts.end()) {
            it = cfg_func_layout_->block_layouts.begin();
        }
        const auto& lo = it->second;
        // Center on entry block (approximate — real centering happens in render)
        cfg_scroll_.x = 200.0f - lo.x * cfg_zoom_;
        cfg_scroll_.y = 40.0f  - lo.y * cfg_zoom_;
    }
}

// ─── CFG Panel ───────────────────────────────────────────────────────────────
// An interactive, pannable, zoomable CFG view.
// Blocks are drawn as rounded rectangles with instruction text.
// Edges are drawn as polylines with arrowheads.

void GuiApp::render_cfg_panel() {
    if (!ImGui::Begin("CFG", &show_cfg_)) {
        ImGui::End();
        return;
    }

    // ── Auto-detect function change and rebuild per-function CFG ──────
    // When full-trace CFG data is available, track which function the
    // current instruction belongs to.  If it changed, extract that
    // function's sub-graph and re-layout automatically.
    if (cfg_result_ && function_result_ && total_inst_ > 0) {
        const FunctionInfo* cur_func = function_result_->function_at(current_inst_);
        uint64_t wanted_pc = cur_func ? cur_func->entry_pc : 0;
        if (wanted_pc != cfg_current_func_pc_) {
            rebuild_cfg_for_function(wanted_pc);
        }
    }

    // Effective CFG data: use per-function sub-graph when available, else full-trace
    const CFGResult* active_cfg = cfg_func_result_ ? cfg_func_result_.get() : cfg_result_;

    // ── Toolbar row 1: controls ───────────────────────────────────────
    if (ImGui::Button("Run CFG Layout")) {
        run_cfg_layout();
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80.0f);
    ImGui::SliderFloat("Zoom##cfg", &cfg_zoom_, 0.05f, 8.0f, "%.1fx");
    ImGui::SameLine();
    if (ImGui::Button("Reset View")) {
        cfg_scroll_ = ImVec2(0.0f, 0.0f);
        cfg_zoom_ = 1.0f;
    }
    ImGui::SameLine();
    // "Center on current block" button
    if (ImGui::Button("Center Here") && active_cfg && cfg_layout_result_) {
        uint64_t cur_pc2 = 0;
        if (total_inst_ > 0) cur_pc2 = fetch_row(current_inst_).pc;
        auto* blk2 = active_cfg->block_containing(cur_pc2);
        if (blk2) {
            auto it2 = cfg_layout_result_->block_layouts.find(blk2->start_pc);
            if (it2 != cfg_layout_result_->block_layouts.end()) {
                const auto& lo = it2->second;
                ImVec2 avail2 = ImGui::GetContentRegionAvail();
                cfg_scroll_.x = avail2.x * 0.5f - (lo.x + lo.width  * 0.5f) * cfg_zoom_;
                cfg_scroll_.y = avail2.y * 0.5f - (lo.y + lo.height * 0.5f) * cfg_zoom_;
            }
        }
    }

    // ── Toolbar row 2: stats + current function name ───────────────────
    if (cfg_layout_result_) {
        // Show current function name if available
        if (cfg_current_func_pc_ != 0 && function_result_) {
            auto fit = function_result_->functions.find(cfg_current_func_pc_);
            if (fit != function_result_->functions.end()) {
                ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.6f, 1.0f),
                    "%s", fit->second.name.c_str());
                ImGui::SameLine();
            }
        }
        ImGui::TextDisabled("%zu blocks, %zu edges",
            cfg_layout_result_->block_layouts.size(),
            cfg_layout_result_->edge_layouts.size());
    } else if (!cfg_result_) {
        ImGui::TextDisabled("(no CFG data — run Analysis > CFG Layout)");
    } else {
        ImGui::TextDisabled("(waiting for function data...)");
    }

    // Jump controls for selected block
    if (cfg_selected_block_ != 0 && xref_result_) {
        auto inst_ids = xref_result_->inst_ids_at(cfg_selected_block_);
        if (!inst_ids.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f),
                "Block 0x%llx (%zu visits)",
                (unsigned long long)cfg_selected_block_,
                inst_ids.size());
            ImGui::SameLine();
            if (ImGui::Button("|<##cfg_first")) {
                cfg_block_cursor_ = 0;
                navigate_to(inst_ids[0]);
            }
            ImGui::SetItemTooltip("Jump to first visit in trace");
            ImGui::SameLine();
            if (ImGui::Button("<##cfg_prev") && cfg_block_cursor_ > 0) {
                cfg_block_cursor_--;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Previous visit");
            ImGui::SameLine();
            ImGui::Text("%zu/%zu", cfg_block_cursor_ + 1, inst_ids.size());
            ImGui::SameLine();
            if (ImGui::Button(">##cfg_next") && cfg_block_cursor_ + 1 < inst_ids.size()) {
                cfg_block_cursor_++;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Next visit");
            ImGui::SameLine();
            if (ImGui::Button(">|##cfg_last")) {
                cfg_block_cursor_ = inst_ids.size() - 1;
                navigate_to(inst_ids[cfg_block_cursor_]);
            }
            ImGui::SetItemTooltip("Jump to last visit in trace");
        }
    }

    ImGui::Separator();

    if (!cfg_layout_result_ || cfg_layout_result_->block_layouts.empty()) {
        ImGui::TextDisabled("No CFG available.\nRun Analysis > CFG Layout first.");
        ImGui::End();
        return;
    }

    // ── Canvas ────────────────────────────────────────────────────────
    ImVec2 canvas_size = ImGui::GetContentRegionAvail();
    if (canvas_size.x < 10.0f || canvas_size.y < 10.0f) {
        ImGui::End();
        return;
    }

    ImVec2 canvas_origin = ImGui::GetCursorScreenPos();

    // Invisible button captures mouse events for the canvas area
    ImGui::InvisibleButton("##cfg_canvas", canvas_size,
        ImGuiButtonFlags_MouseButtonLeft |
        ImGuiButtonFlags_MouseButtonRight |
        ImGuiButtonFlags_MouseButtonMiddle);

    bool canvas_hovered = ImGui::IsItemHovered();
    bool canvas_active  = ImGui::IsItemActive();

    // Pan with left mouse drag
    if (canvas_active && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        ImVec2 delta = ImGui::GetIO().MouseDelta;
        cfg_scroll_.x += delta.x;
        cfg_scroll_.y += delta.y;
    }

    // Zoom with scroll wheel
    if (canvas_hovered) {
        float scroll = ImGui::GetIO().MouseWheel;
        if (scroll != 0.0f) {
            // Zoom towards mouse cursor
            ImVec2 mouse_pos = ImGui::GetIO().MousePos;
            ImVec2 mouse_canvas = ImVec2(
                mouse_pos.x - canvas_origin.x - cfg_scroll_.x,
                mouse_pos.y - canvas_origin.y - cfg_scroll_.y);

            float old_zoom = cfg_zoom_;
            cfg_zoom_ *= (scroll > 0.0f ? 1.1f : 0.9f);
            cfg_zoom_ = std::max(0.05f, std::min(cfg_zoom_, 8.0f));

            float scale_change = cfg_zoom_ / old_zoom;
            cfg_scroll_.x -= mouse_canvas.x * (scale_change - 1.0f);
            cfg_scroll_.y -= mouse_canvas.y * (scale_change - 1.0f);
        }
    }

    // Draw background
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(canvas_origin,
        ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y),
        IM_COL32(18, 20, 26, 255));

    // Grid dots for reference
    {
        const float grid_step = 40.0f * cfg_zoom_;
        float grid_x = fmodf(cfg_scroll_.x, grid_step);
        float grid_y = fmodf(cfg_scroll_.y, grid_step);
        for (float x = canvas_origin.x + grid_x; x < canvas_origin.x + canvas_size.x; x += grid_step) {
            for (float y = canvas_origin.y + grid_y; y < canvas_origin.y + canvas_size.y; y += grid_step) {
                draw->AddCircleFilled(ImVec2(x, y), 1.0f, IM_COL32(50, 55, 70, 120));
            }
        }
    }

    // Helper: convert layout coordinate to screen coordinate
    auto to_screen = [&](float lx, float ly) -> ImVec2 {
        return ImVec2(
            canvas_origin.x + cfg_scroll_.x + lx * cfg_zoom_,
            canvas_origin.y + cfg_scroll_.y + ly * cfg_zoom_);
    };

    // Clip to canvas
    draw->PushClipRect(canvas_origin,
        ImVec2(canvas_origin.x + canvas_size.x, canvas_origin.y + canvas_size.y), true);

    // Determine the "current" block (containing current_inst_'s PC)
    uint64_t cur_pc = 0;
    if (total_inst_ > 0) {
        auto row = fetch_row(current_inst_);
        cur_pc = row.pc;
    }
    // Find block containing cur_pc
    uint64_t highlight_block_pc = 0;
    if (active_cfg) {
        auto* blk = active_cfg->block_containing(cur_pc);
        if (blk) highlight_block_pc = blk->start_pc;
    }

    // ── Helper: heatmap colour (cold blue → hot red) ──────────────────
    // t in [0,1]; returns RGBA
    auto heatmap_color = [](float t, uint8_t alpha) -> ImU32 {
        // cold (0) = dark blue, warm (0.5) = teal/green, hot (1) = red/orange
        t = std::max(0.0f, std::min(t, 1.0f));
        uint8_t r, g, b;
        if (t < 0.5f) {
            float s = t * 2.0f;
            r = static_cast<uint8_t>(20  + s * 60);   // 20→80
            g = static_cast<uint8_t>(60  + s * 100);  // 60→160
            b = static_cast<uint8_t>(120 - s * 60);   // 120→60
        } else {
            float s = (t - 0.5f) * 2.0f;
            r = static_cast<uint8_t>(80  + s * 175);  // 80→255
            g = static_cast<uint8_t>(160 - s * 130);  // 160→30
            b = static_cast<uint8_t>(60  - s * 50);   // 60→10
        }
        return IM_COL32(r, g, b, alpha);
    };

    // Handle click on canvas to select a block
    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && !ImGui::IsMouseDragging(ImGuiMouseButton_Left, 3.0f)) {
        ImVec2 mouse = ImGui::GetIO().MousePos;
        // Convert mouse position to layout coordinates
        float lx = (mouse.x - canvas_origin.x - cfg_scroll_.x) / cfg_zoom_;
        float ly = (mouse.y - canvas_origin.y - cfg_scroll_.y) / cfg_zoom_;

        // Hit-test all blocks
        uint64_t clicked_block = 0;
        for (const auto& [bpc, lo] : cfg_layout_result_->block_layouts) {
            if (lx >= lo.x && lx <= lo.x + lo.width &&
                ly >= lo.y && ly <= lo.y + lo.height) {
                clicked_block = bpc;
                break;
            }
        }
        if (clicked_block != 0 && clicked_block != cfg_selected_block_) {
            cfg_selected_block_ = clicked_block;
            cfg_block_cursor_   = 0;
            // Auto-navigate to first execution of this block
            if (xref_result_) {
                auto ids = xref_result_->inst_ids_at(clicked_block);
                if (!ids.empty()) navigate_to(ids[0]);
            }
        }
    }

    // ── Draw edges ───────────────────────────────────────────────────
    for (const auto& edge : cfg_layout_result_->edge_layouts) {
        if (edge.polyline.size() < 2) continue;

        // Defaults
        ImU32 edge_color = IM_COL32(70, 75, 100, 180);
        float  edge_width = 1.0f;

        if (active_cfg) {
            for (const auto& cfg_edge : active_cfg->edges) {
                if (cfg_edge.from_block == edge.from_block &&
                    cfg_edge.to_block   == edge.to_block) {
                    // Width proportional to taken_count (log scale, 1..4px)
                    float t_edge = (cfg_max_edge_count_ > 1)
                        ? static_cast<float>(cfg_edge.taken_count) / static_cast<float>(cfg_max_edge_count_)
                        : 0.0f;
                    edge_width = 1.0f + t_edge * 3.0f;

                    // Hue: fallthrough = green tint, branch = orange/red tint, scaled by hotness
                    if (cfg_edge.is_fallthrough) {
                        uint8_t g_val = static_cast<uint8_t>(100 + t_edge * 155);
                        edge_color = IM_COL32(40, g_val, 60, 200);
                    } else {
                        uint8_t r_val = static_cast<uint8_t>(120 + t_edge * 135);
                        edge_color = IM_COL32(r_val, static_cast<uint8_t>(80 - t_edge * 40), 40, 200);
                    }

                    // Extra highlight if this edge connects to/from current block
                    bool is_active_edge = (cfg_edge.from_block == highlight_block_pc ||
                                           cfg_edge.to_block   == highlight_block_pc);
                    if (is_active_edge) {
                        edge_color = IM_COL32(100, 200, 255, 255);
                        edge_width = std::max(edge_width, 2.0f);
                    }
                    break;
                }
            }
        }

        // Draw polyline segments
        for (size_t i = 0; i + 1 < edge.polyline.size(); ++i) {
            ImVec2 p0 = to_screen(edge.polyline[i].x, edge.polyline[i].y);
            ImVec2 p1 = to_screen(edge.polyline[i + 1].x, edge.polyline[i + 1].y);
            draw->AddLine(p0, p1, edge_color, edge_width);
        }

        // Arrowhead at last segment
        if (edge.polyline.size() >= 2) {
            size_t n = edge.polyline.size();
            ImVec2 tip  = to_screen(edge.polyline[n - 1].x, edge.polyline[n - 1].y);
            ImVec2 base = to_screen(edge.polyline[n - 2].x, edge.polyline[n - 2].y);
            float dx = tip.x - base.x;
            float dy = tip.y - base.y;
            float len = sqrtf(dx * dx + dy * dy);
            if (len > 0.001f) {
                float ux = dx / len, uy = dy / len;
                float px = -uy, py = ux;
                float arrow_len  = (6.0f + edge_width * 2.0f) * cfg_zoom_;
                float arrow_half = (3.0f + edge_width) * cfg_zoom_;
                ImVec2 left  = ImVec2(tip.x - ux * arrow_len + px * arrow_half,
                                       tip.y - uy * arrow_len + py * arrow_half);
                ImVec2 right = ImVec2(tip.x - ux * arrow_len - px * arrow_half,
                                       tip.y - uy * arrow_len - py * arrow_half);
                draw->AddTriangleFilled(tip, left, right, edge_color);
            }
        }
    }

    // ── Draw blocks ──────────────────────────────────────────────────
    const float corner_radius = 4.0f;
    const float font_size = 11.0f * cfg_zoom_;
    ImVec2 mouse_pos_canvas = ImGui::GetIO().MousePos;

    for (const auto& [block_pc, layout] : cfg_layout_result_->block_layouts) {
        ImVec2 tl = to_screen((float)layout.x, (float)layout.y);
        ImVec2 br = to_screen((float)(layout.x + layout.width),
                               (float)(layout.y + layout.height));

        // Skip blocks outside canvas (rough cull)
        if (br.x < canvas_origin.x || tl.x > canvas_origin.x + canvas_size.x) continue;
        if (br.y < canvas_origin.y || tl.y > canvas_origin.y + canvas_size.y) continue;

        // ── Compute heatmap intensity ─────────────────────────────────
        float heat = 0.0f;
        uint64_t exec_count = 0;
        if (active_cfg) {
            auto it_blk = active_cfg->blocks.find(block_pc);
            if (it_blk != active_cfg->blocks.end()) {
                exec_count = it_blk->second.execution_count;
                if (cfg_max_exec_count_ > 0)
                    heat = static_cast<float>(exec_count) / static_cast<float>(cfg_max_exec_count_);
            }
        }
        // Use log scale so cold blocks (executed once) are visible
        if (exec_count > 0 && cfg_max_exec_count_ > 1) {
            heat = logf(1.0f + static_cast<float>(exec_count)) /
                   logf(1.0f + static_cast<float>(cfg_max_exec_count_));
        }

        // ── State flags ───────────────────────────────────────────────
        bool is_current   = (block_pc == highlight_block_pc);    // block containing current PC
        bool is_selected  = (block_pc == cfg_selected_block_);   // user-clicked block
        bool is_hovered   = (mouse_pos_canvas.x >= tl.x && mouse_pos_canvas.x <= br.x &&
                             mouse_pos_canvas.y >= tl.y && mouse_pos_canvas.y <= br.y &&
                             canvas_hovered);

        // ── Colours ───────────────────────────────────────────────────
        ImU32 bg_color, border_color, header_color;

        if (is_current) {
            // Bright blue for the block the trace cursor is in
            bg_color     = IM_COL32(30, 70, 130, 245);
            border_color = IM_COL32(80, 180, 255, 255);
            header_color = IM_COL32(50, 110, 180, 255);
        } else if (is_selected) {
            // Cyan outline for user-selected block
            bg_color     = heatmap_color(heat, 230);
            border_color = IM_COL32(0, 220, 220, 255);
            header_color = IM_COL32(0, 100, 120, 255);
        } else if (exec_count == 0) {
            // Never executed (dead code or not-yet-visited) — dim grey
            bg_color     = IM_COL32(20, 22, 28, 200);
            border_color = IM_COL32(50, 55, 70, 150);
            header_color = IM_COL32(28, 30, 38, 200);
        } else {
            // Heatmap colouring for executed blocks
            bg_color     = heatmap_color(heat, 220);
            border_color = heatmap_color(heat, 255);
            header_color = heatmap_color(heat * 0.8f, 255);
        }

        // Lighten border on hover
        if (is_hovered && !is_current && !is_selected) {
            border_color = IM_COL32(200, 200, 255, 255);
        }

        draw->AddRectFilled(tl, br, bg_color, corner_radius);
        draw->AddRect(tl, br, border_color, corner_radius, 0,
                      is_current || is_selected ? 2.0f : 1.0f);

        // Header bar with address
        float header_h = 16.0f * cfg_zoom_;
        draw->AddRectFilled(tl, ImVec2(br.x, tl.y + header_h),
            header_color, corner_radius, ImDrawFlags_RoundCornersTop);

        // Draw text only if zoom is large enough to be readable
        if (cfg_zoom_ >= 0.35f) {
            // Address + exec count in header
            char addr_buf[64];
            if (exec_count > 0) {
                snprintf(addr_buf, sizeof(addr_buf), "0x%llx  ×%llu",
                    (unsigned long long)block_pc,
                    (unsigned long long)exec_count);
            } else {
                snprintf(addr_buf, sizeof(addr_buf), "0x%llx",
                    (unsigned long long)block_pc);
            }
            draw->AddText(nullptr, font_size,
                ImVec2(tl.x + 4.0f * cfg_zoom_, tl.y + 2.0f * cfg_zoom_),
                IM_COL32(220, 230, 255, 230),
                addr_buf);

            // Instruction body
            if (active_cfg) {
                auto it = active_cfg->blocks.find(block_pc);
                if (it != active_cfg->blocks.end()) {
                    const auto& blk = it->second;
                    float text_y = tl.y + header_h + 2.0f * cfg_zoom_;

                    if (cfg_zoom_ >= 0.7f) {
                        // Show individual instructions
                        for (size_t i = 0; i < blk.instructions.size() && text_y + font_size < br.y; ++i) {
                            uint64_t insn_pc = blk.instructions[i];
                            bool is_cur_insn = (insn_pc == cur_pc);
                            ImU32 insn_color = is_cur_insn
                                ? IM_COL32(255, 245, 60, 255)   // bright yellow for current insn
                                : IM_COL32(200, 210, 225, 200);

                            // Current-instruction marker on left
                            if (is_cur_insn) {
                                draw->AddTriangleFilled(
                                    ImVec2(tl.x + 2.0f * cfg_zoom_,    text_y + font_size * 0.15f),
                                    ImVec2(tl.x + 2.0f * cfg_zoom_,    text_y + font_size * 0.85f),
                                    ImVec2(tl.x + 5.0f * cfg_zoom_,    text_y + font_size * 0.5f),
                                    IM_COL32(255, 240, 60, 255));
                            }

                            // Get disassembly
                            auto opcode = code_table_.opcode_at(insn_pc);
                            std::string disasm_str;
                            if (opcode) {
                                auto d = decoder_.decode(insn_pc, *opcode);
                                if (d) {
                                    disasm_str = fmt::format("{:x}: {} {}",
                                        insn_pc - reader_.header().module_slide,
                                        d->mnemonic, d->op_str);
                                } else {
                                    disasm_str = fmt::format("{:x}: .word 0x{:08x}",
                                        insn_pc - reader_.header().module_slide, *opcode);
                                }
                            } else {
                                disasm_str = fmt::format("{:x}: ?", insn_pc);
                            }

                            float text_x  = tl.x + 7.0f * cfg_zoom_;
                            float max_w   = br.x - text_x - 4.0f * cfg_zoom_;
                            if (max_w > 0.0f) {
                                draw->AddText(nullptr, font_size,
                                    ImVec2(text_x, text_y), insn_color,
                                    disasm_str.c_str(),
                                    disasm_str.c_str() + disasm_str.size(),
                                    max_w);
                            }
                            text_y += font_size + 1.5f * cfg_zoom_;
                        }
                    } else {
                        // Compact: instruction count + exec count
                        char cnt_buf[64];
                        snprintf(cnt_buf, sizeof(cnt_buf), "%zu insns", blk.instructions.size());
                        draw->AddText(nullptr, font_size,
                            ImVec2(tl.x + 4.0f * cfg_zoom_, text_y),
                            IM_COL32(180, 190, 210, 200), cnt_buf);
                    }
                }
            }
        }

        // Hover tooltip with execution count + right-click menu trigger
        if (is_hovered && ImGui::IsItemHovered()) {
            std::string tip = fmt::format(
                "0x{:016x}\n{} executions\n",
                (unsigned long long)block_pc,
                (unsigned long long)exec_count);
            if (active_cfg) {
                auto it = active_cfg->blocks.find(block_pc);
                if (it != active_cfg->blocks.end()) {
                    tip += fmt::format("{} instructions in block\n", it->second.instructions.size());
                }
            }
            tip += "Left-click: select & navigate\nRight-click: more options";
            ImGui::SetTooltip("%s", tip.c_str());

            // Right-click → CFG block context menu
            if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                // Store block info for context menu
                ImGui::OpenPopup("##cfg_ctx");
                // Save state for menu
                ctx_inst_pc_        = block_pc;  // reuse ctx field for block PC
                ctx_inst_static_pc_ = block_pc - reader_.header().module_slide;
            }
        }
    }

    // ── CFG right-click context menu ─────────────────────────────────
    if (ImGui::BeginPopup("##cfg_ctx")) {
        ImGui::TextDisabled("Block: 0x%llx", (unsigned long long)ctx_inst_static_pc_);
        if (active_cfg) {
            auto it = active_cfg->blocks.find(ctx_inst_pc_);
            if (it != active_cfg->blocks.end()) {
                ImGui::TextDisabled("%zu instructions, %llu executions",
                    it->second.instructions.size(),
                    (unsigned long long)it->second.execution_count);
            }
        }
        ImGui::Separator();

        // Navigation
        if (ImGui::MenuItem("Navigate to Block Entry")) {
            if (xref_result_) {
                auto ids = xref_result_->inst_ids_at(ctx_inst_pc_);
                if (!ids.empty()) {
                    cfg_selected_block_ = ctx_inst_pc_;
                    cfg_block_cursor_ = 0;
                    navigate_to(ids[0]);
                }
            }
        }
        if (xref_result_) {
            auto ids = xref_result_->inst_ids_at(ctx_inst_pc_);
            if (!ids.empty() && ImGui::BeginMenu(fmt::format("Jump to Execution ({})...", ids.size()).c_str())) {
                size_t limit = std::min(ids.size(), size_t(15));
                for (size_t xi = 0; xi < limit; xi++) {
                    char lbl[48];
                    snprintf(lbl, sizeof(lbl), "  inst #%llu", (unsigned long long)ids[xi]);
                    if (ImGui::MenuItem(lbl)) {
                        cfg_selected_block_ = ctx_inst_pc_;
                        cfg_block_cursor_   = xi;
                        navigate_to(ids[xi]);
                    }
                }
                if (ids.size() > 15) {
                    ImGui::TextDisabled("  ... and %zu more", ids.size() - 15);
                }
                ImGui::EndMenu();
            }
        }

        ImGui::Separator();

        // Zoom controls
        if (ImGui::MenuItem("Zoom In (+)")) {
            cfg_zoom_ = std::min(cfg_zoom_ * 1.25f, 8.0f);
        }
        if (ImGui::MenuItem("Zoom Out (-)")) {
            cfg_zoom_ = std::max(cfg_zoom_ * 0.8f, 0.05f);
        }
        if (ImGui::MenuItem("Reset Zoom (1:1)")) {
            cfg_zoom_   = 1.0f;
        }
        if (ImGui::MenuItem("Fit to Window")) {
            // Auto-fit: center all blocks
            if (cfg_layout_result_ && !cfg_layout_result_->block_layouts.empty()) {
                float lo_x = FLT_MAX, lo_y = FLT_MAX, hi_x = -FLT_MAX, hi_y = -FLT_MAX;
                for (const auto& [bpc, lo] : cfg_layout_result_->block_layouts) {
                    lo_x = std::min(lo_x, static_cast<float>(lo.x));
                    lo_y = std::min(lo_y, static_cast<float>(lo.y));
                    hi_x = std::max(hi_x, static_cast<float>(lo.x + lo.width));
                    hi_y = std::max(hi_y, static_cast<float>(lo.y + lo.height));
                }
                float avail_w = ImGui::GetWindowWidth();
                float avail_h = ImGui::GetWindowHeight();
                float box_w = hi_x - lo_x;
                float box_h = hi_y - lo_y;
                if (box_w > 0 && box_h > 0) {
                    cfg_zoom_ = std::min(avail_w / box_w, avail_h / box_h) * 0.85f;
                    cfg_zoom_ = std::max(0.05f, std::min(cfg_zoom_, 8.0f));
                    cfg_scroll_.x = avail_w * 0.5f - (lo_x + box_w * 0.5f) * cfg_zoom_;
                    cfg_scroll_.y = avail_h * 0.5f - (lo_y + box_h * 0.5f) * cfg_zoom_;
                }
            }
        }

        ImGui::Separator();

        // Copy
        if (ImGui::MenuItem("Copy Block Address")) {
            char buf[24];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_inst_static_pc_);
            ImGui::SetClipboardText(buf);
        }

        ImGui::EndPopup();
    }

    draw->PopClipRect();

    ImGui::End();
}

// ─── Status Bar ─────────────────────────────────────────────────────────────
// VS Code / IDA style: fixed-height strip at the very bottom of the viewport.
// Shows: inst position | mnemonic | active analyses | trace stats | mode badges

void GuiApp::render_status_bar() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float bar_y = vp->WorkPos.y + vp->WorkSize.y - kStatusBarHeight;

    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, bar_y));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, kStatusBarHeight));
    ImGui::SetNextWindowViewport(vp->ID);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,  0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,   ImVec2(8.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.055f, 0.060f, 0.085f, 1.0f));

    ImGui::Begin("##StatusBar", nullptr,
        ImGuiWindowFlags_NoTitleBar    | ImGuiWindowFlags_NoResize  |
        ImGuiWindowFlags_NoMove        | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoDocking     | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoFocusOnAppearing);

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();

    // ─── Left section: position + current instruction ────────────────
    // Instruction index / total (IDA style: "0001234 / 0056789")
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.65f, 0.85f, 1.0f));
    ImGui::TextUnformatted("\xe2\x96\xb6");   // ▶
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 4.0f);

    ImGui::TextColored(ImVec4(0.80f, 0.85f, 1.00f, 1.0f),
        "%llu / %llu",
        (unsigned long long)current_inst_,
        (unsigned long long)total_inst_);

    ImGui::SameLine(0, 10.0f);

    // Progress percentage
    float pct = (total_inst_ > 1)
        ? 100.0f * static_cast<float>(current_inst_) / static_cast<float>(total_inst_ - 1)
        : 0.0f;
    ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.65f, 1.0f), "(%.1f%%)", pct);

    ImGui::SameLine(0, 14.0f);

    // Current PC in muted monospace
    {
        auto row = fetch_row(current_inst_);
        if (!row.mnemonic.empty()) {
            // Vertical separator
            ImGui::TextColored(ImVec4(0.25f, 0.28f, 0.38f, 1.0f), "|");
            ImGui::SameLine(0, 10.0f);

            ImGui::TextColored(ImVec4(0.45f, 0.50f, 0.65f, 1.0f),
                "0x%llx", (unsigned long long)row.static_pc);
            ImGui::SameLine(0, 6.0f);
            ImGui::TextColored(inst_color(row.mnemonic), "%s", row.mnemonic.c_str());
            ImGui::SameLine(0, 4.0f);
            ImGui::TextColored(ImVec4(0.70f, 0.72f, 0.80f, 1.0f), "%s", row.operands.c_str());
        }
    }

    // ─── Right section: active analyses + bookmarks + file ───────────
    // We compute items right-to-left, accumulate total width, then set cursor.
    // For simplicity, build a string for the right side and right-align.
    std::string right;

    // Bookmarks count
    if (!bookmarks_.empty()) {
        right += fmt::format("  \xe2\x98\x85 {} bkm", bookmarks_.size());  // ★
    }

    // Active analyses badges
    if (show_taint_ && taint_result_) {
        right += "  [TAINT]";
    }
    if (show_backward_taint_ && backward_taint_result_) {
        right += "  [BT]";
    }
    if (show_slice_ && slice_result_) {
        right += "  [SLICE]";
    }
    if (show_loops_ && loop_result_) {
        right += fmt::format("  [\xe2\x86\xba {}L]", loop_result_->loops.size());  // ↺
    }
    if (analysis_running_.load()) {
        right += "  \xe2\xa3\xbe Analyzing...";  // ⣾
    }

    // Search result position
    if (search_active_ && !search_results_.empty()) {
        right += fmt::format("  Search: {}/{}", search_current_ + 1, search_results_.size());
    }

    if (!right.empty()) {
        float text_w = ImGui::CalcTextSize(right.c_str()).x;
        float win_w  = ImGui::GetWindowWidth();
        ImGui::SameLine(win_w - text_w - 8.0f);
        ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.70f, 1.0f), "%s", right.c_str());
    }

    ImGui::End();
}

}  // namespace tenet
