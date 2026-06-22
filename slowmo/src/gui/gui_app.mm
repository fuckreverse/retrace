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
