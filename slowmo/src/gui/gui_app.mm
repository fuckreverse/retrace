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
#include "common/Profiling.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/cfg_layout_pass.h"

#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_sdl3.h>
#include <imgui_impl_metal.h>

#include <SDL3/SDL.h>
#include <SDL3/SDL_metal.h>

#include <fmt/core.h>

// FontAwesome 6 icon font (embedded as compressed C array)
#include "gui/icons/IconsFontAwesome6.h"
#include "gui/icons/fa_solid_900_ttf.h"

#include <algorithm>
#include <cstring>
#include <string>

// Metal/ObjC interop (this file is compiled as Objective-C++)
#import <Metal/Metal.h>
#import <QuartzCore/QuartzCore.h>
#import <AppKit/AppKit.h>     // NSMenu, NSMenuItem, NSMenuDelegate, NSApp
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>  // UTType (NSSavePanel allowedContentTypes)

namespace tenet {

// ─── Constructor / Destructor ───────────────────────────────────────────────

GuiApp::GuiApp(TraceReader& reader, TraceIndex& index, CodeTable& code_table,
               InstructionDecoder& decoder, RegisterFile& regfile, MemoryModel& memory,
               const std::filesystem::path& trace_path)
    : reader_(reader), index_(index), code_table_(code_table),
      decoder_(decoder), regfile_(regfile), memory_(memory),
      trace_path_(trace_path.empty() ? reader.path() : trace_path) {
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

    metal_view_ = SDL_Metal_CreateView(window_);
    if (!metal_view_) {
        fmt::print(stderr, "SDL_Metal_CreateView failed: {}\n", SDL_GetError());
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

    // Disable imgui.ini persistence — window/table layout is fully managed
    // by our own GuiSettings and code-side TableSetupColumn defaults.
    io.IniFilename = nullptr;

    // Setup platform/renderer backends
    ImGui_ImplSDL3_InitForMetal(window_);

    // Get CAMetalLayer from the explicit SDL metal view and keep ownership local
    // to GuiApp instead of mixing SDL's Metal renderer with our own command queue.
    metal_layer_ = (__bridge CAMetalLayer*)SDL_Metal_GetLayer(metal_view_);
    if (!metal_layer_) {
        fmt::print(stderr, "Failed to get CAMetalLayer from SDL_MetalView\n");
        return false;
    }
    metal_layer_.pixelFormat = MTLPixelFormatBGRA8Unorm;

    metal_device_ = MTLCreateSystemDefaultDevice();
    if (!metal_device_) {
        fmt::print(stderr, "MTLCreateSystemDefaultDevice failed\n");
        return false;
    }
    metal_layer_.device = metal_device_;

    // Keep the default maximumDrawableCount (3) to match kMaxInflightFrames.
    // Apple recommends aligning these values — the semaphore count should equal
    // the drawable count to avoid one throttle mechanism shadowing the other.

    // Ensure the layer syncs to display refresh so we do not outrun the GPU.
    metal_layer_.displaySyncEnabled = YES;

    ImGui_ImplMetal_Init(metal_device_);

    // Create our own command queue for ImGui rendering.
    metal_command_queue_ = [metal_device_ newCommandQueue];
    metal_render_pass_desc_ = [MTLRenderPassDescriptor new];

    // Create the in-flight frame semaphore (triple buffering).
    // The render loop waits on this before submitting a new command buffer,
    // ensuring at most kMaxInflightFrames are queued at once.
    frame_semaphore_ = dispatch_semaphore_create(kMaxInflightFrames);

    // Load persistent settings
    settings_.load(GuiSettings::default_path());
    available_fonts_ = GuiSettings::available_mono_fonts();

    setup_style();
    setup_fonts();

    return true;
}

// ─── Graceful async shutdown ────────────────────────────────────────────────
//
// begin_shutdown() is called the moment the user requests close.  It sets
// shutdown_requested_ (so render_frame switches to the overlay) and spins up
// a background thread that does the slow work: cancel passes, join workers,
// persist state.  When all of that is done it sets shutdown_complete_ and the
// main render loop falls through.

void GuiApp::begin_shutdown() {
    bool expected = false;
    if (!shutdown_requested_.compare_exchange_strong(expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) {
        return;  // already shutting down
    }

    shutdown_thread_ = std::thread([this]() {
        // Step 1 – cancel all in-flight passes so workers unblock quickly.
        auto set_msg = [this](const char* m) {
            std::lock_guard<std::mutex> lk(shutdown_msg_mutex_);
            shutdown_msg_ = m;
        };

        set_msg("Cancelling analysis passes\u2026");
        if (pass_manager_) {
            pass_manager_->cancel_all();
        }

        // Step 2 – stop the serial worker queue.
        set_msg("Stopping worker threads\u2026");
        analysis_worker_stop_.store(true, std::memory_order_release);
        analysis_queue_cv_.notify_all();
        if (analysis_worker_thread_.joinable()) {
            analysis_worker_thread_.join();
        }

        // Step 3 – join startup analysis thread (run_all internal threads
        // are joined before run_all returns, so this waits for them too).
        set_msg("Waiting for analysis to finish\u2026");
        if (startup_analysis_thread_.joinable()) {
            startup_analysis_thread_.join();
        }

        // Step 4 – wait for all detached enqueue_async() threads.
        set_msg("Waiting for background tasks\u2026");
        {
            std::unique_lock<std::mutex> lk(detached_thread_mutex_);
            detached_thread_cv_.wait(lk, [this] {
                return detached_thread_count_.load(std::memory_order_acquire) == 0;
            });
        }

        // Step 5 – persist state to RocksDB.
        set_msg("Saving state\u2026");
        index_.save_bookmarks(bookmarks_);
        index_.save_last_inst(current_inst_);

        // Done – signal the render loop to exit.
        set_msg("Done");
        shutdown_complete_.store(true, std::memory_order_release);
    });
}

void GuiApp::render_shutdown_overlay() {
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 screen = io.DisplaySize;

    // Full-screen semi-transparent black backdrop
    ImDrawList* bg = ImGui::GetBackgroundDrawList();
    bg->AddRectFilled(ImVec2(0, 0), screen,
                      IM_COL32(10, 10, 16, 210));

    // Centre the card
    const float card_w = 380.0f;
    const float card_h = 130.0f;
    ImVec2 card_pos((screen.x - card_w) * 0.5f, (screen.y - card_h) * 0.5f);

    ImDrawList* fg = ImGui::GetForegroundDrawList();

    // Card background
    fg->AddRectFilled(card_pos,
                      ImVec2(card_pos.x + card_w, card_pos.y + card_h),
                      IM_COL32(22, 22, 30, 245), 10.0f);
    fg->AddRect(card_pos,
                ImVec2(card_pos.x + card_w, card_pos.y + card_h),
                IM_COL32(60, 90, 140, 180), 10.0f, 0, 1.5f);

    // Title
    const char* title = "Shutting down Tenet";
    ImVec2 title_sz = ImGui::CalcTextSize(title);
    fg->AddText(ImVec2(card_pos.x + (card_w - title_sz.x) * 0.5f,
                       card_pos.y + 18.0f),
                IM_COL32(220, 225, 240, 255), title);

    // Spinner — a simple arc that rotates each frame
    const float t = static_cast<float>(ImGui::GetTime());
    const float cx = card_pos.x + card_w * 0.5f;
    const float cy = card_pos.y + 68.0f;
    const float r  = 14.0f;
    const int   seg = 32;
    const float arc = 0.65f;   // fraction of full circle drawn
    const float speed = 2.8f;
    for (int i = 0; i < seg; i++) {
        float a0 = t * speed + (float)i       / seg * IM_PI * 2.0f * arc;
        float a1 = t * speed + (float)(i + 1) / seg * IM_PI * 2.0f * arc;
        // Fade the tail
        float alpha = 80.0f + 170.0f * ((float)i / seg);
        fg->AddLine(
            ImVec2(cx + cosf(a0) * r, cy + sinf(a0) * r),
            ImVec2(cx + cosf(a1) * r, cy + sinf(a1) * r),
            IM_COL32(80, 140, 230, (int)alpha), 2.5f);
    }

    // Status message
    std::string msg;
    {
        std::lock_guard<std::mutex> lk(shutdown_msg_mutex_);
        msg = shutdown_msg_;
    }
    ImVec2 msg_sz = ImGui::CalcTextSize(msg.c_str());
    fg->AddText(ImVec2(card_pos.x + (card_w - msg_sz.x) * 0.5f,
                       card_pos.y + card_h - 28.0f),
                IM_COL32(130, 150, 190, 220), msg.c_str());
}

// ─── Shutdown (platform resources only) ─────────────────────────────────────
// All thread joining and state persistence are handled by begin_shutdown().
// By the time we reach here, shutdown_complete_ is true and no background
// thread accesses any of these objects any more.

void GuiApp::auto_start_mcp() {
    ensure_pass_manager();

    mcp_service_ = std::make_unique<TenetMcpService>(
        reader_, index_, regfile_, memory_,
        pass_manager_.get(), &code_table_, &decoder_);

    McpHttpConfig cfg;
    cfg.host = mcp_gui_.host;
    auto base_port = static_cast<uint16_t>(mcp_gui_.port);

    constexpr int kMaxRetries = 16;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        cfg.port = static_cast<uint16_t>(base_port + attempt);
        if (mcp_service_->start_http(cfg)) {
            auto actual_port = mcp_service_->http_listening_port();
            mcp_gui_.port = actual_port;
            mcp_status_msg_ = fmt::format(
                "Auto-started on {}:{}", cfg.host, actual_port);
            return;
        }
    }

    // All attempts failed — clean up
    mcp_status_msg_ = fmt::format(
        "Auto-start failed: ports {}-{} all in use.",
        base_port, base_port + kMaxRetries - 1);
    mcp_service_.reset();
}

void GuiApp::shutdown() {
    if (!window_) return;  // Already shut down

    // Stop the in-GUI MCP HTTP SSE server if running.
    if (mcp_service_) {
        mcp_service_->stop_http();
        mcp_service_.reset();
    }

    // Join the shutdown coordination thread (it is very short-lived).
    if (shutdown_thread_.joinable()) {
        shutdown_thread_.join();
    }

    ImGui_ImplMetal_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();

    metal_render_pass_desc_ = nil;
    metal_command_queue_ = nil;
    metal_layer_ = nil;
    metal_device_ = nil;
    if (metal_view_) {
        SDL_Metal_DestroyView(metal_view_);
        metal_view_ = nullptr;
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

    // ── Extended glyph range for the primary font ─────────────────────────
    // The primary monospace font (SF Mono / Menlo) already contains many
    // useful Unicode glyphs (✓, ✗, ✕, ·, ×, —, …) beyond ASCII.
    // Load them upfront so they render from the primary font directly.
    // Remaining symbols (arrows, geometric, Braille, etc.) are merged from
    // Apple Symbols as a fallback below.
    static const ImWchar primary_ranges[] = {
        0x0020, 0x00FF,   // Basic Latin + Latin-1 Supplement (default)
        0x00B7, 0x00B7,   // · (middle dot, used as separator)
        0x00D7, 0x00D7,   // × (multiplication sign)
        0x2013, 0x2026,   // General Punctuation (–, —, …)
        0x2190, 0x21FF,   // Arrows (←→↑↓↺↳↵⇆ etc.)
        0x2200, 0x22FF,   // Mathematical Operators (≥ etc.)
        0x2300, 0x23FF,   // Misc Technical (⌕⌛⌘ etc.)
        0x2500, 0x25FF,   // Box Drawing + Block Elements + Geometric Shapes
        0x2600, 0x26FF,   // Misc Symbols (★☆⚠⚙⚡ etc.)
        0x2700, 0x27FF,   // Dingbats (✂✓✕✗ etc.)
        0x2800, 0x28FF,   // Braille Patterns (spinner: ⣾⣽⣻⢿⡿⣟⣯⣷)
        0,
    };

    bool font_loaded = false;
    if (!font_to_load.empty()) {
        if (FILE* f = fopen(font_to_load.c_str(), "rb")) {
            fclose(f);
            ImFontConfig config;
            config.OversampleH = settings_.oversample_h;  // typically 3 for HiDPI
            config.OversampleV = settings_.oversample_v;  // typically 2 for HiDPI
            config.PixelSnapH  = settings_.pixel_snap;    // keep OFF on Retina
            config.GlyphRanges = primary_ranges;
            io.Fonts->AddFontFromFileTTF(font_to_load.c_str(), font_size, &config);
            font_loaded = true;
        }
    }

    if (!font_loaded) {
        ImFontConfig config;
        config.SizePixels = font_size;
        io.Fonts->AddFontDefault(&config);
        // Merge extended ranges from a system fallback font
        ImFontConfig fallback_cfg;
        fallback_cfg.MergeMode   = true;
        fallback_cfg.GlyphRanges = primary_ranges;
        fallback_cfg.SizePixels  = font_size;
        static const char* fallback_paths[] = {
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/SFNSMono.ttf",
            nullptr
        };
        for (int i = 0; fallback_paths[i]; i++) {
            if (FILE* fb = fopen(fallback_paths[i], "rb")) {
                fclose(fb);
                io.Fonts->AddFontFromFileTTF(fallback_paths[i], font_size, &fallback_cfg, primary_ranges);
                break;
            }
        }
    }

    // ── Merge additional symbols from Apple Symbols ──────────────────────
    // Apple Symbols provides high-quality glyphs for arrows, geometric shapes,
    // Braille patterns, and misc symbols. It does NOT cover Dingbats well
    // (✓✕✗✂ are missing), so those come from the primary font above.
    // This merge fills gaps for glyphs the primary monospace font may lack
    // (e.g. Braille, some arrows, geometric shapes).
    static const char* symbol_font = "/System/Library/Fonts/Apple Symbols.ttf";
    if (FILE* sf = fopen(symbol_font, "rb")) {
        fclose(sf);

        // Ranges where Apple Symbols is known to have good coverage:
        static const ImWchar symbol_ranges[] = {
            0x00D7, 0x00D7,   // ×
            0x2013, 0x2026,   // —…
            0x2190, 0x21FF,   // Arrows
            0x2300, 0x23FF,   // Misc Technical (⌕⌛⌘⌦ etc.)
            0x2500, 0x25FF,   // Box Drawing + Block Elements + Geometric Shapes
            0x2600, 0x26FF,   // Misc Symbols (★☆⚠⚙ etc.)
            0x2800, 0x28FF,   // Braille Patterns (spinner: ⣾⣽⣻⢿⡿⣟⣯⣷)
            0,
        };

        ImFontConfig sym_cfg;
        sym_cfg.MergeMode   = true;   // merge into the already-loaded font
        sym_cfg.OversampleH = 1;      // symbols don't need sub-pixel AA
        sym_cfg.OversampleV = 1;
        sym_cfg.GlyphOffset = ImVec2(0.0f, 1.0f);  // minor baseline alignment
        io.Fonts->AddFontFromFileTTF(symbol_font, font_size, &sym_cfg, symbol_ranges);
    }

    // ── Merge Dingbats from Menlo (fallback for ✓✕✗✂) ────────────────────
    // Apple Symbols lacks most of the Dingbats range (U+2700–U+27FF).
    // Menlo and Arial Unicode have them. Merge only Dingbats from Menlo.
    static const char* dingbat_fonts[] = {
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        nullptr
    };
    static const ImWchar dingbat_ranges[] = {
        0x2700, 0x27FF,   // Dingbats (✂✓✕✗ etc.)
        0,
    };
    for (int i = 0; dingbat_fonts[i]; i++) {
        if (FILE* df = fopen(dingbat_fonts[i], "rb")) {
            fclose(df);
            ImFontConfig ding_cfg;
            ding_cfg.MergeMode   = true;
            ding_cfg.OversampleH = 1;
            ding_cfg.OversampleV = 1;
            ding_cfg.GlyphOffset = ImVec2(0.0f, 1.0f);
            io.Fonts->AddFontFromFileTTF(dingbat_fonts[i], font_size, &ding_cfg, dingbat_ranges);
            break;
        }
    }

    // ── Merge FontAwesome 6 Solid icons ─────────────────────────────────
    // Embedded as compressed C array — no file path dependency at runtime.
    // Covers PUA range U+E005–U+F8FF used by FA6 solid icons.
    {
        static const ImWchar fa_ranges[] = {
            ICON_MIN_FA, ICON_MAX_FA,
            0,
        };
        ImFontConfig fa_cfg;
        fa_cfg.MergeMode   = true;
        fa_cfg.OversampleH = 1;
        fa_cfg.OversampleV = 1;
        fa_cfg.GlyphOffset = ImVec2(0.0f, 1.0f);  // baseline alignment tweak
        fa_cfg.FontDataOwnedByAtlas = false;       // we manage the static data
        io.Fonts->AddFontFromMemoryCompressedTTF(
            FontAwesomeSolid_compressed_data,
            FontAwesomeSolid_compressed_size,
            font_size, &fa_cfg, fa_ranges);
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

    // ScaleAllSizes is CUMULATIVE — calling it every time apply_settings() is
    // invoked multiplies sizes by dpi_scale_ again and again, eventually making
    // the UI either gigantic or invisible.  The initial call in setup_style()
    // already scaled the style once; subsequent calls must NOT scale again.
    // (Font size changes go through rebuild_fonts(); the style sizes are always
    //  based on the logical unscaled values set above, scaled once at init.)

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
//
// Tag space layout:
//   100-199  File / App
//   200-299  Edit
//   300-399  View  (panels)
//   400-499  Navigate
//   500-599  Analysis  (run passes)
//   600-699  Export
//   700-799  Tools  (one-shot queries / diagnostics)
//   800-899  Help
//
enum MenuTag : NSInteger {
    // ── File / App: 100-199 ──────────────────────────────────────────
    kTagFileQuit              = 100,

    // ── Edit: 200-299 ───────────────────────────────────────────────
    kTagEditSettings          = 200,

    // ── View — Core panels: 300-309 ─────────────────────────────────
    kTagViewRegisters         = 300,
    kTagViewMemory            = 301,
    kTagViewCallStack         = 302,
    kTagViewAnalysis          = 303,
    kTagViewHexDump           = 304,
    kTagViewStrings           = 305,
    kTagViewFunctions         = 306,
    kTagViewThreads           = 307,

    // ── View — Visualization: 310-319 ───────────────────────────────
    kTagViewMinimap           = 310,
    kTagViewLoops             = 311,
    kTagViewCFG               = 312,

    // ── View — Analysis Results (ObjC/iOS): 320-329 ─────────────────
    kTagViewObjC              = 320,
    kTagViewLoopSemantics     = 321,
    kTagViewPatterns          = 322,
    kTagViewConstants         = 323,
    kTagViewAlgoSummary       = 324,
    kTagViewCallGraph         = 325,
    kTagViewObjCCrypto        = 326,
    kTagViewMemStrings        = 327,
        kTagViewSyscallIntercept  = 328,


    // ── View — Profiling & Diff: 330-339 ────────────────────────────
    kTagViewRegTimeline       = 330,
    kTagViewDwarf             = 331,
    kTagViewTraceDiff         = 332,
    kTagViewTraceFold         = 333,
    kTagViewLog               = 334,
    kTagViewCacheManager      = 335,

    // ── Navigate: 400-419 ───────────────────────────────────────────
    kTagNavGoto               = 400,
    kTagNavSearch             = 401,
    kTagNavBack               = 402,
    kTagNavForward            = 403,
    kTagNavFirst              = 404,
    kTagNavLast               = 405,
    kTagNavBookmark           = 406,
    kTagNavFollowCall         = 407,
    kTagNavFollowReturn       = 408,
    kTagNavNextTainted        = 410,
    kTagNavPrevTainted        = 411,
    kTagNavNextBackTainted    = 412,
    kTagNavPrevBackTainted    = 413,

    // ── Analysis — Data Flow: 500-509 ───────────────────────────────
    kTagAnaTaint              = 500,
    kTagAnaBackTaint          = 501,
    kTagAnaRegTimeline        = 503,
    kTagAnaProducerChain      = 504,

    // ── Analysis — Structure: 510-519 ───────────────────────────────
    kTagAnaFunction           = 510,
    kTagAnaXref               = 511,
    kTagAnaStrings            = 512,
    kTagAnaThread             = 513,
    kTagAnaCallGraph          = 514,
    kTagAnaLoop               = 515,
    kTagAnaCFG                = 516,

    // ── Analysis — Crypto & Pattern: 520-529 ────────────────────────
    kTagAnaPattern            = 520,
    kTagAnaConstants          = 521,
    kTagAnaLoopSemantics      = 522,
    kTagAnaAlgoSummary        = 523,
    kTagAnaObjCCrypto         = 524,

    // ── Analysis — ObjC / iOS: 530-539 ──────────────────────────────
    kTagAnaObjC               = 530,
    kTagAnaAPIIntercepts      = 531,

    // ── Analysis — Profiling: 540-549 ───────────────────────────────
        kTagAnaTraceFold          = 541,
    kTagAnaTraceDiff          = 542,
    kTagAnaMemStrings         = 543,

    // ── Analysis — Reverse Engineering / VM: 550-559 ────────────────
    kTagAnaVMAbstract         = 550,

    // ── View — VM Abstract / Workspace: 340-349 ──────────────────────
    kTagViewVMAbstract        = 340,
    kTagViewVMWorkspace       = 341,

    // ── Analysis — Maintenance: 590-599 ─────────────────────────────
    kTagAnaClearTaint         = 590,
    kTagAnaClear              = 591,

    // ── Export: 600-699 ─────────────────────────────────────────────
    kTagExportCFG             = 600,
    kTagExportCallGraph       = 601,
    kTagExportBackwardTaintGraph = 602,
    kTagExportDataflowGraph   = 603,

    // ── Tools: 700-799 ──────────────────────────────────────────────
    kTagToolEntropy           = 700,
    kTagToolMemSnapshot       = 701,
    kTagToolLiteralSearch     = 702,
    kTagToolMemSearch         = 703,
    kTagToolYaraScan          = 704,
    kTagToolMemHistory        = 705,
    kTagToolCallContext       = 706,

    // ── Help: 800-899 ───────────────────────────────────────────────
    kTagHelpAbout             = 800,
    kTagHelpDocs              = 801,
    kTagHelpShortcuts         = 802,
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
        // ── File / App ──────────────────────────────────────────────────
        case kTagFileQuit:          action = [this]{ begin_shutdown(); }; break;
        case kTagEditSettings:      action = [this]{ show_settings_ = true; }; break;

        // ── View — Core Panels ───────────────────────────────────────────
        case kTagViewRegisters:     action = [this]{ show_registers_         = !show_registers_;         }; break;
        case kTagViewMemory:        action = [this]{ show_memory_             = !show_memory_;             }; break;
        case kTagViewCallStack:     action = [this]{ show_callstack_          = !show_callstack_;          }; break;
        case kTagViewAnalysis:      action = [this]{ show_analysis_           = !show_analysis_;           }; break;
        case kTagViewHexDump:       action = [this]{ show_hex_dump_           = !show_hex_dump_;           }; break;
        case kTagViewStrings:       action = [this]{ show_strings_            = !show_strings_;            }; break;
        case kTagViewFunctions:     action = [this]{ show_functions_          = !show_functions_;          }; break;
        case kTagViewThreads:       action = [this]{ show_threads_            = !show_threads_;            }; break;

        // ── View — Visualization ─────────────────────────────────────────
        case kTagViewMinimap:       action = [this]{ show_minimap_            = !show_minimap_;            }; break;
        case kTagViewLoops:         action = [this]{ show_loops_              = !show_loops_;              }; break;
        case kTagViewCFG:           action = [this]{ show_cfg_                = !show_cfg_;                }; break;
        case kTagViewCallGraph:     action = [this]{ show_call_graph_         = !show_call_graph_;         }; break;

        // ── View — Analysis Results ──────────────────────────────────────
        case kTagViewObjC:          action = [this]{ show_objc_               = !show_objc_;               }; break;
        case kTagViewLoopSemantics: action = [this]{ show_loop_semantics_     = !show_loop_semantics_;     }; break;
        case kTagViewPatterns:      action = [this]{ show_pattern_            = !show_pattern_;            }; break;
        case kTagViewConstants:     action = [this]{ show_constant_           = !show_constant_;           }; break;
        case kTagViewAlgoSummary:   action = [this]{ show_algorithm_summary_  = !show_algorithm_summary_;  }; break;
        case kTagViewObjCCrypto:       action = [this]{ show_objc_crypto_        = !show_objc_crypto_;        }; break;
        case kTagViewMemStrings:       action = [this]{ show_mem_strings_        = !show_mem_strings_;        }; break;
case kTagViewSyscallIntercept: action = [this]{ show_syscall_intercept_  = !show_syscall_intercept_;  }; break;
case kTagViewVMAbstract:       action = [this]{ show_vm_abstract_        = !show_vm_abstract_;        }; break;
case kTagViewVMWorkspace:      action = [this]{
    vm_ws_open_ = !vm_ws_open_;
    if (vm_ws_open_) vm_ws_first_frame_ = true;
}; break;

// ── View — Profiling & Diff ──────────────────────────────────────
        case kTagViewTraceFold:        action = [this]{ show_trace_fold_         = !show_trace_fold_;         }; break;
        case kTagViewRegTimeline:      action = [this]{ show_reg_timeline_       = !show_reg_timeline_;       }; break;
        case kTagViewDwarf:         action = [this]{ show_dwarf_panel_        = !show_dwarf_panel_;        }; break;
        case kTagViewTraceDiff:     action = [this]{ show_trace_diff_         = !show_trace_diff_;         }; break;

        // ── View — Tools ─────────────────────────────────────────────────
        case kTagViewLog:           action = [this]{ show_log_                = !show_log_;                }; break;
        case kTagViewCacheManager:  action = [this]{ show_cache_manager_      = !show_cache_manager_;      cache_manager_dirty_ = true; }; break;

        // ── Navigate ─────────────────────────────────────────────────────
        case kTagNavGoto:           action = [this]{ show_goto_popup_   = true; }; break;
        case kTagNavSearch:         action = [this]{ show_search_popup_ = true; }; break;
        case kTagNavBack:           action = [this]{ nav_back();    }; break;
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
        // Taint navigation (enabled only when taint/backward-taint result is present)
        case kTagNavNextTainted:      action = [this]{ if (show_taint_ && taint_result_) jump_taint_next(); }; break;
        case kTagNavPrevTainted:      action = [this]{ if (show_taint_ && taint_result_) jump_taint_prev(); }; break;
        case kTagNavNextBackTainted:  action = [this]{ if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_next(); }; break;
        case kTagNavPrevBackTainted:  action = [this]{ if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_prev(); }; break;

        // ── Analysis — Data Flow ─────────────────────────────────────────
case kTagAnaTaint:          action = [this]{ run_taint_analysis(); }; break;
case kTagAnaBackTaint:      action = [this]{ run_backward_taint_analysis(); }; break;
case kTagAnaRegTimeline:
            action = [this]{ show_reg_timeline_ = true; reg_timeline_dirty_ = true; };
            break;
        case kTagAnaProducerChain:
            action = [this]{ show_reg_timeline_ = true; run_producer_chain(current_inst_, reg_timeline_reg_); };
            break;

        // ── Analysis — Structure ─────────────────────────────────────────
        case kTagAnaFunction:       action = [this]{ run_pass_by_name("function"); }; break;
        case kTagAnaXref:           action = [this]{ run_pass_by_name("xref"); }; break;
        case kTagAnaStrings:        action = [this]{ run_pass_by_name("strings"); }; break;
        case kTagAnaThread:         action = [this]{ run_pass_by_name("thread"); }; break;
        case kTagAnaCallGraph:      action = [this]{ run_call_graph_analysis(); }; break;
        case kTagAnaLoop:           action = [this]{ run_pass_by_name("loop"); }; break;
        case kTagAnaCFG:            action = [this]{ run_cfg_layout(); }; break;

        // ── Analysis — Crypto & Pattern ──────────────────────────────────
        case kTagAnaPattern:        action = [this]{ run_pass_by_name("pattern"); show_pattern_ = true; }; break;
        case kTagAnaConstants:      action = [this]{ run_pass_by_name("pattern"); show_constant_ = true; }; break;
        case kTagAnaLoopSemantics:  action = [this]{ run_pass_by_name("loop_semantics"); show_loop_semantics_ = true; }; break;
        case kTagAnaAlgoSummary:    action = [this]{ run_pass_by_name("algorithm_summary"); show_algorithm_summary_ = true; }; break;
        case kTagAnaObjCCrypto:     action = [this]{ run_pass_by_name("objc_crypto"); show_objc_crypto_ = true; }; break;

// ── Analysis — ObjC / iOS ────────────────────────────────────────
case kTagAnaObjC:           action = [this]{ run_pass_by_name("objc"); show_objc_ = true; }; break;
case kTagAnaAPIIntercepts:  action = [this]{ run_pass_by_name("syscall_intercept"); show_syscall_intercept_ = true; }; break;

// ── Analysis — Reverse Engineering / VM ──────────────────────────
// vm_abstract requires static-analysis hints before it can run (its
// heuristic auto-detection is unreliable on real traces) — just open the
// panel where the user loads a hints file / opts into auto-detect, rather
// than attempting (and silently failing) to run immediately.
case kTagAnaVMAbstract:     action = [this]{
    show_vm_abstract_ = true;
    if (vm_abstract_result_) {
        vm_ws_open_ = true;
        vm_ws_first_frame_ = true;
    }
}; break;

        // ── Analysis — Profiling ─────────────────────────────────────────
        case kTagAnaTraceFold:      action = [this]{ run_pass_by_name("trace_fold"); show_trace_fold_ = true; }; break;
        case kTagAnaTraceDiff:      action = [this]{ show_trace_diff_ = true; }; break;
        case kTagAnaMemStrings:     action = [this]{ run_pass_by_name("memory_strings"); show_mem_strings_ = true; }; break;

        // ── Analysis — Maintenance ───────────────────────────────────────
        case kTagAnaClearTaint:
            action = [this]{
        show_taint_           = false;
        show_backward_taint_  = false;
        taint_result_         = nullptr;
        backward_taint_result_= nullptr;
        taint_sorted_ids_dirty_ = true;
            };
            break;
        case kTagAnaClear:          action = [this]{ clear_analysis(); }; break;

        // ── Export ───────────────────────────────────────────────────────
        case kTagExportCFG:
            action = [this]{ export_cfg_to_file(); }; break;
        case kTagExportCallGraph:
            action = [this]{ export_call_graph_to_file(); }; break;
        case kTagExportBackwardTaintGraph:
            action = [this]{ export_backward_taint_graph_to_file(); }; break;
        case kTagExportDataflowGraph:
            action = [this]{ /* TODO: dataflow_graph pass not yet plumbed into GUI */ }; break;

        // ── Tools ────────────────────────────────────────────────────────
        // Tools open a small modal in the Analysis panel (reuse show_analysis_)
        case kTagToolEntropy:
            action = [this]{ show_entropy_ = true; /* pre-fill from memory context */
                if (ctx_mem_addr_ != 0 && entropy_addr_buf_[0] == '\0') {
                    snprintf(entropy_addr_buf_, sizeof(entropy_addr_buf_),
                             "%llx", (unsigned long long)ctx_mem_addr_);
                }
            }; break;
        case kTagToolMemSnapshot:
            action = [this]{ run_pass_by_name("memory_snapshot"); show_analysis_ = true; }; break;
        case kTagToolLiteralSearch:
            action = [this]{ run_pass_by_name("literal_search"); show_analysis_ = true; }; break;
        case kTagToolMemSearch:
            action = [this]{ run_pass_by_name("mem_search"); show_analysis_ = true; }; break;
        case kTagToolYaraScan:
            action = [this]{ run_pass_by_name("yara_mem_scan"); show_analysis_ = true; }; break;
        case kTagToolMemHistory:
            action = [this]{ show_memory_ = true; }; break;
        case kTagToolCallContext:
            action = [this]{ run_pass_by_name("call_context"); show_analysis_ = true; }; break;

        // ── Help ─────────────────────────────────────────────────────────
        case kTagHelpShortcuts:
            action = [this]{ show_settings_ = true; /* TODO: jump to shortcuts tab */ }; break;
        case kTagHelpAbout:
        case kTagHelpDocs:
            break;  // handled by native NSApp actions or not yet implemented

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

            // ── Navigate: enable/disable based on state ──────────────────
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
            // Taint jump items: only enabled when the corresponding result is active
            case kTagNavNextTainted:
            case kTagNavPrevTainted:
                it.enabled = (show_taint_ && taint_result_ != nullptr); break;
            case kTagNavNextBackTainted:
            case kTagNavPrevBackTainted:
                it.enabled = (show_backward_taint_ && backward_taint_result_ != nullptr); break;

            // ── View: checkmarks for panel visibility ────────────────────
            case kTagViewRegisters:        it.state = show_registers_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMemory:           it.state = show_memory_             ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCallStack:        it.state = show_callstack_          ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewAnalysis:         it.state = show_analysis_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewHexDump:          it.state = show_hex_dump_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewStrings:          it.state = show_strings_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewFunctions:        it.state = show_functions_          ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewThreads:          it.state = show_threads_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMinimap:          it.state = show_minimap_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewLoops:            it.state = show_loops_              ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCFG:              it.state = show_cfg_                ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCallGraph:        it.state = show_call_graph_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewObjC:             it.state = show_objc_               ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewLoopSemantics:    it.state = show_loop_semantics_     ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewPatterns:         it.state = show_pattern_            ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewConstants:        it.state = show_constant_           ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewAlgoSummary:      it.state = show_algorithm_summary_  ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewObjCCrypto:       it.state = show_objc_crypto_        ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewMemStrings:       it.state = show_mem_strings_        ? NSControlStateValueOn : NSControlStateValueOff; break;
case kTagViewSyscallIntercept: it.state = show_syscall_intercept_  ? NSControlStateValueOn : NSControlStateValueOff; break;
case kTagViewVMAbstract:       it.state = show_vm_abstract_        ? NSControlStateValueOn : NSControlStateValueOff; break;
case kTagViewVMWorkspace:      it.state = vm_ws_open_              ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewTraceFold:        it.state = show_trace_fold_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewRegTimeline:      it.state = show_reg_timeline_       ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewDwarf:            it.state = show_dwarf_panel_        ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewTraceDiff:        it.state = show_trace_diff_         ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewLog:              it.state = show_log_                ? NSControlStateValueOn : NSControlStateValueOff; break;
            case kTagViewCacheManager:     it.state = show_cache_manager_      ? NSControlStateValueOn : NSControlStateValueOff; break;

            // ── Export: disable if required result not yet computed ───────
            case kTagExportBackwardTaintGraph:
                it.enabled = (backward_taint_result_ != nullptr); break;

            // ── Analysis — Clear Taint: only useful when taint is active ─
        case kTagAnaClearTaint:
            it.enabled = (show_taint_ || show_backward_taint_); break;

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
    const NSUInteger Opt   = NSEventModifierFlagOption;

    auto mk = [&](NSString* title, NSString* key, NSUInteger mods, NSInteger tag) -> NSMenuItem* {
        return tenet_make_item(title, key, mods, tag, target);
    };
    auto sep = []() -> NSMenuItem* { return [NSMenuItem separatorItem]; };
    auto sub = [&](NSString* title) -> NSMenu* {
        return tenet_make_submenu(title, delegate);
    };
    // Helper: build a titled submenu item and attach it as a child menu
    auto mksub = [&](NSMenu* parent, NSString* title) -> NSMenu* {
        NSMenuItem* holder = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
        NSMenu* m = sub(title);
        holder.submenu = m;
        [parent addItem:holder];
        return m;
    };

    NSMenu* bar = [[NSMenu alloc] initWithTitle:@"MainMenu"];

    // ╔═══════════════════════════════════╗
    // ║         Tenet (App) menu          ║
    // ╚═══════════════════════════════════╝
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

    // ╔═══════════════════════════════════╗
    // ║            File menu              ║
    // ╚═══════════════════════════════════╝
    {
        NSMenuItem* fileItem = [[NSMenuItem alloc] initWithTitle:@"File" action:nil keyEquivalent:@""];
        NSMenu* fileMenu = sub(@"File");
        NSMenuItem* openItem = [[NSMenuItem alloc] initWithTitle:@"Open Trace\u2026"
                                                          action:nil
                                                   keyEquivalent:@"o"];
        openItem.keyEquivalentModifierMask = Cmd;
        openItem.enabled = NO;  // TODO: file dialog
        [fileMenu addItem:openItem];
        // Recent files are managed in the ImGui menu (dynamic list);
        // native side only shows the static items.
        fileItem.submenu = fileMenu;
        [bar addItem:fileItem];
    }

    // ╔═══════════════════════════════════════════════════════════════╗
    // ║  View menu  —  organised into four sub-menus + Log at bottom  ║
    // ╚═══════════════════════════════════════════════════════════════╝
    {
        NSMenuItem* viewItem = [[NSMenuItem alloc] initWithTitle:@"View" action:nil keyEquivalent:@""];
        NSMenu* viewMenu = sub(@"View");

        // ── Core Panels ──────────────────────────────────────────────
        NSMenu* coreMenu = mksub(viewMenu, @"Core Panels");
        [coreMenu addItem:mk(@"Registers",       @"r", Cmd, kTagViewRegisters)];
        [coreMenu addItem:mk(@"Memory",          @"m", Cmd, kTagViewMemory)];
        [coreMenu addItem:mk(@"Hex Dump",        @"", 0,   kTagViewHexDump)];
        [coreMenu addItem:sep()];
        [coreMenu addItem:mk(@"Call Stack",      @"", 0,   kTagViewCallStack)];
        [coreMenu addItem:mk(@"Functions",       @"", 0,   kTagViewFunctions)];
        [coreMenu addItem:mk(@"Strings",         @"", 0,   kTagViewStrings)];
        [coreMenu addItem:mk(@"Threads",         @"", 0,   kTagViewThreads)];
        [coreMenu addItem:sep()];
        [coreMenu addItem:mk(@"Analysis",        @"", 0,   kTagViewAnalysis)];

        // ── Visualization ─────────────────────────────────────────────
        NSMenu* vizMenu = mksub(viewMenu, @"Visualization");
        [vizMenu addItem:mk(@"CFG View",         @"", 0, kTagViewCFG)];
        [vizMenu addItem:mk(@"Call Graph",       @"", 0, kTagViewCallGraph)];
        [vizMenu addItem:mk(@"Minimap",          @"", 0, kTagViewMinimap)];
        [vizMenu addItem:mk(@"Loop Highlight",   @"", 0, kTagViewLoops)];

        // ── Analysis Results ─────────────────────────────────────────
        NSMenu* resMenu = mksub(viewMenu, @"Analysis Results");
        [resMenu addItem:mk(@"Patterns",           @"", 0, kTagViewPatterns)];
        [resMenu addItem:mk(@"Constants",          @"", 0, kTagViewConstants)];
        [resMenu addItem:mk(@"Loop Semantics",     @"", 0, kTagViewLoopSemantics)];
        [resMenu addItem:mk(@"Algorithm Summary",  @"", 0, kTagViewAlgoSummary)];
        [resMenu addItem:sep()];
        [resMenu addItem:mk(@"ObjC Messages",      @"", 0, kTagViewObjC)];
        [resMenu addItem:mk(@"ObjC Crypto",        @"", 0, kTagViewObjCCrypto)];
        [resMenu addItem:mk(@"API Intercepts",     @"", 0, kTagViewSyscallIntercept)];
        [resMenu addItem:sep()];
        [resMenu addItem:mk(@"Memory Strings",     @"", 0, kTagViewMemStrings)];
        [resMenu addItem:sep()];
        [resMenu addItem:mk(@"VM Abstract",        @"", 0, kTagViewVMAbstract)];
[resMenu addItem:mk(@"VM Workspace",       @"", 0, kTagViewVMWorkspace)];

        // ── Profiling & Diff ──────────────────────────────────────────
        NSMenu* profMenu = mksub(viewMenu, @"Profiling & Diff");
        [profMenu addItem:mk(@"Trace Fold",          @"", 0, kTagViewTraceFold)];
        [profMenu addItem:mk(@"Register Timeline",   @"", 0, kTagViewRegTimeline)];
        [profMenu addItem:mk(@"Trace Diff",          @"", 0, kTagViewTraceDiff)];
        [profMenu addItem:sep()];
        [profMenu addItem:mk(@"Symbol Info (DWARF)", @"", 0, kTagViewDwarf)];

        [viewMenu addItem:sep()];
        [viewMenu addItem:mk(@"Output (Log)",        @"", 0, kTagViewLog)];
        [viewMenu addItem:mk(@"Cache Manager",       @"", 0, kTagViewCacheManager)];

        viewItem.submenu = viewMenu;
        [bar addItem:viewItem];
    }

    // ╔═══════════════════════════════════╗
    // ║          Navigate menu            ║
    // ╚═══════════════════════════════════╝
    {
        NSMenuItem* navItem = [[NSMenuItem alloc] initWithTitle:@"Navigate" action:nil keyEquivalent:@""];
        NSMenu* navMenu = sub(@"Navigate");

        [navMenu addItem:mk(@"Go to Instruction\u2026", @"g", Cmd, kTagNavGoto)];
        [navMenu addItem:mk(@"Search\u2026",            @"f", Cmd, kTagNavSearch)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Back",                    @"[", Cmd, kTagNavBack)];
        [navMenu addItem:mk(@"Forward",                 @"]", Cmd, kTagNavForward)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"First Instruction",       @"", 0, kTagNavFirst)];
        [navMenu addItem:mk(@"Last Instruction",        @"", 0, kTagNavLast)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Toggle Bookmark",         @"b", Cmd, kTagNavBookmark)];
        [navMenu addItem:sep()];
        [navMenu addItem:mk(@"Follow Call",             @"", 0, kTagNavFollowCall)];
        [navMenu addItem:mk(@"Follow Return",           @"", 0, kTagNavFollowReturn)];
        [navMenu addItem:sep()];
        // Taint navigation — dynamically enabled/disabled via _update_native_menu
        [navMenu addItem:mk(@"Next Tainted Instruction",          @"", 0, kTagNavNextTainted)];
        [navMenu addItem:mk(@"Prev Tainted Instruction",          @"", 0, kTagNavPrevTainted)];
        [navMenu addItem:mk(@"Next Backward-Tainted Instruction", @"", 0, kTagNavNextBackTainted)];
        [navMenu addItem:mk(@"Prev Backward-Tainted Instruction", @"", 0, kTagNavPrevBackTainted)];

        navItem.submenu = navMenu;
        [bar addItem:navItem];
    }

    // ╔════════════════════════════════════════════════════════════════════╗
    // ║  Analysis menu  —  grouped by category, each triggers a pass run  ║
    // ╚════════════════════════════════════════════════════════════════════╝
    {
        NSMenuItem* anaItem = [[NSMenuItem alloc] initWithTitle:@"Analysis" action:nil keyEquivalent:@""];
        NSMenu* anaMenu = sub(@"Analysis");

        // ── Data Flow ─────────────────────────────────────────────────
        NSMenu* dfMenu = mksub(anaMenu, @"Data Flow");
[dfMenu addItem:mk(@"Forward Taint\u2026",     @"t", Cmd,         kTagAnaTaint)];
[dfMenu addItem:mk(@"Backward Taint\u2026",    @"t", Cmd | Shift, kTagAnaBackTaint)];
[dfMenu addItem:sep()];
        [dfMenu addItem:mk(@"Register Timeline",       @"", 0, kTagAnaRegTimeline)];
        [dfMenu addItem:mk(@"Producer Chain",          @"", 0, kTagAnaProducerChain)];

        // ── Structure ─────────────────────────────────────────────────
        NSMenu* strMenu = mksub(anaMenu, @"Structure");
        [strMenu addItem:mk(@"Function Analysis",  @"", 0, kTagAnaFunction)];
        [strMenu addItem:mk(@"Xref Analysis",      @"", 0, kTagAnaXref)];
        [strMenu addItem:mk(@"String Analysis",    @"", 0, kTagAnaStrings)];
        [strMenu addItem:mk(@"Thread Analysis",    @"", 0, kTagAnaThread)];
        [strMenu addItem:sep()];
        [strMenu addItem:mk(@"Call Graph",         @"", 0, kTagAnaCallGraph)];
        [strMenu addItem:mk(@"Loop Analysis",      @"", 0, kTagAnaLoop)];
        [strMenu addItem:mk(@"CFG Layout",         @"", 0, kTagAnaCFG)];

        // ── Crypto & Pattern ──────────────────────────────────────────
        NSMenu* cpMenu = mksub(anaMenu, @"Crypto & Pattern");
        [cpMenu addItem:mk(@"Pattern Detection",   @"", 0, kTagAnaPattern)];
        [cpMenu addItem:mk(@"Constants",           @"", 0, kTagAnaConstants)];
        [cpMenu addItem:mk(@"Loop Semantics",      @"", 0, kTagAnaLoopSemantics)];
        [cpMenu addItem:mk(@"Algorithm Summary",   @"", 0, kTagAnaAlgoSummary)];
        [cpMenu addItem:mk(@"ObjC Crypto",         @"", 0, kTagAnaObjCCrypto)];

        // ── ObjC / Platform API ─────────────────────────────────────────
        NSMenu* objcMenu = mksub(anaMenu, @"ObjC / API");
        [objcMenu addItem:mk(@"ObjC Messages",     @"", 0, kTagAnaObjC)];
        [objcMenu addItem:mk(@"API Intercepts",    @"", 0, kTagAnaAPIIntercepts)];

        // ── Reverse Engineering / VM ─────────────────────────────────────
        NSMenu* reMenu = mksub(anaMenu, @"Reverse Eng / VM");
        [reMenu addItem:mk(@"VM Abstract Analysis", @"", 0, kTagAnaVMAbstract)];

        // ── Profiling ─────────────────────────────────────────────────
        NSMenu* profAnaMenu = mksub(anaMenu, @"Profiling");
        [profAnaMenu addItem:mk(@"Trace Fold",        @"", 0, kTagAnaTraceFold)];
        [profAnaMenu addItem:mk(@"Trace Diff",        @"", 0, kTagAnaTraceDiff)];
        [profAnaMenu addItem:mk(@"Memory Strings",    @"", 0, kTagAnaMemStrings)];

        [anaMenu addItem:sep()];
        [anaMenu addItem:mk(@"Clear Taint",         @"", 0, kTagAnaClearTaint)];
        [anaMenu addItem:mk(@"Clear All Analysis",  @"", 0, kTagAnaClear)];

        anaItem.submenu = anaMenu;
        [bar addItem:anaItem];
    }

    // ╔═══════════════════════════════════╗
    // ║           Export menu             ║
    // ╚═══════════════════════════════════╝
    {
        NSMenuItem* expItem = [[NSMenuItem alloc] initWithTitle:@"Export" action:nil keyEquivalent:@""];
        NSMenu* expMenu = sub(@"Export");

        [expMenu addItem:mk(@"Export CFG\u2026 (DOT)",           @"", 0, kTagExportCFG)];
        [expMenu addItem:mk(@"Export Call Graph\u2026 (DOT)",    @"", 0, kTagExportCallGraph)];
        [expMenu addItem:sep()];
        [expMenu addItem:mk(@"Export Backward Taint Graph\u2026 (DOT)", @"", 0, kTagExportBackwardTaintGraph)];
        [expMenu addItem:mk(@"Export Dataflow Graph\u2026 (DOT/JSON)",  @"", 0, kTagExportDataflowGraph)];

        expItem.submenu = expMenu;
        [bar addItem:expItem];
    }

    // ╔═══════════════════════════════════╗
    // ║            Tools menu             ║
    // ╚═══════════════════════════════════╝
    {
        NSMenuItem* toolItem = [[NSMenuItem alloc] initWithTitle:@"Tools" action:nil keyEquivalent:@""];
        NSMenu* toolMenu = sub(@"Tools");

        [toolMenu addItem:mk(@"Entropy at Cursor\u2026",         @"", 0, kTagToolEntropy)];
        [toolMenu addItem:mk(@"Memory Snapshot\u2026",           @"", 0, kTagToolMemSnapshot)];
        [toolMenu addItem:sep()];
        [toolMenu addItem:mk(@"Literal Search\u2026",            @"", 0, kTagToolLiteralSearch)];
        [toolMenu addItem:mk(@"Memory Pattern Search\u2026",     @"", 0, kTagToolMemSearch)];
#if TENET_ENABLE_YARA
        [toolMenu addItem:mk(@"YARA Scan\u2026",                 @"", 0, kTagToolYaraScan)];
#endif
        [toolMenu addItem:sep()];
        [toolMenu addItem:mk(@"Memory Write History\u2026",      @"", 0, kTagToolMemHistory)];
        [toolMenu addItem:mk(@"Call Context at Cursor\u2026",    @"", 0, kTagToolCallContext)];

        toolItem.submenu = toolMenu;
        [bar addItem:toolItem];
    }

    // ╔═══════════════════════════════════╗
    // ║            Help menu              ║
    // ╚═══════════════════════════════════╝
    {
        NSMenuItem* helpItem = [[NSMenuItem alloc] initWithTitle:@"Help" action:nil keyEquivalent:@""];
        NSMenu* helpMenu = sub(@"Help");

        [helpMenu addItem:mk(@"Keyboard Shortcuts",  @"/", Cmd, kTagHelpShortcuts)];
        [helpMenu addItem:sep()];
        NSMenuItem* docsItem = [[NSMenuItem alloc] initWithTitle:@"Documentation"
                                                          action:nil
                                                   keyEquivalent:@""];
        docsItem.enabled = NO;   // TODO: open docs URL
        [helpMenu addItem:docsItem];

        helpItem.submenu = helpMenu;
        [bar addItem:helpItem];
    }

    [NSApp setMainMenu:bar];
}

// Re-open namespace for the rest of the file (run loop, render_frame, etc.)
namespace tenet {

// ─── Main Run Loop ──────────────────────────────────────────────────────────

int GuiApp::run() {
    if (!init_sdl()) return 1;
    if (!init_imgui()) return 1;

    // Set window title to include trace file info
    {
        std::string filename = trace_path_.filename().string();
        const auto& hdr = reader_.header();
        std::string title = fmt::format("Tenet - {} [{}  {}  {} instrs]",
            filename, hdr.module_name,
            hdr.arch == 1 ? "AArch64" : "x86_64",
            index_.inst_count());
        SDL_SetWindowTitle(window_, title.c_str());
    }

    // Build native macOS menu bar and assign to [NSApp mainMenu].
    // Must be called after SDL/ImGui are initialised (NSApp is ready).
    setup_native_menu();

    // Force the application to become the active (foreground) app immediately.
    // Without this, macOS keeps showing the previously-active app's menu bar
    // until the user clicks the window, because SDL3 does not call
    // -activateIgnoringOtherApps: on launch.
    [NSApp activateIgnoringOtherApps:YES];

    // Pump the AppKit run loop briefly so that:
    //  1. The [NSApp setMainMenu:] change is committed and the new menu bar
    //     is actually drawn at the top of the screen.
    //  2. The activateIgnoringOtherApps: notification is delivered so the
    //     app becomes the frontmost application immediately.
    //
    // Without this, macOS queues NSUpdateMenuItemRequest and the activation
    // events internally, but they are not processed until SDL_PollEvent()
    // calls nextEventMatchingMask:, which only happens after all setup.
    // The result: a noticeable delay between launch and the menu bar appearing.
    //
    // Strategy:
    //  a) Run the NSDefaultRunLoopMode briefly (50 ms max, non-blocking after
    //     the first empty drain) to flush pending AppKit notifications.
    //  b) Call [NSApp updateWindows] to force any deferred window/menu updates.
    {
        // Drain pending AppKit events non-blockingly.
        // [NSDate distantPast] = return immediately when queue is empty.
        NSDate* deadline = [NSDate distantPast];
        for (;;) {
            NSEvent* ev = [NSApp nextEventMatchingMask:NSEventMaskAny
                                             untilDate:deadline
                                                inMode:NSDefaultRunLoopMode
                                               dequeue:YES];
            if (!ev) break;
            [NSApp sendEvent:ev];
        }
        // Run the default run-loop mode for one short spin to let AppKit
        // dispatch NSApplicationDidBecomeActiveNotification and redraw the
        // menu bar.  CFRunLoopRunInMode returns immediately if nothing fires.
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, false);
    }

    // Start the background analysis worker thread (processes manual triggers).
    start_analysis_worker();

    // Kick off background startup analysis immediately after UI is ready.
    // The analyses run in a separate thread; results are delivered via
    // pending_apply_ and applied on the UI thread each frame.
    run_startup_analysis();

    // NOTE: auto_start_mcp() is intentionally deferred to the first rendered
    // frame (see below).  Calling it here — before the SDL event loop starts —
    // blocks the main thread on socket bind / port-scan retries, which prevents
    // macOS from processing AppKit events and delays the menu bar appearance.

    while (running_) {
        // ─── 0. Per-frame autorelease pool ──────────────────────────
        // SDL3's SDL_PollEvent() calls Cocoa's nextEventMatchingMask: which
        // creates autorelease ObjC objects (NSCGEventBuffer, NSEvent, etc.)
        // every mouse/keyboard event.  Without a local pool these accumulate
        // indefinitely — SDL3 Issue #14256.  The inner @autoreleasepool around
        // Metal rendering (below) does NOT cover SDL event polling, so we add
        // an outer pool spanning the entire loop iteration.
        @autoreleasepool {

        // ─── 1. Poll SDL events ─────────────────────────────────────
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            // During shutdown, suppress all input except the raw quit signal
            // (which we handle ourselves below).
            if (!shutdown_requested_.load(std::memory_order_acquire)) {
                ImGui_ImplSDL3_ProcessEvent(&event);
            }

            if (event.type == SDL_EVENT_QUIT ||
               (event.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                event.window.windowID == SDL_GetWindowID(window_))) {
                begin_shutdown();
            }
        }

        // ─── 1.45. Drain the main dispatch queue (non-blocking) ────────
        // ImGui's Metal backend returns used MTLBuffers to its cache via
        // dispatch_async(dispatch_get_main_queue(), ...) in the command buffer
        // completion handler.  In a SDL tight render loop (no CFRunLoop), these
        // blocks never execute unless we explicitly drain the queue.  Without
        // this, ImGui allocates new Metal buffers every frame instead of
        // reusing old ones, causing unbounded IOAccelerator memory growth.
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, false);

        // ─── 1.5. Check whether async shutdown has completed ─────────
        if (shutdown_complete_.load(std::memory_order_acquire)) {
            running_ = false;
            continue;   // skip rendering and fall out of the loop
        }

        // ─── 1.55. Deferred MCP auto-start (after first rendered frame) ──
        // auto_start_mcp() does up to 16 socket bind attempts, each of which
        // can block the calling thread briefly.  Doing this before the render
        // loop starts would stall macOS AppKit event processing and delay
        // the menu bar appearance.  Instead we post it to the analysis worker
        // queue after the first frame has been drawn so the UI is already visible.
        // auto_start_mcp() accesses mcp_service_ (a UI-thread-only member), so it
        // must run on the UI thread via enqueue_async → post_apply.
        if (!first_frame_ && !mcp_autostart_done_.exchange(true)) {
            enqueue_async("mcp_autostart", [this]() {
                // Perform the blocking socket bind off the UI thread.
                // We cannot touch mcp_service_ here; instead we capture the
                // result and apply it back on the UI thread via post_apply.
                ensure_pass_manager();  // pass_manager_ is thread-safe for init

                // Build a temporary TenetMcpService and try to bind a port.
                // This is the only blocking part; everything else is quick.
                auto svc = std::make_unique<TenetMcpService>(
                    reader_, index_, regfile_, memory_,
                    pass_manager_.get(), &code_table_, &decoder_);

                McpHttpConfig cfg;
                cfg.host = mcp_gui_.host;
                auto base_port = static_cast<uint16_t>(mcp_gui_.port);

                constexpr int kMaxRetries = 16;
                bool started = false;
                uint16_t actual_port = base_port;
                for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
                    cfg.port = static_cast<uint16_t>(base_port + attempt);
                    if (svc->start_http(cfg)) {
                        actual_port = svc->http_listening_port();
                        started = true;
                        break;
                    }
                }

                // Hand ownership and result back to the UI thread.
                // std::function requires copyable captures, so wrap in shared_ptr.
                auto svc_owner = std::make_shared<std::unique_ptr<TenetMcpService>>(std::move(svc));
                post_apply([this, svc_owner, started, actual_port, base_port]() {
                    if (started) {
                        mcp_service_ = std::move(*svc_owner);
                        mcp_gui_.port = actual_port;
                        mcp_status_msg_ = fmt::format(
                            "Auto-started on {}:{}", mcp_gui_.host, actual_port);
                    } else {
                        // svc_owner (and the TenetMcpService it wraps) are
                        // destroyed here on the UI thread — correct teardown.
                        svc_owner->reset();
                        mcp_status_msg_ = fmt::format(
                            "Auto-start failed: ports {}-{} all in use.",
                            base_port, base_port + kMaxRetries - 1);
                    }
                });
            });
        }

        // ─── 1.6. Apply pending analysis results on the UI thread ────
        // Skip during shutdown — workers are already being drained.
        if (!shutdown_requested_.load(std::memory_order_acquire)) {
            apply_pending_results();
        }

        // ─── 2.5. Rebuild fonts if needed (must happen BEFORE acquiring
        //         the drawable / creating the render encoder).
        // ImGui_ImplMetal_DestroyFontsTexture() enqueues GPU work and must
        // not be called while a render pass is already open.  Doing it here
        // — before dispatch_semaphore_wait — guarantees no render pass is
        // in flight when the old texture is destroyed.
        if (settings_font_dirty_) {
            rebuild_fonts();
            settings_font_dirty_ = false;
        }

        // ─── 2. Acquire Metal drawable and begin render pass ─────────
        // The entire Metal rendering block (semaphore wait → drawable acquire
        // → submit → commit) is wrapped in a SINGLE @autoreleasepool.
        // This ensures the CAMetalDrawable (and its backing texture) are
        // released immediately at the end of the block — not delayed until
        // the outer per-frame pool drains.  Holding a drawable too long
        // prevents Metal from reusing it and causes unbounded VRAM growth.
        @autoreleasepool {

        // Throttle: wait until the GPU has finished one of the in-flight
        // frames before submitting another.  This caps memory usage to
        // kMaxInflightFrames worth of GPU resources (~a few hundred MB)
        // instead of letting hundreds of command buffers pile up (30+ GB).
        dispatch_semaphore_wait(frame_semaphore_, DISPATCH_TIME_FOREVER);

        id<CAMetalDrawable> drawable = [metal_layer_ nextDrawable];
        if (!drawable) {
            // No drawable available — signal semaphore back so we don't
            // permanently consume a slot, then retry next iteration.
            dispatch_semaphore_signal(frame_semaphore_);
            // Pool drains here — no drawable was retained.
        } else {
            // Configure render pass descriptor
            metal_render_pass_desc_.colorAttachments[0].texture = drawable.texture;
            metal_render_pass_desc_.colorAttachments[0].loadAction = MTLLoadActionClear;
            metal_render_pass_desc_.colorAttachments[0].storeAction = MTLStoreActionStore;
            metal_render_pass_desc_.colorAttachments[0].clearColor = MTLClearColorMake(0.098, 0.098, 0.118, 1.0);

            id<MTLCommandBuffer> commandBuffer = [metal_command_queue_ commandBuffer];
            id<MTLRenderCommandEncoder> renderEncoder =
                [commandBuffer renderCommandEncoderWithDescriptor:metal_render_pass_desc_];

            // ─── 3. Start ImGui frame ────────────────────────────────
            ImGui_ImplMetal_NewFrame(metal_render_pass_desc_);
            ImGui_ImplSDL3_NewFrame();
            ImGui::NewFrame();

            // ─── 4. Render application content (DockSpace + panels) ──
            render_frame();

            // ─── 5. Finalize ImGui rendering ─────────────────────────
            ImGui::Render();
            TENET_FRAME_MARK;
            ImGui_ImplMetal_RenderDrawData(
                ImGui::GetDrawData(), commandBuffer, renderEncoder);

            // ─── 6. End encoding and present ─────────────────────────
            [renderEncoder endEncoding];
            [commandBuffer presentDrawable:drawable];

            // Signal the in-flight semaphore once the GPU finishes this frame.
            // This allows the render loop to submit the next command buffer.
            __block dispatch_semaphore_t sema = frame_semaphore_;
            [commandBuffer addCompletedHandler:^(id<MTLCommandBuffer>) {
                dispatch_semaphore_signal(sema);
            }];

            [commandBuffer commit];

            // ─── 7. Release the drawable texture reference immediately ──
            // metal_render_pass_desc_ is a long-lived GuiApp member.  Its
            // colorAttachments[0].texture property holds a strong ARC reference
            // to the drawable's backing texture.  If we leave it set, the
            // drawable cannot be returned to Metal's reuse pool until the next
            // frame overwrites it — effectively keeping TWO drawables live at
            // all times instead of one, doubling peak VRAM pressure.
            // Clearing to nil here releases the reference immediately after
            // commit, allowing Metal to recycle the drawable right away.
            metal_render_pass_desc_.colorAttachments[0].texture = nil;
        }

        } // @autoreleasepool (Metal rendering — drawable released here)

        } // @autoreleasepool (outer per-frame pool — SDL event ObjC objects)
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
    TENET_ZONE_NAMED("GuiApp::render_frame");
    // During shutdown: skip all panels/popups and just render the overlay.
    // This keeps the window alive and animated while background threads drain.
    if (shutdown_requested_.load(std::memory_order_acquire)) {
        render_shutdown_overlay();
        return;
    }

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
    // Layout proportions (IDA Pro / Binary Ninja inspired):
    //   Left  15% : Functions / Threads / Symbol Info sidebar
    //   Center 65%: Instructions / CFG / Strings / all analysis-result panels
    //               (tabbed together — user switches between them)
    //   Right  20%: Registers (top) / Memory Accesses + Register Timeline (bottom)
    //   Bottom 22% of center: Analysis / Call Stack / Hex Dump / Minimap
    //
    // Every panel gets a pre-assigned dock slot so ImGui never creates a
    // floating window on first launch.  Analysis-result panels (ObjC, Crypto,
    // Pattern, Constants, etc.) are placed in center_main alongside Instructions
    // so they feel like IDA's tabbed sub-views, not random pop-ups.
    if (first_frame_) {
        first_frame_ = false;

        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, ImVec2(viewport->WorkSize.x, dockspace_h));

        // ── Step 1: carve off left sidebar (15%) ──
        ImGuiID dock_left_sidebar, dock_rest;
        ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.15f,
                                    &dock_left_sidebar, &dock_rest);

        // ── Step 2: carve off right panel (≈24% of remaining ≈ 20% of total) ──
        ImGuiID dock_center, dock_right;
        ImGui::DockBuilderSplitNode(dock_rest, ImGuiDir_Right, 0.24f,
                                    &dock_right, &dock_center);

        // ── Step 3: split center vertically: main (72%) | bottom area (28%) ──
        ImGuiID dock_center_main, dock_center_bottom_full;
        ImGui::DockBuilderSplitNode(dock_center, ImGuiDir_Down, 0.28f,
                                    &dock_center_bottom_full, &dock_center_main);

        // ── Step 3b: bottom area is a single tab group (no left/right split) ──
        ImGuiID dock_center_bottom = dock_center_bottom_full;

        // ── Step 4: split right vertically: registers (62%) | right-bottom (38%) ──
        ImGuiID dock_right_regs, dock_right_bottom;
        ImGui::DockBuilderSplitNode(dock_right, ImGuiDir_Down, 0.38f,
                                    &dock_right_bottom, &dock_right_regs);

        // ── Assign windows to nodes ──────────────────────────────────────

        // Left sidebar: Symbol Info + Threads + Functions
        // Functions is last → default active tab
        ImGui::DockBuilderDockWindow("Symbol Info (DWARF / nm)##P213", dock_left_sidebar);
        ImGui::DockBuilderDockWindow("Threads",   dock_left_sidebar);
        ImGui::DockBuilderDockWindow("Functions", dock_left_sidebar);

        // Center main (tabbed): all analysis-result panels + core viewers.
        // Order matters: the LAST call is the default active tab → Instructions.
        // Analysis-result panels (loaded lazily) are placed here so they pop up
        // as tabs next to Instructions rather than floating windows.
        ImGui::DockBuilderDockWindow("Trace Diff##P214",    dock_center_main);
        ImGui::DockBuilderDockWindow("Trace Fold",          dock_center_main);
        ImGui::DockBuilderDockWindow("Loop Semantics",      dock_center_main);
        ImGui::DockBuilderDockWindow("Algorithm Summary",   dock_center_main);
        ImGui::DockBuilderDockWindow("Call Graph",          dock_center_main);
        ImGui::DockBuilderDockWindow("Memory Strings",      dock_center_main);
        ImGui::DockBuilderDockWindow("API Intercepts",      dock_center_main);
        ImGui::DockBuilderDockWindow("ObjC Crypto",         dock_center_main);
        ImGui::DockBuilderDockWindow("ObjC Messages",       dock_center_main);
        ImGui::DockBuilderDockWindow("Patterns",            dock_center_main);
        ImGui::DockBuilderDockWindow("Constants",           dock_center_main);
        ImGui::DockBuilderDockWindow("CFG",                 dock_center_main);
        ImGui::DockBuilderDockWindow("Strings",             dock_center_main);
        ImGui::DockBuilderDockWindow("Instructions",        dock_center_main);  // ← default active

        // Center bottom: all secondary panels in a single tab group
        ImGui::DockBuilderDockWindow("Call Stack",  dock_center_bottom);
        ImGui::DockBuilderDockWindow("Hex Dump",    dock_center_bottom);
        ImGui::DockBuilderDockWindow("Output",      dock_center_bottom);
        ImGui::DockBuilderDockWindow("Minimap",     dock_center_bottom);
        ImGui::DockBuilderDockWindow("Analysis",    dock_center_bottom);  // ← default active

        // Right top: Registers
        ImGui::DockBuilderDockWindow("Registers", dock_right_regs);

        // Right bottom: Memory Accesses + Register Timeline
        // Memory Accesses is last → default active tab
        ImGui::DockBuilderDockWindow("Register Timeline##P212", dock_right_bottom);
        ImGui::DockBuilderDockWindow("Memory Accesses",         dock_right_bottom);  // ← default active

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
        // (Cmd+Q: quit) — route through begin_shutdown() so background threads
        // are properly joined before the window closes.  Direct running_=false
        // would skip thread teardown and cause hangs/crashes in the destructor.
        if ((super || ctrl) && ImGui::IsKeyPressed(ImGuiKey_Q)) {
            begin_shutdown();
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

    if (show_pattern_) {
        render_pattern_panel();
    }
    if (show_constant_) {
        render_constant_panel();
    }
    if (show_loop_semantics_) {
        render_loop_semantics_panel();
    }
    if (show_algorithm_summary_) {
        render_algorithm_summary_panel();
    }
    if (show_call_graph_) {
        render_call_graph_panel();
    }
    if (show_objc_) {
        render_objc_panel();
    }
    if (show_mem_strings_) {
        render_memory_strings_panel();
    }
    if (show_entropy_) {
        render_entropy_panel();
    }
    if (show_syscall_intercept_) {
        render_syscall_intercept_panel();
    }
    if (show_objc_crypto_) {
        render_objc_crypto_panel();
    }
    if (show_trace_fold_) {
        render_trace_fold_panel();
    }
    if (show_vm_abstract_) {
        render_vm_abstract_panel();
    }
    // VM Workspace: independent floating window, always rendered when open.
    // vm_ws_open_ is toggled by the "Open Workspace" button in the legacy panel
    // or directly via the View menu.
    if (vm_ws_open_) {
        render_vm_workspace();
    }

    // ─── Log panel (always rendered) ────────────────────────────────
    if (show_log_) {
        render_log_panel();
    }

    // ─── Cache Manager panel ────────────────────────────────────────
    if (show_cache_manager_) {
        render_cache_manager_panel();
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

// ─── Export helpers ──────────────────────────────────────────────────────────
//
// Each helper follows the same pattern:
//   1. If the required pass result is already available, go straight to
//      the NSSavePanel flow.
//   2. Otherwise, run the pass and then open the save panel in the
//      post_apply callback (which executes on the UI thread).
//
// NSSavePanel must be called on the main thread.  Both the pending_native_actions_
// drain and post_apply callbacks execute on the UI thread, so no extra
// dispatch is needed — but we keep dispatch_async(main) as an explicit
// safety belt for any future refactor.

// ── Helper: show an NSSavePanel and write the given text to the chosen file ──
static void save_text_to_file_async(NSString* default_name,
                                    NSString* file_type_desc,
                                    NSString* file_ext,
                                    std::string content) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSSavePanel* panel = [NSSavePanel savePanel];
        panel.nameFieldStringValue = default_name;
        panel.allowedContentTypes  = @[
            [UTType typeWithFilenameExtension:file_ext]
        ];
        panel.message = [NSString stringWithFormat:@"Save %@ file", file_type_desc];

        [panel beginSheetModalForWindow:[NSApp keyWindow]
                      completionHandler:^(NSModalResponse result) {
            if (result != NSModalResponseOK) return;
            NSURL* url = panel.URL;
            if (!url) return;
            NSError* err = nil;
            NSString* ns = [NSString stringWithUTF8String:content.c_str()];
            [ns writeToURL:url atomically:YES encoding:NSUTF8StringEncoding error:&err];
            if (err) {
                NSAlert* alert = [[NSAlert alloc] init];
                alert.messageText     = @"Export failed";
                alert.informativeText = err.localizedDescription;
                [alert runModal];
            }
        }];
    });
}

// ── Export CFG ────────────────────────────────────────────────────────────────

void tenet::GuiApp::export_cfg_to_file() {
    // If the cfg_layout pass has already run, grab the DOT immediately.
    auto* raw = completed_result("cfg_layout");
    if (raw && raw->ok()) {
        std::string dot = raw->get<CFGLayoutResult>().dot_annotated;
        if (dot.empty()) dot = raw->get<CFGLayoutResult>().dot;
        if (dot.empty()) {
            last_pass_status_ = "CFG layout has no DOT output; try re-running CFG Layout.";
            return;
        }
        save_text_to_file_async(@"cfg.dot", @"DOT (CFG)", @"dot", std::move(dot));
        return;
    }

    // Pass not yet done — run it, then export in the completion callback.
    last_pass_status_ = "Running CFG layout for export…";
    run_cfg_layout();

    // post_apply fires on the UI thread after run_cfg_layout's post_apply.
    post_apply([this]() {
        auto* r = completed_result("cfg_layout");
        if (!r || !r->ok()) {
            last_pass_status_ = "CFG layout failed; cannot export.";
            return;
        }
        std::string dot = r->get<CFGLayoutResult>().dot_annotated;
        if (dot.empty()) dot = r->get<CFGLayoutResult>().dot;
        save_text_to_file_async(@"cfg.dot", @"DOT (CFG)", @"dot", std::move(dot));
    });
}

// ── Export Call Graph ─────────────────────────────────────────────────────────

// Mirrors batch_analysis.cpp run_call_graph() DOT generation.
static std::string build_call_graph_dot(const tenet::CallGraphResult& cg) {
    std::string dot;
    dot.reserve(4096);
    dot += "digraph callgraph {\n";
    dot += "  node [shape=box, style=filled, fillcolor=lightyellow];\n";
    dot += "  edge [color=gray40];\n\n";
    for (const auto& [pc, node] : cg.nodes) {
        std::string label = node.name.empty()
            ? fmt::format("sub_{:X}", pc)
            : node.name;
        dot += fmt::format("  \"0x{:X}\" [label=\"{}\"];\n", pc, label);
    }
    dot += "\n";
    for (const auto& edge : cg.edges) {
        dot += fmt::format("  \"0x{:X}\" -> \"0x{:X}\" [label=\"{}\"];\n",
                           edge.caller_pc, edge.callee_pc, edge.call_count);
    }
    dot += "}\n";
    return dot;
}

void tenet::GuiApp::export_call_graph_to_file() {
    auto* raw = completed_result("call_graph");
    if (raw && raw->ok()) {
        std::string dot = build_call_graph_dot(raw->get<CallGraphResult>());
        save_text_to_file_async(@"callgraph.dot", @"DOT (Call Graph)", @"dot",
                                std::move(dot));
        return;
    }

    last_pass_status_ = "Running call graph for export…";
    run_call_graph_analysis();

    post_apply([this]() {
        auto* r = completed_result("call_graph");
        if (!r || !r->ok()) {
            last_pass_status_ = "Call graph failed; cannot export.";
            return;
        }
        std::string dot = build_call_graph_dot(r->get<CallGraphResult>());
        save_text_to_file_async(@"callgraph.dot", @"DOT (Call Graph)", @"dot",
                                std::move(dot));
    });
}

// ── Export Backward Taint Graph ───────────────────────────────────────────────

void tenet::GuiApp::export_backward_taint_graph_to_file() {
    if (!backward_taint_result_) {
        last_pass_status_ =
            "Run Backward Taint analysis first "
            "(Analysis > Data Flow > Backward Taint\u2026).";
        return;
    }
    std::string dot = backward_taint_result_->to_dot();
    save_text_to_file_async(@"backward_taint.dot",
                            @"DOT (Backward Taint Graph)", @"dot",
                            std::move(dot));
}

}  // namespace tenet
