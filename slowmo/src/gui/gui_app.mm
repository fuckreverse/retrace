#include "gui/gui_app.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/slice_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/loop_pass.h"

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

void GuiApp::setup_style() {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();

    // Compact spacing for dense data display
    style.WindowPadding = ImVec2(6.0f, 6.0f);
    style.FramePadding = ImVec2(4.0f, 2.0f);
    style.ItemSpacing = ImVec2(6.0f, 3.0f);
    style.ItemInnerSpacing = ImVec2(4.0f, 4.0f);
    style.ScrollbarSize = 12.0f;
    style.GrabMinSize = 8.0f;
    style.WindowRounding = 4.0f;
    style.FrameRounding = 2.0f;
    style.ScrollbarRounding = 2.0f;
    style.GrabRounding = 2.0f;
    style.TabRounding = 2.0f;

    // Custom dark theme for reverse engineering tool
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
    colors[ImGuiCol_ScrollbarBg]          = ImVec4(0.05f, 0.05f, 0.07f, 0.80f);
    colors[ImGuiCol_ScrollbarGrab]        = ImVec4(0.30f, 0.30f, 0.35f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.40f, 0.40f, 0.45f, 1.00f);
    colors[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.50f, 0.50f, 0.55f, 1.00f);
    colors[ImGuiCol_Header]               = ImVec4(0.18f, 0.18f, 0.22f, 1.00f);
    colors[ImGuiCol_HeaderHovered]        = ImVec4(0.25f, 0.25f, 0.32f, 1.00f);
    colors[ImGuiCol_HeaderActive]         = ImVec4(0.30f, 0.30f, 0.38f, 1.00f);
    colors[ImGuiCol_Tab]                  = ImVec4(0.12f, 0.12f, 0.15f, 1.00f);
    colors[ImGuiCol_TabHovered]           = ImVec4(0.25f, 0.40f, 0.55f, 1.00f);
    colors[ImGuiCol_TabSelected]          = ImVec4(0.18f, 0.30f, 0.45f, 1.00f);
    colors[ImGuiCol_DockingPreview]       = ImVec4(0.20f, 0.40f, 0.70f, 0.70f);
    colors[ImGuiCol_TextSelectedBg]       = ImVec4(0.20f, 0.40f, 0.70f, 0.50f);

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

    // Rebuild fonts if dirty
    if (settings_font_dirty_) {
        rebuild_fonts();
        settings_font_dirty_ = false;
    }
}

// ─── Main Run Loop ──────────────────────────────────────────────────────────

int GuiApp::run() {
    if (!init_sdl()) return 1;
    if (!init_imgui()) return 1;

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

void GuiApp::render_frame() {
    // Create a DockSpace over the entire viewport
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags dock_flags =
        ImGuiWindowFlags_MenuBar |
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

    ImGui::Begin("DockSpace", nullptr, dock_flags);
    ImGui::PopStyleVar(3);

    // Create the DockSpace
    ImGuiID dockspace_id = ImGui::GetID("TenetDockSpace");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    // ─── Default layout (first frame only) ───────────────────────────
    if (first_frame_) {
        first_frame_ = false;

        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, viewport->WorkSize);

        // Split: far-left minimap (6%) | center (66%) | right (28%)
        ImGuiID dock_minimap, dock_rest;
        ImGui::DockBuilderSplitNode(dockspace_id, ImGuiDir_Left, 0.06f, &dock_minimap, &dock_rest);

        ImGuiID dock_left, dock_right;
        ImGui::DockBuilderSplitNode(dock_rest, ImGuiDir_Left, 0.70f, &dock_left, &dock_right);

        // Split left: top 75% (instructions) | bottom 25% (analysis)
        ImGuiID dock_left_top, dock_left_bottom;
        ImGui::DockBuilderSplitNode(dock_left, ImGuiDir_Up, 0.75f, &dock_left_top, &dock_left_bottom);

        // Split right: top 55% (registers) | bottom 45% (memory)
        ImGuiID dock_right_top, dock_right_bottom;
        ImGui::DockBuilderSplitNode(dock_right, ImGuiDir_Up, 0.55f, &dock_right_top, &dock_right_bottom);

        // Dock panels into their slots
        ImGui::DockBuilderDockWindow("Minimap", dock_minimap);
        ImGui::DockBuilderDockWindow("Instructions", dock_left_top);
        ImGui::DockBuilderDockWindow("Registers", dock_right_top);
        ImGui::DockBuilderDockWindow("Memory Accesses", dock_right_bottom);
        ImGui::DockBuilderDockWindow("Analysis", dock_left_bottom);
        // Tabbed together in bottom-left
        ImGui::DockBuilderDockWindow("Call Stack", dock_left_bottom);
        ImGui::DockBuilderDockWindow("Hex Dump", dock_left_bottom);
        ImGui::DockBuilderDockWindow("Functions", dock_left_bottom);
        ImGui::DockBuilderDockWindow("Strings", dock_left_bottom);

        ImGui::DockBuilderFinish(dockspace_id);
    }

    // ─── Menu bar ───────────────────────────────────────────────────
    render_menu_bar();

    ImGui::End();

    // ─── Toolbar ────────────────────────────────────────────────────
    render_toolbar();

    // ─── Global keyboard shortcuts ───────────────────────────────────
    // Note: ImGui keyboard shortcuts work best when no text input has focus
    if (!ImGui::GetIO().WantCaptureKeyboard || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        // Navigation history: Alt+Left / Alt+Right (or Cmd+[ / Cmd+] on Mac)
        bool alt_down = ImGui::GetIO().KeyAlt;
        if (alt_down && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) {
            nav_back();
        }
        if (alt_down && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) {
            nav_forward();
        }

        // Taint jump: [ and ]
        bool shift_down = ImGui::GetIO().KeyShift;
        if (!shift_down && ImGui::IsKeyPressed(ImGuiKey_RightBracket)) {
            if (show_taint_ && taint_result_) jump_taint_next();
            else if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_next();
        }
        if (!shift_down && ImGui::IsKeyPressed(ImGuiKey_LeftBracket)) {
            if (show_taint_ && taint_result_) jump_taint_prev();
            else if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_prev();
        }
        if (shift_down && ImGui::IsKeyPressed(ImGuiKey_RightBracket)) {
            if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_next();
        }
        if (shift_down && ImGui::IsKeyPressed(ImGuiKey_LeftBracket)) {
            if (show_backward_taint_ && backward_taint_result_) jump_backward_taint_prev();
        }

        // Navigate step with arrow keys (without modifier)
        if (!alt_down && !shift_down) {
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
                navigate_to(current_inst_ + 1);
            }
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
                if (current_inst_ > 0) navigate_to(current_inst_ - 1);
            }
        }

        // G → goto popup
        if (ImGui::IsKeyPressed(ImGuiKey_G) && !show_goto_popup_) {
            show_goto_popup_ = true;
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
            ImGui::Separator();
            ImGui::MenuItem("Minimap", "V", &show_minimap_);
            ImGui::MenuItem("Loop Highlight", "O", &show_loops_);
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
            if (ImGui::MenuItem("Call Graph Analysis")) {
                run_call_graph_analysis();
            }
            if (ImGui::MenuItem("Loop Analysis", "O")) {
                run_loop_analysis();
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

void GuiApp::render_toolbar() {
    ImGui::Begin("##Toolbar", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings);

    // ── Navigation history: Back / Forward ────────────────────────────
    {
        bool can_back = can_nav_back();
        bool can_fwd  = can_nav_forward();

        if (!can_back) ImGui::BeginDisabled();
        if (ImGui::Button("<<")) nav_back();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Back (Alt+Left)\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        }
        if (!can_back) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!can_fwd) ImGui::BeginDisabled();
        if (ImGui::Button(">>")) nav_forward();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Forward (Alt+Right)\nHistory: [%zu/%zu]",
                nav_history_pos_ + 1, nav_history_.size());
        }
        if (!can_fwd) ImGui::EndDisabled();
    }

    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();

    // ── Step navigation ───────────────────────────────────────────────
    if (ImGui::Button("|<")) navigate_to(0);
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("First instruction");
    ImGui::SameLine();
    if (ImGui::Button("<")) {
        if (current_inst_ > 0) navigate_to(current_inst_ - 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Previous instruction");
    ImGui::SameLine();
    if (ImGui::Button(">")) {
        navigate_to(current_inst_ + 1);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next instruction");
    ImGui::SameLine();
    if (ImGui::Button(">|")) {
        navigate_to(total_inst_ > 0 ? total_inst_ - 1 : 0);
    }
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Last instruction");

    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();

    // ── Follow call / return ─────────────────────────────────────────
    if (function_result_) {
        bool has_call = (function_result_->call_at(current_inst_) != nullptr);
        bool has_ret  = (function_result_->return_at(current_inst_) != nullptr ||
                         !function_result_->call_stack_at(current_inst_).empty());

        if (!has_call) ImGui::BeginDisabled();
        if (ImGui::Button("Enter")) {
            auto* evt = function_result_->call_at(current_inst_);
            if (evt && evt->call_inst_id + 1 < total_inst_) {
                navigate_to(evt->call_inst_id + 1);
            }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Follow call into callee (E)");
        }
        if (!has_call) ImGui::EndDisabled();

        ImGui::SameLine();

        if (!has_ret) ImGui::BeginDisabled();
        if (ImGui::Button("Return")) {
            auto* evt = function_result_->return_at(current_inst_);
            if (evt) {
                navigate_to(evt->call_inst_id);
            } else {
                auto stk = function_result_->call_stack_at(current_inst_);
                if (!stk.empty()) navigate_to(stk.back()->call_inst_id);
            }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
            ImGui::SetTooltip("Follow return to call site (R)");
        }
        if (!has_ret) ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    }

    // ── Taint jump buttons ────────────────────────────────────────────
    if (show_taint_ && taint_result_) {
        if (ImGui::Button("[T")) jump_taint_prev();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev tainted inst ([)");
        ImGui::SameLine();
        if (ImGui::Button("T]")) jump_taint_next();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next tainted inst (])");
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    }
    if (show_backward_taint_ && backward_taint_result_) {
        if (ImGui::Button("[BT")) jump_backward_taint_prev();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prev backward-tainted inst");
        ImGui::SameLine();
        if (ImGui::Button("BT]")) jump_backward_taint_next();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Next backward-tainted inst");
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
    }

    // ── Current instruction display ───────────────────────────────────
    auto row = fetch_row(current_inst_);
    ImGui::Text("PC: 0x%016llx", (unsigned long long)row.static_pc);
    ImGui::SameLine();
    ImGui::TextColored(inst_color(row.mnemonic), "%s", row.mnemonic.c_str());
    ImGui::SameLine(0, 0);
    ImGui::TextColored(ImVec4(0.75f, 0.75f, 0.8f, 1.0f), " %s", row.operands.c_str());

    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();

    // ── Analysis status ───────────────────────────────────────────────
    if (analysis_running_.load()) {
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Analyzing...");
    } else if (show_backward_taint_) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "BACK-TAINT");
    } else if (show_taint_) {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "TAINT");
    } else if (show_slice_) {
        ImGui::TextColored(ImVec4(1.0f, 0.0f, 1.0f, 1.0f), "SLICE");
    }

    if (show_loops_ && loop_result_) {
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.1f, 1.0f), "LOOPS(%zu)",
                           loop_result_->loops.size());
    }

    // ── Compact progress bar ──────────────────────────────────────────
    if (total_inst_ > 0) {
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        float progress = static_cast<float>(current_inst_) / static_cast<float>(total_inst_);
        char overlay[32];
        snprintf(overlay, sizeof(overlay), "%llu / %llu",
                 (unsigned long long)current_inst_,
                 (unsigned long long)total_inst_);
        ImGui::SetNextItemWidth(200.0f);
        ImGui::ProgressBar(progress, ImVec2(200.0f, 0.0f), overlay);
    }

    ImGui::End();
}

// ─── Instruction Panel ──────────────────────────────────────────────────────

void GuiApp::render_instruction_panel() {
    ImGui::Begin("Instructions");

    // Table: marker | index | address | mnemonic | operands
    const ImGuiTableFlags table_flags =
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit |
        ImGuiTableFlags_Resizable | ImGuiTableFlags_NoHostExtendX;

    if (ImGui::BeginTable("InstTable", 5, table_flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);  // Freeze header row
        ImGui::TableSetupColumn(" ",        ImGuiTableColumnFlags_WidthFixed, 24.0f);
        ImGui::TableSetupColumn("#",        ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Address",  ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Use a clipper for efficient rendering of large instruction lists
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(total_inst_));

        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                uint64_t inst_id = static_cast<uint64_t>(i);
                auto row = fetch_row(inst_id);

                bool is_current = (inst_id == current_inst_);
                bool is_bookmarked = row.has_bookmark;
                bool is_tainted = show_taint_ && taint_result_ && taint_result_->has_event_at(inst_id);
                bool is_sliced = show_slice_ && slice_result_ && slice_result_->is_in_slice(inst_id);
                bool is_backward_tainted = show_backward_taint_ && backward_taint_result_ &&
                    backward_taint_result_->is_contributing(inst_id);

                // Loop state
                bool is_loop_header = show_loops_ && loop_result_ && loop_result_->is_loop_header(row.pc);
                uint32_t loop_depth = (show_loops_ && loop_result_) ? loop_result_->loop_depth_at(row.pc) : 0;
                bool is_in_loop = loop_depth > 0;

                ImGui::TableNextRow();

                // Row background highlight (priority: current > analysis > loop header > loop body)
                if (is_current) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.20f, 0.30f, 0.50f, 0.65f)));
                } else if (is_backward_tainted) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.40f, 0.10f, 0.10f, 0.45f)));
                } else if (is_sliced) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.30f, 0.10f, 0.40f, 0.45f)));
                } else if (is_tainted) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.10f, 0.30f, 0.10f, 0.45f)));
                } else if (is_loop_header) {
                    // Loop header: vivid orange tint
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.55f, 0.25f, 0.02f, 0.80f)));
                } else if (is_in_loop) {
                    // Loop body: subtle warm tint, darker with nesting depth
                    float d = std::min(static_cast<float>(loop_depth - 1) * 0.06f, 0.18f);
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1,
                        ImGui::GetColorU32(ImVec4(0.28f + d, 0.15f, 0.02f, 0.40f)));
                }

                // Column 0: Marker (bookmark / current / loop indicator)
                ImGui::TableNextColumn();
                if (is_bookmarked && is_current)
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "*>");
                else if (is_bookmarked)
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.2f, 1.0f), "* ");
                else if (is_current)
                    ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), " >");
                else if (is_loop_header)
                    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.1f, 1.0f), "\xE2\x87\x86 "); // ⇆ loop-head marker
                else if (is_in_loop)
                    ImGui::TextColored(ImVec4(0.75f, 0.45f, 0.1f, 0.8f), "\xE2\x86\xBA "); // ↺ loop body
                else
                    ImGui::TextDisabled("  ");

                // Column 1: Instruction index
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%llu", (unsigned long long)inst_id);

                // Column 2: Address (gray)
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.55f, 0.55f, 0.65f, 1.0f), "%016llx",
                    (unsigned long long)row.static_pc);

                // Column 3: Mnemonic (syntax-colored)
                ImGui::TableNextColumn();
                ImVec4 mnem_color = inst_color(row.mnemonic);
                ImGui::TextColored(mnem_color, "%s", row.mnemonic.c_str());

                // Column 4: Operands (light color, highlight registers/immediates)
                ImGui::TableNextColumn();
                render_operands_highlighted(row.operands);

                // Handle click on entire row via invisible button overlay
                ImGui::SameLine(0, 0);
                char sel_id[32];
                snprintf(sel_id, sizeof(sel_id), "##inst%llu", (unsigned long long)inst_id);
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() - ImGui::GetContentRegionAvail().x);
                if (ImGui::InvisibleButton(sel_id, ImVec2(-FLT_MIN, ImGui::GetTextLineHeight()))) {
                    navigate_to(inst_id);
                }
            }
        }
        clipper.End();

        // Auto-scroll to keep current instruction visible
        if (current_inst_ < total_inst_) {
            float item_height = ImGui::GetTextLineHeightWithSpacing();
            float target_scroll = static_cast<float>(current_inst_) * item_height -
                                  ImGui::GetWindowHeight() * 0.5f;
            if (target_scroll < 0.0f) target_scroll = 0.0f;
            ImGui::SetScrollY(target_scroll);
        }

        ImGui::EndTable();
    }

    ImGui::End();
}

// ─── Register Panel ─────────────────────────────────────────────────────────

void GuiApp::render_register_panel() {
    if (!ImGui::Begin("Registers", &show_registers_)) {
        ImGui::End();
        return;
    }

    const auto& state = regfile_.state_before(current_inst_);

    // Determine read/written registers
    std::vector<uint8_t> read_regs, write_regs;
    {
        uint64_t offset = index_.offset_of(current_inst_, reader_);
        auto rec = reader_.record_at(offset);
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

    auto get_reg_color = [&](uint8_t idx) -> ImVec4 {
        bool r = is_in(read_regs, idx);
        bool w = is_in(write_regs, idx);
        if (r && w) return reg_color_both();
        if (w) return reg_color_write();
        if (r) return reg_color_read();
        return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    };

    // Legend
    ImGui::TextColored(reg_color_read(), "R");
    ImGui::SameLine();
    ImGui::TextDisabled("/");
    ImGui::SameLine();
    ImGui::TextColored(reg_color_write(), "W");
    ImGui::SameLine();
    ImGui::TextDisabled("/");
    ImGui::SameLine();
    ImGui::TextColored(reg_color_both(), "RW");
    ImGui::Separator();

    // Helper: render a register row with right-click context menu
    auto render_reg_row = [&](uint8_t idx, const char* name, uint64_t value) {
        ImGui::PushStyleColor(ImGuiCol_Text, get_reg_color(idx));
        char label[64];
        snprintf(label, sizeof(label), "%s=0x%016llx##regrow%u",
                 name, (unsigned long long)value, idx);
        ImGui::Selectable(label, false, ImGuiSelectableFlags_AllowOverlap);
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Right-click for options");
        }
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
            ctx_reg_idx_   = idx;
            ctx_reg_value_ = value;
            show_reg_ctx_menu_ = true;
        }
    };

    // GPR x0-x28 (two columns)
    if (ImGui::BeginTable("GPR", 2, ImGuiTableFlags_SizingFixedFit)) {
        for (int i = 0; i < 29; i += 2) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            render_reg_row(static_cast<uint8_t>(i),
                reg_name(static_cast<uint8_t>(i)).c_str(), state.gpr[i]);
            ImGui::TableNextColumn();
            if (i + 1 < 29) {
                render_reg_row(static_cast<uint8_t>(i + 1),
                    reg_name(static_cast<uint8_t>(i + 1)).c_str(), state.gpr[i + 1]);
            }
        }
        ImGui::EndTable();
    }

    ImGui::Separator();

    // Special registers
    render_reg_row(IDX_FP, " fp", state.fp());
    render_reg_row(IDX_LR, " lr", state.lr());
    render_reg_row(IDX_SP, " sp", state.sp());
    render_reg_row(IDX_PC, " pc", state.pc());
    ImGui::TextColored(get_reg_color(IDX_NZCV), "nzcv=%x", state.nzcv());

    // Render register context menu
    render_reg_context_menu();

    // Cache stats
    ImGui::Separator();
    auto stats = regfile_.cache_stats();
    ImGui::TextDisabled("Cache: %llu hits / %llu misses",
        (unsigned long long)stats.hits, (unsigned long long)stats.misses);

    ImGui::End();
}

// ─── Memory Panel ───────────────────────────────────────────────────────────

void GuiApp::render_memory_panel() {
    if (!ImGui::Begin("Memory Accesses", &show_memory_)) {
        ImGui::End();
        return;
    }

    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
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
                // Double click → open hex dump at this address
                open_hex_dump_at(mem.addr);
            }
        }
        if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
            ctx_mem_addr_ = mem.addr;
            ctx_mem_inst_id_ = current_inst_;
            show_mem_ctx_menu_ = true;
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
            // Right-click context menu
            if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                ctx_callstack_frame_ = i;
                show_callstack_ctx_menu_ = true;
            }
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

    // Status
    if (analysis_running_.load()) {
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Running...");
        std::lock_guard<std::mutex> lock(analysis_mutex_);
        if (!analysis_status_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", analysis_status_.c_str());
        }
    } else {
        ImGui::TextDisabled("Idle");
    }

    ImGui::Separator();

    // Results summary
    if (show_taint_ && taint_result_) {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Taint:");
        ImGui::SameLine();
        ImGui::Text("%llu instructions tainted",
            (unsigned long long)taint_result_->tainted_inst_count());
    }
    if (show_slice_ && slice_result_) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 1.0f, 1.0f), "Slice:");
        ImGui::SameLine();
        ImGui::Text("active");
    }
    if (show_backward_taint_ && backward_taint_result_) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Backward Taint:");
        ImGui::SameLine();
        ImGui::Text("active");
    }
    if (function_result_) {
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Functions:");
        ImGui::SameLine();
        ImGui::Text("%zu discovered", function_result_->functions.size());
    }

    ImGui::Separator();
    if (ImGui::Button("Clear All")) {
        clear_analysis();
    }

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
        uint64_t offset = index_.offset_of(current_inst_, reader_);
        auto rec = reader_.record_at(offset);
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

        // Hex bytes
        char hex_part[64] = {};
        char ascii_part[20] = {};
        int hex_pos = 0;

        for (int b = 0; b < 16; b++) {
            uint64_t byte_addr = row_addr + b;
            auto byte_val = memory_.byte_at(byte_addr, current_inst_);

            bool is_highlighted = (byte_addr == display_addr);

            if (b == 8) hex_pos += snprintf(hex_part + hex_pos, sizeof(hex_part) - hex_pos, " ");

            if (is_highlighted) {
                // Render hex bytes up to this point
                if (hex_pos > 0) {
                    ImGui::TextDisabled("%s", hex_part);
                    ImGui::SameLine(0, 0);
                    hex_pos = 0;
                }
            }

            if (byte_val.has_value()) {
                uint8_t v = *byte_val;
                hex_pos += snprintf(hex_part + hex_pos, sizeof(hex_part) - hex_pos, "%02x ", v);
                ascii_part[b] = (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '.';
            } else {
                hex_pos += snprintf(hex_part + hex_pos, sizeof(hex_part) - hex_pos, "?? ");
                ascii_part[b] = '?';
            }
        }
        ascii_part[16] = '\0';

        if (is_active_row) {
            ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "%s", hex_part);
        } else {
            ImGui::TextDisabled("%s", hex_part);
        }
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", ascii_part);

        // Allow clicking on a row to update the target address
        if (ImGui::IsItemClicked()) {
            display_addr = row_addr;
            ctx_mem_addr_ = row_addr;
        }
    }

    ImGui::Separator();
    ImGui::TextDisabled("Click row to focus  |  Use 'From Inst' to follow current instruction");

    ImGui::End();
}

// ─── Popups ─────────────────────────────────────────────────────────────────

void GuiApp::render_goto_popup() {
    if (!show_goto_popup_) return;

    ImGui::OpenPopup("Goto Instruction");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Goto Instruction", &show_goto_popup_,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Enter instruction ID (0 - %llu):",
                    (unsigned long long)(total_inst_ > 0 ? total_inst_ - 1 : 0));

        bool enter_pressed = ImGui::InputText("##goto", goto_buf_, sizeof(goto_buf_),
                                              ImGuiInputTextFlags_EnterReturnsTrue);

        if (ImGui::IsWindowAppearing()) {
            ImGui::SetKeyboardFocusHere(-1);
        }

        if (enter_pressed || ImGui::Button("Go")) {
            try {
                uint64_t target = std::stoull(goto_buf_);
                navigate_to(target);
            } catch (...) {
                // Invalid input, ignore
            }
            show_goto_popup_ = false;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_goto_popup_ = false;
            std::memset(goto_buf_, 0, sizeof(goto_buf_));
            ImGui::CloseCurrentPopup();
        }

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

    uint64_t offset = index_.offset_of(inst_id, reader_);
    auto rec = reader_.record_at(offset);
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
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.source_regs.insert(diff.index);
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
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
        for (uint8_t i = 0; i < inst.reg_diff_count; i++) {
            auto diff = inst.reg_diff(i);
            config.sink_regs.insert(diff.index);
        }
    }

    if (config.sink_regs.empty()) {
        // No reg diffs at this instruction - default to X0
        config.sink_regs.insert(0);
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
    uint64_t offset = index_.offset_of(current_inst_, reader_);
    auto rec = reader_.record_at(offset);
    if (rec.kind == RecordKind::Inst) {
        auto inst = rec.as_inst();
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
                if (ImGui::IsItemHovered() && call_graph_result_) {
                    // Tooltip with callers/callees info
                    auto* node = call_graph_result_->node_at(entry.pc);
                    if (node) {
                        std::string tip = fmt::format("Callees: {}, Callers: {}",
                            node->outgoing_edges.size(), node->incoming_edges.size());
                        ImGui::SetTooltip("%s", tip.c_str());
                    }
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
                // Double-click to jump
                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    navigate_to(ref->discovered_at);
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
    show_taint_ = false;
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
    if (!show_mem_ctx_menu_) return;
    ImGui::OpenPopup("##mem_ctx");
    show_mem_ctx_menu_ = false;

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
    if (!show_reg_ctx_menu_) return;
    ImGui::OpenPopup("##reg_ctx");
    show_reg_ctx_menu_ = false;

    if (ImGui::BeginPopup("##reg_ctx")) {
        std::string rname;
        if (ctx_reg_idx_ <= 28) rname = fmt::format("x{}", ctx_reg_idx_);
        else if (ctx_reg_idx_ == 29) rname = "fp";
        else if (ctx_reg_idx_ == 30) rname = "lr";
        else if (ctx_reg_idx_ == 31) rname = "sp";
        else rname = fmt::format("reg{}", ctx_reg_idx_);

        ImGui::TextDisabled("%s = 0x%016llx", rname.c_str(), (unsigned long long)ctx_reg_value_);
        ImGui::Separator();

        if (ImGui::MenuItem("Open Value in Hex Dump")) {
            open_hex_dump_at(ctx_reg_value_);
        }
        if (ImGui::MenuItem("Copy Value")) {
            char buf[32];
            snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)ctx_reg_value_);
            ImGui::SetClipboardText(buf);
        }
        if (ctx_reg_idx_ == 30 && function_result_) {
            // LR — jump to caller
            ImGui::Separator();
            if (ImGui::MenuItem("Follow LR (jump to call site)")) {
                auto stack = function_result_->call_stack_at(current_inst_);
                if (!stack.empty()) {
                    navigate_to(stack.back()->call_inst_id);
                }
            }
        }
        if ((ctx_reg_idx_ == 29 || ctx_reg_idx_ == 31) && function_result_) {
            // FP/SP context
            ImGui::Separator();
            ImGui::TextDisabled("(stack pointer/frame pointer)");
        }
        ImGui::EndPopup();
    }
}

void GuiApp::render_callstack_context_menu() {
    if (!show_callstack_ctx_menu_) return;
    ImGui::OpenPopup("##cs_ctx");
    show_callstack_ctx_menu_ = false;

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

// ─── Settings Window ────────────────────────────────────────────────────────

void GuiApp::render_settings_window() {
    ImGui::SetNextWindowSize(ImVec2(550, 600), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Settings", &show_settings_)) {
        ImGui::End();
        return;
    }

    bool changed = false;
    bool font_changed = false;

    if (ImGui::BeginTabBar("SettingsTabs")) {

        // ─── Font Tab ──────────────────────────────────────────────────
        if (ImGui::BeginTabItem("Font")) {
            ImGui::SeparatorText("Font Selection");

            // Font path combo
            {
                // Current display name
                std::string current_name = settings_.font_path.empty()
                    ? "Auto (system default)"
                    : settings_.font_path.substr(settings_.font_path.rfind('/') + 1);

                if (ImGui::BeginCombo("Font", current_name.c_str())) {
                    // Auto option
                    if (ImGui::Selectable("Auto (system default)", settings_.font_path.empty())) {
                        settings_.font_path.clear();
                        font_changed = true;
                    }
                    ImGui::Separator();

                    // Available fonts
                    for (const auto& path : available_fonts_) {
                        std::string name = path.substr(path.rfind('/') + 1);
                        bool selected = (path == settings_.font_path);
                        if (ImGui::Selectable(name.c_str(), selected)) {
                            settings_.font_path = path;
                            font_changed = true;
                        }
                        if (ImGui::IsItemHovered()) {
                            ImGui::SetTooltip("%s", path.c_str());
                        }
                    }
                    ImGui::EndCombo();
                }
            }

            // Font size slider
            if (ImGui::SliderFloat("Size", &settings_.font_size, 9.0f, 24.0f, "%.1f pt")) {
                font_changed = true;
            }

            // Oversampling
            if (ImGui::SliderInt("Oversampling H", &settings_.oversample_h, 1, 3)) {
                font_changed = true;
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Higher = smoother text, more VRAM");
            }

            // Pixel snap
            if (ImGui::Checkbox("Pixel Snap", &settings_.pixel_snap)) {
                font_changed = true;
            }

            // Custom font path input
            ImGui::SeparatorText("Custom Font Path");
            static char custom_path_buf[512] = {};
            if (custom_path_buf[0] == '\0' && !settings_.font_path.empty()) {
                strncpy(custom_path_buf, settings_.font_path.c_str(), sizeof(custom_path_buf) - 1);
            }
            ImGui::SetNextItemWidth(-80.0f);
            ImGui::InputText("##CustomPath", custom_path_buf, sizeof(custom_path_buf));
            ImGui::SameLine();
            if (ImGui::Button("Apply##font")) {
                settings_.font_path = custom_path_buf;
                font_changed = true;
            }
            ImGui::TextDisabled("Enter full path to .ttf/.otf file");

            // Preview
            ImGui::SeparatorText("Preview");
            ImGui::Text("AaBbCcDd 0123456789");
            ImGui::Text("mov x0, #0x1234; ldr x1, [sp, #0x10]");
            ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1.0f), "x0 x1 sp lr fp pc");

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

    // ─── Bottom buttons ────────────────────────────────────────────────
    if (font_changed) {
        settings_font_dirty_ = true;
        changed = true;
    }

    if (changed) {
        apply_settings();
        settings_.save(GuiSettings::default_path());
    }

    ImGui::TextDisabled("Settings saved to: %s", GuiSettings::default_path().c_str());

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

// ─── Progress Overlay ─────────────────────────────────────────────────────────
// Renders a full-width execution timeline bar as a separate floating window
// overlaid above the instruction list. Markers for bookmarks, tainted insts,
// and loop headers are drawn using ImDrawList.

void GuiApp::render_progress_overlay() {
    if (total_inst_ == 0) return;

    // Position: just below the toolbar, full width
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float bar_height = 18.0f;
    const float bar_y = vp->WorkPos.y + ImGui::GetFrameHeight() * 2.2f;  // below menu + toolbar
    ImVec2 bar_pos(vp->WorkPos.x, bar_y);
    ImVec2 bar_size(vp->WorkSize.x, bar_height);

    ImGui::SetNextWindowPos(bar_pos);
    ImGui::SetNextWindowSize(bar_size);
    ImGui::SetNextWindowBgAlpha(0.85f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs;

    if (!ImGui::Begin("##ProgressBar", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetWindowPos();
    float W = ImGui::GetWindowWidth();
    float H = bar_height;

    // Background gradient: dark gray track
    draw->AddRectFilled(p0, ImVec2(p0.x + W, p0.y + H),
                        IM_COL32(25, 25, 30, 220));

    // Progress fill (current position)
    float progress = static_cast<float>(current_inst_) / static_cast<float>(total_inst_);
    float fill_x = p0.x + progress * W;
    draw->AddRectFilled(p0, ImVec2(fill_x, p0.y + H),
                        IM_COL32(40, 70, 120, 180));

    // Current position cursor line
    draw->AddLine(ImVec2(fill_x, p0.y), ImVec2(fill_x, p0.y + H),
                  IM_COL32(100, 160, 255, 255), 2.0f);

    // Helper: inst_id → x coordinate
    auto inst_to_x = [&](uint64_t id) -> float {
        return p0.x + static_cast<float>(id) / static_cast<float>(total_inst_) * W;
    };

    // Draw bookmark markers (gold diamonds)
    for (uint64_t bid : bookmarks_) {
        float bx = inst_to_x(bid);
        draw->AddTriangleFilled(
            ImVec2(bx, p0.y + H * 0.1f),
            ImVec2(bx - 3.0f, p0.y + H * 0.6f),
            ImVec2(bx + 3.0f, p0.y + H * 0.6f),
            IM_COL32(255, 200, 40, 230));
    }

    // Draw taint markers (green tick marks)
    if (show_taint_ && taint_result_ && !taint_sorted_ids_.empty()) {
        // Sample at most 2000 markers to avoid overloading the draw list
        const size_t kMaxMarkers = 2000;
        size_t step = std::max(size_t(1), taint_sorted_ids_.size() / kMaxMarkers);
        for (size_t ti = 0; ti < taint_sorted_ids_.size(); ti += step) {
            float tx = inst_to_x(taint_sorted_ids_[ti]);
            draw->AddLine(ImVec2(tx, p0.y + H * 0.5f), ImVec2(tx, p0.y + H),
                          IM_COL32(40, 200, 80, 180), 1.0f);
        }
    }

    // Draw backward taint markers (red)
    if (show_backward_taint_ && backward_taint_result_) {
        // Build sorted list on-the-fly (cap at 2000)
        size_t shown = 0;
        for (uint64_t id = 0; id < total_inst_ && shown < 2000; id++) {
            if (backward_taint_result_->is_contributing(id)) {
                float tx = inst_to_x(id);
                draw->AddLine(ImVec2(tx, p0.y), ImVec2(tx, p0.y + H * 0.5f),
                              IM_COL32(220, 60, 60, 180), 1.0f);
                shown++;
            }
        }
    }

    // Draw loop header markers (orange notch at top)
    if (show_loops_ && loop_result_) {
        for (const auto& loop : loop_result_->loops) {
            // Find an inst_id that corresponds to loop.header_pc
            // We use xref_result_ if available, else skip
            if (xref_result_) {
                auto inst_ids = xref_result_->inst_ids_at(loop.header_pc);
                if (!inst_ids.empty()) {
                    float lx = inst_to_x(inst_ids.front());
                    draw->AddRectFilled(ImVec2(lx - 2.0f, p0.y),
                                       ImVec2(lx + 2.0f, p0.y + H * 0.45f),
                                       IM_COL32(255, 140, 30, 230));
                }
            }
        }
    }

    // Bottom edge separator
    draw->AddLine(ImVec2(p0.x, p0.y + H - 1.0f), ImVec2(p0.x + W, p0.y + H - 1.0f),
                  IM_COL32(60, 60, 80, 200), 1.0f);

    // Tooltip: clicking the bar navigates to that position
    if (ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
        float mx = ImGui::GetIO().MousePos.x;
        float rel = (mx - p0.x) / W;
        if (rel >= 0.0f && rel <= 1.0f) {
            uint64_t hover_id = static_cast<uint64_t>(rel * static_cast<float>(total_inst_));
            if (hover_id >= total_inst_) hover_id = total_inst_ - 1;
            auto hover_row = fetch_row(hover_id);
            ImGui::SetTooltip("inst %llu  PC:0x%llx\n%s",
                (unsigned long long)hover_id,
                (unsigned long long)hover_row.static_pc,
                hover_row.disasm.c_str());
        }
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

}  // namespace tenet
