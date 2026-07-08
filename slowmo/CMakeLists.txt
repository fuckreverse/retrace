cmake_minimum_required(VERSION 3.20)
project(tenet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Default build type: Debug for fast iterative development ───────────────
# Three-tier build strategy:
#   Debug          — -O0 -g, fastest compile, slowest runtime
#   RelWithDebInfo — -O2 -g -DNDEBUG, no LTO/PGO/-mcpu; incremental compile
#                    stays fast (per-TU only), runtime ~2-3× faster than Debug
#   Release        — -O3 + ThinLTO + -mcpu=apple-m1; slowest compile, fastest
#                    runtime (use for final profiling / distribution)
# Pass -DCMAKE_BUILD_TYPE=RelWithDebInfo for optimized dev builds.
# Pass -DCMAKE_BUILD_TYPE=Release for fully-optimized builds.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
        "Build type (Debug/Release/RelWithDebInfo/MinSizeRel)" FORCE)
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# ─── Performance: LTO, PGO, and architecture-specific tuning ────────────────
# ThinLTO only applies to Release builds; Debug and RelWithDebInfo keep the
# compiler/linker fast for tight edit-compile-test loops (a single LTO link
# costs ~13s, and the default `ninja` target rebuilds 41 executables on any
# tenet_lib change).  RelWithDebInfo gives -O2 without LTO — the sweet spot
# for "fast enough at runtime, fast to recompile" during development.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT _ipo_supported OUTPUT _ipo_error)
    if(_ipo_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
        message(STATUS "ThinLTO enabled (interprocedural optimization)")
    else()
        message(STATUS "LTO not supported: ${_ipo_error}")
    endif()
endif()

# ─── PGO (Profile-Guided Optimization) ─────────────────────────────────────
# Usage:
#   1. Generate: cmake .. -DTENET_PGO_MODE=generate && ninja && ./tenet <trace>
#   2. Merge:    llvm-profdata merge -output=default.profdata default_*.profraw
#   3. Use:      cmake .. -DTENET_PGO_MODE=use -DTENET_PGO_PROFILE=default.profdata
#   4. Build:    ninja
# This typically yields 15-30% speedup on hot iteration loops.
set(TENET_PGO_MODE "" CACHE STRING "PGO mode: '' (off), 'generate', or 'use'")
set(TENET_PGO_PROFILE "${CMAKE_BINARY_DIR}/default.profdata" CACHE FILEPATH
    "Path to merged .profdata file (for PGO 'use' mode)")

if(TENET_PGO_MODE STREQUAL "generate")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-generate")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-generate")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-generate")
    message(STATUS "PGO: instrumented build (profile generation)")
elseif(TENET_PGO_MODE STREQUAL "use")
    if(NOT EXISTS "${TENET_PGO_PROFILE}")
        message(WARNING "PGO profile not found: ${TENET_PGO_PROFILE} — building without PGO")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-use=${TENET_PGO_PROFILE}")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-use=${TENET_PGO_PROFILE}")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-use=${TENET_PGO_PROFILE}")
        message(STATUS "PGO: optimized build using ${TENET_PGO_PROFILE}")
    endif()
endif()

# Target Apple Silicon (M1+) for NEON auto-vectorization and LSE atomics.
# Only set for Release builds; RelWithDebInfo keeps generic codegen to avoid
# recompiling everything when switching between machines, and to stay
# consistent with "no global optimizations" philosophy.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" AND NOT CMAKE_CROSSCOMPILING)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=apple-m1")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=apple-m1")
        message(STATUS "Targeting Apple M1+ (NEON + LSE atomics)")
    endif()
endif()

# ─── Options ────────────────────────────────────────────────────────────────
option(TENET_USE_SYSTEM_ROCKSDB "Use system-installed RocksDB" OFF)
option(TENET_USE_SYSTEM_CAPSTONE "Use system-installed Capstone" OFF)
option(TENET_ENABLE_TRITON "Enable Triton semantic oracle for precise taint analysis" ON)
option(TENET_ENABLE_YARA "Enable YARA rule engine for pattern detection" ON)
option(TENET_ENABLE_GUI "Build with ImGui GUI (requires SDL3 + Metal on macOS)" ON)
option(TENET_BUILD_TESTS "Build unit tests" ON)
option(TENET_ENABLE_PYTHON "Build Python bindings via pybind11" OFF)
option(TENET_ENABLE_RPC "Build JSON-RPC Unix socket server" ON)
option(TENET_ENABLE_PROFILING "Enable os_signpost profiling instrumentation (macOS only, visible in Instruments)" ON)

# ─── FetchContent global shared cache ──────────────────────────────────────
# All build trees (build/, build-triton/, build-no-triton/, …) share a single
# _deps directory so sources are only git-cloned once.
#
# FETCHCONTENT_BASE_DIR  – points every build tree at the same source pool.
# FETCHCONTENT_UPDATES_DISCONNECTED – once a package is cloned, never contact
#   the network again (even on re-configure).  Use -DFETCHCONTENT_UPDATES_DISCONNECTED=OFF
#   or delete the shared _deps/<pkg>-src dir to force a fresh fetch.
#
# The canonical location is <project-root>/_deps so it survives wipe-and-rebuild
# of any individual build sub-directory.  Override with
#   cmake -DFETCHCONTENT_BASE_DIR=/your/path …
if(NOT DEFINED FETCHCONTENT_BASE_DIR OR FETCHCONTENT_BASE_DIR STREQUAL "")
    set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/_deps" CACHE PATH
        "Shared FetchContent source cache (shared across all build trees)" FORCE)
endif()
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Skip network update check for already-downloaded FetchContent packages" FORCE)
message(STATUS "FetchContent cache : ${FETCHCONTENT_BASE_DIR}")
message(STATUS "FetchContent offline: ${FETCHCONTENT_UPDATES_DISCONNECTED}")

# ─── FetchContent dependencies ──────────────────────────────────────────────
include(FetchContent)

# Capstone - disassembler
if(NOT TENET_USE_SYSTEM_CAPSTONE)
    FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG        5.0.1
        GIT_SHALLOW    TRUE
    )
    set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(capstone)
else()
    # Homebrew capstone does not ship a CMake config file; use pkg-config instead.
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CAPSTONE REQUIRED capstone)
    # Expose an imported target named 'capstone' so target_link_libraries works unchanged.
    if(NOT TARGET capstone)
        add_library(capstone INTERFACE IMPORTED)
        set_target_properties(capstone PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${CAPSTONE_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES      "${CAPSTONE_LINK_LIBRARIES}"
            INTERFACE_COMPILE_OPTIONS     "${CAPSTONE_CFLAGS_OTHER}"
        )
    endif()
endif()

# RocksDB
if(NOT TENET_USE_SYSTEM_ROCKSDB)
    FetchContent_Declare(
        rocksdb
        GIT_REPOSITORY https://github.com/facebook/rocksdb.git
        GIT_TAG        v9.4.0
        GIT_SHALLOW    TRUE
    )
    set(WITH_TESTS OFF CACHE BOOL "" FORCE)
    set(WITH_BENCHMARK_TOOLS OFF CACHE BOOL "" FORCE)
    set(WITH_TOOLS OFF CACHE BOOL "" FORCE)
    set(WITH_CORE_TOOLS OFF CACHE BOOL "" FORCE)
    set(WITH_GFLAGS OFF CACHE BOOL "" FORCE)
    set(WITH_LZ4 ON CACHE BOOL "Enable LZ4 compression in RocksDB" FORCE)
    set(ROCKSDB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(FAIL_ON_WARNINGS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(rocksdb)
else()
    find_package(RocksDB REQUIRED)
endif()

# CRoaring - compressed bitmaps
FetchContent_Declare(
    roaring
    GIT_REPOSITORY https://github.com/RoaringBitmap/CRoaring.git
    GIT_TAG        v4.1.1
    GIT_SHALLOW    TRUE
)
set(ROARING_BUILD_LTO OFF CACHE BOOL "" FORCE)
set(ENABLE_ROARING_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(roaring)

# FTXUI - terminal UI
FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
    GIT_TAG        v5.0.0
    GIT_SHALLOW    TRUE
)
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(ftxui)

# ─── GUI dependencies (ImGui + SDL3 + imgui-node-editor) ────────────────────
if(TENET_ENABLE_GUI)
    if(APPLE)
        enable_language(OBJCXX)
    endif()

    FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.6-docking
        GIT_SHALLOW    TRUE
    )

    FetchContent_Declare(
        SDL3
        GIT_REPOSITORY https://github.com/libsdl-org/SDL.git
        GIT_TAG        release-3.2.0
        GIT_SHALLOW    TRUE
    )

    FetchContent_Declare(
        imgui_node_editor
        GIT_REPOSITORY https://github.com/thedmd/imgui-node-editor.git
        GIT_TAG        v0.9.3
        GIT_SHALLOW    TRUE
    )

    set(SDL_TESTS OFF CACHE BOOL "" FORCE)
    set(SDL_EXAMPLES OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(imgui SDL3 imgui_node_editor)

    # ─── ImGui custom library (no native CMake build system) ────────────────
    add_library(imgui_lib STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_demo.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_metal.mm
    )

    target_include_directories(imgui_lib PUBLIC
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
    )

    target_link_libraries(imgui_lib PUBLIC
        SDL3::SDL3
        "-framework Metal"
        "-framework QuartzCore"
        "-framework GameController"
        "-framework CoreHaptics"
        "-framework AppKit"
    )

    # imgui_impl_sdl3.cpp's multi-viewport support (ImGui_ImplSDL3_SetupPlatformHandles)
    # branches on `#elif defined(__APPLE__) && defined(SDL_VIDEO_DRIVER_COCOA)` to fetch
    # the real NSWindow* via SDL_GetPointerProperty(..., SDL_PROP_WINDOW_COCOA_WINDOW_POINTER).
    # SDL_VIDEO_DRIVER_COCOA is normally only defined in SDL's own *private*
    # build_config/SDL_build_config.h (SDL3's own CMakeLists.txt marks that
    # include dir PRIVATE — by design it is not propagated to consumers via
    # the public SDL3::SDL3 target). Since imgui_lib only links the public
    # SDL3 headers, that macro is invisible here and the branch is silently
    # skipped, leaving ImGuiViewport::PlatformHandleRaw == nullptr.
    #
    # imgui_impl_metal.mm's ImGui_ImplMetal_CreateWindow() then falls back to
    # PlatformHandle, which SDL3 sets to a small SDL_WindowID integer (NOT a
    # pointer) — treating that as an NSWindow* and sending it -contentView
    # crashes with SIGSEGV (bad access at a tiny address, e.g. 0x4 for
    # window ID 4). This only manifests once ImGuiConfigFlags_ViewportsEnable
    # is on and a panel is dragged into its own OS window.
    #
    # Fix: this app only ever builds/runs on macOS, where SDL3 always uses
    # the Cocoa video backend, so it's safe to define the macro directly for
    # this translation unit instead of trying to reach into SDL3's private
    # generated-header directory.
    set_source_files_properties(
        ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl3.cpp
        PROPERTIES COMPILE_DEFINITIONS "SDL_VIDEO_DRIVER_COCOA=1"
    )

    set_source_files_properties(
        ${imgui_SOURCE_DIR}/backends/imgui_impl_metal.mm
        PROPERTIES LANGUAGE OBJCXX
    )
endif()

# fmt - formatting (useful utility, header-only mode)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG        10.2.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(fmt)

# nlohmann/json - structured JSON serialization
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nlohmann_json)

# ankerl::unordered_dense - fast flat hash map for LRU cache hot path
FetchContent_Declare(
    unordered_dense
    GIT_REPOSITORY https://github.com/martinus/unordered_dense.git
    GIT_TAG        v4.4.0
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(unordered_dense)

# os_signpost profiling (macOS only, zero third-party deps)
if(TENET_ENABLE_PROFILING AND APPLE)
    message(STATUS "os_signpost profiling enabled (visible in Instruments.app)")
endif()

# Zstd - decompression for compressed traces
# Reuses the same FetchContent source cache as qbditrace, so zstd source
# is already available in _deps/ and won't be re-downloaded.
FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG        v1.5.6
    GIT_SHALLOW    TRUE
    SOURCE_SUBDIR  build/cmake
)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# mimalloc - high-performance allocator with global malloc override.
# On macOS, linking the shared library (MI_OVERRIDE=ON) replaces the system
# allocator process-wide via dyld interposing — zero code changes needed.
# Yields 5-15% throughput on allocation-heavy paths (GUI per-frame vectors,
# Pass concurrent containers, MCP serialization).
set(MI_OVERRIDE ON CACHE BOOL "" FORCE)
set(MI_BUILD_SHARED ON CACHE BOOL "" FORCE)
set(MI_BUILD_STATIC OFF CACHE BOOL "" FORCE)
set(MI_BUILD_OBJECT OFF CACHE BOOL "" FORCE)
set(MI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MI_DEBUG_FULL OFF CACHE BOOL "" FORCE)
set(MI_SEE_ASAN OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        v2.1.7
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(mimalloc)

# YARA - rule-based pattern matching (optional)
if(TENET_ENABLE_YARA)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(YARA REQUIRED yara)
    message(STATUS "YARA enabled: ${YARA_LIBRARIES}")
endif()

# Triton - semantic oracle (optional)
if(TENET_ENABLE_TRITON)
    # Save current include_directories so we can undo Triton's global pollution
    get_property(_pre_triton_inc DIRECTORY PROPERTY INCLUDE_DIRECTORIES)
    find_package(triton REQUIRED)
    # Triton's config uses legacy include_directories() which pollutes globally.
    # Remove all system paths it added to avoid header conflicts (e.g. fmt version).
    set_property(DIRECTORY PROPERTY INCLUDE_DIRECTORIES "${_pre_triton_inc}")
    message(STATUS "Triton enabled: ${TRITON_LIBRARY}")
endif()

# pybind11 (optional - for Python bindings)
if(TENET_ENABLE_PYTHON)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG        v2.12.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(pybind11)
    message(STATUS "Python bindings enabled")
endif()

# ─── Main library (tenet_lib) ───────────────────────────────────────────────
add_library(tenet_lib STATIC
    src/io/trace_reader.cpp
    src/io/code_table.cpp
    src/io/index_builder.cpp
    src/io/recent_files.cpp
    src/io/vm_profiles.cpp
    src/core/register_file.cpp
    src/core/instruction_decoder.cpp
    src/core/memory_model.cpp
    src/core/breakpoint_engine.cpp
    src/core/triton_bridge.cpp
    src/analysis/pass_manager.cpp
    src/analysis/pass_registry.cpp
    src/analysis/trace_collector.cpp
    src/analysis/annotation_view.cpp
    src/analysis/passes/taint/taint_pass.cpp
    src/analysis/passes/taint/backward_taint_pass.cpp
    src/analysis/passes/structure/xref_pass.cpp
    src/analysis/passes/structure/function_pass.cpp
    src/analysis/passes/structure/call_graph_pass.cpp
    src/analysis/passes/structure/cfg_pass.cpp
    src/analysis/passes/structure/cfg_layout_pass.cpp
    src/analysis/passes/GraphGridLayout.cpp
    src/analysis/passes/memory/string_pass.cpp
    src/analysis/passes/crypto/pattern_pass.cpp
    src/analysis/passes/structure/loop_pass.cpp
    src/analysis/passes/crypto/loop_semantics_pass.cpp
    src/analysis/passes/vm/vm_abstract_pass.cpp
    src/analysis/passes/vm/vm_hints_json.cpp
    src/analysis/passes/vm/vm_decoder.cpp
    src/analysis/passes/crypto/algorithm_summary_pass.cpp
    src/analysis/passes/profile/trace_diff_pass.cpp
    src/analysis/passes/memory/memory_snapshot_pass.cpp
    src/analysis/passes/memory/memory_string_pass.cpp
    src/analysis/passes/profile/dataflow_graph_pass.cpp
    src/analysis/passes/platform/objc_pass.cpp
    src/analysis/passes/misc/thread_pass.cpp
    src/analysis/passes/profile/trace_fold_pass.cpp
    src/analysis/passes/profile/reg_timeline_pass.cpp
    src/analysis/passes/memory/mem_search_pass.cpp
    src/analysis/passes/profile/call_context_pass.cpp
    src/analysis/passes/profile/window_stats_pass.cpp
    src/analysis/passes/memory/entropy_pass.cpp
    src/analysis/passes/memory/yara_mem_scan_pass.cpp
    src/analysis/passes/misc/thread_filter_pass.cpp
    src/analysis/passes/crypto/objc_crypto_pass.cpp
    src/analysis/passes/platform/syscall_intercept_pass.cpp
    src/analysis/passes/taint/taint_source_annotation_pass.cpp
    src/io/rpc_server.cpp
    src/io/mcp/mcp_server.cpp
    src/io/mcp/mcp_http.cpp
    src/io/mcp/mcp_hub.cpp
    src/io/mcp/mcp_tools_core.cpp
    src/io/mcp/mcp_tools_analysis.cpp
    src/io/mcp/mcp_tools_vm.cpp
    src/io/mcp/mcp_tools_ai.cpp
    src/io/mcp/hypothesis_ledger.cpp
    src/io/mcp/discipline_injector.cpp
    src/io/streaming_index.cpp
    src/tui/tui_app.cpp
    src/tui/hex_dump_view.cpp
    src/tui/panels/register_panel.cpp
    src/tui/panels/memory_panel.cpp
    src/tui/panels/callstack_panel.cpp
    src/tui/panels/functions_panel.cpp
    src/tui/panels/strings_panel.cpp
    src/tui/panels/thread_panel.cpp
    src/tui/panels/breakpoint_panel.cpp
    src/tui/panels/results_panel.cpp
    src/service/tenet_service.cpp
)

target_include_directories(tenet_lib BEFORE PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # Access qbditrace TraceFormat.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../qbditrace
    # FTXUI headers
    ${ftxui_SOURCE_DIR}/include
    # Ensure our FetchContent'd fmt headers take priority over system headers
    ${fmt_SOURCE_DIR}/include
)

target_link_libraries(tenet_lib PUBLIC
    capstone
    rocksdb
    roaring
    fmt::fmt
    nlohmann_json::nlohmann_json
    unordered_dense::unordered_dense
    ftxui::screen
    ftxui::dom
    ftxui::component
)

# YARA linkage (optional)
if(TENET_ENABLE_YARA)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_YARA=1)
    target_include_directories(tenet_lib SYSTEM PUBLIC ${YARA_INCLUDE_DIRS})
    target_link_libraries(tenet_lib PUBLIC ${YARA_LIBRARIES})
    target_link_directories(tenet_lib PUBLIC ${YARA_LIBRARY_DIRS})
endif()

# Triton linkage (optional)
if(TENET_ENABLE_TRITON)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_TRITON=1)
    # Add Triton and Z3 headers as SYSTEM includes (after our own deps)
    target_include_directories(tenet_lib SYSTEM PUBLIC
        ${TRITON_INCLUDE_DIRS}
        /opt/homebrew/include  # Z3 headers needed by Triton's z3Solver.hpp
    )
    target_link_libraries(tenet_lib PUBLIC ${TRITON_LIBRARY})
endif()

# Zstd linkage (for decompressing compressed traces)
if(TARGET libzstd_static)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_ZSTD=1)
    target_link_libraries(tenet_lib PUBLIC libzstd_static)
    message(STATUS "Zstd linked for compressed trace support")
else()
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_ZSTD=0)
    message(STATUS "Zstd NOT available — compressed traces will be rejected")
endif()

# os_signpost profiling compile definition
if(TENET_ENABLE_PROFILING AND APPLE)
    target_compile_definitions(tenet_lib PUBLIC TENET_ENABLE_PROFILING=1)
else()
    target_compile_definitions(tenet_lib PUBLIC TENET_ENABLE_PROFILING=0)
endif()

# Platform libraries
if(APPLE)
    target_link_libraries(tenet_lib PUBLIC "-framework CoreFoundation" "-framework IOKit")
endif()

# ─── GUI library (tenet_gui_lib) ────────────────────────────────────────────
if(TENET_ENABLE_GUI)
add_library(tenet_gui_lib STATIC
    src/gui/gui_app.mm
    src/gui/gui_settings.cpp
    src/gui/gui_chrome.cpp
    src/gui/gui_colors.cpp
    src/gui/navigation.cpp
    src/gui/panels_instruction.cpp
    src/gui/panels_registers.cpp
    src/gui/panels_memory.cpp
    src/gui/panels_callstack_funcs.cpp
    src/gui/panels_analysis.cpp
    src/gui/panels_cfg.cpp
src/gui/panels_misc.cpp
src/gui/panels_reg_timeline.cpp
src/gui/panels_dwarf.cpp
src/gui/panels_trace_diff.cpp
src/gui/panels_objc.cpp
src/gui/panels_objc_crypto.cpp
src/gui/panels_call_graph.cpp
src/gui/panels_loop_semantics.cpp
src/gui/panels_pattern.cpp
src/gui/panels_constant.cpp
src/gui/panels_algorithm_summary.cpp
src/gui/panels_trace_fold.cpp
src/gui/panels_window_stats.cpp
src/gui/panels_dataflow_graph.cpp
src/gui/panels_memory_strings.cpp
src/gui/panels_entropy.cpp
src/gui/panels_mem_search.cpp
src/gui/panels_memory_snapshot.cpp
src/gui/panels_yara_mem_scan.cpp
src/gui/panels_call_context.cpp
src/gui/panels_syscall_intercept.cpp
src/gui/panels_objc_crypto.cpp
src/gui/panels_vm_abstract.cpp
src/gui/panels_taint_source_annotation.cpp
src/gui/panels_log.cpp
src/gui/panels_cache_manager.cpp
src/gui/popups.cpp
)

    # Ensure gui_app.mm is compiled as Objective-C++ (for Metal __bridge casts)
    set_source_files_properties(src/gui/gui_app.mm PROPERTIES LANGUAGE OBJCXX)

    target_link_libraries(tenet_gui_lib PUBLIC
        tenet_lib
        imgui_lib
        SDL3::SDL3
    )

    target_compile_definitions(tenet_gui_lib PUBLIC TENET_HAS_GUI=1)
endif()

# ─── Main executable ────────────────────────────────────────────────────────
add_executable(tenet src/main.cpp src/cli_options.cpp src/batch_analysis.cpp)

if(TENET_ENABLE_GUI)
    # tenet_gui_lib already PUBLIC-links tenet_lib; no need to add tenet_lib again
    # (avoids "ignoring duplicate libraries" linker warning on Apple ld).
    target_link_libraries(tenet PRIVATE tenet_gui_lib)
    target_compile_definitions(tenet PRIVATE TENET_HAS_GUI=1)
else()
    target_link_libraries(tenet PRIVATE tenet_lib)
endif()

# mimalloc: global malloc override (linked to final executables so its dyld
# interpose records take effect process-wide, including code in tenet_lib).
target_link_libraries(tenet PRIVATE mimalloc)

# ─── Benchmark ───────────────────────────────────────────────────────────────
add_executable(bench_tenet bench/bench_tenet.cpp)
target_link_libraries(bench_tenet PRIVATE tenet_lib mimalloc)

add_executable(bench_all_passes bench/bench_all_passes.cpp)
target_link_libraries(bench_all_passes PRIVATE tenet_lib mimalloc)

add_executable(bench_memory_snapshot bench/bench_memory_snapshot.cpp)
target_link_libraries(bench_memory_snapshot PRIVATE tenet_lib mimalloc)

add_executable(bench_loop_only bench/bench_loop_only.cpp)
target_link_libraries(bench_loop_only PRIVATE tenet_lib mimalloc)

# ─── Python bindings (tenet._core pybind11 module) ──────────────────────────
if(TENET_ENABLE_PYTHON)
    pybind11_add_module(tenet_core
        src/python/tenet_bindings.cpp
    )
    target_link_libraries(tenet_core PRIVATE tenet_lib)
    target_compile_definitions(tenet_core PRIVATE TENET_HAS_PYTHON=1)
    # Install into python/tenet/ so `import tenet` works from the build tree
    set_target_properties(tenet_core PROPERTIES
        OUTPUT_NAME "_core"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/python/tenet"
    )
    message(STATUS "Python bindings target: tenet_core")
endif()

# ─── Tests ──────────────────────────────────────────────────────────────────
if(TENET_BUILD_TESTS)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.4
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(Catch2)

    enable_testing()
    add_subdirectory(tests)
endif()
