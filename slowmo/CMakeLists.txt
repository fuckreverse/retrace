cmake_minimum_required(VERSION 3.20)
project(tenet VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ─── Performance: LTO and architecture-specific tuning ──────────────────────
include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_supported OUTPUT _ipo_error)
if(_ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
    message(STATUS "LTO enabled (interprocedural optimization)")
else()
    message(STATUS "LTO not supported: ${_ipo_error}")
endif()

# Target Apple Silicon (M1+) for NEON auto-vectorization and LSE atomics.
# Only set for native builds; cross-compilation should specify its own -mcpu.
if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" AND NOT CMAKE_CROSSCOMPILING)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=apple-m1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=apple-m1")
    message(STATUS "Targeting Apple M1+ (NEON + LSE atomics)")
endif()

# ─── Options ────────────────────────────────────────────────────────────────
option(TENET_USE_SYSTEM_ROCKSDB "Use system-installed RocksDB" OFF)
option(TENET_USE_SYSTEM_CAPSTONE "Use system-installed Capstone" OFF)
option(TENET_ENABLE_TRITON "Enable Triton semantic oracle for precise taint analysis" OFF)
option(TENET_ENABLE_YARA "Enable YARA rule engine for pattern detection" ON)
option(TENET_ENABLE_GUI "Build with ImGui GUI (requires SDL3 + Metal on macOS)" ON)
option(TENET_BUILD_TESTS "Build unit tests" ON)

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
    find_package(capstone REQUIRED)
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

# ─── Main library (tenet_lib) ───────────────────────────────────────────────
add_library(tenet_lib STATIC
    src/io/trace_reader.cpp
    src/io/code_table.cpp
    src/io/index_builder.cpp
    src/core/register_file.cpp
    src/core/instruction_decoder.cpp
    src/core/memory_model.cpp
    src/core/triton_bridge.cpp
    src/analysis/pass_manager.cpp
    src/analysis/trace_collector.cpp
    src/analysis/passes/index_build_pass.cpp
    src/analysis/passes/disassembly_pass.cpp
    src/analysis/passes/taint_pass.cpp
    src/analysis/passes/slice_pass.cpp
    src/analysis/passes/backward_taint_pass.cpp
    src/analysis/passes/xref_pass.cpp
    src/analysis/passes/function_pass.cpp
    src/analysis/passes/call_graph_pass.cpp
    src/analysis/passes/cfg_pass.cpp
    src/analysis/passes/cfg_layout_pass.cpp
    src/analysis/passes/string_pass.cpp
    src/analysis/passes/pattern_pass.cpp
    src/analysis/passes/loop_pass.cpp
    src/tui/tui_app.cpp
    src/tui/hex_dump_view.cpp
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

# Platform libraries
if(APPLE)
    target_link_libraries(tenet_lib PUBLIC "-framework CoreFoundation" "-framework IOKit")
endif()

# ─── GUI library (tenet_gui_lib) ────────────────────────────────────────────
if(TENET_ENABLE_GUI)
add_library(tenet_gui_lib STATIC
    src/gui/gui_app.mm
    src/gui/gui_settings.cpp
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
add_executable(tenet src/main.cpp)
target_link_libraries(tenet PRIVATE tenet_lib)

if(TENET_ENABLE_GUI)
    target_link_libraries(tenet PRIVATE tenet_gui_lib)
    target_compile_definitions(tenet PRIVATE TENET_HAS_GUI=1)
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

    # Tests will be added as they are written
    # add_executable(tenet_tests tests/unit/test_trace_reader.cpp)
    # target_link_libraries(tenet_tests PRIVATE tenet_lib Catch2::Catch2WithMain)
endif()
