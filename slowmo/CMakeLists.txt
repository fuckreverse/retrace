cmake_minimum_required(VERSION 3.20)
# Embed MSVC debug information in object files so parallel builds and sccache
# do not contend for a shared compiler PDB. CMP0141 must be set before project().
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo>:Embedded>")
endif()

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

# GCC/Clang-only flags (-fprofile-generate/-use have no MSVC equivalent here;
# MSVC has its own /GENPROFILE /USEPROFILE PGO flow, out of scope for now).
if(NOT MSVC)
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
elseif(NOT TENET_PGO_MODE STREQUAL "")
    message(STATUS "PGO: TENET_PGO_MODE ignored under MSVC (no -fprofile-* support)")
endif()

# Target Apple Silicon (M1+) for NEON auto-vectorization and LSE atomics.
# Only set for Release builds; RelWithDebInfo keeps generic codegen to avoid
# recompiling everything when switching between machines, and to stay
# consistent with "no global optimizations" philosophy.
# This is strictly an Apple/arm64 tuning flag — GCC/Clang only, never passed
# under MSVC (which has no -mcpu flag and would fail to parse it).
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64" AND NOT CMAKE_CROSSCOMPILING)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=apple-m1")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=apple-m1")
        message(STATUS "Targeting Apple M1+ (NEON + LSE atomics)")
    endif()
endif()

# ─── MSVC compatibility ──────────────────────────────────────────────────────
# tenet is written against GCC/Clang idioms in a few places (e.g. __builtin_*,
# POSIX headers guarded by platform_compat.h). This block only adjusts MSVC's
# *compiler* behavior (exception handling model, __cplusplus reporting,
# UTF-8 source/execution charset, min/max macro pollution) — it does not by
# itself make every source file MSVC-portable.
if(MSVC)
    add_compile_options(/EHsc /utf-8 /Zc:__cplusplus /permissive-)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()

# ─── Options ────────────────────────────────────────────────────────────────
option(TENET_USE_SYSTEM_ROCKSDB "Use system-installed RocksDB" OFF)
option(TENET_USE_SYSTEM_CAPSTONE "Use system-installed Capstone" OFF)
# Triton and YARA are discovered via find_package()/pkg-config, both of which
# are a macOS/Linux (Homebrew/apt/vcpkg-with-pkgconfig) convention; neither
# ships an out-of-the-box story on Windows, so default them OFF there rather
# than fail configure for users who just want the core CLI/TUI/WS backend.
if(WIN32)
    option(TENET_ENABLE_TRITON "Enable Triton semantic oracle for precise taint analysis" OFF)
    option(TENET_ENABLE_YARA "Enable YARA rule engine for pattern detection" OFF)
else()
    option(TENET_ENABLE_TRITON "Enable Triton semantic oracle for precise taint analysis" ON)
    option(TENET_ENABLE_YARA "Enable YARA rule engine for pattern detection" ON)
endif()
option(TENET_BUILD_TESTS "Build unit tests" ON)
option(TENET_ENABLE_PYTHON "Build Python bindings via pybind11" OFF)
option(TENET_ENABLE_RPC "Build JSON-RPC TCP loopback server" ON)
# uWebSockets/uSockets' bundled event loop only has POSIX epoll/kqueue
# backends (see the TENET_ENABLE_WS block below) — no Windows IOCP backend
# is wired up yet, so default WS OFF on Windows until that's ported.
if(WIN32)
    option(TENET_ENABLE_WS "Build WebSocket service (uWebSockets + FlatBuffers)" OFF)
else()
    option(TENET_ENABLE_WS "Build WebSocket service (uWebSockets + FlatBuffers)" ON)
endif()
option(TENET_ENABLE_PROFILING "Enable os_signpost profiling instrumentation (macOS only, visible in Instruments)" ON)
option(TENET_ENABLE_TBB "Enable Intel oneTBB for parallel algorithms and task scheduling" ON)

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
    # LZ4 is picked up via find_package(lz4)/pkg-config on Linux/macOS (both
    # typically ship it or make it trivial to apt/brew install). RocksDB's
    # Windows CMake path instead expects LZ4_INCLUDE/LZ4_LIB_DEBUG/
    # LZ4_LIB_RELEASE to point at an external install (see thirdparty.inc) —
    # since tenet doesn't vendor or FetchContent LZ4, leave it off on Windows
    # rather than fail the RocksDB configure/build looking for a library that
    # was never provided.
    if(WIN32)
        set(WITH_LZ4 OFF CACHE BOOL "Enable LZ4 compression in RocksDB" FORCE)
    else()
        set(WITH_LZ4 ON CACHE BOOL "Enable LZ4 compression in RocksDB" FORCE)
    endif()
    set(ROCKSDB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(FAIL_ON_WARNINGS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(rocksdb)
    # RocksDB 9.4 globally injects ccache, wrapping our configured launcher
    # (including sccache on Windows). Use the project launcher only.
    get_property(_rocksdb_compile_launcher GLOBAL PROPERTY RULE_LAUNCH_COMPILE)
    if(_rocksdb_compile_launcher STREQUAL "ccache")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "")
        set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK "")
    endif()
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

# oneTBB - parallel algorithms & task scheduling (optional)
# Used by MemoryModel (parallel_sort), TraceIndex (parallel_sort), and
# MemorySnapshotPass (parallel_for_each).  Gated behind TENET_HAS_TBB so
# source files can #if-guard the <tbb/*> includes.
if(TENET_ENABLE_TBB)
    FetchContent_Declare(
        onetbb
        GIT_REPOSITORY https://github.com/oneapi-src/oneTBB.git
        GIT_TAG        v2023.0.0
        GIT_SHALLOW    TRUE
    )
    set(TBB_TEST OFF CACHE BOOL "" FORCE)
    set(TBB_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(TBB_STRICT OFF CACHE BOOL "" FORCE)
    # Keep TBB's own LTO off — it slows rebuilds of the tbb static lib and we
    # don't need it for the parallel-algorithm hot paths.
    set(TBB_ENABLE_IPO OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(onetbb)
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

# ── FlatBuffers (binary serialization for WS service) ────────────────────────
if(TENET_ENABLE_WS)
    FetchContent_Declare(
        flatbuffers
        GIT_REPOSITORY https://github.com/google/flatbuffers.git
        GIT_TAG        v25.2.10
        GIT_SHALLOW    TRUE
    )
    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_INSTALL OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_SHAREDLIB OFF CACHE BOOL "" FORCE)
    set(FLATBUFFERS_BUILD_FLATC ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(flatbuffers)

    # Generate C++ headers from FlatBuffers schema
    set(FBS_SCHEMA ${CMAKE_CURRENT_SOURCE_DIR}/src/ws/schema/tenet_ws.fbs)
    set(FBS_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
    file(MAKE_DIRECTORY ${FBS_GENERATED_DIR})

    add_custom_command(
        OUTPUT ${FBS_GENERATED_DIR}/tenet_ws_generated.h
        COMMAND flatc --cpp --gen-object-api
                -o ${FBS_GENERATED_DIR}
                ${FBS_SCHEMA}
        DEPENDS ${FBS_SCHEMA} flatc
        COMMENT "Compiling FlatBuffers schema: tenet_ws.fbs"
    )

    add_custom_target(tenet_ws_schema DEPENDS ${FBS_GENERATED_DIR}/tenet_ws_generated.h)
endif()

# ── uWebSockets + uSockets (WebSocket transport for WS service) ──────────────
if(TENET_ENABLE_WS AND WIN32)
    message(FATAL_ERROR
        "TENET_ENABLE_WS=ON is not supported on Windows yet: uSockets' bundled "
        "event loop (src/eventing/epoll_kqueue.c) only implements POSIX "
        "epoll/kqueue backends, with no libuv/IOCP backend wired into this "
        "build. Use -DTENET_ENABLE_WS=OFF (the Windows default) until that "
        "port lands.")
endif()
if(TENET_ENABLE_WS)
    FetchContent_Declare(
        uwebsockets
        GIT_REPOSITORY https://github.com/uNetworking/uWebSockets.git
        GIT_TAG        v20.73.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(
        usockets
        GIT_REPOSITORY https://github.com/uNetworking/uSockets.git
        GIT_TAG        v0.8.8
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(uwebsockets usockets)

    # uSockets — build as a static C library (no SSL, no libuv)
    file(GLOB USOCKETS_SRCS
        ${usockets_SOURCE_DIR}/src/*.c
        ${usockets_SOURCE_DIR}/src/eventing/epoll_kqueue.c
        ${usockets_SOURCE_DIR}/src/crypto/openssl.c
    )
    # Remove SSL source if present (we don't need TLS)
    list(FILTER USOCKETS_SRCS EXCLUDE REGEX ".*ssl\\.c$")

    add_library(usockets STATIC ${USOCKETS_SRCS})
    target_include_directories(usockets PUBLIC ${usockets_SOURCE_DIR}/src)
    target_compile_definitions(usockets PUBLIC LIBUS_NO_SSL=1)
    # Link zlib for permessage-deflate
    find_package(ZLIB REQUIRED)
    target_link_libraries(usockets PUBLIC ZLIB::ZLIB)

    # uWebSockets — header-only C++ wrapper
    add_library(uwebsockets INTERFACE)
    target_include_directories(uwebsockets INTERFACE ${uwebsockets_SOURCE_DIR}/src)
    target_link_libraries(uwebsockets INTERFACE usockets)
endif()

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
# On macOS/Linux, linking the shared library (MI_OVERRIDE=ON) replaces the
# system allocator process-wide via dyld/ld.so interposing — zero code
# changes needed. Yields 5-15% throughput on allocation-heavy paths (Pass
# concurrent containers, MCP serialization).
#
# On Windows, shared-library malloc override needs mimalloc's special
# "mimalloc-redirect" DLL + linker trick (see mimalloc's readme, "Overriding
# Malloc on Windows") which requires extra deployment steps (shipping
# mimalloc-redirect.dll next to the exe, /INCLUDE:malloc-override linker
# flag). Until that's wired into the sidecar packaging, default to a plain
# static build without global override on Windows — tenet still explicitly
# links mimalloc for its own allocations, it just won't intercept every
# malloc() process-wide.
if(WIN32)
    set(MI_OVERRIDE OFF CACHE BOOL "" FORCE)
    set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(MI_BUILD_STATIC ON CACHE BOOL "" FORCE)
else()
    set(MI_OVERRIDE ON CACHE BOOL "" FORCE)
    set(MI_BUILD_SHARED ON CACHE BOOL "" FORCE)
    set(MI_BUILD_STATIC OFF CACHE BOOL "" FORCE)
endif()
if(MI_BUILD_SHARED)
    set(TENET_MIMALLOC_TARGET mimalloc)
else()
    set(TENET_MIMALLOC_TARGET mimalloc-static)
endif()
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
    src/common/progress_manager.cpp
    src/io/trace_reader.cpp
    src/io/code_table.cpp
    src/io/index_builder.cpp
    src/io/recent_files.cpp
    src/io/vm_profiles.cpp
    src/io/trace_lock.cpp
    src/core/register_file.cpp
    src/core/instruction_decoder.cpp
    src/core/memory_model.cpp
    src/core/breakpoint_engine.cpp
    src/core/triton_bridge.cpp
    src/analysis/pass_manager.cpp
    src/analysis/pass_registry.cpp
    src/analysis/trace_collector.cpp
    src/infra/scan_orchestrator.cpp
    src/infra/page_stats.cpp
    src/infra/string_resolver.cpp
    src/infra/checkpoint_manager.cpp
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
    src/analysis/passes/platform/linux_syscalls.cpp
    src/analysis/passes/misc/thread_pass.cpp
    src/analysis/passes/profile/trace_fold_pass.cpp
    src/analysis/passes/profile/reg_timeline_pass.cpp
    src/analysis/passes/memory/mem_search_pass.cpp
    src/analysis/passes/profile/call_context_pass.cpp
    src/analysis/passes/profile/window_stats_pass.cpp
    src/analysis/passes/memory/entropy_pass.cpp
    src/analysis/passes/memory/yara_mem_scan_pass.cpp
    src/analysis/passes/misc/thread_filter_pass.cpp
    src/analysis/passes/misc/cross_thread_dataflow_pass.cpp
    src/analysis/passes/crypto/objc_crypto_pass.cpp
    src/analysis/passes/platform/syscall_intercept_pass.cpp
    src/analysis/passes/taint/taint_source_annotation_pass.cpp
    src/io/rpc_server.cpp
    src/io/mcp/mcp_server.cpp
    src/io/mcp/mcp_http.cpp
    src/io/mcp/mcp_hub.cpp
    src/io/mcp/mcp_websocket.cpp
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
    src/cli_options.cpp
    src/cli/trace_dump.cpp
)

target_include_directories(tenet_lib BEFORE PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    # Access qbditrace TraceFormat.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../dashcam
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
    # Add Triton and Z3 headers as SYSTEM includes (after our own deps).
    # Z3 headers needed by Triton's z3Solver.hpp aren't reported by Triton's
    # own CMake config, so we resolve them explicitly via find_path() instead
    # of hardcoding a Homebrew-only path (which doesn't exist on Linux/apt,
    # vcpkg, or Windows installs).
    find_path(Z3_INCLUDE_DIR NAMES z3++.h z3.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include
        DOC "Directory containing z3.h / z3++.h (required by Triton's z3Solver.hpp)")
    if(Z3_INCLUDE_DIR)
        message(STATUS "Z3 headers found: ${Z3_INCLUDE_DIR}")
    else()
        message(WARNING "Z3 headers not found via find_path(); Triton build may fail. "
                         "Pass -DZ3_INCLUDE_DIR=/path/to/z3/include if needed.")
    endif()
    target_include_directories(tenet_lib SYSTEM PUBLIC
        ${TRITON_INCLUDE_DIRS}
        ${Z3_INCLUDE_DIR}
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

# oneTBB linkage (optional). When enabled, TENET_HAS_TBB=1 lights up the
# parallel_sort / parallel_for_each code paths in MemoryModel, TraceIndex,
# and MemorySnapshotPass.
if(TENET_ENABLE_TBB AND TARGET TBB::tbb)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_TBB=1)
    target_link_libraries(tenet_lib PUBLIC TBB::tbb)
    message(STATUS "oneTBB linked for parallel algorithm support")
else()
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_TBB=0)
    message(STATUS "oneTBB NOT available — parallel algorithms disabled")
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

# WebSocket service (uWebSockets + FlatBuffers)
if(TENET_ENABLE_WS)
    target_sources(tenet_lib PRIVATE
        src/ws/tenet_ws_service.cpp
        src/ws/ws_analysis_jobs.cpp
        src/ws/ws_analysis_task_queue.cpp
        src/ws/ws_async_reply_dispatcher.cpp
        src/ws/ws_handlers_hotpath.cpp
        src/ws/ws_handlers_nav.cpp
        src/ws/ws_handlers_analysis.cpp
    )

    target_link_libraries(tenet_lib PUBLIC uwebsockets flatbuffers)
    target_include_directories(tenet_lib PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/generated)
    add_dependencies(tenet_lib tenet_ws_schema)
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_WS=1)
else()
    target_compile_definitions(tenet_lib PUBLIC TENET_HAS_WS=0)
endif()

# ─── Main executable ────────────────────────────────────────────────────────
add_executable(tenet src/main.cpp src/batch_analysis.cpp)

target_link_libraries(tenet PRIVATE tenet_lib)

# mimalloc: global malloc override (linked to final executables so its dyld
# interpose records take effect process-wide, including code in tenet_lib).
target_link_libraries(tenet PRIVATE ${TENET_MIMALLOC_TARGET})

# ─── Benchmark ───────────────────────────────────────────────────────────────
add_executable(bench_tenet bench/bench_tenet.cpp)
target_link_libraries(bench_tenet PRIVATE tenet_lib ${TENET_MIMALLOC_TARGET})

add_executable(bench_all_passes bench/bench_all_passes.cpp)
target_link_libraries(bench_all_passes PRIVATE tenet_lib ${TENET_MIMALLOC_TARGET})

add_executable(bench_memory_snapshot bench/bench_memory_snapshot.cpp)
target_link_libraries(bench_memory_snapshot PRIVATE tenet_lib ${TENET_MIMALLOC_TARGET})

add_executable(bench_loop_only bench/bench_loop_only.cpp)
target_link_libraries(bench_loop_only PRIVATE tenet_lib ${TENET_MIMALLOC_TARGET})

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
