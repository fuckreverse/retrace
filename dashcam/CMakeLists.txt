# qbditrace — high-performance instruction tracer built on QBDI
#
# Self-contained CMake project (not wired into the main QBDI build).
# Produces three categories of artifacts:
#
#   * libqbditrace (SHARED)  — tracer dylib, loaded into the target by Frida
#   * unit / integration tests (host) — lightweight, no QBDI required
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Fixed build directories (DO NOT create new ones)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   Directory               Purpose                          cmake command
#   ──────────────────────  ───────────────────────────────── ─────────────
#   build/                  Host tests (default)             cmake ..
#   build-ios/              iOS dylib (cross-compile)        (see below)
#   build-android/          Android .so (cross-compile)      (see below)
#
# All FetchContent sources are cached in _deps/ (shared across all build
# dirs).  Never delete _deps/ — it avoids re-downloading zstd, Catch2, etc.
#
# Daily development (incremental build):
#
#   cd tools/qbditrace/build && ninja -j$(nproc)
#
# First-time setup (host tests):
#
#   cd tools/qbditrace && mkdir build && cd build
#   cmake .. -G Ninja -DQBDITRACE_BUILD_DYLIB=OFF
#   ninja -j$(nproc)
#   ctest --output-on-failure
#
# iOS dylib cross-compile (from repo root):
#
#   bash tools/qbditrace/build-qbditrace-ios.sh
#
# Or manually:
#
#   cmake -S tools/qbditrace -B tools/qbditrace/build-ios \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/config/ios.toolchain.cmake \
#         -DPLATFORM=OS64 \
#         -DQBDI_INCLUDE_DIR=$PWD/include \
#         -DQBDI_BUILD_INCLUDE_DIR="$PWD/build-ios/include;$PWD/build-ios/include-static" \
#         -DQBDI_STATIC_LIB=$PWD/build-ios/libQBDI.a \
#         -DQBDITRACE_BUILD_DYLIB=ON \
#         -DQBDITRACE_BUILD_TESTS=OFF
#   cmake --build tools/qbditrace/build-ios
#
# Android .so cross-compile (from repo root):
#
#   bash tools/qbditrace/build-qbditrace-android.sh
#
# Or manually:
#
#   cmake -S tools/qbditrace -B tools/qbditrace/build-android -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=$NDK_PATH/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=24 \
#         -DQBDI_INCLUDE_DIR=$PWD/include \
#         -DQBDI_BUILD_INCLUDE_DIR="$PWD/build-android/include;$PWD/build-android/include-static" \
#         -DQBDI_STATIC_LIB=$PWD/build-android/libQBDI.a \
#         -DQBDITRACE_BUILD_DYLIB=ON \
#         -DQBDITRACE_BUILD_TESTS=OFF
#   cmake --build tools/qbditrace/build-android

cmake_minimum_required(VERSION 3.16)
project(qbditrace C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(QBDITRACE_BUILD_DYLIB "Build the tracer dylib" ON)
option(QBDITRACE_BUILD_TESTS "Build unit tests (host)" ON)
option(QBDITRACE_ENABLE_ZSTD "Enable zstd compression for trace output" ON)

# ---------------------------------------------------------------------------
# FetchContent shared cache (same pattern as tenet)
# ---------------------------------------------------------------------------
# All FetchContent sources are cached under tools/qbditrace/_deps/.  This
# directory is shared across all build trees (build/, build-host-test/, etc.)
# so dependencies are downloaded once and never re-cloned.
#
# If tenet's _deps/ already has the source (e.g. zstd, Catch2), the
# FETCHCONTENT_UPDATES_DISCONNECTED flag skips network checks entirely.
include(FetchContent)
if(NOT DEFINED FETCHCONTENT_BASE_DIR OR FETCHCONTENT_BASE_DIR STREQUAL "")
  set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/_deps" CACHE PATH
      "Shared FetchContent source cache (shared across all build trees)" FORCE)
endif()
set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Skip network update check for already-downloaded FetchContent packages" FORCE)

# ---------------------------------------------------------------------------
# Zstd (static, source build via FetchContent)
# ---------------------------------------------------------------------------
if(QBDITRACE_ENABLE_ZSTD)
  # Disable everything except the static library.
  set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
  set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)

  FetchContent_Declare(zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG        v1.5.6
    SOURCE_SUBDIR  build/cmake   # the CMakeLists.txt lives here
  )
  FetchContent_MakeAvailable(zstd)
endif()

# ---------------------------------------------------------------------------
# Tracer dylib (target build)
# ---------------------------------------------------------------------------
if(QBDITRACE_BUILD_DYLIB)
  set(QBDI_INCLUDE_DIR "" CACHE PATH "QBDI public include dir (the one with QBDI.h)")
  set(QBDI_BUILD_INCLUDE_DIR "" CACHE PATH "QBDI build-generated include dir (Version.h, Config.h)")
  set(QBDI_STATIC_LIB "" CACHE FILEPATH "Path to prebuilt libQBDI.a")

  if(NOT QBDI_INCLUDE_DIR OR NOT QBDI_STATIC_LIB)
    message(FATAL_ERROR
      "QBDITRACE_BUILD_DYLIB requires -DQBDI_INCLUDE_DIR and -DQBDI_STATIC_LIB. "
      "See the comment header of this CMakeLists for an example invocation.")
  endif()

  add_library(qbditrace SHARED
    QBDITrace.cpp)

  target_include_directories(qbditrace PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${QBDI_INCLUDE_DIR})
  if(QBDI_BUILD_INCLUDE_DIR)
    target_include_directories(qbditrace PRIVATE ${QBDI_BUILD_INCLUDE_DIR})
  endif()

  target_link_libraries(qbditrace PRIVATE ${QBDI_STATIC_LIB})

  # QBDI may also need libqbdi-llvm.a; link it if present next to libQBDI.a.
  get_filename_component(_qbdi_libdir "${QBDI_STATIC_LIB}" DIRECTORY)
  if(EXISTS "${_qbdi_libdir}/libqbdi-llvm.a")
    target_link_libraries(qbditrace PRIVATE "${_qbdi_libdir}/libqbdi-llvm.a")
  endif()

  if(APPLE)
    target_link_libraries(qbditrace PRIVATE
      "-framework Foundation" "-framework CoreFoundation")
  endif()

  if(QBDITRACE_ENABLE_ZSTD AND TARGET libzstd_static)
    target_link_libraries(qbditrace PRIVATE libzstd_static)
    target_compile_definitions(qbditrace PRIVATE QBDITRACE_HAVE_ZSTD=1)
  endif()

  set_target_properties(qbditrace PROPERTIES
    OUTPUT_NAME qbditrace)
  if(APPLE)
    set_target_properties(qbditrace PROPERTIES MACOSX_RPATH ON)
  endif()
endif()

# ---------------------------------------------------------------------------
# NOTE: The offline decoder (trace_decode) has been removed.
# Use tenet --dump text|jsonl instead:
#   tenet --dump text trace.bin       # human-readable listing
#   tenet --dump jsonl trace.bin      # machine-readable JSON Lines
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Unit tests (host build)
# ---------------------------------------------------------------------------
# These are lightweight, self-contained tests that do NOT require QBDI or
# Frida — they validate the on-disk trace format layout (static_asserts +
# runtime field checks) and the RingBuffer producer/consumer round-trip.
#
#   ctest --test-dir <build> --output-on-failure
# ---------------------------------------------------------------------------
option(QBDITRACE_BUILD_TESTS_INTEGRATION
    "Build the macOS in-process integration test (requires QBDI + tenet headers)"
    OFF)

if(QBDITRACE_BUILD_TESTS)
  enable_testing()

  # ── Legacy standalone tests (no Catch2 dependency) ─────────────────────────

  # test_trace_format: pure C, validates struct sizes / magic / field offsets.
  # All checks are _Static_assert (compile-time) plus a few runtime asserts.
  add_executable(test_trace_format tests/unit/test_trace_format.c)
  target_include_directories(test_trace_format PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME trace_format COMMAND test_trace_format)

  # test_ring_buffer: C++, exercises BackgroundWriter + ThreadBuffer round-trip,
  # chunk rotation, header-first ordering, and multi-thread buffer correctness.
  add_executable(test_ring_buffer tests/unit/test_ring_buffer.cpp)
  target_include_directories(test_ring_buffer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  find_package(Threads REQUIRED)
  target_link_libraries(test_ring_buffer PRIVATE Threads::Threads)
  add_test(NAME ring_buffer COMMAND test_ring_buffer)

  # ── Catch2 unit tests ───────────────────────────────────────────────────────
  # These require Catch2 3.x.  If tenet is available as a sibling CMake project
  # it already fetches Catch2 — we can borrow its target when present.
  # Otherwise, fetch Catch2 standalone so the tests can still be built.
  if(NOT TARGET Catch2::Catch2WithMain)
    FetchContent_Declare(Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG        v3.5.4
      GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH ${Catch2_SOURCE_DIR}/extras)
  endif()
  if(TARGET Catch2::Catch2WithMain)
    include(Catch)

    # test_trace_format_catch2: Catch2 version of the trace-format layout tests.
    add_executable(test_trace_format_catch2
        tests/unit/test_trace_format_catch2.cpp)
    target_include_directories(test_trace_format_catch2 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_trace_format_catch2 PRIVATE
        Catch2::Catch2WithMain)
    catch_discover_tests(test_trace_format_catch2 DISCOVERY_MODE PRE_TEST)

    # test_ring_buffer_catch2: Catch2 version of the RingBuffer tests.
    add_executable(test_ring_buffer_catch2
        tests/unit/test_ring_buffer_catch2.cpp)
    target_include_directories(test_ring_buffer_catch2 PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_ring_buffer_catch2 PRIVATE
        Catch2::Catch2WithMain Threads::Threads)
    catch_discover_tests(test_ring_buffer_catch2 DISCOVERY_MODE PRE_TEST)

    # test_flat_containers: FlatPcSet, FlatWriteRegCache, WriteRegList tests.
    add_executable(test_flat_containers
        tests/unit/test_flat_containers.cpp)
    target_include_directories(test_flat_containers PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_flat_containers PRIVATE
        Catch2::Catch2WithMain)
    catch_discover_tests(test_flat_containers DISCOVERY_MODE PRE_TEST)

    # test_qbditrace_ios: iOS/Darwin-specific logic — classifySyscall (Darwin
    # BSD + Mach trap), classifyObjcTarget (msgSend family), lookupCApiFunc
    # (binary-search table), TraceFormat iOS enum values, and Config defaults.
    # Depends only on QBDITraceInternal.h (no QBDI, no Frida required).
    add_executable(test_qbditrace_ios
        tests/unit/test_qbditrace_ios.cpp)
    target_include_directories(test_qbditrace_ios PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_qbditrace_ios PRIVATE
        Catch2::Catch2WithMain)
    catch_discover_tests(test_qbditrace_ios DISCOVERY_MODE PRE_TEST)
  endif()

  # ── macOS arm64 in-process integration test ─────────────────────────────────
  # Builds only on Apple arm64 when the QBDI static libs are present.
  # Optionally links against tenet_lib for full qbditrace+tenet joint tests
  # (QBDITRACE_TENET_INTEGRATION=1) when tenet is configured as a sibling.
  #
  # To enable the tenet joint tests, pass:
  #   -DQBDITRACE_BUILD_TESTS_INTEGRATION=ON
  #   -DTENET_BUILD_DIR=<path/to/tenet/build>   (e.g. tools/tenet/build)
  #
  # TENET_BUILD_DIR imports tenet_lib and its Catch2 from the existing tenet
  # build tree without re-running tenet's own cmake or rebuilding from source.
  set(TENET_BUILD_DIR "" CACHE PATH
      "Path to an existing tenet build directory (for tenet_lib import)")

  if(TENET_BUILD_DIR AND EXISTS "${TENET_BUILD_DIR}/build.ninja")
    get_filename_component(_tenet_src_dir "${TENET_BUILD_DIR}/.." ABSOLUTE)

    # Import Catch2 from tenet's pre-built _deps/ if not already available.
    if(NOT TARGET Catch2::Catch2WithMain)
      set(_c2src "${_tenet_src_dir}/_deps/catch2-src/src")
      set(_c2gen "${_tenet_src_dir}/_deps/catch2-build/generated-includes")
      set(_c2lib "${_tenet_src_dir}/_deps/catch2-build/src/libCatch2.a")
      set(_c2mainlib "${_tenet_src_dir}/_deps/catch2-build/src/libCatch2Main.a")

      if(EXISTS "${_c2lib}" AND EXISTS "${_c2mainlib}")
        add_library(Catch2::Catch2 STATIC IMPORTED GLOBAL)
        set_target_properties(Catch2::Catch2 PROPERTIES
            IMPORTED_LOCATION "${_c2lib}")
        if(EXISTS "${_c2src}" AND EXISTS "${_c2gen}")
          set_target_properties(Catch2::Catch2 PROPERTIES
              INTERFACE_INCLUDE_DIRECTORIES "${_c2src};${_c2gen}")
        endif()

        add_library(Catch2::Catch2WithMain STATIC IMPORTED GLOBAL)
        set_target_properties(Catch2::Catch2WithMain PROPERTIES
            IMPORTED_LOCATION "${_c2mainlib}"
            INTERFACE_LINK_LIBRARIES "Catch2::Catch2")
        if(EXISTS "${_c2src}" AND EXISTS "${_c2gen}")
          set_target_properties(Catch2::Catch2WithMain PROPERTIES
              INTERFACE_INCLUDE_DIRECTORIES "${_c2src};${_c2gen}")
        endif()

        # Provide include(Catch) module from tenet's Catch2 source.
        list(APPEND CMAKE_MODULE_PATH "${_tenet_src_dir}/_deps/catch2-src/extras")
        message(STATUS "qbditrace: imported Catch2::Catch2WithMain from tenet _deps")
      endif()
    endif()

    if(NOT TARGET tenet_lib)
      # Build the minimal imported target for tenet_lib.
      # We need the static library path and tenet source include dirs.
      set(_tenet_lib_path "${TENET_BUILD_DIR}/libtenet_lib.a")
      if(NOT EXISTS "${_tenet_lib_path}")
        # Try the non-lib prefix variant.
        set(_tenet_lib_path "${TENET_BUILD_DIR}/tenet_lib.a")
      endif()

      if(EXISTS "${_tenet_lib_path}")
        add_library(tenet_lib STATIC IMPORTED GLOBAL)
        set_target_properties(tenet_lib PROPERTIES
            IMPORTED_LOCATION "${_tenet_lib_path}")

        # Collect include directories from tenet source + build trees.
        # Directory names match the actual FetchContent naming in tenet's CMakeLists.
        set(_tenet_inc_dirs
            "${_tenet_src_dir}/src"
            "${TENET_BUILD_DIR}"
            "${_tenet_src_dir}/_deps/rocksdb-src/include"
            "${_tenet_src_dir}/_deps/roaring-src/include"
            "${_tenet_src_dir}/_deps/roaring-src/include/roaring"
            "${_tenet_src_dir}/_deps/roaring-src/cpp"              # roaring64map.hh
            "${_tenet_src_dir}/_deps/unordered_dense-src/include"  # ankerl::unordered_dense
            "${_tenet_src_dir}/_deps/fmt-src/include"
            "${_tenet_src_dir}/_deps/nlohmann_json-src/include"    # nlohmann::json
            "${_tenet_src_dir}/_deps/capstone-src/include"
        )

        # TBB headers (oneTBB fetched by tenet via FetchContent)
        if(EXISTS "${_tenet_src_dir}/_deps/onetbb-src/include")
          list(APPEND _tenet_inc_dirs "${_tenet_src_dir}/_deps/onetbb-src/include")
        endif()
        set_target_properties(tenet_lib PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${_tenet_inc_dirs}")

        # tenet_lib depends on several 3rd-party libs already built.
        # Paths match the actual layout of tools/tenet/_deps/.
        set(_tenet_extra_libs "")

        # rocksdb
        set(_p "${_tenet_src_dir}/_deps/rocksdb-build/librocksdb.a")
        if(EXISTS "${_p}")
          list(APPEND _tenet_extra_libs "${_p}")
        endif()

        # roaring (library lives in src/ sub-directory)
        set(_p "${_tenet_src_dir}/_deps/roaring-build/src/libroaring.a")
        if(EXISTS "${_p}")
          list(APPEND _tenet_extra_libs "${_p}")
        endif()

        # fmt (release build)
        set(_p "${_tenet_src_dir}/_deps/fmt-build/libfmt.a")
        if(NOT EXISTS "${_p}")
          set(_p "${_tenet_src_dir}/_deps/fmt-build/libfmtd.a")
        endif()
        if(EXISTS "${_p}")
          list(APPEND _tenet_extra_libs "${_p}")
        endif()

        # capstone
        set(_p "${_tenet_src_dir}/_deps/capstone-build/libcapstone.a")
        if(EXISTS "${_p}")
          list(APPEND _tenet_extra_libs "${_p}")
        endif()

        # zstd (used by rocksdb internally, needed for link)
        set(_p "${_tenet_src_dir}/_deps/zstd-build/lib/libzstd.a")
        if(EXISTS "${_p}")
          list(APPEND _tenet_extra_libs "${_p}")
        endif()

        # lz4 (used by rocksdb for compression, usually a system library)
        find_library(_lz4_lib NAMES lz4)
        if(_lz4_lib)
          list(APPEND _tenet_extra_libs "${_lz4_lib}")
        endif()
        unset(_lz4_lib)

        # TBB (oneTBB — built by tenet via FetchContent; the static lib lands in
        # a compiler-id subdirectory under the tenet build tree, e.g.
        #   <build>/appleclang_17.0_cxx17_64_relwithdebinfo/libtbb.a
        # Use file(GLOB_RECURSE) to find it regardless of the exact subdir name.)
        file(GLOB_RECURSE _tbb_lib "${TENET_BUILD_DIR}/*/libtbb.a")
        if(_tbb_lib)
          list(GET _tbb_lib 0 _tbb_lib)
          list(APPEND _tenet_extra_libs "${_tbb_lib}")
          message(STATUS "qbditrace: found TBB at ${_tbb_lib}")
        else()
          # Fallback: try system-installed TBB
          find_library(_tbb_sys_lib NAMES tbb)
          if(_tbb_sys_lib)
            list(APPEND _tenet_extra_libs "${_tbb_sys_lib}")
            message(STATUS "qbditrace: found system TBB at ${_tbb_sys_lib}")
          endif()
          unset(_tbb_sys_lib)
        endif()
        unset(_tbb_lib)

        if(_tenet_extra_libs)
          set_target_properties(tenet_lib PROPERTIES
              INTERFACE_LINK_LIBRARIES "${_tenet_extra_libs}")
        endif()

        message(STATUS "qbditrace: imported tenet_lib from ${_tenet_lib_path}")
      else()
        message(STATUS "qbditrace: tenet_lib not found in TENET_BUILD_DIR=${TENET_BUILD_DIR} (libtenet_lib.a missing)")
      endif()
    endif()
  endif()

  if(QBDITRACE_BUILD_TESTS_INTEGRATION AND APPLE AND
     CMAKE_SYSTEM_PROCESSOR MATCHES "arm64" AND
     QBDI_STATIC_LIB AND EXISTS "${QBDI_STATIC_LIB}")

    set(_integ_libs
        ${QBDI_STATIC_LIB}
        Threads::Threads)

    get_filename_component(_qbdi_libdir "${QBDI_STATIC_LIB}" DIRECTORY)
    if(EXISTS "${_qbdi_libdir}/libqbdi-llvm.a")
      list(APPEND _integ_libs "${_qbdi_libdir}/libqbdi-llvm.a")
    endif()

    set(_integ_defs "")
    set(_integ_include_dirs
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${QBDI_INCLUDE_DIR})
    if(QBDI_BUILD_INCLUDE_DIR)
      list(APPEND _integ_include_dirs ${QBDI_BUILD_INCLUDE_DIR})
    endif()

    # Optional tenet integration: link against tenet_lib if available
    if(TARGET tenet_lib AND TARGET Catch2::Catch2WithMain)
      list(APPEND _integ_libs tenet_lib Catch2::Catch2WithMain)
      list(APPEND _integ_defs QBDITRACE_TENET_INTEGRATION=1)
      # tenet source include dirs (for io/, core/, analysis/ headers)
      get_target_property(_tenet_incs tenet_lib INTERFACE_INCLUDE_DIRECTORIES)
      if(_tenet_incs)
        list(APPEND _integ_include_dirs ${_tenet_incs})
      endif()
    elseif(TARGET Catch2::Catch2WithMain)
      list(APPEND _integ_libs Catch2::Catch2WithMain)
    endif()

    add_executable(test_qbditrace_macos
        tests/integration/test_qbditrace_macos.cpp
        QBDITrace.cpp)

    target_include_directories(test_qbditrace_macos PRIVATE
        ${_integ_include_dirs})
    # zstd: the integration test embeds QBDITrace.cpp which uses zstd.
    # Link the same libzstd that was built for qbditrace (or the one in tenet's _deps).
    if(TARGET libzstd_static)
      list(APPEND _integ_libs libzstd_static)
      list(APPEND _integ_defs QBDITRACE_HAVE_ZSTD=1)
    elseif(TARGET tenet_lib)
      # tenet already has zstd in its INTERFACE_LINK_LIBRARIES; add the define.
      list(APPEND _integ_defs QBDITRACE_HAVE_ZSTD=1)
    endif()

    target_compile_definitions(test_qbditrace_macos PRIVATE
        ${_integ_defs})
    target_link_libraries(test_qbditrace_macos PRIVATE
        ${_integ_libs}
        "-framework Foundation" "-framework CoreFoundation"
        "-framework Security")
    target_compile_options(test_qbditrace_macos PRIVATE -O2)

    if(TARGET Catch2::Catch2WithMain)
      include(Catch)
      catch_discover_tests(test_qbditrace_macos
          TEST_PREFIX "qbditrace_macos::"
          DISCOVERY_MODE PRE_TEST)
    else()
      add_test(NAME qbditrace_macos COMMAND test_qbditrace_macos)
    endif()
  endif()
endif()
