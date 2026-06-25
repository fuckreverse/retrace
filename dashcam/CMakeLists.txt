# qbditrace - high performance instruction tracer built on QBDI
#
# This is a self-contained CMake project (not wired into the main QBDI build)
# so it can be built against an already-compiled QBDI without re-running the
# heavy LLVM build. It produces two artifacts:
#
#   * libqbditrace (SHARED)  - the tracer dylib, loaded into the target by Frida.
#                              Built for the TARGET (e.g. iOS arm64), linking the
#                              prebuilt static libQBDI.a.
#   * trace_decode (host)    - the offline decoder. Built for the HOST. Disable
#                              with -DQBDITRACE_BUILD_DECODER=OFF if you only
#                              want the dylib (e.g. during cross-compilation).
#
# Because the dylib and the decoder usually target different platforms, build
# them in separate configure runs:
#
#   # 1) the dylib for iOS (reuse the same toolchain used to build QBDI).
#   #    Note: Config.h for the STATIC lib lives in build-ios/include-static,
#   #    while Version.h lives in build-ios/include -- pass BOTH.
#   cmake -S tools/qbditrace -B build-trace-ios \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/config/ios.toolchain.cmake \
#         -DPLATFORM=OS64 \
#         -DQBDI_INCLUDE_DIR=$PWD/include \
#         -DQBDI_BUILD_INCLUDE_DIR="$PWD/build-ios/include;$PWD/build-ios/include-static" \
#         -DQBDI_STATIC_LIB=$PWD/build-ios/libQBDI.a \
#         -DQBDITRACE_BUILD_DYLIB=ON -DQBDITRACE_BUILD_DECODER=OFF
#   cmake --build build-trace-ios
#
#   # 2) the decoder for the host (with Capstone):
#   cmake -S tools/qbditrace -B build-trace-host \
#         -DQBDITRACE_BUILD_DYLIB=OFF -DQBDITRACE_BUILD_DECODER=ON
#   cmake --build build-trace-host
#
# Or skip CMake entirely.  Use the build-qbditrace-ios.sh helper script from
# the repo root, which also cross-compiles zstd and enables compression:
#
#   bash tools/qbditrace/build-qbditrace-ios.sh
#
# Manual equivalent (without zstd — compression will be SILENTLY DISABLED):
#   xcrun --sdk iphoneos clang++ -arch arm64 -std=c++17 -O2 -dynamiclib \
#       -Iinclude -Ibuild-ios/include -Ibuild-ios/include-static -Itools/qbditrace \
#       tools/qbditrace/QBDITrace.cpp build-ios/libQBDI.a build-ios/libqbdi-llvm.a \
#       -framework Foundation -framework CoreFoundation -o libqbditrace.dylib
#
# With zstd (recommended — adds ~1.5MB to dylib, enables ~3-10x trace compression):
#   # First build libzstd for iOS (one-time):
#   ZSTD_SRC=tools/tenet/_deps/zstd-src/lib
#   xcrun --sdk iphoneos clang -arch arm64 -O2 -DZSTD_MULTITHREAD=0 \
#       -I${ZSTD_SRC} -I${ZSTD_SRC}/common \
#       -c ${ZSTD_SRC}/common/*.c ${ZSTD_SRC}/compress/*.c ${ZSTD_SRC}/decompress/*.c
#   ar rcs build-ios/libzstd.a *.o && rm -f *.o
#   # Then build dylib with zstd:
#   xcrun --sdk iphoneos clang++ -arch arm64 -std=c++17 -O2 -dynamiclib \
#       -DQBDITRACE_HAVE_ZSTD=1 \
#       -Iinclude -Ibuild-ios/include -Ibuild-ios/include-static \
#       -Itools/qbditrace -I${ZSTD_SRC} \
#       tools/qbditrace/QBDITrace.cpp build-ios/libQBDI.a build-ios/libqbdi-llvm.a \
#       build-ios/libzstd.a \
#       -framework Foundation -framework CoreFoundation -o libqbditrace.dylib

cmake_minimum_required(VERSION 3.16)
project(qbditrace C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(QBDITRACE_BUILD_DYLIB "Build the tracer dylib" ON)
option(QBDITRACE_BUILD_DECODER "Build the offline decoder (host tool)" ON)
option(QBDITRACE_BUILD_TESTS "Build unit tests (host)" ON)
option(QBDITRACE_ENABLE_ZSTD "Enable zstd compression for trace output" ON)

# ---------------------------------------------------------------------------
# Zstd (static, source build via FetchContent)
# ---------------------------------------------------------------------------
if(QBDITRACE_ENABLE_ZSTD)
  include(FetchContent)

  # Use the shared _deps cache from tenet if available, otherwise local.
  if(NOT FETCHCONTENT_BASE_DIR)
    set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../tenet/_deps"
        CACHE PATH "Shared FetchContent cache (reuse tenet's)")
  endif()

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
    OUTPUT_NAME qbditrace
    MACOSX_RPATH ON)
endif()

# ---------------------------------------------------------------------------
# Offline decoder (host build)
# ---------------------------------------------------------------------------
if(QBDITRACE_BUILD_DECODER)
  add_executable(trace_decode decoder/trace_decode.cpp)
  target_include_directories(trace_decode PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  # Try to locate Capstone for disassembly; degrade gracefully if absent.
  find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
  find_library(CAPSTONE_LIBRARY NAMES capstone)
  if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
    message(STATUS "qbditrace decoder: Capstone found, disassembly enabled")
    target_compile_definitions(trace_decode PRIVATE QBDITRACE_HAVE_CAPSTONE=1)
    target_include_directories(trace_decode PRIVATE ${CAPSTONE_INCLUDE_DIR})
    target_link_libraries(trace_decode PRIVATE ${CAPSTONE_LIBRARY})
  else()
    message(WARNING
      "qbditrace decoder: Capstone not found; will emit raw opcode words only. "
      "Install capstone (brew install capstone) for full disassembly.")
  endif()
endif()

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
  # Otherwise, skip silently (legacy tests above cover the same code paths).
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
  endif()

  # ── macOS arm64 in-process integration test ─────────────────────────────────
  # Builds only on Apple arm64 when the QBDI static libs are present.
  # Optionally links against tenet_lib for full qbditrace+tenet joint tests
  # (QBDITRACE_TENET_INTEGRATION=1) when tenet is configured as a sibling.
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
      get_target_property(_tenet_incs tenet_lib INCLUDE_DIRECTORIES)
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
    target_compile_definitions(test_qbditrace_macos PRIVATE
        ${_integ_defs})
    target_link_libraries(test_qbditrace_macos PRIVATE
        ${_integ_libs}
        "-framework Foundation" "-framework CoreFoundation")
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
