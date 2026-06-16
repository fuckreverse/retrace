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
# Or skip CMake entirely (this exact command is verified to link):
#   xcrun --sdk iphoneos clang++ -arch arm64 -std=c++17 -O2 -dynamiclib \
#       -Iinclude -Ibuild-ios/include -Ibuild-ios/include-static -Itools/qbditrace \
#       tools/qbditrace/QBDITrace.cpp build-ios/libQBDI.a build-ios/libqbdi-llvm.a \
#       -framework Foundation -framework CoreFoundation -o libqbditrace.dylib

cmake_minimum_required(VERSION 3.16)
project(qbditrace CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(QBDITRACE_BUILD_DYLIB "Build the tracer dylib" ON)
option(QBDITRACE_BUILD_DECODER "Build the offline decoder (host tool)" ON)

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
