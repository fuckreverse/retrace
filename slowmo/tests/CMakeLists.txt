# ═══════════════════════════════════════════════════════════════════════════════
# Tenet test suite — CMake configuration
#
# Directory layout:
#   tests/
#   ├── CMakeLists.txt          ← this file
#   ├── fixtures/               ← shared headers (trace_writer.h, trace_fixture.h)
#   ├── unit/                   ← unit tests (one file per module/pass)
#   ├── integration/            ← integration tests (full pipeline)
#   ├── tools/                  ← test tools (gen_test_traces, gen_and_validate.sh)
#   └── traces/                 ← generated traces (gitignored, runtime only)
#
# All test executables link against tenet_lib + Catch2::Catch2WithMain.
# Run tests with:  ctest --test-dir build --output-on-failure
# ═══════════════════════════════════════════════════════════════════════════════

# Catch2's CTest integration: provides catch_discover_tests() which registers
# each TEST_CASE as an individual CTest entry (runnable via ctest -R <name>).
include(Catch)

# Test fixtures are headers; expose them to all test targets.
set(TENET_TEST_INCLUDES
    "${CMAKE_CURRENT_SOURCE_DIR}"           # for #include "fixtures/..."
    "${CMAKE_CURRENT_SOURCE_DIR}/../qbditrace"  # for TraceFormat.h
)

# ─── Helper: add a Catch2 test executable ───────────────────────────────────
function(tenet_add_test target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} PRIVATE tenet_lib Catch2::Catch2WithMain)
    target_include_directories(${target_name} PRIVATE ${TENET_TEST_INCLUDES})
    # Catch2 test discovery: registers each TEST_CASE as a CTest entry.
    # PRE_TEST mode defers discovery to ctest run-time so configure-stage
    # doesn't need the binary to already be built (avoids _NOT_BUILT entries).
    catch_discover_tests(${target_name} DISCOVERY_MODE PRE_TEST)
endfunction()

# ─── Unit tests: core layer ─────────────────────────────────────────────────
tenet_add_test(test_common_lru_cache       unit/test_common_lru_cache.cpp)
tenet_add_test(test_io_trace_reader        unit/test_io_trace_reader.cpp)
tenet_add_test(test_core_register_file     unit/test_core_register_file.cpp)
tenet_add_test(test_core_instruction_decoder unit/test_core_instruction_decoder.cpp)

# ─── Unit tests: analysis passes ────────────────────────────────────────────
tenet_add_test(test_pass_xref              unit/test_pass_xref.cpp)
tenet_add_test(test_pass_cfg               unit/test_pass_cfg.cpp)
tenet_add_test(test_pass_taint             unit/test_pass_taint.cpp)
tenet_add_test(test_pass_loop              unit/test_pass_loop.cpp)
tenet_add_test(test_pass_function          unit/test_pass_function.cpp)
tenet_add_test(test_pass_call_graph        unit/test_pass_call_graph.cpp)
tenet_add_test(test_pass_string            unit/test_pass_string.cpp)
tenet_add_test(test_pass_disassembly       unit/test_pass_disassembly.cpp)

# ─── Integration tests ──────────────────────────────────────────────────────
tenet_add_test(test_pipeline               integration/test_pipeline.cpp)

# ─── Performance regression tests ──────────────────────────────────────────
# Tagged [perf]; run with:  ctest -R perf --output-on-failure
# Exclude with:             ctest -E perf
# Thresholds are env-overridable (see perf/perf_utils.h).
tenet_add_test(test_perf_io               perf/test_perf_io.cpp)
tenet_add_test(test_perf_core             perf/test_perf_core.cpp)
tenet_add_test(test_perf_passes           perf/test_perf_passes.cpp)

# ─── Test tool: synthetic trace generator ───────────────────────────────────
add_executable(gen_test_traces tools/gen_test_traces.cpp)
target_link_libraries(gen_test_traces PRIVATE tenet_lib)
target_include_directories(gen_test_traces PRIVATE ${TENET_TEST_INCLUDES})
