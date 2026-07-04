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
    # Tests prioritize build speed over runtime speed:
    #  - Never use LTO (each test links ~10x faster without it).
    #  - Cap optimization at -O1 in non-Debug configs; -O3 is pointless for
    #    unit tests and significantly slows compilation.
    set_target_properties(${target_name} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF)
    target_compile_options(${target_name} PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:-O1>)
    # Catch2 test discovery: registers each TEST_CASE as a CTest entry.
    # PRE_TEST mode defers discovery to ctest run-time so configure-stage
    # doesn't need the binary to already be built (avoids _NOT_BUILT entries).
    catch_discover_tests(${target_name} DISCOVERY_MODE PRE_TEST)
endfunction()

# ─── Unit tests: core layer ─────────────────────────────────────────────────
tenet_add_test(test_common_lru_cache       unit/test_common_lru_cache.cpp)
tenet_add_test(test_io_trace_reader        unit/test_io_trace_reader.cpp)
tenet_add_test(test_io_trace_reader_v5     unit/test_io_trace_reader_v5.cpp)
tenet_add_test(test_io_trace_reader_v6     unit/test_io_trace_reader_v6.cpp)
tenet_add_test(test_io_trace_reader_special unit/test_io_trace_reader_special.cpp)
tenet_add_test(test_io_trace_reader_compressed unit/test_io_trace_reader_compressed.cpp)
tenet_add_test(test_io_block_compressed    unit/test_io_block_compressed.cpp)
tenet_add_test(test_core_register_file     unit/test_core_register_file.cpp)
tenet_add_test(test_core_instruction_decoder unit/test_core_instruction_decoder.cpp)
tenet_add_test(test_core_memory_model      unit/test_core_memory_model.cpp)
tenet_add_test(test_core_breakpoint_engine unit/test_core_breakpoint_engine.cpp)
tenet_add_test(test_gui_metal_ownership    unit/test_gui_metal_ownership.cpp)

# ─── Unit tests: analysis passes ────────────────────────────────────────────
tenet_add_test(test_pass_xref              unit/test_pass_xref.cpp)
tenet_add_test(test_pass_cfg               unit/test_pass_cfg.cpp)
tenet_add_test(test_pass_cfg_layout        unit/test_pass_cfg_layout.cpp)
tenet_add_test(test_graph_grid_layout      unit/test_graph_grid_layout.cpp)
tenet_add_test(test_pass_taint             unit/test_pass_taint.cpp)
tenet_add_test(test_pass_loop              unit/test_pass_loop.cpp)
tenet_add_test(test_pass_function          unit/test_pass_function.cpp)
tenet_add_test(test_pass_call_graph        unit/test_pass_call_graph.cpp)
tenet_add_test(test_pass_string            unit/test_pass_string.cpp)
tenet_add_test(test_pass_memory_string     unit/test_pass_memory_string.cpp)
tenet_add_test(test_pass_window_stats      unit/test_pass_window_stats.cpp)
tenet_add_test(test_pass_objc              unit/test_pass_objc.cpp)

# ─── Unit tests: newly-added analysis passes ────────────────────────────────
tenet_add_test(test_pass_backward_taint    unit/test_pass_backward_taint.cpp)
tenet_add_test(test_pass_taint_critical_path unit/test_pass_taint_critical_path.cpp)
tenet_add_test(test_pass_entropy           unit/test_pass_entropy.cpp)
tenet_add_test(test_pass_reg_timeline      unit/test_pass_reg_timeline.cpp)
tenet_add_test(test_pass_call_context      unit/test_pass_call_context.cpp)
tenet_add_test(test_pass_memory_snapshot   unit/test_pass_memory_snapshot.cpp)
tenet_add_test(test_pass_loop_semantics    unit/test_pass_loop_semantics.cpp)
tenet_add_test(test_pass_pattern           unit/test_pass_pattern.cpp)
tenet_add_test(test_pass_thread_filter     unit/test_pass_thread_filter.cpp)
tenet_add_test(test_pass_mem_search        unit/test_pass_mem_search.cpp)
tenet_add_test(test_exclude_range          unit/test_exclude_range.cpp)
tenet_add_test(test_pass_yara_mem_scan     unit/test_pass_yara_mem_scan.cpp)
tenet_add_test(test_pass_trace_diff        unit/test_pass_trace_diff.cpp)
tenet_add_test(test_pass_vm_abstract       unit/test_pass_vm_abstract.cpp)
tenet_add_test(test_pass_trace_fold        unit/test_pass_trace_fold.cpp)
tenet_add_test(test_pass_dataflow_graph    unit/test_pass_dataflow_graph.cpp)
tenet_add_test(test_dbg_loop               unit/test_dbg_loop.cpp)

# ─── Unit tests: iOS-specific analysis passes ────────────────────────────────
tenet_add_test(test_pass_algorithm_summary     unit/test_pass_algorithm_summary.cpp)
tenet_add_test(test_pass_objc_crypto           unit/test_pass_objc_crypto.cpp)
tenet_add_test(test_pass_syscall_intercept     unit/test_pass_syscall_intercept.cpp)
tenet_add_test(test_pass_taint_source_annotation unit/test_pass_taint_source_annotation.cpp)

# ─── Unit tests: MCP layer (hypothesis ledger, evidence verification, batch query)
tenet_add_test(test_mcp_hypothesis_ledger      unit/test_mcp_hypothesis_ledger.cpp)
tenet_add_test(test_mcp_tools_ai               unit/test_mcp_tools_ai.cpp)

# ─── Integration tests ──────────────────────────────────────────────────────
tenet_add_test(test_pipeline               integration/test_pipeline.cpp)
tenet_add_test(test_pipeline_objc          integration/test_pipeline_objc.cpp)
tenet_add_test(test_memory_reconstruction  integration/test_memory_reconstruction.cpp)

# test_mcp_http uses a shared in-process server environment (static singleton).
# Running all TEST_CASEs in a single process (instead of per-test discovery)
# avoids rebuilding the trace+RocksDB+server 48× and eliminates port races.
add_executable(test_mcp_http integration/test_mcp_http.cpp)
target_link_libraries(test_mcp_http PRIVATE tenet_lib Catch2::Catch2WithMain)
target_include_directories(test_mcp_http PRIVATE ${TENET_TEST_INCLUDES})
set_target_properties(test_mcp_http PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_options(test_mcp_http PRIVATE $<$<NOT:$<CONFIG:Debug>>:-O1>)
add_test(NAME "MCP HTTP (all)" COMMAND test_mcp_http --order rand)

# ─── Performance regression tests ──────────────────────────────────────────
# Tagged [perf]; run with:  ctest -R perf --output-on-failure
# Exclude with:             ctest -E perf
# Thresholds are env-overridable (see perf/perf_utils.h).
tenet_add_test(test_perf_io               perf/test_perf_io.cpp)
tenet_add_test(test_perf_core             perf/test_perf_core.cpp)
tenet_add_test(test_perf_passes           perf/test_perf_passes.cpp)
tenet_add_test(test_perf_block_vs_stream  perf/test_perf_block_vs_stream.cpp)

# ─── Test tool: synthetic trace generator ───────────────────────────────────
add_executable(gen_test_traces tools/gen_test_traces.cpp)
target_link_libraries(gen_test_traces PRIVATE tenet_lib)
target_include_directories(gen_test_traces PRIVATE ${TENET_TEST_INCLUDES})
# Same fast-build treatment as the test targets above.
set_target_properties(gen_test_traces PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
target_compile_options(gen_test_traces PRIVATE $<$<NOT:$<CONFIG:Debug>>:-O1>)
