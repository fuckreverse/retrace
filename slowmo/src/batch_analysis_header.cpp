#include "batch_analysis.h"

#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/xref_pass.h"
#include "analysis/passes/cfg_pass.h"
#include "analysis/passes/cfg_layout_pass.h"
#include "analysis/passes/string_pass.h"
#include "analysis/passes/pattern_pass.h"
#include "analysis/passes/constant_materialization_pass.h"
#include "analysis/passes/call_graph_pass.h"
#include "analysis/passes/function_pass.h"
#include "analysis/passes/taint_pass.h"
#include "analysis/passes/backward_taint_pass.h"
#include "analysis/passes/loop_pass.h"
#include "analysis/passes/loop_semantics_pass.h"
#include "analysis/passes/trace_diff_pass.h"
#include "analysis/passes/symbol_annotation_pass.h"
#include "analysis/passes/memory_snapshot_pass.h"
#include "analysis/passes/memory_string_pass.h"
#include "analysis/passes/dataflow_graph_pass.h"
#include "analysis/passes/algorithm_summary_pass.h"
#include "analysis/passes/objc_pass.h"
#include "analysis/passes/thread_pass.h"
#include "analysis/passes/trace_fold_pass.h"
#include "analysis/passes/reg_timeline_pass.h"
#include "analysis/passes/mem_search_pass.h"
#include "analysis/passes/call_context_pass.h"
#include "analysis/passes/window_stats_pass.h"
#include "analysis/passes/entropy_pass.h"
#include "analysis/passes/literal_search_pass.h"
#include "analysis/passes/cache_sim_pass.h"
#include "analysis/passes/yara_mem_scan_pass.h"
#include "analysis/passes/thread_filter_pass.h"
#include "analysis/passes/objc_crypto_pass.h"
#include "analysis/passes/syscall_intercept_pass.h"
#include "analysis/passes/taint_source_annotation_pass.h"
#include "io/rpc_server.h"
#include "io/mcp/mcp_server.h"
#include "io/streaming_index.h"

#include "common/logger.h"

#include <fmt/core.h>
#include <fmt/color.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace tenet;
using json = nlohmann::json;

