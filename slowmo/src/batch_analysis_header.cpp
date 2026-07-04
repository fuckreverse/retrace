#include "batch_analysis.h"

#include "analysis/pass_manager.h"
#include "analysis/pass_registry.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/cfg_layout_pass.h"
#include "analysis/passes/memory/string_pass.h"
#include "analysis/passes/crypto/pattern_pass.h"  // also defines ConstantMaterializationResult
#include "analysis/passes/structure/call_graph_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/crypto/loop_semantics_pass.h"
#include "analysis/passes/profile/trace_diff_pass.h"
#include "analysis/annotation_view.h"
#include "analysis/passes/memory/memory_snapshot_pass.h"
#include "analysis/passes/memory/memory_string_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "analysis/passes/crypto/algorithm_summary_pass.h"
#include "analysis/passes/platform/objc_pass.h"
#include "analysis/passes/misc/thread_pass.h"
#include "analysis/passes/profile/trace_fold_pass.h"
#include "analysis/passes/profile/reg_timeline_pass.h"
#include "analysis/passes/memory/mem_search_pass.h"
#include "analysis/passes/profile/call_context_pass.h"
#include "analysis/passes/profile/window_stats_pass.h"
#include "analysis/passes/memory/entropy_pass.h"
#include "analysis/passes/memory/yara_mem_scan_pass.h"
#include "analysis/passes/misc/thread_filter_pass.h"
#include "analysis/passes/crypto/objc_crypto_pass.h"
#include "analysis/passes/platform/syscall_intercept_pass.h"
#include "analysis/passes/taint/taint_source_annotation_pass.h"
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

