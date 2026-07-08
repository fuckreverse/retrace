#pragma once
// ═══════════════════════════════════════════════════════════════════════════
// Batch analysis runner for tenet CLI
//
// Encapsulates the entire "register passes → run → format output" pipeline
// that was previously inlined in main(). Main now only calls run_batch_analysis()
// when has_analysis_option() is true.
// ═══════════════════════════════════════════════════════════════════════════

#include "cli_options.h"
#include "io/trace_reader.h"
#include "io/code_table.h"
#include "io/index_builder.h"
#include "core/register_file.h"
#include "core/instruction_decoder.h"
#include "core/memory_model.h"
#include "service/tenet_service.h"

namespace tenet {

/// Run all CLI-requested analysis passes and print results.
/// Returns 0 on success, non-zero on any pass failure.
int run_batch_analysis(const CliOptions& opts,
                       TraceReader& reader,
                       TraceIndex& index,
                       CodeTable& code_table,
                       InstructionDecoder& decoder,
                       RegisterFile& regfile,
                       MemoryModel& memory);

/// Convenience overload — delegates to the 7-argument version.
int run_batch_analysis(const CliOptions& opts, TenetService& service);

}  // namespace tenet
